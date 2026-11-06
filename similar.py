#!/usr/bin/env python3
"""Подбор серверов, похожих на те, что реально работают у тебя (экспорт из v2rayNG).

Берёт:
  my_working.txt  — серверы, которые у тебя работают (экспорт из v2rayNG после проверки пинга)
  my_bad.txt      — (необязательно) серверы, которые у тебя НЕ работают
  my_all.txt      — (необязательно) всё, что ты проверял до чистки: «не рабочие» = my_all минус my_working
  work/pool.txt   — все найденные collector.py ссылки (collector.py --pool-out work/pool.txt)

Как оценивает: запоминает признаки твоих рабочих серверов (ключ Reality pbk, UUID, подсеть /24,
провайдер/ASN, домен сервера, SNI, порт, транспорт, страна адреса) и даёт каждому кандидату баллы.
Признаки нерабочих серверов дают штраф. Редкие признаки весят больше частых.

Результат (папка out/):
  similar_to_mine.txt           — похожие И прошедшие проверку через Xray (имя по выходному IP)
  similar_to_mine_untested.txt  — похожие, но с раннера США не проверились (могут работать только из РФ);
                                  имя по адресу сервера, выход неизвестен
  similar_report.txt            — чему научился скрипт и сколько кандидатов отсеялось

Нужен collector.py в той же папке. Только стандартная библиотека Python 3.9+.
"""
import argparse
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
import collector as C  # noqa: E402

ROOT = Path(__file__).parent
OUT = ROOT / "out"

# ───────────────────────────── НАСТРОЙКИ ─────────────────────────────
WEIGHTS = {  # насколько сильно совпадение признака говорит «этот сервер такой же, как мой рабочий»
    "pbk": 5.0,     # тот же ключ Reality — почти наверняка тот же провайдер
    "net": 4.0,     # та же подсеть /24 (IPv6 — /48)
    "net16": 2.0,   # тот же блок /16: у одного хостера серверы часто лежат в соседних подсетях
    "sni_dom": 2.5, # SNI на поддомене того же сайта (у оператора это обычно его домен: tickets.x.net, api14.x.net)
    "uuid": 3.0,
    "asn": 3.0,     # тот же хостинг/оператор
    "domain": 2.0,  # тот же домен сервера (если адрес — доменное имя)
    "sni": 1.5,
    "cc": 1.0,      # та же страна адреса
    "port": 0.7,
    "type": 0.5,    # транспорт
}
MIN_SCORE = 2.0         # ниже — не берём
TOP_N = 150             # сколько серверов в каждом из двух итоговых файлов
TEST_TOP = 600          # сколько лучших по баллам проверять TCP и Xray
MAX_POOL = 8000         # потолок кандидатов (если собрано больше — берём по предварительным баллам)
MAX_ASN_IPS = 4000      # сколько IP спрашивать у ip-api про ASN
MAX_PER_PBK = 30        # не больше стольких серверов одного провайдера (pbk) в итоговом файле
# ─────────────────────────────────────────────────────────────────────


def key(c):
    return (c["host"], c["port"], c["uuid"])


def load(path):
    p = Path(path) if path else None
    if not p or not p.exists():
        return []
    out, seen = [], set()
    for link in C.extract_links(p.read_text(encoding="utf-8", errors="ignore")):
        c = C.parse_vless(link, keep_other=True)  # SNI не фильтруем: свои серверы берём как есть
        if c and key(c) not in seen:
            seen.add(key(c))
            out.append(c)
    return out


def subnet(ip):
    try:
        a = ipaddress.ip_address(ip)
        return str(ipaddress.ip_network(f"{ip}/{24 if a.version == 4 else 48}", strict=False))
    except ValueError:
        return ""


def subnet16(ip):
    try:
        if ipaddress.ip_address(ip).version == 4:
            return str(ipaddress.ip_network(f"{ip}/16", strict=False))
    except ValueError:
        pass
    return ""


def reg_domain(host):
    try:
        ipaddress.ip_address(host)
        return ""
    except ValueError:
        parts = host.split(".")
        return ".".join(parts[-2:]) if len(parts) >= 2 else ""


def features(c):
    f = {"pbk": c["q"]["pbk"], "uuid": c["uuid"], "sni": c["sni"], "port": str(c["port"]), "type": c["type"],
         "net": subnet(c["ip"]), "net16": subnet16(c["ip"]), "domain": reg_domain(c["host"]),
         "sni_dom": reg_domain(c["sni"]), "asn": c.get("asn", ""), "cc": c.get("cc", "")}
    return {k: v for k, v in f.items() if v}


def asn_lookup(ips):
    """ASN и страна по IP через ip-api.com (пакеты по 100; бесплатный лимит — 15 пакетов в минуту)."""
    res, ips = {}, list(ips)
    for i in range(0, len(ips), 100):
        body = json.dumps([{"query": ip, "fields": "status,countryCode,as,query"} for ip in ips[i:i + 100]]).encode()
        txt = C.http("http://ip-api.com/batch", headers={"Content-Type": "application/json"}, data=body)
        try:
            for r in json.loads(txt or "[]"):
                if r.get("status") == "success":
                    m = re.match(r"AS(\d+)", r.get("as", ""))
                    res[r["query"]] = {"asn": m.group(1) if m else "", "cc": r.get("countryCode", "")}
        except ValueError:
            pass
        time.sleep(4.5)
    return res


def enrich(servers, priority, use_asn, resolver=C.resolve, asn_fn=asn_lookup):
    """Добавляет каждому серверу IP (c['ip']) и, если можно, ASN/страну. Возвращает только тех, у кого есть IP."""
    hosts = sorted({c["host"] for c in servers})
    with cf.ThreadPoolExecutor(64) as ex:
        ip_of = dict(zip(hosts, ex.map(resolver, hosts)))
    servers = [c for c in servers if ip_of.get(c["host"])]
    for c in servers:
        c["ip"] = ip_of[c["host"]]
    if use_asn and servers:
        first = [c["ip"] for c in priority if c.get("ip")]  # сначала IP твоих серверов
        order = list(dict.fromkeys(first + sorted({c["ip"] for c in servers})))[:MAX_ASN_IPS]
        info = asn_fn(order)
        for c in servers:
            c.update({k: v for k, v in info.get(c["ip"], {}).items() if v})
    return servers


class Model:
    """Что мы знаем о твоих рабочих (pos) и нерабочих (neg) серверах, и как часто признак встречается в пуле (df)."""

    def __init__(self, good, bad, pool):
        self.pos, self.neg, self.df = Counter(), Counter(), Counter()
        for c in good:
            self.pos.update(features(c).items())
        for c in bad:
            self.neg.update(features(c).items())
        for c in pool:
            self.df.update(features(c).items())
        self.n = len(pool)

    def score(self, c):
        total = 0.0
        for kv in features(c).items():
            p, n = self.pos[kv], self.neg[kv]
            if p or n:
                rarity = 1 - self.df[kv] / (self.n + 1)  # признак есть у всех → почти ничего не значит
                total += WEIGHTS[kv[0]] * (p - n) / (p + n + 1) * rarity
        return total

    def top_features(self, kinds=("pbk", "net", "net16", "asn", "domain", "sni_dom", "sni", "cc"), k=5):
        lines = []
        for kind in kinds:
            items = sorted(((v, p) for (kk, v), p in self.pos.items() if kk == kind), key=lambda x: -x[1])[:k]
            if items:
                shown = ", ".join(f"{(v[:8] + '…') if kind == 'pbk' else v}×{p}" for v, p in items)
                lines.append(f"  {kind}: {shown}")
        return lines


def pick(items, n):
    """Лимиты: не больше MAX_PER_IP на адрес и MAX_PER_PBK на провайдера."""
    per_ip, per_pbk, out = Counter(), Counter(), []
    for c in items:
        pbk = c["q"]["pbk"]
        if per_ip[c["ip"]] >= C.MAX_PER_IP or per_pbk[pbk] >= MAX_PER_PBK:
            continue
        per_ip[c["ip"]] += 1
        per_pbk[pbk] += 1
        out.append(c)
        if len(out) >= n:
            break
    return out


def run(good, bad, pool, xray_bin=None, use_asn=True, use_geo=True, top_n=TOP_N, min_score=MIN_SCORE,
        test_top=TEST_TOP, sort="score", resolver=C.resolve, asn_fn=asn_lookup, tcp_fn=C.tcp_ping,
        probe_fn=C.probe, geo_fn=C.geo_lookup):
    st = Counter(my_working=len(good), my_bad=len(bad), pool_links=len(pool))

    good_keys, bad_keys = {key(c) for c in good}, {key(c) for c in bad}
    pool = [c for c in pool if key(c) not in good_keys and key(c) not in bad_keys]
    st["pool_after_removing_mine_and_bad"] = len(pool)

    # предварительный отбор, если пул огромный: по признакам, не требующим сети
    if len(pool) > MAX_POOL:
        for c in good + bad + pool:
            c.setdefault("ip", "")
        pre = Model(good, bad, pool)
        pool = sorted(pool, key=lambda c: -pre.score(c))[:MAX_POOL]
        st["pool_trimmed_to"] = len(pool)

    everything = enrich(good + bad + pool, good + bad, use_asn, resolver, asn_fn)
    ok = {id(c) for c in everything}
    good, bad, pool = [c for c in good if id(c) in ok], [c for c in bad if id(c) in ok], [c for c in pool if id(c) in ok]
    st["pool_resolved"] = len(pool)
    if not good:
        return [], [], Model([], [], []), st

    model = Model(good, bad, pool)
    scored = sorted(((model.score(c), c) for c in pool), key=lambda t: (-t[0], t[1]["base"]))
    scored = [(s, c) for s, c in scored if s >= min_score]
    st["similar_candidates"] = len(scored)

    # проверка лучших: TCP, затем реальный запуск в Xray
    head, tail = scored[:test_top], scored[test_top:]
    with cf.ThreadPoolExecutor(100) as ex:
        pings = list(ex.map(lambda t: tcp_fn(t[1]), head))
    alive = [(s, c, ms) for (s, c), ms in zip(head, pings) if ms is not None]
    st["tcp_ok"] = len(alive)
    tested, failed = [], []
    if xray_bin:
        with cf.ThreadPoolExecutor(C.SPEED_WORKERS) as ex:
            res = list(ex.map(lambda t: probe_fn(t[1], xray_bin), alive))
        for (s, c, ms), r in zip(alive, res):
            (tested if r else failed).append(dict(c, score=s, ms=ms, **(r or {})))
    else:
        failed = [dict(c, score=s, ms=ms) for s, c, ms in alive]
    st["xray_ok"] = len(tested)

    if sort == "speed":
        tested.sort(key=lambda c: (-c.get("mbps", 0.0), -c["score"]))
    else:
        tested.sort(key=lambda c: (-c["score"], -c.get("mbps", 0.0)))
    untested = sorted(failed + [dict(c, score=s, ms=0.0) for s, c in tail], key=lambda c: -c["score"])

    final_t, final_u = pick(tested, top_n), pick(untested, top_n)
    st["final_tested"], st["final_untested"] = len(final_t), len(final_u)

    ips = {c["exit_ip"] for c in final_t} | {c["ip"] for c in final_u}
    geo = geo_fn(ips) if use_geo and ips else {}
    for c in final_t:
        c["name"] = C.make_name(geo.get(c["exit_ip"], {}), c.get("exit_cc", ""))
    for c in final_u:
        c["name"] = C.make_name(geo.get(c["ip"], {}))
    return final_t, final_u, model, st


def write(final_t, final_u, model, st):
    OUT.mkdir(exist_ok=True)
    line = lambda c: f"{c['base']}#{C.up.quote(c['name'])}"
    for name, items in (("similar_to_mine.txt", final_t), ("similar_to_mine_untested.txt", final_u)):
        (OUT / name).write_text("".join(line(c) + "\n" for c in items), encoding="utf-8")
    rep = [f"{k}: {v}" for k, v in st.items()]
    rep += ["", "Чему научился (признаки твоих рабочих серверов):"] + model.top_features()
    (OUT / "similar_report.txt").write_text("\n".join(rep) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--good", default="my_working.txt")
    ap.add_argument("--bad", default="my_bad.txt")
    ap.add_argument("--all", default="my_all.txt", dest="all_", help="всё, что проверял до чистки; нерабочие = all − good")
    ap.add_argument("--pool", default="work/pool.txt", help="файл от collector.py --pool-out")
    ap.add_argument("--xray", help="путь к xray (или переменная XRAY_BIN); без него все результаты идут в untested")
    ap.add_argument("--no-asn", action="store_true", help="не запрашивать ASN (быстрее, но без признаков «тот же хостинг/страна»)")
    ap.add_argument("--no-geo", action="store_true")
    ap.add_argument("--any-sni", action="store_true", help="не ограничивать кандидатов российским SNI")
    ap.add_argument("--top", type=int, default=TOP_N)
    ap.add_argument("--min-score", type=float, default=MIN_SCORE)
    ap.add_argument("--sort", choices=["score", "speed"], default="score")
    args = ap.parse_args()

    good = load(args.good)
    if not good:
        C.log(f"! {args.good} пуст или не найден (нужны vless Reality ссылки) — подбирать не на чем, выхожу")
        return
    gk = {key(c) for c in good}
    bad = load(args.bad)
    bk = {key(b) for b in bad}
    bad += [c for c in load(args.all_) if key(c) not in gk and key(c) not in bk]
    if len(good) < 3:
        C.log(f"! в {args.good} всего {len(good)} серверов — подбор будет грубым, лучше 10+")

    pool = []
    pool_path = Path(args.pool)
    if not pool_path.exists():
        C.log(f"! нет {pool_path}: запусти collector.py с --pool-out {pool_path}")
        return
    seen = set()
    for link in C.extract_links(pool_path.read_text(encoding="utf-8", errors="ignore")):
        c = C.parse_vless(link, keep_other=True)
        if c and key(c) not in seen and (args.any_sni or c["tier"] > 0):
            seen.add(key(c))
            pool.append(c)

    found = shutil.which(args.xray or os.environ.get("XRAY_BIN") or "xray")
    xray_bin = str(Path(found).resolve()) if found and shutil.which("curl") else None
    if not xray_bin:
        C.log("! xray/curl не найдены — проверка через Xray пропущена, всё попадёт в similar_to_mine_untested.txt")

    final_t, final_u, model, st = run(good, bad, pool, xray_bin, not args.no_asn, not args.no_geo,
                                      args.top, args.min_score, sort=args.sort)
    write(final_t, final_u, model, st)
    C.log("Итого:\n" + "\n".join(f"  {k}: {v}" for k, v in st.items()))
    C.log("\n".join(["Признаки твоих серверов:"] + model.top_features()))


if __name__ == "__main__":
    main()
