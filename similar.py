#!/usr/bin/env python3
"""Поиск серверов, ПОХОЖИХ на твои рабочие (my_working.txt), среди всех найденных сборщиком ссылок.

Идея. Проверка с GitHub (США) не показывает, что работает у тебя в России, а твой список —
единственный честный сигнал. Серверы одного оператора обычно настроены одинаково, поэтому мы ищем
в пуле ссылок (work/pool.txt, его сохраняет collector.py с флагом --pool-out) серверы, у которых
совпадает с рабочими:
  pbk      — ключ Reality (один оператор часто ставит его на много серверов)        — самый сильный признак
  uuid     — один и тот же пользователь панели на нескольких серверах
  host     — тот же сервер с другим портом/пользователем
  family   — семейство домена (betust.net: tickets.betust.net, app.betust.net…) у адреса или SNI
  subnet   — подсеть /24 того же хостера
  sni      — точное совпадение SNI
Признак, который в пуле встречается у сотен чужих серверов (например SNI www.apple.com), ослабляется:
он ничего не говорит о похожести.

Дальше: DNS → TCP-проверка (отсев мёртвых) → (если есть xray) проверка Reality-серверов через Xray →
рейтинг по похожести → не больше N на адрес/ключ/семейство → до 450 серверов с именем «флаг, страна, город».

Результат (папка out/):
  similar_to_working.txt        — похожие серверы, самые похожие сверху
  similar_to_working_b64.txt    — то же, подпиской base64
  similar_verified.txt          — из них прошедшие Xray (отвечают и из США), по скорости
  similar_report.txt            — сколько серверов отсеялось на каждом шаге и почему похожи первые
  working_profile.json          — короткая сводка по твоим рабочим серверам (её удобно показать ИИ)

Запуск:  python similar.py --pool work/pool.txt --working my_working.txt --xray "$XRAY_BIN"
Нужен collector.py рядом (берём из него разбор ссылок, DNS, TCP, Xray, определение страны).
Только стандартная библиотека Python 3.9+; для проверки через Xray нужны xray и curl.
"""
from __future__ import annotations

import argparse
import base64
import collections
import concurrent.futures as cf
import ipaddress
import json
import os
import re
import shutil
import sys
import urllib.parse as up
from pathlib import Path
from types import SimpleNamespace

import collector as C  # разбор ссылок, DNS, TCP, Xray и страна — как в сборщике

# ───────────────────────────── НАСТРОЙКИ ─────────────────────────────
MAX_TOTAL = 450        # размер итогового списка
MIN_SCORE = 12         # порог «похожести» (без мелких поправок): ниже — сервер не считается похожим
MAX_PER_IP = 2         # не больше стольких серверов на один адрес
MAX_PER_PBK = 12       # не больше стольких серверов с одним ключом Reality (чтобы один оператор не занял весь список)
MAX_PER_FAMILY = 15    # ... с одного семейства доменов / подсети
MAX_DNS = 20000        # сколько хостов резолвить (сначала самые вероятные)
MAX_TCP = 8000         # сколько кандидатов пинговать по TCP
MAX_PROBE = 1200       # сколько Reality-кандидатов проверять через Xray
VERIFIED_BONUS = 8     # прибавка к рейтингу за успешную проверку Xray (жив даже из США)
WEIGHTS = {"pbk": 50, "uuid": 40, "host": 35, "fam": 30, "subnet": 25, "sni": 15}
COMMON = 40            # признак, который в пуле встречается чаще, считается слабым (вес × COMMON / число)
# ─────────────────────────────────────────────────────────────────────

SLD2 = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.br", "com.tr", "com.ua", "co.jp", "co.kr", "co.in",
    "co.za", "com.cn", "com.hk", "com.sg", "com.tw", "com.mx", "com.ar", "net.ru", "org.ru", "com.ru",
    "msk.ru", "spb.ru", "pp.ru", "co.il", "com.pl", "com.ro", "com.vn",
}


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def subnet24(ip):
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return ""
    return ".".join(str(ip).split(".")[:3]) if a.version == 4 else ""


def reg_domain(host):
    """Семейство домена: tickets.betust.net -> betust.net (для IP — пусто)."""
    host = (host or "").lower().rstrip(".")
    if not host or is_ip(host):
        return ""
    p = host.split(".")
    if len(p) <= 2:
        return host
    return ".".join(p[-3:]) if ".".join(p[-2:]) in SLD2 else ".".join(p[-2:])


def b64(text):
    s = re.sub(r"\s+", "", text).replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", "ignore")


# ───────────────────────────── признаки ссылки ─────────────────────────────
def features(link):
    """Любая ссылка (vless/vmess/trojan/hysteria2/…) -> dict признаков или None."""
    link = link.strip()
    if "://" not in link:
        return None
    scheme = link.split("://", 1)[0].lower()
    base = link.split("#", 1)[0]
    try:
        if scheme == "vmess":
            d = json.loads(b64(base[8:]))
            return {
                "scheme": "vmess", "base": base, "q": {}, "host": str(d.get("add", "")).lower(),
                "port": int(d.get("port") or 0), "uuid": str(d.get("id", "")).lower(), "pbk": "", "sid": "",
                "sni": str(d.get("sni") or d.get("host") or "").lower(), "type": str(d.get("net") or "tcp").lower(),
                "sec": "tls" if str(d.get("tls", "")).lower() == "tls" else "", "flow": "", "fp": str(d.get("fp") or ""),
            }
        u = up.urlsplit(base)
        q = {k.lower(): v for k, v in up.parse_qsl(u.query, keep_blank_values=True)}
        return {
            "scheme": scheme, "base": base, "q": q, "host": (u.hostname or "").lower(), "port": u.port or 0,
            "uuid": (u.username or "").lower() if scheme == "vless" else "", "pbk": q.get("pbk", ""),
            "sid": q.get("sid", ""), "sni": (q.get("sni") or q.get("peer") or q.get("servername") or "").strip().lower(),
            "type": (q.get("type") or "tcp").lower(), "sec": (q.get("security") or "").lower(),
            "flow": q.get("flow", ""), "fp": q.get("fp", ""),
        }
    except (ValueError, TypeError):
        return None


def known_key(f):
    return (f["host"], f["port"], f["uuid"], f["sni"], f["type"])


def build_profile(lines):
    """Что общего у твоих рабочих серверов -> (счётчики признаков, число серверов по типам, множество ключей)."""
    prof = {k: collections.Counter() for k in ("pbk", "uuid", "host", "fam", "sni", "subnet", "port", "type", "flow", "fp")}
    n, keys = collections.Counter(), set()
    for line in lines:
        f = features(line)
        if not f or not f["host"]:
            continue
        keys.add(known_key(f))
        n["servers"] += 1
        n[f["scheme"]] += 1
        prof["host"][f["host"]] += 1
        for fam in {reg_domain(f["host"]), reg_domain(f["sni"])} - {""}:
            prof["fam"][fam] += 1
        for key in ("sni", "pbk", "uuid"):
            if f[key]:
                prof[key][f[key]] += 1
        if is_ip(f["host"]) and subnet24(f["host"]):
            prof["subnet"][subnet24(f["host"])] += 1
        if f["scheme"] == "vless":
            n["vless_" + (f["sec"] or "none")] += 1
            prof["port"][f["port"]] += 1
            prof["type"][f["type"]] += 1
            prof["flow"][f["flow"]] += 1
            prof["fp"][f["fp"]] += 1
    return prof, n, keys


def parse_pool(link):
    """Ссылка из пула -> кандидат (vless Reality/TLS) или None."""
    f = features(link)
    if not f or f["scheme"] != "vless" or not f["port"] or not C.public_host(f["host"]):
        return None
    if not C.UUID_RE.match(f["uuid"]) or f["sec"] not in ("reality", "tls"):
        return None
    if (f["q"].get("encryption", "none") or "none").lower() != "none":
        return None
    if f["sec"] == "reality" and (not C.PBK_RE.match(f["pbk"]) or not C.SID_RE.match(f["sid"]) or not f["sni"]):
        return None
    f["fams"] = sorted({reg_domain(f["host"]), reg_domain(f["sni"])} - {""})
    f["ip"] = f["host"] if is_ip(f["host"]) else ""
    f["subnet"] = subnet24(f["ip"]) if f["ip"] else ""
    return f


def score(c, prof, pool_cnt, n_vless):
    """-> (сильные совпадения, мелкая поправка «типичность», причины)."""
    strong, why = 0.0, []

    def add(key, val, w):
        if not val:
            return 0.0
        work_n = prof[key].get(val, 0)
        if not work_n:
            return 0.0
        p = w * (1 + 0.15 * min(work_n - 1, 6))          # чем больше рабочих с этим признаком — тем увереннее
        pool_n = pool_cnt[key].get(val, 1)
        if pool_n > COMMON:                               # признак слишком частый в пуле — почти не говорит о похожести
            p *= COMMON / pool_n
        if p >= 2:
            why.append((key, val, round(p, 1)))
        return p

    strong += add("pbk", c["pbk"], WEIGHTS["pbk"])
    strong += add("uuid", c["uuid"], WEIGHTS["uuid"])
    strong += add("host", c["host"], WEIGHTS["host"])
    strong += max([add("fam", f, WEIGHTS["fam"]) for f in c["fams"]] or [0.0])
    strong += add("sni", c["sni"], WEIGHTS["sni"])
    strong += add("subnet", c.get("subnet", ""), WEIGHTS["subnet"])
    soft = 0.0
    if n_vless:  # «типичность»: порт, транспорт, flow и fingerprint как у большинства рабочих (только для порядка)
        soft = (6 * prof["port"].get(c["port"], 0) + 4 * prof["type"].get(c["type"], 0)
                + 3 * prof["flow"].get(c["q"].get("flow", ""), 0) + 2 * prof["fp"].get(c["q"].get("fp", ""), 0)) / n_vless
    return strong, soft, why


# ───────────────────────────── основной конвейер ─────────────────────────────
def pool_counters(cands):
    cnt = {k: collections.Counter() for k in ("pbk", "uuid", "host", "fam", "sni", "subnet")}
    for c in cands:
        for key in ("pbk", "uuid", "host", "sni"):
            if c[key]:
                cnt[key][c[key]] += 1
        for fam in c["fams"]:
            cnt["fam"][fam] += 1
        if c.get("subnet"):
            cnt["subnet"][c["subnet"]] += 1
    return cnt


def run(pool_links, working_lines, o, resolver=C.resolve, tcp_fn=C.tcp_ping, probe_fn=C.probe,
        geo_fn=C.geo_lookup, xray_bin=None, use_geo=True):
    stats = collections.Counter()
    prof, n, known = build_profile(working_lines)
    n_vless = n["vless"]
    stats["working_servers"] = n["servers"]

    # 1. разбор пула и дедупликация; уже известные (есть в my_working) пропускаем
    cands = {}
    for link in pool_links:
        c = parse_pool(link)
        if not c:
            stats["pool_unusable"] += 1
            continue
        key = known_key(c)
        if key in known:
            stats["pool_already_in_working"] += 1
            continue
        cands.setdefault(key, c)
    cands = list(cands.values())
    stats["pool_candidates"] = len(cands)
    pool_cnt = pool_counters(cands)

    # 2. первичный рейтинг без DNS; домены без совпадений резолвим для поиска общих подсетей
    for c in cands:
        c["strong"], c["soft"], c["why"] = score(c, prof, pool_cnt, n_vless)
    direct = [c for c in cands if c["strong"] >= o.min_score]
    stats["matched_before_dns"] = len(direct)
    rest = sorted((c for c in cands if c["strong"] < o.min_score and not c["ip"]), key=lambda c: -c["soft"])
    to_resolve = [c for c in direct if not c["ip"]] + rest
    hosts = list(dict.fromkeys(c["host"] for c in to_resolve))[: o.max_dns]

    # 3. DNS -> IP и подсеть /24; затем пересчёт рейтинга уже с подсетями
    with cf.ThreadPoolExecutor(64) as ex:
        ip_of = dict(zip(hosts, ex.map(resolver, hosts)))
    pool = []
    for c in cands:
        if not c["ip"]:
            c["ip"] = ip_of.get(c["host"]) or ""
            c["subnet"] = subnet24(c["ip"]) if c["ip"] else ""
        if c["ip"]:
            pool.append(c)
    stats["dns_ok"] = len(pool)
    pool_cnt = pool_counters(pool)
    for c in pool:
        c["strong"], c["soft"], c["why"] = score(c, prof, pool_cnt, n_vless)
    similar = sorted((c for c in pool if c["strong"] >= o.min_score), key=lambda c: (-c["strong"] - c["soft"], c["base"]))
    stats["similar_found"] = len(similar)
    for c in similar:
        for key, _, _ in c["why"]:
            stats[f"match_{key}"] += 1

    # 4. TCP: отсев мёртвых
    batch = similar[: o.max_tcp]
    with cf.ThreadPoolExecutor(100) as ex:
        pings = list(ex.map(tcp_fn, batch))
    alive = [dict(c, ms=ms) for c, ms in zip(batch, pings) if ms is not None]
    stats["tcp_ok"] = len(alive)

    # 5. проверка через Xray: только Reality (у TLS-серверов сборщик не умеет строить конфиг)
    if xray_bin:
        targets = [c for c in alive if c["sec"] == "reality"][: o.max_probe]
        log(f"Проверка через Xray: {len(targets)} серверов…")
        with cf.ThreadPoolExecutor(C.SPEED_WORKERS) as ex:
            res = list(ex.map(lambda c: probe_fn(c, xray_bin), targets))
        for c, r in zip(targets, res):
            if r:
                c.update(r)
                c["verified"] = True
        stats["xray_ok"] = sum(1 for c in alive if c.get("verified"))
    for c in alive:
        c.setdefault("verified", False)
        c.setdefault("mbps", 0.0)
        c["rank"] = c["strong"] + c["soft"] + (VERIFIED_BONUS if c["verified"] else 0)
    alive.sort(key=lambda c: (-c["rank"], -c["mbps"], c["ms"], c["base"]))

    # 6. лимиты: на адрес, на ключ Reality, на семейство/подсеть — чтобы список был разнообразным
    per_ip, per_pbk, per_group, final = (collections.Counter() for _ in range(4))
    final = []
    for c in alive:
        group = reg_domain(c["host"]) or c["subnet"] or c["ip"]
        if per_ip[c["ip"]] >= o.max_per_ip:
            stats["dropped_per_ip"] += 1
            continue
        if c["pbk"] and per_pbk[c["pbk"]] >= o.max_pbk:
            stats["dropped_per_pbk"] += 1
            continue
        if per_group[group] >= o.max_family:
            stats["dropped_per_family"] += 1
            continue
        per_ip[c["ip"]] += 1
        per_pbk[c["pbk"]] += 1
        per_group[group] += 1
        final.append(c)
        if len(final) >= o.max_total:
            break
    stats["final"] = len(final)

    # 7. имя: флаг, страна, город (по выходному IP, если проверяли через Xray)
    ips = {c["ip"] for c in final} | {c["exit_ip"] for c in final if c.get("exit_ip")}
    geo = geo_fn(ips) if use_geo and ips else {}
    for c in final:
        place = c.get("exit_ip") or c["ip"]
        c["name"] = C.make_name(geo.get(place, {}), c.get("exit_cc", ""))
    return final, stats, prof, n


def profile_summary(prof, n):
    """Короткая сводка по рабочим серверам: удобно показать ИИ (мало токенов)."""
    top = lambda k, m=12: [[v, c] for v, c in prof[k].most_common(m)]
    return {
        "servers": dict(n),
        "pbk_groups": [[v[:8] + "…", c] for v, c in prof["pbk"].most_common(12)],
        "domain_families": top("fam"), "sni": top("sni"), "subnets_24": top("subnet"),
        "ports": top("port", 8), "transports": top("type", 6), "flows": top("flow", 4), "fingerprints": top("fp", 6),
    }


def make_report(final, stats, prof, n):
    L = ["Похожие на рабочие серверы — отчёт", ""]
    L.append(f"Твоих рабочих серверов: {n['servers']} (vless {n['vless']}: reality {n['vless_reality']}, tls {n['vless_tls']}; "
             f"vmess {n['vmess']}, trojan {n['trojan']}, hysteria2 {n['hysteria2']})")
    L.append(f"Ключей Reality (pbk) среди рабочих: {len(prof['pbk'])}; семейств доменов: {len(prof['fam'])}; подсетей /24: {len(prof['subnet'])}")
    L.append("")
    for k in ("pool_unusable", "pool_already_in_working", "pool_candidates", "matched_before_dns", "dns_ok", "similar_found",
              "match_pbk", "match_uuid", "match_host", "match_fam", "match_subnet", "match_sni", "tcp_ok", "xray_ok",
              "dropped_per_ip", "dropped_per_pbk", "dropped_per_family", "final"):
        if k in stats:
            L.append(f"{k}: {stats[k]}")
    L += ["", "Первые 25 серверов и почему они похожи:"]
    for c in final[:25]:
        why = ", ".join(f"{k}={v[:24]}(+{p})" for k, v, p in c["why"][:3])
        L.append(f"  {c['rank']:.0f} {'✓' if c['verified'] else ' '} {c['name']} — {why}")
    return "\n".join(L) + "\n"


def write_outputs(out, final, stats, prof, n):
    out.mkdir(parents=True, exist_ok=True)
    line = lambda c: f"{c['base']}#{up.quote(c['name'])}"
    allp = "".join(line(c) + "\n" for c in final)
    (out / "similar_to_working.txt").write_text(allp, encoding="utf-8")
    (out / "similar_to_working_b64.txt").write_text(base64.b64encode(allp.encode()).decode(), encoding="utf-8")
    ver = sorted((c for c in final if c["verified"]), key=lambda c: -c["mbps"])
    (out / "similar_verified.txt").write_text("".join(line(c) + "\n" for c in ver), encoding="utf-8")
    (out / "similar_report.txt").write_text(make_report(final, stats, prof, n), encoding="utf-8")
    (out / "working_profile.json").write_text(
        json.dumps(profile_summary(prof, n), ensure_ascii=False, indent=1), encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Серверы, похожие на рабочие из my_working.txt")
    ap.add_argument("--pool", default="work/pool.txt", help="все найденные ссылки (collector.py --pool-out work/pool.txt)")
    ap.add_argument("--working", default="my_working.txt", help="твои рабочие серверы (экспорт из v2rayNG после проверки пинга)")
    ap.add_argument("--out", default="out", help="папка результата")
    ap.add_argument("--xray", help="путь к xray (или переменная XRAY_BIN); без него проверка только по TCP")
    ap.add_argument("--no-xray", action="store_true", help="не проверять через Xray")
    ap.add_argument("--no-geo", action="store_true", help="не определять страну по IP")
    ap.add_argument("--max-total", type=int, default=MAX_TOTAL)
    ap.add_argument("--min-score", type=float, default=MIN_SCORE, help="порог похожести (меньше — больше серверов, но менее похожих)")
    a = ap.parse_args()

    pool_path, work_path = Path(a.pool), Path(a.working)
    if not pool_path.exists():
        sys.exit(f"Нет файла {pool_path}: запусти collector.py с флагом --pool-out {pool_path}")
    if not work_path.exists():
        sys.exit(f"Нет файла {work_path}: положи туда рабочие серверы (экспорт из v2rayNG)")
    xray_bin = None
    if not a.no_xray:
        found = shutil.which(a.xray or os.environ.get("XRAY_BIN") or "xray")
        if found and shutil.which("curl"):
            xray_bin = str(Path(found).resolve())
        else:
            log("! xray или curl не найден — проверка только по TCP, имена по адресу сервера")
    o = SimpleNamespace(max_total=a.max_total, min_score=a.min_score, max_per_ip=MAX_PER_IP, max_pbk=MAX_PER_PBK,
                        max_family=MAX_PER_FAMILY, max_dns=MAX_DNS, max_tcp=MAX_TCP, max_probe=MAX_PROBE)
    pool = [x.strip() for x in pool_path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    working = [x.strip() for x in work_path.read_text(encoding="utf-8", errors="ignore").splitlines() if x.strip()]
    log(f"Пул: {len(pool)} ссылок; рабочих серверов в профиле: {len(working)}")
    final, stats, prof, n = run(pool, working, o, xray_bin=xray_bin, use_geo=not a.no_geo)
    write_outputs(Path(a.out), final, stats, prof, n)
    log(make_report(final, stats, prof, n))
    if not final:
        log("! похожих серверов не найдено — смотри similar_report.txt (можно снизить --min-score)")


if __name__ == "__main__":
    main()
