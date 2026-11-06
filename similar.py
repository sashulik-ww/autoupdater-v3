#!/usr/bin/env python3
"""Поиск серверов, ПОХОЖИХ на те, что работают у тебя (my_working.txt).

Идея: сервера одного оператора настроены одинаково. Если у тебя работает сервер с каким-то ключом
Reality (pbk), UUID, доменом или подсетью, то другие сервера из пула с теми же признаками
работают с большой вероятностью — и это проверено ТВОИМ телефоном в России, а не раннером в США.

Что делает:
  1. читает my_working.txt (любые протоколы) и пул work/pool.txt (его делает collector.py --pool-out);
  2. считает, какие признаки встречаются у рабочих серверов заметно чаще, чем в пуле («лифт» признака):
       - личность оператора: pbk, uuid, домен адреса, домен SNI;
       - сеть: подсеть /24 и /16 адреса;
       - профиль настроек: порт, транспорт, тип защиты, SNI, flow, fingerprint, длина sid;
  3. оценивает каждый сервер пула (чем больше редких общих признаков, тем выше оценка);
  4. лучших проверяет: DNS → TCP → (если есть xray) запуск и выходной IP со скоростью;
  5. имена по IP на английском: «🇩🇪 Germany, Frankfurt» (как в collector.py).

Результат (папка out/):
  similar_verified.txt    — похожие, прошедшие проверку Xray (самые быстрые сверху)
  similar_candidates.txt  — похожие, ответившие по TCP, но не прошедшие проверку с раннера США: проверь пингом сам
  similar_ruip.txt        — из обоих файлов только серверы с адресом в РФ
  similar_why.txt         — оценка и причины («совпал pbk…») для лучших кандидатов
  similar_report.txt      — воронка и самые «весомые» признаки твоих рабочих серверов

ИИ не нужен: оценка считается формулой, бесплатно и за секунды. Только стандартная библиотека Python;
лежит рядом с collector.py и использует его функции (сеть, Xray, определение страны).
"""
import argparse
import base64
import concurrent.futures as cf
import ipaddress
import json
import math
import re
import shutil
import sys
import time
import urllib.parse as up
from collections import Counter
from pathlib import Path

import collector as col

ROOT = Path(__file__).parent
OUT = col.OUT

# ───────────────────────────── настройки ─────────────────────────────
MAX_VERIFIED = 450      # размер similar_verified.txt
MAX_CANDIDATES = 1500   # размер similar_candidates.txt
MAX_PER_IP = 2          # не больше стольких серверов на один адрес
SHORTLIST = 20000       # сколько лучших по оценке берём в DNS
TCP_MAX = 4000          # сколько лучших проверяем по TCP
PROBE_MAX = 900         # сколько лучших из ответивших по TCP гоняем через Xray
W_ID, W_NET, W_PROF = 1.0, 0.7, 0.35  # вклад личности оператора, сети и профиля настроек в оценку
SUPPORTED_TYPES = {"tcp", "raw", "grpc", "http", "h2", "xhttp", "splithttp", "ws", "httpupgrade", "kcp"}
MULTI_SUFFIX = {
    "co.uk", "org.uk", "ac.uk", "com.au", "net.au", "com.br", "com.cn", "com.tr", "co.jp", "co.kr",
    "co.za", "com.ua", "com.ru", "net.ru", "org.ru", "com.hk", "com.tw", "com.sg", "co.in", "com.mx",
}


def log(*a):
    col.log(*a)


# ───────────────────────────── разбор ─────────────────────────────
def is_ip(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def reg_domain(host):
    """Регистрируемый домен: api.bachidze.com → bachidze.com. Для IP и одиночных имён — None."""
    host = (host or "").lower().strip(".")
    if not host or is_ip(host) or "." not in host:
        return None
    parts = host.split(".")
    tail2 = ".".join(parts[-2:])
    return ".".join(parts[-3:]) if tail2 in MULTI_SUFFIX and len(parts) >= 3 else tail2


def link_host(link):
    """Адрес сервера из ссылки любого протокола (vless, trojan, hysteria2, vmess…)."""
    try:
        if link.lower().startswith("vmess://"):
            payload = link.split("://", 1)[1].split("#", 1)[0].replace("-", "+").replace("_", "/")
            payload += "=" * (-len(payload) % 4)
            data = json.loads(base64.b64decode(payload).decode("utf-8", "ignore"))
            return (data.get("add") or "").lower() or None
        return (up.urlsplit(link).hostname or "").lower() or None
    except Exception:
        return None


def parse_vless_any(link, why):
    """Любой vless (Reality, TLS, без защиты; любой SNI и транспорт). None + причина в why, если не годится."""
    def no(reason):
        why[reason] += 1
        return None

    try:
        u = up.urlsplit(link)
        port, host = u.port, u.hostname
    except ValueError:
        return no("bad_url")
    if u.scheme != "vless" or not u.username or not port:
        return no("bad_url")
    if not col.public_host(host):
        return no("bad_host")
    if not col.UUID_RE.match(u.username):
        return no("bad_uuid")
    q = {k.lower(): v for k, v in up.parse_qsl(u.query, keep_blank_values=True)}
    sec = (q.get("security") or "none").lower()
    if sec not in ("reality", "tls", "none"):
        return no("security_unsupported")
    typ = (q.get("type") or "tcp").lower()
    if typ not in SUPPORTED_TYPES:
        return no("transport_unsupported")
    if sec == "reality" and (not col.PBK_RE.match(q.get("pbk", "")) or not col.SID_RE.match(q.get("sid", ""))):
        return no("bad_pbk_sid")
    sni = (q.get("sni") or q.get("servername") or q.get("peer") or "").strip().lower()
    if sec == "reality" and not sni:
        return no("no_sni")
    return {
        "base": link.split("#", 1)[0], "q": q, "type": typ, "host": host.lower(), "port": port,
        "uuid": u.username.lower(), "sni": sni, "sec": sec, "tier": col.match_tier(sni) if sni else 0,
    }


def ckey(c):
    return (c["host"], c["port"], c["uuid"], c["sni"], c["type"])


# ───────────────────────────── признаки ─────────────────────────────
def net_features(addr):
    if not addr or ":" in addr or not is_ip(addr):
        return []
    a = addr.split(".")
    return [f"net24:{'.'.join(a[:3])}", f"net16:{'.'.join(a[:2])}"]


def host_features(host, ip=None):
    """Признаки одного только адреса (для рабочих trojan/vmess/hysteria2 — их в пуле нет, но адрес выдаёт оператора)."""
    ids = []
    h2 = reg_domain(host)
    if h2:
        ids.append("host2:" + h2)
    return {"id": ids, "net": net_features(host if is_ip(host or "") else ip), "prof": []}


def features(c, ip=None):
    """Признаки vless-сервера по группам: id — личность оператора, net — сеть, prof — профиль настроек."""
    q = c["q"]
    ids = ["uuid:" + c["uuid"]]
    if q.get("pbk"):
        ids.append("pbk:" + q["pbk"])
    for tag, host in (("host2", c["host"]), ("sni2", c["sni"])):
        d = reg_domain(host)
        if d:
            ids.append(f"{tag}:{d}")
    prof = [f"port:{c['port']}", f"type:{c['type']}", f"sec:{c['sec']}"]
    if c["sni"]:
        prof.append("sni:" + c["sni"])
    if q.get("flow"):
        prof.append("flow:" + q["flow"])
    if q.get("fp"):
        prof.append("fp:" + q["fp"])
    if c["sec"] == "reality":
        prof.append(f"sidlen:{len(q.get('sid', ''))}")
    addr = c["host"] if is_ip(c["host"]) else ip
    return {"id": ids, "net": net_features(addr), "prof": prof}


def build_weights(work_feats, pool_counts, n_pool):
    """Вес признака = log(доля рабочих серверов с ним / доля пула с ним). Чем он у рабочих чаще, чем в пуле,
    тем сильнее говорит о сходстве. pbk/uuid, встречающиеся у рабочих и почти не встречающиеся в пуле, весят больше всего."""
    n_work = len(work_feats)
    cnt = Counter()
    for f in work_feats:
        cnt.update({x for group in f.values() for x in group})
    weights = {}
    for feat, cw in cnt.items():
        p_work = cw / n_work
        p_pool = (pool_counts.get(feat, 0) + 1) / (n_pool + 1)
        weights[feat] = max(0.0, math.log(p_work / p_pool))
    return weights


def short(feat):
    kind, _, val = feat.partition(":")
    return f"{kind}:{val[:10]}…" if kind in ("pbk", "uuid") and len(val) > 10 else feat


def score(feats, w):
    """-> (оценка, есть ли совпадение по личности/сети, причины)."""
    groups = {}
    for g, items in feats.items():
        groups[g] = sorted(((w.get(f, 0.0), f) for f in items if w.get(f, 0.0) > 0), reverse=True)
    ids, net, prof = groups["id"], groups["net"], groups["prof"]
    s_id = (ids[0][0] + 0.3 * sum(x for x, _ in ids[1:])) if ids else 0.0   # несколько совпадений усиливают друг друга
    s_net = net[0][0] if net else 0.0
    s_prof = min(3.0, sum(x for x, _ in prof))
    why = [short(f) for _, f in sorted(ids + net + prof, reverse=True)[:4]]
    return W_ID * s_id + W_NET * s_net + W_PROF * s_prof, bool(ids or net), why


# ───────────────────────────── Xray для любых vless ─────────────────────────────
_orig_xray_config = col.xray_config


def xray_config_any(c, port):
    """collector.xray_config умеет только Reality. Берём его (транспорты уже разобраны) и подменяем защиту."""
    c2 = dict(c, q=dict(c["q"]))
    c2["q"].setdefault("pbk", "x")
    cfg = _orig_xray_config(c2, port)
    if cfg is None:
        return None
    out = cfg["outbounds"][0]
    ss = out["streamSettings"]
    sec = c.get("sec", "reality")
    if sec == "tls":
        ss.pop("realitySettings", None)
        tls = {"serverName": c["sni"] or c["host"]}
        if c["q"].get("fp"):
            tls["fingerprint"] = c["q"]["fp"]
        if c["q"].get("alpn"):
            tls["alpn"] = [a for a in c["q"]["alpn"].split(",") if a]
        if (c["q"].get("allowinsecure") or c["q"].get("insecure")) in ("1", "true"):
            tls["allowInsecure"] = True
        ss["security"], ss["tlsSettings"] = "tls", tls
    elif sec == "none":
        ss.pop("realitySettings", None)
        ss["security"] = "none"
    user = out["settings"]["vnext"][0]["users"][0]
    user["encryption"] = c["q"].get("encryption") or "none"
    if c["q"].get("flow") and c["type"] in ("tcp", "raw"):
        user["flow"] = c["q"]["flow"]
    return cfg


col.xray_config = xray_config_any  # col.probe ищет эту функцию по имени в своём модуле


# ───────────────────────────── основная работа ─────────────────────────────
def read_lines(path):
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="ignore")
    if "://" not in text:  # файл целиком в base64
        text = col.try_b64(text) or text
    return [ln.strip() for ln in text.splitlines() if "://" in ln]


def load_working(path, why):
    """-> (vless-серверы, признаки всех рабочих, ссылки)"""
    links = read_lines(path)
    vless, feats = [], []
    hosts_to_resolve = set()
    others = []
    for link in links:
        c = parse_vless_any(link, why) if link.lower().startswith("vless://") else None
        if c:
            vless.append(c)
            if not is_ip(c["host"]):
                hosts_to_resolve.add(c["host"])
        else:
            h = link_host(link)
            if h:
                others.append(h)
                if not is_ip(h):
                    hosts_to_resolve.add(h)
    ip_of = {}
    if hosts_to_resolve:
        hs = sorted(hosts_to_resolve)
        with cf.ThreadPoolExecutor(32) as ex:
            ip_of = dict(zip(hs, ex.map(col.resolve, hs)))
    for c in vless:
        feats.append(features(c, ip_of.get(c["host"])))
    for h in others:
        feats.append(host_features(h, ip_of.get(h)))
    return vless, feats, links


def run(args):
    t0 = time.monotonic()
    stats = Counter()
    why = Counter()

    work_vless, work_feats, work_links = load_working(Path(args.working), why)
    stats["working_total"] = len(work_links)
    stats["working_vless"] = len(work_vless)
    if not work_feats:
        log(f"! в {args.working} нет ни одной ссылки — нечего сравнивать")
        return None, stats
    work_keys = {ckey(c) for c in work_vless}

    pool_lines = read_lines(Path(args.pool))
    stats["pool_links"] = len(pool_lines)
    if not pool_lines:
        log(f"! пул {args.pool} пуст: запусти collector.py с --pool-out work/pool.txt")
        return None, stats
    cands = {}
    for link in pool_lines:
        c = parse_vless_any(link, why)
        if c and ckey(c) not in work_keys:
            cands.setdefault(ckey(c), c)
    cands = list(cands.values())
    stats["pool_valid_unique"] = len(cands)
    for k, v in why.items():
        stats[f"drop_{k}"] = v

    # веса признаков
    wanted = {x for f in work_feats for group in f.values() for x in group}
    pool_counts = Counter()
    cand_feats = []
    for c in cands:
        f = features(c)
        cand_feats.append(f)
        pool_counts.update(x for group in f.values() for x in group if x in wanted)
    weights = build_weights(work_feats, pool_counts, len(cands))
    stats["features_with_weight"] = sum(1 for v in weights.values() if v > 0)

    # первая оценка (без DNS)
    scored = []
    for c, f in zip(cands, cand_feats):
        s, strong, why_ = score(f, weights)
        if s > 0:
            scored.append((s, strong, c, f))
    scored.sort(key=lambda t: (-t[0], t[2]["base"]))
    strong_n = sum(1 for t in scored if t[1])
    stats["similar_by_identity_or_network"] = strong_n
    if args.no_fill:
        scored = [t for t in scored if t[1]]
    shortlist = scored[:SHORTLIST]

    # DNS для адресов-доменов: подсеть выдаёт оператора и у серверов с доменным именем
    hosts = sorted({t[2]["host"] for t in shortlist if not is_ip(t[2]["host"])})
    log(f"DNS: {len(hosts)} адресов…")
    with cf.ThreadPoolExecutor(64) as ex:
        ip_of = dict(zip(hosts, ex.map(col.resolve, hosts)))
    rescored = []
    for s, strong, c, f in shortlist:
        ip = c["host"] if is_ip(c["host"]) else ip_of.get(c["host"])
        if not ip:
            stats["dns_failed"] += 1
            continue
        c["ip"] = ip
        s2, strong2, why_ = score(features(c, ip), weights)
        rescored.append((s2, strong2, why_, c))
    rescored.sort(key=lambda t: (-t[0], t[3]["base"]))

    # TCP
    batch = rescored[:TCP_MAX]
    log(f"TCP: {len(batch)} серверов…")
    with cf.ThreadPoolExecutor(100) as ex:
        pings = list(ex.map(lambda t: col.tcp_ping(t[3]), batch))
    alive = []
    for (s, strong, why_, c), ms in zip(batch, pings):
        if ms is not None:
            c.update(score=s, why=why_, ms=ms)
            alive.append(c)
    stats["tcp_checked"] = len(batch)
    stats["tcp_ok"] = len(alive)

    # Xray
    verified = []
    if args.xray_bin:
        probe_batch = alive[:PROBE_MAX]
        log(f"Xray: {len(probe_batch)} серверов, {col.SPEED_WORKERS} параллельно…")
        col.PROBE_FAIL.clear()
        with cf.ThreadPoolExecutor(col.SPEED_WORKERS) as ex:
            res = list(ex.map(lambda c: col.probe(c, args.xray_bin), probe_batch))
        verified = [dict(c, **r) for c, r in zip(probe_batch, res) if r]
        stats["xray_ok"] = len(verified)
        for k, v in sorted(col.PROBE_FAIL.items()):
            if k != "ok":
                stats[f"probe_fail_{k}"] = v
    verified.sort(key=lambda c: (-c.get("mbps", 0.0), -c["score"]))

    def limit(items, cap_total):
        per_ip, out = Counter(), []
        for c in items:
            if per_ip[c["ip"]] >= args.max_per_ip:
                continue
            per_ip[c["ip"]] += 1
            out.append(c)
            if len(out) >= cap_total:
                break
        return out

    final = limit(verified, args.max_verified)
    final_keys = {ckey(c) for c in final}
    rest = [c for c in alive if ckey(c) not in final_keys]  # уже отсортированы по оценке
    candidates = limit(rest, args.max_candidates)

    # имена по IP
    ips = ({c["ip"] for c in final} | {c["exit_ip"] for c in final if c.get("exit_ip")} | {c["ip"] for c in candidates})
    geo = col.geo_lookup(ips) if (args.geo and ips) else {}
    for c in final:
        place = c.get("exit_ip") or c["ip"]
        c["name"] = col.make_name(geo.get(place, {}), c.get("exit_cc", ""))
        c["entry_cc"] = geo.get(c["ip"], {}).get("countryCode", "")
    for c in candidates:
        c["name"] = col.make_name(geo.get(c["ip"], {}))
        c["entry_cc"] = geo.get(c["ip"], {}).get("countryCode", "")

    stats["similar_verified"] = len(final)
    stats["similar_candidates"] = len(candidates)
    stats["entry_in_ru"] = sum(c["entry_cc"] == "RU" for c in final + candidates)
    stats["ru_sni_share_percent"] = round(100 * sum(c["tier"] > 0 for c in final + candidates)
                                          / max(1, len(final) + len(candidates)))
    stats["seconds"] = round(time.monotonic() - t0)
    return (final, candidates, weights), stats


def write_outputs(result, stats):
    final, candidates, weights = result
    OUT.mkdir(exist_ok=True)
    line = lambda c: f"{c['base']}#{up.quote(c['name'])}"
    (OUT / "similar_verified.txt").write_text("".join(line(c) + "\n" for c in final), encoding="utf-8")
    (OUT / "similar_candidates.txt").write_text("".join(line(c) + "\n" for c in candidates), encoding="utf-8")
    (OUT / "similar_ruip.txt").write_text(
        "".join(line(c) + "\n" for c in final + candidates if c["entry_cc"] == "RU"), encoding="utf-8")
    (OUT / "similar_why.txt").write_text(
        "".join(f"{c['score']:.2f}\t{c['name']}\t{', '.join(c['why'])}\n" for c in (final + candidates)[:300]),
        encoding="utf-8")
    top = sorted(((w, f) for f, w in weights.items() if w > 0), reverse=True)[:15]
    lines = [f"{k}: {v}" for k, v in stats.items()]
    lines += ["", "самые весомые признаки твоих рабочих серверов (вес, признак):"]
    lines += [f"  {w:.2f}  {short(f)}" for w, f in top]
    (OUT / "similar_report.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")


def main():
    ap = argparse.ArgumentParser(description="Поиск серверов, похожих на твои рабочие")
    ap.add_argument("--working", default=str(ROOT / "my_working.txt"), help="твои рабочие серверы (экспорт из v2rayNG)")
    ap.add_argument("--pool", default=str(ROOT / "work" / "pool.txt"), help="пул ссылок от collector.py --pool-out")
    ap.add_argument("--xray", help="путь к xray (или переменная XRAY_BIN)")
    ap.add_argument("--no-probe", action="store_true", help="не запускать Xray")
    ap.add_argument("--no-geo", dest="geo", action="store_false", help="не определять страну по IP")
    ap.add_argument("--no-fill", action="store_true", help="только совпадения по оператору/сети, без добора по профилю")
    ap.add_argument("--max-verified", type=int, default=MAX_VERIFIED)
    ap.add_argument("--max-candidates", type=int, default=MAX_CANDIDATES)
    ap.add_argument("--max-per-ip", type=int, default=MAX_PER_IP)
    args = ap.parse_args()

    args.xray_bin = None
    if not args.no_probe:
        found = shutil.which(args.xray or __import__("os").environ.get("XRAY_BIN") or "xray")
        if found and shutil.which("curl"):
            args.xray_bin = str(Path(found).resolve())
        else:
            log("! xray или curl не найден — похожие без проверки через Xray (только TCP)")

    result, stats = run(args)
    if result is None:
        sys.exit(1)
    write_outputs(result, stats)
    log("Итого:\n" + "\n".join(f"  {k}: {v}" for k, v in stats.items()))


if __name__ == "__main__":
    main()
