#!/usr/bin/env python3
"""
Проверка прокси/VPN-конфигов из публичных списков.

Как проверяется «работает»:
  * http, socks5, socks4  — РЕАЛЬНЫЙ запрос через прокси: gstatic (204) + cloudflare (trace).
  * vless, vmess, trojan, ss, ssr, https — TCP-соединение с сервером (без ядра Xray
    полноценно проверить нельзя).
  * hysteria, hysteria2, tuic — работают по UDP, проверить нельзя: попадают только
    в файл своего протокола, помечены как «unchecked» в stats.json.

Проверка идёт с того места, где запущен скрипт (на GitHub — США, не Россия).
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import socket
import sys
import time
import urllib.request
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

import aiohttp
from aiohttp_socks import ProxyConnector

# ============================ НАСТРОЙКИ ============================
DEFAULT_SOURCE = "https://raw.githubusercontent.com/nikita29a/FreeProxyList/refs/heads/main/mirror/1.txt"
# Можно несколько ссылок через запятую: SOURCE_URLS="url1,url2"
SOURCE_URLS = [
    u.strip()
    for u in os.getenv("SOURCE_URLS", os.getenv("SOURCE_URL", DEFAULT_SOURCE)).split(",")
    if u.strip()
]


def env_bool(name: str, default: bool) -> bool:
    return os.getenv(name, str(default)).strip().lower() in ("1", "true", "yes", "on")


TIMEOUT = float(os.getenv("TIMEOUT", "8"))
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

# Основные списки (all.txt и файлы по протоколам)
MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "4"))
MAX_TOTAL = int(os.getenv("MAX_TOTAL", "250"))

# white_checked.txt
WHITE_MAX_PER_IP = int(os.getenv("WHITE_MAX_PER_IP", "2"))
WHITE_MAX_PER_COUNTRY = int(os.getenv("WHITE_MAX_PER_COUNTRY", "5"))
WHITE_MAX_TOTAL = int(os.getenv("WHITE_MAX_TOTAL", "450"))
WHITE_REALITY_ONLY = env_bool("WHITE_REALITY_ONLY", True)   # только VLESS Reality
WHITE_RU_SNI_ONLY = env_bool("WHITE_RU_SNI_ONLY", False)    # только с российским SNI

# Определение страны по IP для серверов с меткой XX (ip-api.com, бесплатно)
GEO_FALLBACK = env_bool("GEO_FALLBACK", True)
GEO_MAX_IPS = int(os.getenv("GEO_MAX_IPS", "1500"))

TEST_GSTATIC = "http://www.gstatic.com/generate_204"
TEST_CLOUDFLARE = "https://www.cloudflare.com/cdn-cgi/trace"

SCHEME_ALIASES = {"hy2": "hysteria2", "socks": "socks5", "socks5h": "socks5", "socks4a": "socks4"}
SUPPORTED = {
    "vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic",
    "socks5", "socks4", "http", "https",
}
REAL_TEST = {"http", "socks5", "socks4"}        # реальный запрос через прокси
UDP_ONLY = {"hysteria", "hysteria2", "tuic"}    # проверить нельзя
DEFAULT_PORT = {"http": 80, "socks5": 1080, "socks4": 1080}

# SNI для белых списков. Любой домен на .ru считается российским + эти:
RU_SNI_DOMAINS = (
    "vk.com", "vk-cdn.net", "userapi.com", "vkuser.net", "mycdn.me",
    "yandex.net", "yandex.com", "yastatic.net",
)

# ============================ СТРАНЫ ============================
COUNTRIES_RAW = """AD Andorra
AE United Arab Emirates
AF Afghanistan
AG Antigua and Barbuda
AI Anguilla
AL Albania
AM Armenia
AO Angola
AQ Antarctica
AR Argentina
AS American Samoa
AT Austria
AU Australia
AW Aruba
AX Åland Islands
AZ Azerbaijan
BA Bosnia and Herzegovina
BB Barbados
BD Bangladesh
BE Belgium
BF Burkina Faso
BG Bulgaria
BH Bahrain
BI Burundi
BJ Benin
BL Saint Barthélemy
BM Bermuda
BN Brunei
BO Bolivia
BQ Caribbean Netherlands
BR Brazil
BS Bahamas
BT Bhutan
BV Bouvet Island
BW Botswana
BY Belarus
BZ Belize
CA Canada
CC Cocos Islands
CD DR Congo
CF Central African Republic
CG Congo
CH Switzerland
CI Côte d'Ivoire
CK Cook Islands
CL Chile
CM Cameroon
CN China
CO Colombia
CR Costa Rica
CU Cuba
CV Cape Verde
CW Curaçao
CX Christmas Island
CY Cyprus
CZ Czechia
DE Germany
DJ Djibouti
DK Denmark
DM Dominica
DO Dominican Republic
DZ Algeria
EC Ecuador
EE Estonia
EG Egypt
EH Western Sahara
ER Eritrea
ES Spain
ET Ethiopia
FI Finland
FJ Fiji
FK Falkland Islands
FM Micronesia
FO Faroe Islands
FR France
GA Gabon
GB United Kingdom
GD Grenada
GE Georgia
GF French Guiana
GG Guernsey
GH Ghana
GI Gibraltar
GL Greenland
GM Gambia
GN Guinea
GP Guadeloupe
GQ Equatorial Guinea
GR Greece
GS South Georgia
GT Guatemala
GU Guam
GW Guinea-Bissau
GY Guyana
HK Hong Kong
HM Heard Island
HN Honduras
HR Croatia
HT Haiti
HU Hungary
ID Indonesia
IE Ireland
IL Israel
IM Isle of Man
IN India
IO British Indian Ocean Territory
IQ Iraq
IR Iran
IS Iceland
IT Italy
JE Jersey
JM Jamaica
JO Jordan
JP Japan
KE Kenya
KG Kyrgyzstan
KH Cambodia
KI Kiribati
KM Comoros
KN Saint Kitts and Nevis
KP North Korea
KR South Korea
KW Kuwait
KY Cayman Islands
KZ Kazakhstan
LA Laos
LB Lebanon
LC Saint Lucia
LI Liechtenstein
LK Sri Lanka
LR Liberia
LS Lesotho
LT Lithuania
LU Luxembourg
LV Latvia
LY Libya
MA Morocco
MC Monaco
MD Moldova
ME Montenegro
MF Saint Martin
MG Madagascar
MH Marshall Islands
MK North Macedonia
ML Mali
MM Myanmar
MN Mongolia
MO Macao
MP Northern Mariana Islands
MQ Martinique
MR Mauritania
MS Montserrat
MT Malta
MU Mauritius
MV Maldives
MW Malawi
MX Mexico
MY Malaysia
MZ Mozambique
NA Namibia
NC New Caledonia
NE Niger
NF Norfolk Island
NG Nigeria
NI Nicaragua
NL Netherlands
NO Norway
NP Nepal
NR Nauru
NU Niue
NZ New Zealand
OM Oman
PA Panama
PE Peru
PF French Polynesia
PG Papua New Guinea
PH Philippines
PK Pakistan
PL Poland
PM Saint Pierre and Miquelon
PN Pitcairn
PR Puerto Rico
PS Palestine
PT Portugal
PW Palau
PY Paraguay
QA Qatar
RE Réunion
RO Romania
RS Serbia
RU Russia
RW Rwanda
SA Saudi Arabia
SB Solomon Islands
SC Seychelles
SD Sudan
SE Sweden
SG Singapore
SH Saint Helena
SI Slovenia
SJ Svalbard and Jan Mayen
SK Slovakia
SL Sierra Leone
SM San Marino
SN Senegal
SO Somalia
SR Suriname
SS South Sudan
ST São Tomé and Príncipe
SV El Salvador
SX Sint Maarten
SY Syria
SZ Eswatini
TC Turks and Caicos Islands
TD Chad
TF French Southern Territories
TG Togo
TH Thailand
TJ Tajikistan
TK Tokelau
TL Timor-Leste
TM Turkmenistan
TN Tunisia
TO Tonga
TR Turkey
TT Trinidad and Tobago
TV Tuvalu
TW Taiwan
TZ Tanzania
UA Ukraine
UG Uganda
UM U.S. Minor Outlying Islands
US United States
UY Uruguay
UZ Uzbekistan
VA Vatican City
VC Saint Vincent and the Grenadines
VE Venezuela
VG British Virgin Islands
VI U.S. Virgin Islands
VN Vietnam
VU Vanuatu
WF Wallis and Futuna
WS Samoa
XK Kosovo
YE Yemen
YT Mayotte
ZA South Africa
ZM Zambia
ZW Zimbabwe"""
COUNTRIES = dict(line.split(" ", 1) for line in COUNTRIES_RAW.splitlines())

# Метка источника: "[OpenRay] 🇺🇸US-4648" -> US. XX = страна неизвестна.
LABEL_CC_RE = re.compile(r"(?<![A-Za-z])([A-Z]{2})-\d+\s*$")


def code_to_flag(code: str) -> str:
    if len(code) != 2 or not code.isalpha() or code.upper() == "XX":
        return "🌐"
    return "".join(chr(0x1F1E6 + ord(c) - 65) for c in code.upper())


def flag_to_code(text: str) -> str:
    letters: list[str] = []
    for ch in text:
        o = ord(ch)
        if 0x1F1E6 <= o <= 0x1F1FF:
            letters.append(chr(o - 0x1F1E6 + 65))
            if len(letters) == 2:
                return "".join(letters)
        else:
            letters = []
    return ""


def country_name(code: str) -> str:
    return COUNTRIES.get(code, "Unknown")


# ============================ РАЗБОР ССЫЛОК ============================
def fetch_url(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
    with urllib.request.urlopen(req, timeout=60) as response:
        return response.read().decode("utf-8", errors="ignore")


def b64decode_loose(s: str) -> str:
    s = s.strip().replace("-", "+").replace("_", "/")
    s += "=" * (-len(s) % 4)
    return base64.b64decode(s).decode("utf-8", errors="ignore")


def maybe_decode_subscription(text: str) -> str:
    """Подписка целиком в base64 -> раскодировать."""
    if "://" in text:
        return text
    try:
        decoded = b64decode_loose(text.replace("\n", "").replace("\r", ""))
        if "://" in decoded:
            return decoded
    except Exception:
        pass
    return text


def parse_line(line: str) -> str | None:
    line = line.strip()
    if not line or line.startswith(("#", "//")) or "://" not in line:
        return None
    scheme, rest = line.split("://", 1)
    scheme = SCHEME_ALIASES.get(scheme.lower(), scheme.lower())
    if scheme not in SUPPORTED:
        return None
    return f"{scheme}://{rest}"


def get_scheme(line: str) -> str:
    return line.split("://", 1)[0].lower()


def extract_host_port(line: str) -> tuple[str | None, int]:
    scheme = get_scheme(line)
    body = line.split("://", 1)[1].split("#", 1)[0]
    try:
        if scheme == "vmess":
            data = json.loads(b64decode_loose(body))
            host = data.get("add") or data.get("host")
            return (host, int(data.get("port") or 443)) if host else (None, 0)

        if scheme == "ssr":
            fields = b64decode_loose(body.split("/", 1)[0]).split(":")
            return fields[0], int(fields[1])

        if scheme == "ss":
            netloc = body.split("?", 1)[0].split("/", 1)[0]
            if "@" not in netloc:  # старый формат ss://base64(method:pass@host:port)
                raw = b64decode_loose(netloc)
                host, _, port = raw.rsplit("@", 1)[1].rpartition(":")
                return host.strip("[]"), int(port)

        parts = urlsplit(f"{scheme}://{body}")
        host, port = parts.hostname, parts.port
        if host:
            return host, port or DEFAULT_PORT.get(scheme, 443)
    except Exception:
        pass
    return None, 0


def get_remark(line: str) -> str:
    if get_scheme(line) == "vmess":
        try:
            data = json.loads(b64decode_loose(line.split("://", 1)[1].split("#", 1)[0]))
            return str(data.get("ps", ""))
        except Exception:
            return ""
    return unquote(line.split("#", 1)[1]) if "#" in line else ""


def detect_country(line: str) -> str:
    remark = get_remark(line)
    code = flag_to_code(remark)
    if not code:
        m = LABEL_CC_RE.search(remark)
        code = m.group(1) if m else ""
    return code if code in COUNTRIES else "XX"


def parse_vless_params(line: str) -> dict:
    result = {"security": "", "sni": "", "is_reality": False}
    try:
        parts = urlsplit(line.split("#", 1)[0])
        qs = parse_qs(parts.query)
        security = (qs.get("security") or [""])[0].lower()
        sni = (qs.get("sni") or qs.get("host") or [""])[0].lower()
        result.update(
            security=security,
            sni=sni,
            is_reality=security == "reality" or "pbk" in qs,
        )
    except Exception:
        pass
    return result


def sni_is_ru(sni: str) -> bool:
    sni = (sni or "").lower().rstrip(".")
    if not sni:
        return False
    if sni.endswith(".ru") or sni == "ru":
        return True
    return any(sni == d or sni.endswith("." + d) for d in RU_SNI_DOMAINS)


def format_clean_proxy(line: str, country: str, latency_ms: int | None) -> str:
    scheme = get_scheme(line)
    name = f"{code_to_flag(country)} {country_name(country)} | {scheme}"
    if latency_ms is not None:
        name += f" | {latency_ms}ms"

    if scheme == "ssr":
        return line
    if scheme == "vmess":
        try:
            prefix, payload = line.split("://", 1)
            data = json.loads(b64decode_loose(payload.split("#", 1)[0]))
            data["ps"] = name
            new_json = json.dumps(data, ensure_ascii=False, separators=(",", ":"))
            return f"{prefix}://{base64.b64encode(new_json.encode()).decode('ascii')}"
        except Exception:
            return line
    return f"{line.split('#', 1)[0]}#{quote(name)}"


def is_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
        return True
    except ValueError:
        return False


async def resolve_to_ip(host: str) -> str:
    if not host or is_ip(host):
        return host or ""
    try:
        infos = await asyncio.get_running_loop().getaddrinfo(host, None, proto=socket.IPPROTO_TCP)
        return infos[0][4][0]
    except Exception:
        return host


# ============================ ПРОВЕРКИ ============================
async def tcp_check(host: str, port: int) -> int | None:
    started = time.monotonic()
    try:
        _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=TIMEOUT)
    except Exception:
        return None
    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return int((time.monotonic() - started) * 1000)


async def real_check(line: str, scheme: str) -> int | None:
    """Реальный запрос через прокси: gstatic -> 204, cloudflare trace -> 200 + ip=."""
    proxy_url = f"{scheme}://{urlsplit(line.split('#', 1)[0]).netloc}"
    timeout = aiohttp.ClientTimeout(total=TIMEOUT)
    try:
        if scheme == "http":
            session = aiohttp.ClientSession(timeout=timeout)
            kw = {"proxy": proxy_url}
        else:
            opts = {"rdns": True} if scheme == "socks5" else {}
            connector = ProxyConnector.from_url(proxy_url, **opts)
            session = aiohttp.ClientSession(connector=connector, timeout=timeout)
            kw = {}
        async with session:
            started = time.monotonic()
            async with session.get(TEST_GSTATIC, allow_redirects=False, **kw) as r:
                await r.read()
                if r.status != 204:
                    return None
            latency = int((time.monotonic() - started) * 1000)
            async with session.get(TEST_CLOUDFLARE, allow_redirects=False, **kw) as r:
                if r.status != 200 or "ip=" not in await r.text():
                    return None
            return latency
    except Exception:
        return None


async def check_one(line: str, sem: asyncio.Semaphore) -> dict | None:
    async with sem:
        try:
            scheme = get_scheme(line)
            host, port = extract_host_port(line)
            if not host or not port:
                return None

            if scheme in REAL_TEST:
                latency, method = await real_check(line, scheme), "traffic"
            elif scheme in UDP_ONLY:
                latency, method = None, "unchecked"
            else:
                latency, method = await tcp_check(host, port), "tcp"

            if method != "unchecked" and latency is None:
                return None

            ip = await resolve_to_ip(host)
            if method == "unchecked" and not is_ip(ip):
                return None  # хост даже не резолвится

            vless = parse_vless_params(line) if scheme == "vless" else {}
            return {
                "raw": line,
                "proxy": line,
                "ip": ip,
                "country": detect_country(line),
                "scheme": scheme,
                "latency_ms": latency,
                "method": method,
                "is_reality": vless.get("is_reality", False),
                "sni": vless.get("sni", ""),
            }
        except Exception:
            return None


def geo_lookup(ips: list[str]) -> dict[str, str]:
    """Страна по IP (ip-api.com, пакетами по 100)."""
    result: dict[str, str] = {}
    for i in range(0, len(ips), 100):
        chunk = ips[i:i + 100]
        try:
            req = urllib.request.Request(
                "http://ip-api.com/batch?fields=status,countryCode,query",
                data=json.dumps(chunk).encode(),
                headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
            )
            with urllib.request.urlopen(req, timeout=20) as resp:
                rows = json.loads(resp.read().decode())
        except Exception as e:
            print(f"  geo: остановились на пакете {i // 100 + 1}: {e}")
            break
        for row in rows:
            if row.get("status") == "success" and row.get("countryCode") in COUNTRIES:
                result[row["query"]] = row["countryCode"]
        time.sleep(4.5)  # лимит бесплатного ip-api
    return result


# ============================ ФИЛЬТРАЦИЯ ============================
def latency_key(item: dict) -> tuple:
    return (item["latency_ms"] is None, item["latency_ms"] or 0)


def smart_filter(
    items: list[dict],
    max_per_country: int = MAX_PER_COUNTRY,
    max_total: int = MAX_TOTAL,
    unique_ip: bool = True,
) -> list[dict]:
    seen_ips: set[str] = set()
    per_country: dict[str, int] = defaultdict(int)
    result: list[dict] = []
    for item in sorted(items, key=latency_key):
        if len(result) >= max_total:
            break
        ip, country = item["ip"], item["country"]
        if unique_ip and ip in seen_ips:
            continue
        if per_country[country] >= max_per_country:
            continue
        seen_ips.add(ip)
        per_country[country] += 1
        result.append(item)
    return result


def smart_filter_white(items: list[dict]) -> list[dict]:
    """VLESS (по умолчанию только Reality); российский SNI — в начало очереди."""
    cand = [i for i in items if i["scheme"] == "vless" and i["method"] != "unchecked"]
    if WHITE_REALITY_ONLY:
        cand = [i for i in cand if i["is_reality"]]
    if WHITE_RU_SNI_ONLY:
        cand = [i for i in cand if sni_is_ru(i["sni"])]
    cand.sort(key=lambda i: (not i["is_reality"], not sni_is_ru(i["sni"]), *latency_key(i)))

    per_ip: dict[str, int] = defaultdict(int)
    per_country: dict[str, int] = defaultdict(int)
    result: list[dict] = []
    for item in cand:
        if len(result) >= WHITE_MAX_TOTAL:
            break
        if per_ip[item["ip"]] >= WHITE_MAX_PER_IP:
            continue
        if per_country[item["country"]] >= WHITE_MAX_PER_COUNTRY:
            continue
        per_ip[item["ip"]] += 1
        per_country[item["country"]] += 1
        result.append(item)
    return result


def write_list(path: Path, items: list[dict]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    lines = [i["proxy"] for i in items]
    path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


# ============================ MAIN ============================
async def main_async() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[{stamp}] Источников: {len(SOURCE_URLS)}  timeout={TIMEOUT}s  concurrency={CONCURRENCY}")

    # 1. Скачиваем и разбираем
    texts = []
    for url in SOURCE_URLS:
        try:
            texts.append(await asyncio.to_thread(fetch_url, url))
        except Exception as e:
            print(f"ОШИБКА скачивания {url}: {e}")
    if not texts:
        return 1

    seen: set[str] = set()
    configs: list[str] = []
    for text in texts:
        for raw_line in maybe_decode_subscription(text).splitlines():
            line = parse_line(raw_line)
            if not line:
                continue
            key = line.split("#", 1)[0]
            if key not in seen:
                seen.add(key)
                configs.append(line)

    parsed_by_scheme: dict[str, int] = defaultdict(int)
    for c in configs:
        parsed_by_scheme[get_scheme(c)] += 1
    print(f"Уникальных конфигов: {len(configs)}  {dict(parsed_by_scheme)}")
    if not configs:
        print("Список пуст — результаты не меняем")
        return 0

    # 2. Проверяем
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.create_task(check_one(c, sem)) for c in configs]
    working: list[dict] = []
    done = 0
    for fut in asyncio.as_completed(tasks):
        res = await fut
        done += 1
        if res:
            working.append(res)
        if done % 1000 == 0 or done == len(tasks):
            print(f"  проверено {done}/{len(tasks)} | живых: {len(working)}", flush=True)

    if not working:
        print("Нет рабочих серверов — результаты не меняем")
        return 0

    # 3. Страны для меток XX
    if GEO_FALLBACK:
        unknown = sorted({i["ip"] for i in working if i["country"] == "XX" and is_ip(i["ip"])})[:GEO_MAX_IPS]
        if unknown:
            print(f"Определяем страну по IP для {len(unknown)} адресов...")
            geo = await asyncio.to_thread(geo_lookup, unknown)
            for item in working:
                if item["country"] == "XX" and item["ip"] in geo:
                    item["country"] = geo[item["ip"]]
            print(f"  определено: {len(geo)}")

    for item in working:
        item["proxy"] = format_clean_proxy(item["raw"], item["country"], item["latency_ms"])

    # 4. Списки
    checked = [i for i in working if i["method"] != "unchecked"]
    main_list = smart_filter(checked)
    white_list = smart_filter_white(working)

    by_scheme: dict[str, list[dict]] = defaultdict(list)
    for item in working:
        by_scheme[item["scheme"]].append(item)

    # 5. Запись (старые файлы по протоколам удаляем, чтобы не оставались устаревшие)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_dir = OUT_DIR / "by_protocol"
    by_dir.mkdir(parents=True, exist_ok=True)
    for old in by_dir.glob("*.txt"):
        old.unlink()

    write_list(OUT_DIR / "all.txt", main_list)
    write_list(OUT_DIR / "working_proxies.txt", main_list)
    write_list(OUT_DIR / "white_checked.txt", white_list)

    per_file: dict[str, int] = {}
    for scheme, items in sorted(by_scheme.items()):
        filtered = smart_filter(items)
        write_list(by_dir / f"{scheme}.txt", filtered)
        per_file[scheme] = len(filtered)

    stats = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": SOURCE_URLS,
        "total_configs": len(configs),
        "alive_or_unchecked": len(working),
        "unchecked_udp": sum(1 for i in working if i["method"] == "unchecked"),
        "all_txt": len(main_list),
        "white_checked_txt": len(white_list),
        "by_protocol": per_file,
        "test_urls": [TEST_GSTATIC, TEST_CLOUDFLARE],
    }
    (OUT_DIR / "stats.json").write_text(json.dumps(stats, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Рабочих/непроверяемых: {len(working)}")
    print(f"all.txt: {len(main_list)} | white_checked.txt: {len(white_list)}")
    for scheme, n in per_file.items():
        print(f"  by_protocol/{scheme}.txt -> {n}")
    print("Готово.")
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
