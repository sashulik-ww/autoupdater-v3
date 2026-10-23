#!/usr/bin/env python3
"""
Проверка прокси/VPN-конфигов из публичных списков через Xray-core.

Как проверяется «работает» (ВСЕ протоколы, которые умеет Xray-core):
  vless, vmess, trojan, ss, hysteria2, http, https, socks5, socks4
  1. Быстрый TCP-пинг порта (отсев мёртвых; для UDP-протокола hysteria2 пропускается).
  2. Для каждого сервера запускается свой процесс Xray с локальным SOCKS-входом
     и сервером из ссылки в качестве выхода.
  3. Через этот туннель: http://www.gstatic.com/generate_204 (должен вернуть 204),
     затем https://www.cloudflare.com/cdn-cgi/trace (должен вернуть 200).
  4. Тест скорости: скачивание SPEED_BYTES через туннель с speed.cloudflare.com.
Списки сортируются по скорости (потом по задержке).

Xray не умеет: tuic, hysteria v1, ssr, ss с плагином, vless/vmess с kcp/quic/h2.
Такие конфиги попадают только в файл своего протокола и помечены как «unchecked».

Проверка идёт с того места, где запущен скрипт (на GitHub — США, не Россия).
Нужны: бинарник xray (XRAY_BIN или в PATH) и curl. Только стандартная библиотека Python.
"""
from __future__ import annotations

import asyncio
import base64
import ipaddress
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qs, quote, unquote, urlsplit

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


TIMEOUT = float(os.getenv("TIMEOUT", "8"))                # TCP-пинг, секунд
CONCURRENCY = int(os.getenv("CONCURRENCY", "200"))        # параллельных TCP-пингов
OUT_DIR = Path(os.getenv("OUT_DIR", "results"))

# --- Xray ---
USE_XRAY = env_bool("USE_XRAY", True)
XRAY_BIN = os.getenv("XRAY_BIN", "") or shutil.which("xray") or ""
CURL_BIN = shutil.which("curl") or ""
XRAY_WORKERS = int(os.getenv("XRAY_WORKERS", "100"))      # одновременных процессов Xray
XRAY_BASE_PORT = int(os.getenv("XRAY_BASE_PORT", "21000"))
XRAY_TIMEOUT = float(os.getenv("XRAY_TIMEOUT", "8"))      # секунд на запрос через туннель
XRAY_START_TIMEOUT = float(os.getenv("XRAY_START_TIMEOUT", "10"))
REFUSE_FALLBACK_MIN = int(os.getenv("REFUSE_FALLBACK_MIN", "10"))

TEST_GSTATIC = os.getenv("TEST_GSTATIC", "http://www.gstatic.com/generate_204")
TEST_CLOUDFLARE = os.getenv("TEST_CLOUDFLARE", "https://www.cloudflare.com/cdn-cgi/trace")

# --- Скорость ---
SPEED_TEST = env_bool("SPEED_TEST", True)
SPEED_BYTES = int(os.getenv("SPEED_BYTES", "2000000"))
SPEED_TIMEOUT = float(os.getenv("SPEED_TIMEOUT", "15"))
SPEED_CONCURRENCY = int(os.getenv("SPEED_CONCURRENCY", "12"))   # одновременных тестов скорости
SPEED_URL = os.getenv("SPEED_URL", "https://speed.cloudflare.com/__down?bytes={bytes}")
MIN_SPEED_MBPS = float(os.getenv("MIN_SPEED_MBPS", "0"))        # 0 = не отсеивать по скорости

# --- all.txt (общий список) ---
MAX_PER_COUNTRY = int(os.getenv("MAX_PER_COUNTRY", "4"))
MAX_TOTAL = int(os.getenv("MAX_TOTAL", "250"))

# --- by_protocol/*.txt ---
PROTO_MAX_PER_COUNTRY = int(os.getenv("PROTO_MAX_PER_COUNTRY", "20"))
PROTO_MAX_TOTAL = int(os.getenv("PROTO_MAX_TOTAL", "500"))

# --- xray_checked.txt: только прошедшие проверку Xray, уникальные IP ---
XRAY_FILE_MAX_TOTAL = int(os.getenv("XRAY_FILE_MAX_TOTAL", "600"))
XRAY_FILE_MAX_PER_COUNTRY = int(os.getenv("XRAY_FILE_MAX_PER_COUNTRY", "600"))  # 600 = без лимита

# --- white_checked.txt ---
WHITE_MAX_PER_IP = int(os.getenv("WHITE_MAX_PER_IP", "2"))
WHITE_MAX_PER_COUNTRY = int(os.getenv("WHITE_MAX_PER_COUNTRY", "5"))
WHITE_MAX_TOTAL = int(os.getenv("WHITE_MAX_TOTAL", "450"))
WHITE_REALITY_ONLY = env_bool("WHITE_REALITY_ONLY", True)
WHITE_RU_SNI_ONLY = env_bool("WHITE_RU_SNI_ONLY", False)

# --- Геолокация: страна и город для названия берутся по реальному IP ---
GEO_LOOKUP = env_bool("GEO_LOOKUP", True)
GEO_STRICT = env_bool("GEO_STRICT", True)   # без геоданных — не попадает в списки
GEO_TTL_DAYS = int(os.getenv("GEO_TTL_DAYS", "30"))
GEO_TIME_LIMIT = int(os.getenv("GEO_TIME_LIMIT", "600"))
GEO_MAX_IPS = int(os.getenv("GEO_MAX_IPS", "20000"))
GEO_CACHE_NAME = "geo_cache.json"

SCHEME_ALIASES = {"hy2": "hysteria2", "socks": "socks5", "socks5h": "socks5", "socks4a": "socks4"}
SUPPORTED = {
    "vless", "vmess", "trojan", "ss", "ssr", "hysteria", "hysteria2", "tuic",
    "socks5", "socks4", "http", "https",
}
XRAY_SCHEMES = {"vless", "vmess", "trojan", "ss", "hysteria2", "http", "https", "socks5", "socks4"}
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
            netloc = body.split("?", 1)[0]
            if "@" not in netloc:  # старый формат ss://base64(method:pass@host:port)
                raw = b64decode_loose(unquote(netloc.split("#", 1)[0]))
                host, _, port = raw.rsplit("@", 1)[1].rpartition(":")
                return host.strip("[]"), int(port)

        parts = urlsplit(f"{scheme}://{body}")
        host, port = parts.hostname, parts.port
        if host:
            return host, port or DEFAULT_PORT.get(scheme, 443)
    except Exception:
        pass
    return None, 0


def query_params(line: str) -> dict:
    """Параметры после «?» (ключи в нижнем регистре, значения раскодированы)."""
    body = line.split("://", 1)[1].split("#", 1)[0]
    query = body.partition("?")[2]
    return {k.lower(): v[0] for k, v in parse_qs(query, keep_blank_values=True).items()}


def split_userinfo(line: str) -> str:
    """Всё, что стоит перед «@» (uuid, пароль, user:pass), раскодированное."""
    body = line.split("://", 1)[1].split("#", 1)[0]
    main = body.split("?", 1)[0].split("/", 1)[0]
    return unquote(main.rpartition("@")[0]) if "@" in main else ""


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
    p = query_params(line)
    security = (p.get("security") or "").lower()
    return {
        "sni": (p.get("sni") or p.get("host") or "").lower(),
        "is_reality": security == "reality" or "pbk" in p,
    }


def sni_is_ru(sni: str) -> bool:
    sni = (sni or "").lower().rstrip(".")
    if not sni:
        return False
    if sni.endswith(".ru") or sni == "ru":
        return True
    return any(sni == d or sni.endswith("." + d) for d in RU_SNI_DOMAINS)


def format_clean_proxy(line: str, country: str, city: str = "") -> str:
    """Название сервера: флаг + страна (+ город). Без пинга и протокола."""
    name = f"{code_to_flag(country)} {country_name(country)}"
    if city:
        name += f", {city}"

    scheme = get_scheme(line)
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


# ============================ XRAY: ССЫЛКА -> OUTBOUND ============================
NETWORKS = {
    "tcp": "tcp", "raw": "tcp", "ws": "ws", "websocket": "ws",
    "httpupgrade": "httpupgrade", "grpc": "grpc", "gun": "grpc",
    "xhttp": "splithttp", "splithttp": "splithttp",
}


def as_bool(value) -> bool:
    return str(value).strip().lower() in ("1", "true", "yes")


def build_stream(p: dict, address: str, default_security: str = "none") -> dict | None:
    """Транспорт + TLS/Reality. None — Xray такое не умеет (kcp, quic, h2...)."""
    net = NETWORKS.get((p.get("type") or "tcp").lower())
    if net is None:
        return None
    host = p.get("host", "")
    raw_path = p.get("path", "")
    path = raw_path or "/"
    sec = (p.get("security") or default_security or "none").lower()
    if sec == "xtls":
        sec = "tls"

    stream: dict = {"network": net}
    if net == "ws":
        stream["wsSettings"] = {"path": path, **({"host": host} if host else {})}
    elif net == "httpupgrade":
        stream["httpupgradeSettings"] = {"path": path, **({"host": host} if host else {})}
    elif net == "grpc":
        g = {"serviceName": p.get("servicename") or raw_path, "multiMode": p.get("mode") == "multi"}
        if p.get("authority"):
            g["authority"] = p["authority"]
        stream["grpcSettings"] = g
    elif net == "splithttp":
        s = {"path": path, "mode": p.get("mode") or "auto"}
        if host:
            s["host"] = host
        if p.get("extra"):
            try:
                extra = json.loads(p["extra"])
                if isinstance(extra, dict):
                    s.update(extra)
            except ValueError:
                pass
        stream["splithttpSettings"] = s
    elif net == "tcp" and (p.get("headertype") or "").lower() == "http":
        hosts = [h for h in (host or address).split(",") if h]
        stream["tcpSettings"] = {
            "header": {"type": "http", "request": {"path": [path], "headers": {"Host": hosts}}}
        }

    if sec == "tls":
        tls = {"serverName": p.get("sni") or p.get("peer") or host or address}
        if p.get("fp"):
            tls["fingerprint"] = p["fp"]
        if p.get("alpn"):
            tls["alpn"] = [a for a in p["alpn"].split(",") if a]
        if as_bool(p.get("allowinsecure")) or as_bool(p.get("insecure")):
            tls["allowInsecure"] = True
        stream["security"] = "tls"
        stream["tlsSettings"] = tls
    elif sec == "reality":
        if not p.get("pbk"):
            return None
        stream["security"] = "reality"
        stream["realitySettings"] = {
            "serverName": p.get("sni") or host or address,
            "fingerprint": p.get("fp") or "chrome",
            "publicKey": p["pbk"],
            "shortId": p.get("sid", ""),
            "spiderX": p.get("spx", ""),
        }
    elif sec in ("none", ""):
        stream["security"] = "none"
    else:
        return None
    return stream


def build_vless(line: str) -> dict | None:
    host, port = extract_host_port(line)
    uid = split_userinfo(line)
    p = query_params(line)
    stream = build_stream(p, host or "")
    if not host or not uid or stream is None:
        return None
    settings = {"address": host, "port": port, "id": uid, "encryption": p.get("encryption") or "none"}
    if p.get("flow"):
        settings["flow"] = p["flow"]
    return {"protocol": "vless", "settings": settings, "streamSettings": stream}


def build_vmess(line: str) -> dict | None:
    try:
        d = json.loads(b64decode_loose(line.split("://", 1)[1].split("#", 1)[0]))
        host, port = d.get("add"), int(d.get("port") or 443)
        uid = d.get("id")
    except Exception:
        return None
    if not host or not uid:
        return None
    net = str(d.get("net") or "tcp").lower()
    p = {
        "type": net,
        "host": d.get("host") or "",
        "path": d.get("path") or "",
        "sni": d.get("sni") or "",
        "alpn": d.get("alpn") or "",
        "fp": d.get("fp") or "",
        "security": "tls" if str(d.get("tls", "")).lower() == "tls" else "none",
        "headertype": d.get("type") or "",
        "servicename": d.get("path") or "" if net == "grpc" else "",
        "mode": "multi" if net == "grpc" and d.get("type") == "multi" else "",
        "allowinsecure": d.get("allowInsecure") or d.get("insecure") or "",
    }
    stream = build_stream(p, host)
    if stream is None:
        return None
    scy = str(d.get("scy") or "auto").lower()
    if scy not in ("auto", "aes-128-gcm", "chacha20-poly1305"):
        scy = "auto"
    settings = {"address": host, "port": port, "id": uid, "security": scy}
    return {"protocol": "vmess", "settings": settings, "streamSettings": stream}


def build_trojan(line: str) -> dict | None:
    host, port = extract_host_port(line)
    password = split_userinfo(line)
    stream = build_stream(query_params(line), host or "", default_security="tls")
    if not host or not password or stream is None:
        return None
    settings = {"address": host, "port": port, "password": password}
    return {"protocol": "trojan", "settings": settings, "streamSettings": stream}


def parse_ss_credentials(line: str) -> tuple[str, str] | None:
    body = line.split("://", 1)[1].split("#", 1)[0]
    main, _, query = body.partition("?")
    if "plugin" in {k.lower() for k in parse_qs(query)}:
        return None  # плагины (obfs, v2ray-plugin) Xray не поддерживает
    try:
        if "@" in main:
            userinfo = unquote(main.split("/", 1)[0].rpartition("@")[0])
            if ":" not in userinfo:
                userinfo = b64decode_loose(userinfo)
        else:
            userinfo = b64decode_loose(unquote(main)).rpartition("@")[0]
        method, _, password = userinfo.partition(":")
        return (method, password) if method and password else None
    except Exception:
        return None


def build_ss(line: str) -> dict | None:
    host, port = extract_host_port(line)
    creds = parse_ss_credentials(line)
    if not host or creds is None:
        return None
    settings = {"address": host, "port": port, "method": creds[0], "password": creds[1]}
    return {"protocol": "shadowsocks", "settings": settings}


def build_hysteria2(line: str) -> dict | None:
    host, port = extract_host_port(line)
    auth = split_userinfo(line)
    p = query_params(line)
    if not host or not auth:
        return None
    tls = {"serverName": p.get("sni") or host, "alpn": ["h3"]}
    if as_bool(p.get("insecure")) or as_bool(p.get("allowinsecure")):
        tls["allowInsecure"] = True
    stream = {
        "network": "hysteria",
        "security": "tls",
        "tlsSettings": tls,
        "hysteriaSettings": {"version": 2, "auth": auth},
    }
    if (p.get("obfs") or "").lower() == "salamander":
        stream["finalmask"] = {
            "udp": [{"type": "salamander", "settings": {"password": p.get("obfs-password", "")}}]
        }
    return {
        "protocol": "hysteria",
        "settings": {"version": 2, "address": host, "port": port},
        "streamSettings": stream,
    }


def build_http_like(line: str) -> dict | None:
    scheme = get_scheme(line)
    host, port = extract_host_port(line)
    if not host or not port:
        return None
    server: dict = {"address": host, "port": port}
    userinfo = split_userinfo(line)
    if userinfo:
        user, _, password = userinfo.partition(":")
        server["users"] = [{"user": user, "pass": password}]
    settings: dict = {"servers": [server]}
    if scheme in ("socks5", "socks4"):
        if scheme == "socks4":
            settings["version"] = "4"
        return {"protocol": "socks", "settings": settings}
    outbound = {"protocol": "http", "settings": settings}
    if scheme == "https":  # прокси с TLS; сертификат не проверяем — нужен только факт работы
        outbound["streamSettings"] = {
            "network": "tcp",
            "security": "tls",
            "tlsSettings": {"serverName": host, "allowInsecure": True},
        }
    return outbound


def build_outbound(line: str) -> dict | None:
    scheme = get_scheme(line)
    builders = {
        "vless": build_vless, "vmess": build_vmess, "trojan": build_trojan, "ss": build_ss,
        "hysteria2": build_hysteria2, "http": build_http_like, "https": build_http_like,
        "socks5": build_http_like, "socks4": build_http_like,
    }
    builder = builders.get(scheme)
    try:
        return builder(line) if builder else None
    except Exception:
        return None


def xray_config(port: int, outbound: dict) -> dict:
    return {
        "log": {"loglevel": "none"},
        "inbounds": [{
            "tag": "in", "listen": "127.0.0.1", "port": port, "protocol": "socks",
            "settings": {"auth": "noauth", "udp": False},
        }],
        "outbounds": [{**outbound, "tag": "out"}],
    }


# ============================ ПРОВЕРКИ ============================
_speed_sem: asyncio.Semaphore | None = None


def speed_sem() -> asyncio.Semaphore:
    global _speed_sem
    if _speed_sem is None:
        _speed_sem = asyncio.Semaphore(SPEED_CONCURRENCY)
    return _speed_sem


def speed_url() -> str:
    return SPEED_URL.format(bytes=SPEED_BYTES)


def xray_available() -> bool:
    if not USE_XRAY:
        print("Xray отключён (USE_XRAY=false) — только TCP-проверка")
        return False
    if not XRAY_BIN or not CURL_BIN:
        print(f"ВНИМАНИЕ: нет xray ({XRAY_BIN or '—'}) или curl ({CURL_BIN or '—'}) — только TCP-проверка")
        return False
    try:
        res = subprocess.run([XRAY_BIN, "version"], capture_output=True, text=True, timeout=15)
    except Exception as e:
        print(f"ВНИМАНИЕ: не удалось запустить xray: {e} — только TCP-проверка")
        return False
    first = (res.stdout or res.stderr or "").strip().splitlines()
    print(f"Xray: {first[0] if first else 'ok'}")
    return res.returncode == 0


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
    return max(1, int((time.monotonic() - started) * 1000))


async def curl_probe(args: list[str], url: str, timeout: float):
    """Один запрос через curl -> (http_code, ttfb_сек, байт/сек, скачано_байт) или None."""
    cmd = [
        CURL_BIN, "-sS", "-o", os.devnull, "-m", f"{timeout:g}", "--connect-timeout", f"{min(timeout, 10):g}",
        *args, "-w", "%{http_code} %{time_starttransfer} %{speed_download} %{size_download}", url,
    ]
    proc = await asyncio.create_subprocess_exec(
        *cmd, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL
    )
    try:
        out, _ = await asyncio.wait_for(proc.communicate(), timeout + 5)
    except asyncio.TimeoutError:
        try:
            proc.kill()
        except ProcessLookupError:
            pass
        await proc.wait()
        return None
    parts = out.decode(errors="ignore").split()
    if len(parts) != 4:
        return None
    try:
        return int(parts[0]), float(parts[1]), float(parts[2]), float(parts[3])
    except ValueError:
        return None


async def probe_via(args: list[str]) -> dict | None:
    """gstatic -> cloudflare -> (тест скорости). None — сервер не работает."""
    r = await curl_probe(args, TEST_GSTATIC, XRAY_TIMEOUT)
    if not r or r[0] != 204:
        return None
    latency = max(1, int(r[1] * 1000))
    r = await curl_probe(args, TEST_CLOUDFLARE, XRAY_TIMEOUT)
    if not r or r[0] != 200:
        return None
    speed = None
    if SPEED_TEST:
        async with speed_sem():
            r = await curl_probe(args, speed_url(), SPEED_TIMEOUT)
        if r and r[3] > 0:
            speed = round(r[2] * 8 / 1e6, 2)  # байт/сек -> Мбит/с
    return {"latency_ms": latency, "speed_mbps": speed}


async def wait_port(port: int, proc, limit: float) -> bool:
    deadline = time.monotonic() + limit
    while time.monotonic() < deadline:
        if proc.returncode is not None:
            return False  # Xray отказался от конфига и завершился
        try:
            _, writer = await asyncio.open_connection("127.0.0.1", port)
        except OSError:
            await asyncio.sleep(0.05)
            continue
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass
        return True
    return False


async def xray_check_item(item: dict, port: int, tmpdir: Path):
    """-> ("ok", метрики) | ("dead", None) | ("refused", None)"""
    path = tmpdir / f"{port}.json"
    path.write_text(json.dumps(xray_config(port, item["outbound"])), encoding="utf-8")
    proc = await asyncio.create_subprocess_exec(
        XRAY_BIN, "run", "-c", str(path),
        stdout=asyncio.subprocess.DEVNULL, stderr=asyncio.subprocess.DEVNULL,
    )
    try:
        if not await wait_port(port, proc, XRAY_START_TIMEOUT):
            return "refused", None
        metrics = await probe_via(["-x", f"socks5h://127.0.0.1:{port}"])
        return ("ok", metrics) if metrics else ("dead", None)
    finally:
        if proc.returncode is None:
            try:
                proc.kill()
            except ProcessLookupError:
                pass
        await proc.wait()


async def xray_phase(pending: list[dict]):
    """Пул процессов Xray: у каждого воркера свой порт."""
    tmpdir = Path(tempfile.mkdtemp(prefix="xray_cfg_"))
    queue: asyncio.Queue = asyncio.Queue()
    for item in pending:
        queue.put_nowait(item)
    stats: dict[str, Counter] = defaultdict(Counter)
    ok_items: list[dict] = []
    refused_items: list[dict] = []
    total = len(pending)
    done = 0

    async def worker(port: int) -> None:
        nonlocal done
        while True:
            try:
                item = queue.get_nowait()
            except asyncio.QueueEmpty:
                return
            try:
                outcome, metrics = await xray_check_item(item, port, tmpdir)
            except Exception:
                outcome, metrics = "dead", None
            stats[item["scheme"]][outcome] += 1
            if outcome == "ok":
                item.update(metrics)
                item["method"] = "xray"
                ok_items.append(item)
            elif outcome == "refused":
                refused_items.append(item)
            done += 1
            if done % 500 == 0 or done == total:
                print(f"  Xray: проверено {done}/{total} | работают: {len(ok_items)}", flush=True)

    try:
        await asyncio.gather(*(worker(XRAY_BASE_PORT + i) for i in range(max(1, min(XRAY_WORKERS, total)))))
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)
    return ok_items, refused_items, stats


async def check_light(line: str, sem: asyncio.Semaphore, xray_ok: bool) -> dict | None:
    """Быстрая стадия: TCP-пинг и подготовка конфига для Xray."""
    async with sem:
        try:
            scheme = get_scheme(line)
            host, port = extract_host_port(line)
            if not host or not port:
                return None

            item = {
                "raw": line, "proxy": line, "ip": "", "country": detect_country(line),
                "scheme": scheme, "latency_ms": None, "speed_mbps": None,
                "method": "unchecked", "is_reality": False, "sni": "",
            }
            if scheme == "vless":
                item.update(parse_vless_params(line))

            outbound = build_outbound(line) if scheme in XRAY_SCHEMES else None
            if outbound is not None:
                if scheme != "hysteria2":  # hysteria2 — UDP, TCP-пинг бессмыслен
                    tcp = await tcp_check(host, port)
                    if tcp is None:
                        return None
                    item["latency_ms"] = tcp
                if xray_ok:
                    item["method"] = "xray_pending"
                    item["outbound"] = outbound
                elif scheme != "hysteria2":
                    item["method"] = "tcp"

            ip = await resolve_to_ip(host)
            item["ip"] = ip
            needs_ip = item["method"] == "unchecked" or scheme == "hysteria2"
            if needs_ip and not is_ip(ip):
                return None  # непроверяемый сервер, чей хост даже не резолвится
            return item
        except Exception:
            return None


# ============================ ФИЛЬТРАЦИЯ ============================
def rank_key(item: dict) -> tuple:
    """Быстрее — выше; при равенстве — меньше задержка. Без замера — в конец."""
    s, l = item.get("speed_mbps"), item.get("latency_ms")
    return (s is None, -(s or 0.0), l is None, l or 0)


def passes_speed(item: dict) -> bool:
    if MIN_SPEED_MBPS <= 0 or item["method"] != "xray":
        return True
    return (item.get("speed_mbps") or 0) >= MIN_SPEED_MBPS


def smart_filter(
    items: list[dict],
    max_per_country: int = MAX_PER_COUNTRY,
    max_total: int = MAX_TOTAL,
    unique_ip: bool = True,
) -> list[dict]:
    seen_ips: set[str] = set()
    per_country: dict[str, int] = defaultdict(int)
    result: list[dict] = []
    for item in sorted(items, key=rank_key):
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
    cand.sort(key=lambda i: (not i["is_reality"], not sni_is_ru(i["sni"]), *rank_key(i)))

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


# ============================ ГЕОЛОКАЦИЯ ============================
def load_geo_cache() -> dict:
    try:
        data = json.loads((OUT_DIR / GEO_CACHE_NAME).read_text(encoding="utf-8"))
    except Exception:
        return {}
    cutoff = time.time() - GEO_TTL_DAYS * 86400
    return {
        ip: v for ip, v in data.items()
        if isinstance(v, dict) and v.get("cc") and v.get("ts", 0) >= cutoff
    }


def save_geo_cache(cache: dict) -> None:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    (OUT_DIR / GEO_CACHE_NAME).write_text(
        json.dumps(cache, ensure_ascii=False, sort_keys=True, separators=(",", ":")),
        encoding="utf-8",
    )


def _header_int(headers, name: str, default: int) -> int:
    try:
        return int(headers.get(name, default))
    except (TypeError, ValueError):
        return default


def _geo_request(chunk: list[str]) -> list | None:
    """Один пакетный запрос к ip-api (до 100 IP). None — ошибка."""
    url = "http://ip-api.com/batch?fields=status,countryCode,city,query"
    for _ in range(3):
        req = urllib.request.Request(
            url,
            data=json.dumps(chunk).encode(),
            headers={"Content-Type": "application/json", "User-Agent": "Mozilla/5.0"},
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                rows = json.loads(resp.read().decode())
                if resp.headers.get("X-Rl") == "0":
                    time.sleep(_header_int(resp.headers, "X-Ttl", 5) + 1)
                return rows
        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = _header_int(e.headers, "X-Ttl", 30) + 1
                print(f"  geo: лимит запросов, ждём {wait}с")
                time.sleep(min(wait, 90))
                continue
            print(f"  geo: HTTP {e.code}")
            return None
        except Exception as e:
            print(f"  geo: ошибка {e}")
            return None
    return None


def geo_lookup(ips: list[str]) -> dict[str, dict]:
    """IP -> {"cc": "DE", "city": "Frankfurt am Main"}."""
    result: dict[str, dict] = {}
    started = time.monotonic()
    for n, i in enumerate(range(0, len(ips), 100), start=1):
        if time.monotonic() - started > GEO_TIME_LIMIT:
            print("  geo: лимит времени, остальное доопределится в следующий запуск")
            break
        rows = _geo_request(ips[i:i + 100])
        if rows is None:
            break
        for row in rows:
            cc = row.get("countryCode")
            if row.get("status") == "success" and cc in COUNTRIES:
                result[row["query"]] = {"cc": cc, "city": row.get("city") or ""}
        if n % 10 == 0:
            print(f"  geo: {min(i + 100, len(ips))}/{len(ips)}", flush=True)
        time.sleep(4.5)  # бесплатный лимит ip-api: 15 пакетных запросов в минуту
    return result


def apply_geo(working: list[dict]) -> tuple[list[dict] | None, dict]:
    """Ставит каждому серверу реальные страну и город по IP."""
    cache = load_geo_cache()

    best: dict[str, tuple] = {}  # лучшие серверы определяем первыми
    for item in working:
        if is_ip(item["ip"]):
            key = rank_key(item)
            if item["ip"] not in best or key < best[item["ip"]]:
                best[item["ip"]] = key
    need_all = sorted((ip for ip in best if ip not in cache), key=lambda ip: best[ip])
    need = need_all[:GEO_MAX_IPS]
    print(f"Геолокация: уникальных IP {len(best)}, в кеше {len(best) - len(need_all)}, запрашиваем {len(need)}")

    if need:
        fresh = geo_lookup(need)
        now = int(time.time())
        for ip, info in fresh.items():
            cache[ip] = {**info, "ts": now}
        print(f"  определено: {len(fresh)} из {len(need)}")
    save_geo_cache(cache)

    fixed_wrong = fixed_unknown = no_geo = 0
    result: list[dict] = []
    for item in working:
        label = item["country"]
        info = cache.get(item["ip"])
        item["city"] = ""
        if info:
            if label == "XX":
                fixed_unknown += 1
            elif label != info["cc"]:
                fixed_wrong += 1
            item["country"] = info["cc"]
            item["city"] = info.get("city", "")
            result.append(item)
        else:
            no_geo += 1
            if not GEO_STRICT:
                result.append(item)

    stats = {
        "unique_ips": len(best),
        "labels_corrected": fixed_wrong,
        "labels_filled_from_ip": fixed_unknown,
        "servers_without_geo": no_geo,
        "geo_strict": GEO_STRICT,
    }
    print(
        f"Названия по IP: исправлено неверных меток {fixed_wrong}, "
        f"заполнено неизвестных {fixed_unknown}, без геоданных {no_geo}"
        f"{' (исключены)' if GEO_STRICT else ''}"
    )
    if GEO_STRICT and not result:
        return None, stats
    return result, stats


# ============================ MAIN ============================
async def main_async() -> int:
    global _speed_sem
    _speed_sem = None
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    print(f"[{stamp}] Источников: {len(SOURCE_URLS)}")
    xray_ok = xray_available()

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

    parsed_by_scheme = Counter(get_scheme(c) for c in configs)
    print(f"Уникальных конфигов: {len(configs)}  {dict(parsed_by_scheme)}")
    if not configs:
        print("Список пуст — результаты не меняем")
        return 0

    # 2. Быстрая стадия: TCP-пинг
    sem = asyncio.Semaphore(CONCURRENCY)
    tasks = [asyncio.create_task(check_light(c, sem, xray_ok)) for c in configs]
    light: list[dict] = []
    done = 0
    for fut in asyncio.as_completed(tasks):
        res = await fut
        done += 1
        if res:
            light.append(res)
        if done % 2000 == 0 or done == len(tasks):
            print(f"  TCP: проверено {done}/{len(tasks)} | живых: {len(light)}", flush=True)

    pending = [i for i in light if i["method"] == "xray_pending"]
    working = [i for i in light if i["method"] != "xray_pending"]

    # 3. Xray: реальная проверка + скорость
    xray_stats: dict[str, dict] = {}
    fallback_schemes: list[str] = []
    if pending:
        print(f"Xray: проверяем {len(pending)} серверов ({XRAY_WORKERS} параллельно)...")
        ok_items, refused_items, stats = await xray_phase(pending)
        working += ok_items
        xray_stats = {s: dict(c) for s, c in stats.items()}

        refused_by_scheme: dict[str, list[dict]] = defaultdict(list)
        for item in refused_items:
            refused_by_scheme[item["scheme"]].append(item)
        for scheme, items in refused_by_scheme.items():
            started = stats[scheme]["ok"] + stats[scheme]["dead"]
            if started == 0 and len(items) >= REFUSE_FALLBACK_MIN:
                # Xray не принял НИ ОДНОГО конфига протокола — вероятно, формат не подходит
                # этой версии Xray. Не теряем серверы: оставляем как были после TCP-пинга.
                print(f"ВНИМАНИЕ: Xray отверг все {len(items)} конфигов {scheme} — оставляем по TCP-пингу")
                fallback_schemes.append(scheme)
                for item in items:
                    item["method"] = "tcp" if scheme != "hysteria2" else "unchecked"
                    working.append(item)
    for item in working:
        item.pop("outbound", None)

    if not working:
        print("Нет рабочих серверов — результаты не меняем")
        return 0
    working = [i for i in working if passes_speed(i)]

    # 4. Реальные страна и город по IP
    geo_stats: dict = {}
    if GEO_LOOKUP:
        geo_result, geo_stats = await asyncio.to_thread(apply_geo, working)
        if geo_result is None:
            print("Геолокация не сработала ни для одного IP — результаты не меняем")
            return 0
        working = geo_result

    for item in working:
        item["proxy"] = format_clean_proxy(item["raw"], item["country"], item.get("city", ""))

    # 5. Списки
    checked = [i for i in working if i["method"] != "unchecked"]
    main_list = smart_filter(checked, MAX_PER_COUNTRY, MAX_TOTAL)
    white_list = smart_filter_white(working)
    xray_list = smart_filter(
        [i for i in working if i["method"] == "xray"], XRAY_FILE_MAX_PER_COUNTRY, XRAY_FILE_MAX_TOTAL
    )
    by_scheme: dict[str, list[dict]] = defaultdict(list)
    for item in working:
        by_scheme[item["scheme"]].append(item)

    # 6. Запись (старые файлы по протоколам удаляем, чтобы не оставались устаревшие)
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    by_dir = OUT_DIR / "by_protocol"
    by_dir.mkdir(parents=True, exist_ok=True)
    for old in by_dir.glob("*.txt"):
        old.unlink()

    write_list(OUT_DIR / "all.txt", main_list)
    write_list(OUT_DIR / "working_proxies.txt", main_list)
    write_list(OUT_DIR / "white_checked.txt", white_list)
    write_list(OUT_DIR / "xray_checked.txt", xray_list)

    per_file: dict[str, int] = {}
    for scheme, items in sorted(by_scheme.items()):
        filtered = smart_filter(items, PROTO_MAX_PER_COUNTRY, PROTO_MAX_TOTAL)
        write_list(by_dir / f"{scheme}.txt", filtered)
        per_file[scheme] = len(filtered)

    metrics = [
        {
            "scheme": i["scheme"], "country": i["country"], "city": i.get("city", ""),
            "ip": i["ip"], "latency_ms": i["latency_ms"], "speed_mbps": i["speed_mbps"],
        }
        for i in xray_list
    ]
    (OUT_DIR / "metrics.json").write_text(
        json.dumps(metrics, ensure_ascii=False, separators=(",", ":")), encoding="utf-8"
    )

    speeds = sorted(i["speed_mbps"] for i in xray_list if i["speed_mbps"] is not None)
    stats_out = {
        "checked_at_utc": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "sources": SOURCE_URLS,
        "xray_used": xray_ok,
        "total_configs": len(configs),
        "alive_or_unchecked": len(working),
        "by_method": dict(Counter(i["method"] for i in working)),
        "xray_by_protocol": xray_stats,
        "xray_fallback_protocols": fallback_schemes,
        "all_txt": len(main_list),
        "white_checked_txt": len(white_list),
        "xray_checked_txt": len(xray_list),
        "xray_checked_speed_mbps_median": speeds[len(speeds) // 2] if speeds else None,
        "by_protocol": per_file,
        "limits": {
            "all_txt": {"per_country": MAX_PER_COUNTRY, "total": MAX_TOTAL},
            "by_protocol": {"per_country": PROTO_MAX_PER_COUNTRY, "total": PROTO_MAX_TOTAL},
            "xray_checked_txt": {"per_country": XRAY_FILE_MAX_PER_COUNTRY, "total": XRAY_FILE_MAX_TOTAL},
        },
        "geo": geo_stats,
        "test_urls": [TEST_GSTATIC, TEST_CLOUDFLARE, speed_url() if SPEED_TEST else None],
    }
    (OUT_DIR / "stats.json").write_text(json.dumps(stats_out, ensure_ascii=False, indent=2), encoding="utf-8")

    print(f"Итого: {len(working)} | {dict(Counter(i['method'] for i in working))}")
    print(f"all.txt: {len(main_list)} | xray_checked.txt: {len(xray_list)} | white_checked.txt: {len(white_list)}")
    for scheme, n in per_file.items():
        print(f"  by_protocol/{scheme}.txt -> {n}")
    print("Готово.")
    return 0


def main() -> int:
    return asyncio.run(main_async())


if __name__ == "__main__":
    sys.exit(main())
