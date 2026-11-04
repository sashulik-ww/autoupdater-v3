#!/usr/bin/env python3
"""
Бесплатное AI-ранжирование кандидатов через Groq.
Работает в GitHub Actions.
"""

import argparse
import json
import os
import sys
import time
from pathlib import Path

from openai import OpenAI

# --- НАСТРОЙКИ GROQ ---
BASE_URL = "https://api.groq.com/openai/v1"
MODEL = "openai/gpt-oss-20b"          # быстрая бесплатная модель
# Можно заменить на: "openai/gpt-oss-120b" или "qwen/qwen3.8-27b"

BATCH_SIZE = 18
MAX_CANDIDATES = 120
OUT_DIR = Path("out")
# ----------------------

sys.path.insert(0, str(Path(__file__).parent))
try:
    import collector as C
except ImportError:
    print("! Нужен collector.py рядом")
    sys.exit(1)


def load_servers(path):
    p = Path(path)
    if not p.exists():
        return []
    out, seen = [], set()
    text = p.read_text(encoding="utf-8", errors="ignore")
    for link in C.extract_links(text):
        c = C.parse_vless(link, keep_other=True)
        if not c:
            continue
        k = (c["host"], c["port"], c["uuid"])
        if k not in seen:
            seen.add(k)
            out.append(c)
    return out


def server_brief(c):
    return {
        "host": c["host"],
        "port": c["port"],
        "sni": c.get("sni", ""),
        "type": c.get("type", ""),
        "pbk": (c.get("q") or {}).get("pbk", "")[:10] + "…",
        "uuid": c["uuid"][:8] + "…",
    }


def rank_batch(client, good, candidates):
    good_brief = [server_brief(s) for s in good[:25]]
    cand_brief = [server_brief(s) for s in candidates]

    prompt = f"""Ты эксперт по VLESS+Reality прокси.
Вот мои РАБОЧИЕ серверы:
{json.dumps(good_brief, ensure_ascii=False)}

Вот КАНДИДАТЫ:
{json.dumps(cand_brief, ensure_ascii=False)}

Оцени каждый кандидат от 0 до 100 (насколько похож на мои рабочие).
Учитывай: Reality pbk, SNI, порт, транспорт.
Верни ТОЛЬКО JSON-массив:
[{{"host":"...","port":443,"uuid":"первые8","score":85,"reason":"коротко на русском"}}]
Без markdown и лишнего текста."""

    try:
        resp = client.chat.completions.create(
            model=MODEL,
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            max_tokens=1800,
        )
        content = resp.choices[0].message.content.strip()

        # убираем возможные ```json
        if "```" in content:
            content = content.split("```")[1]
            if content.startswith("json"):
                content = content[4:]
        content = content.strip()

        data = json.loads(content)
        if isinstance(data, dict):
            for v in data.values():
                if isinstance(v, list):
                    data = v
                    break
        return data if isinstance(data, list) else []
    except Exception as e:
        print(f"! Ошибка API: {e}", file=sys.stderr)
        return []


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--good", default="my_working.txt")
    ap.add_argument("--candidates", nargs="+",
                    default=["out/similar_to_mine.txt", "out/similar_to_mine_untested.txt"])
    ap.add_argument("--out", default="out/ai_ranked.txt")
    ap.add_argument("--report", default="out/ai_report.txt")
    args = ap.parse_args()

    api_key = os.getenv("GROQ_API_KEY")
    if not api_key:
        print("! Не найден GROQ_API_KEY. Добавь его в Secrets репозитория.")
        sys.exit(1)

    client = OpenAI(api_key=api_key, base_url=BASE_URL)

    good = load_servers(args.good)
    if not good:
        print(f"! Нет рабочих серверов в {args.good}")
        sys.exit(1)

    candidates = []
    seen = set()
    for path in args.candidates:
        for c in load_servers(path):
            k = (c["host"], c["port"], c["uuid"])
            if k not in seen:
                seen.add(k)
                candidates.append(c)

    candidates = candidates[:MAX_CANDIDATES]
    print(f"Рабочих: {len(good)} | Кандидатов: {len(candidates)} | Модель: {MODEL} (Groq бесплатно)")

    all_ranked = []
    for i in range(0, len(candidates), BATCH_SIZE):
        batch = candidates[i:i + BATCH_SIZE]
        print(f"  пачка {i // BATCH_SIZE + 1}/{((len(candidates)-1)//BATCH_SIZE)+1}...")
        ranked = rank_batch(client, good, batch)
        all_ranked.extend(ranked)
        time.sleep(1.2)

    all_ranked.sort(key=lambda x: -x.get("score", 0))

    by_key = {(c["host"], c["port"], c["uuid"][:8]): c for c in candidates}
    lines = []
    report = [
        "Бесплатное AI-ранжирование через Groq",
        f"Модель: {MODEL}",
        f"Кандидатов обработано: {len(all_ranked)}",
        ""
    ]

    for item in all_ranked:
        key = (item.get("host"), item.get("port"), str(item.get("uuid", ""))[:8])
        orig = by_key.get(key)
        if not orig:
            continue
        score = item.get("score", 0)
        reason = item.get("reason", "")
        name = f"AI{score} {reason[:55]}"
        lines.append(f"{orig['base']}#{C.up.quote(name)}")
        report.append(f"{score:3d} | {orig['host']}:{orig['port']} | {reason}")

    OUT_DIR.mkdir(exist_ok=True)
    Path(args.out).write_text("\n".join(lines) + "\n", encoding="utf-8")
    Path(args.report).write_text("\n".join(report) + "\n", encoding="utf-8")

    print(f"\nГотово → {args.out}")
    print(f"Отчёт  → {args.report}")
    print("Топ-5 по мнению ИИ:")
    for r in all_ranked[:5]:
        print(f"  {r.get('score'):3d} — {r.get('host')}:{r.get('port')} — {r.get('reason','')[:65]}")


if __name__ == "__main__":
    main()
