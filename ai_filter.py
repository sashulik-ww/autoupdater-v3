#!/usr/bin/env python3
"""AI-фильтр результатов similar.py через Gemini API (stdlib, без pip)."""
import json
import os
import urllib.request
from pathlib import Path

URL = "https://generativelanguage.googleapis.com/v1beta/models/gemini-2.5-flash:generateContent"

def ask_gemini(prompt: str) -> str:
    body = json.dumps({
        "contents": [{"parts": [{"text": prompt}]}],
        "generationConfig": {"temperature": 0.2, "responseMimeType": "application/json"},
    }).encode()
    req = urllib.request.Request(
        URL, data=body,
        headers={"x-goog-api-key": os.environ["GEMINI_API_KEY"], "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = json.loads(resp.read().decode())
    return data["candidates"][0]["content"]["parts"][0]["text"]

def lines(path: str) -> list:
    p = Path(path)
    return [l for l in p.read_text(encoding="utf-8").splitlines() if l.strip()] if p.exists() else []

def main():
    tested = lines("out/similar_to_mine.txt")[:30]
    untested = lines("out/similar_to_mine_untested.txt")[:30]
    prompt = (
        "Списки VLESS Reality серверов, похожих на мои рабочие.\n"
        "Проверенные:\n" + "\n".join(tested) +
        "\nНепроверенные:\n" + "\n".join(untested) +
        "\nВыбери до 10 лучших для импорта в v2rayNG: проверенные приоритетнее, провайдеры разнообразнее."
        "\nВерни JSON: {\"best\": [ссылки целиком], \"summary\": \"пара фраз\"}"
    )
    raw = ask_gemini(prompt)
    data = json.loads(raw)
    Path("out").mkdir(exist_ok=True)
    Path("out/ai_picks.json").write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    if data.get("best"):
        Path("out/ai_picked.txt").write_text("\n".join(data["best"]) + "\n", encoding="utf-8")
    print(raw)

if __name__ == "__main__":
    main()
