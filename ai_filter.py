#!/usr/bin/env python3
"""Фильтрация результатов similar.py через GitHub Models API."""
import json
import os
from pathlib import Path
from openai import OpenAI

client = OpenAI(
    base_url="https://models.github.ai/inference",
    api_key=os.environ.get("GITHUB_TOKEN", ""),
)

MODEL = "openai/gpt-4o-mini"

def load_servers(path: Path) -> list[str]:
    """Загружает vless ссылки из файла."""
    if not path.exists():
        return []
    return [line.strip() for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def ask_ai(prompt: str, system: str = "", json_mode: bool = False) -> str:
    """Запрос к модели."""
    messages = []
    if system:
        messages.append({"role": "system", "content": system})
    messages.append({"role": "user", "content": prompt})
    
    kwargs = dict(model=MODEL, messages=messages, temperature=0.2)
    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}
    
    try:
        response = client.chat.completions.create(**kwargs)
        return response.choices[0].message.content
    except Exception as e:
        print(f"Ошибка API: {e}")
        return "{}" if json_mode else ""

def filter_similar(top_n: int = 20) -> dict:
    """Берёт результаты similar.py и просит модель выбрать лучшие."""
    tested = Path("out/similar_to_mine.txt")
    untested = Path("out/similar_to_mine_untested.txt")
    report = Path("out/similar_report.txt")
    
    tested_lines = load_servers(tested)[:50]  # лимит для промпта
    untested_lines = load_servers(untested)[:50]
    report_text = report.read_text(encoding="utf-8") if report.exists() else ""
    
    prompt = f"""У меня есть два списка VLESS Reality серверов, похожих на мои рабочие:

ПРОВЕРЕННЫЕ (прошли Xray, {len(tested_lines)} из них):
{chr(10).join(tested_lines[:20])}

НЕПРОВЕРЕННЫЕ (не проверились с раннера, но могут работать из РФ, {len(untested_lines)} из них):
{chr(10).join(untested_lines[:20])}

Контекст из отчёта:
{report_text[:500]}

Выбери до {top_n} самых перспективных серверов для добавления в v2rayNG.
Критерии: 
- Предпочитай проверенные
- Ищи общие признаки с моими рабочими (pbk, ASN, подсеть)
- Избегай явных дублей
- Разные провайдеры лучше, чем много серверов одного

Верни JSON: {{
  "best": ["vless://ссылка1", "vless://ссылка2"],
  "reasons": ["Почему выбран сервер 1", "Почему выбран сервер 2"],
  "summary": "Краткое резюме (1-2 предложения)"
}}"""

    system = "Ты эксперт по VLESS Reality прокси. Отвечай только валидным JSON без markdown."
    raw = ask_ai(prompt, system, json_mode=True)
    
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        return {"best": [], "reasons": [], "summary": "Ошибка парсинга ответа"}

def main():
    result = filter_similar()
    
    # Сохраняем результат
    out = Path("out/ai_picks.json")
    out.write_text(json.dumps(result, ensure_ascii=False, indent=2), encoding="utf-8")
    
    # Также сохраняем только ссылки для импорта
    if result.get("best"):
        picks = Path("out/ai_picked.txt")
        picks.write_text("\n".join(result["best"]) + "\n", encoding="utf-8")
        print(f"Выбрано серверов: {len(result['best'])}")
    
    print("\nСводка:", result.get("summary", ""))
    if result.get("reasons"):
        print("\nПричины:")
        for i, reason in enumerate(result["reasons"], 1):
            print(f"{i}. {reason}")

if __name__ == "__main__":
    main()
