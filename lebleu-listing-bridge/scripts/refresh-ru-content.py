from __future__ import annotations

import argparse
import json
import re
from datetime import date
from pathlib import Path

ROOT = Path("/opt/lebleu-listing-bridge")
CATALOG = ROOT / "public/data/full/catalog.json"
QUALITY = ROOT / "state/ru-content-quality.json"
MODEL = "Helsinki-NLP/opus-mt-es-ru"

CRITICAL = re.compile(
    r"expensas|garant[ií]a|cauci[oó]n|dep[oó]sito|ajuste|mascota|apto cr[eé]dito|"
    r"apto profesional|amoblad|seguridad|disponible|posesi[oó]n|entrega|financi|"
    r"cochera|pileta|piscina|parrilla|lavadero|laundry|terraza|balc[oó]n|patio|"
    r"jard[ií]n|gimnasio|solarium|baulera|ascensor",
    re.I,
)


def sentences(text: str) -> list[str]:
    text = re.sub(r"\s*•\s*", ". ", text or "")
    text = re.sub(r"[\r\n]+", ". ", text)
    text = re.sub(r"\s+", " ", text).strip()
    if not text:
        return []
    parts = re.split(r"(?<=[.!?])\s+|\s+-\s+(?=[A-ZÁÉÍÓÚÑ])", text)
    out: list[str] = []
    for part in parts:
        part = part.strip(" .;-")
        if len(part) < 18:
            continue
        if part not in out:
            out.append(part)
    return out


def choose(text: str) -> tuple[list[str], list[str]]:
    rows = sentences(text)
    critical = [x for x in rows if CRITICAL.search(x)]
    summary: list[str] = []
    for row in rows:
        if row not in summary:
            summary.append(row)
        if len(summary) >= 3:
            break
    notes = [x for x in critical if x not in summary][:4]
    return summary, notes


def clean(text: str) -> str:
    replacements = {
        "Субте": "метро",
        "субте": "метро",
        "Лаундри": "прачечная",
        "лаундри": "прачечная",
        "Пилет": "Бассейн",
        "пилет": "бассейн",
        "паррилья": "зона барбекю",
        "Паррилья": "Зона барбекю",
        "квинчо": "крытая зона отдыха (quincho)",
        "Квинчо": "Крытая зона отдыха (quincho)",
        "СУМ": "общий зал (SUM)",
    }
    for old, new in replacements.items():
        text = text.replace(old, new)
    text = re.sub(r"\s+", " ", text).strip()
    return text


def translate_batch(tokenizer, model, texts: list[str]) -> list[str]:
    if not texts:
        return []
    encoded = tokenizer(
        texts,
        return_tensors="pt",
        padding=True,
        truncation=True,
        max_length=420,
    )
    generated = model.generate(
        **encoded,
        max_new_tokens=220,
        num_beams=4,
        no_repeat_ngram_size=3,
        early_stopping=True,
    )
    return [clean(x) for x in tokenizer.batch_decode(generated, skip_special_tokens=True)]


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    catalog = json.loads(CATALOG.read_text(encoding="utf-8"))
    quality = json.loads(QUALITY.read_text(encoding="utf-8")) if QUALITY.exists() else {}

    work: list[tuple[dict, list[str], list[str]]] = []
    for item in catalog:
        source = str(item.get("sourceUrl") or "")
        if not source:
            continue
        current_fp = str(item.get("sourceFingerprint") or "")
        existing = quality.get(source) or {}
        if existing.get("summary_ru") and existing.get("sourceFingerprint") == current_fp:
            continue
        summary_src, notes_src = choose(str(item.get("description") or ""))
        work.append((item, summary_src, notes_src))

    print(json.dumps({
        "catalog": len(catalog),
        "current_quality": len(quality),
        "needs_refresh": len(work),
    }, ensure_ascii=False))
    if args.dry_run or not work:
        return

    # Heavy model import/load happens only when a source listing is actually new/changed.
    from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL)

    translated = 0
    for item, summary_src, notes_src in work:
        source_url = str(item.get("sourceUrl") or "")
        texts = summary_src + notes_src
        result = translate_batch(tokenizer, model, texts)
        summary_rows = result[:len(summary_src)]
        note_rows = result[len(summary_src):]
        summary = " ".join(x for x in summary_rows if x).strip()
        if not summary:
            continue
        quality[source_url] = {
            "code": item.get("code"),
            "operation": item.get("operation"),
            "sourceFingerprint": item.get("sourceFingerprint"),
            "summary_ru": summary[:1100],
            "notes_ru": [x for x in note_rows if x][:4],
            "details_override": {},
            "property_type_override": None,
            "reviewed": date.today().isoformat(),
            "editor": "local_marian_auto_v1",
        }
        translated += 1

    backup = QUALITY.with_name("ru-content-quality.before-auto.json")
    if QUALITY.exists():
        backup.write_text(QUALITY.read_text(encoding="utf-8"), encoding="utf-8")
    tmp = QUALITY.with_suffix(".json.tmp")
    tmp.write_text(json.dumps(quality, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    tmp.replace(QUALITY)
    print(json.dumps({"translated": translated, "quality_total": len(quality)}, ensure_ascii=False))


if __name__ == "__main__":
    main()
