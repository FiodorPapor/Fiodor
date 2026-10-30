from __future__ import annotations

import argparse
import hashlib
import json
import re
from pathlib import Path

from transformers import AutoModelForSeq2SeqLM, AutoTokenizer

ROOT = Path('/opt/lebleu-listing-bridge')
CATALOG = ROOT / 'public/data/full/catalog.json'
OUTPUT = ROOT / 'state/ru-content.json'
MODEL = 'Helsinki-NLP/opus-mt-es-ru'

CRITICAL = (
    'ingreso', 'admisión', 'admision', 'garantía', 'garantia', 'caución', 'caucion',
    'depósito', 'deposito', 'ajuste', 'mascota', 'apto crédito', 'apto credito',
    'capacidad', 'amoblad', 'subte', 'seguridad 24', 'expensas', 'requisito',
    'contrato', 'temporari', 'disponible', 'posesión', 'posesion', 'entrega', 'lote',
)
def fingerprint(item: dict) -> str:
    raw = str(item.get('sourceFingerprint') or item.get('description') or item.get('sourceUrl') or '')
    return hashlib.sha256(raw.encode()).hexdigest()


def split_sentences(text: str) -> list[str]:
    text = re.sub(r'\s*•\s*', '. ', text or '')
    text = re.sub(r'\s*[\r\n]+\s*', '. ', text)
    text = re.sub(r'\s+', ' ', text).strip()
    parts = re.split(r'(?<=[.!?])\s+|\s+-\s+(?=[A-ZÁÉÍÓÚÑ])', text)
    out: list[str] = []
    for part in parts:
        part = part.strip(' .;-')
        if len(part) < 20:
            continue
        if part not in out:
            out.append(part)
    return out


def pick_texts(description: str) -> tuple[list[str], list[str]]:
    sentences = split_sentences(description)
    important = [s for s in sentences if any(k in s.lower() for k in CRITICAL)]
    ordinary = [s for s in sentences if s not in important]
    summary = ordinary[:2] if ordinary else sentences[:2]
    return summary[:2], important[:3]
def clean_ru(text: str) -> str:
    replacements = {
        'Субте': 'метро', 'субте': 'метро', 'Лаундри': 'прачечная', 'лаундри': 'прачечная',
        'солнечный зал': 'солярий', 'Жареное': 'зона барбекю', 'жареное': 'зона барбекю',
        'квинчо': 'кинчо', 'Квинчо': 'Кинчо', 'пилет': 'бассейн', 'Пилет': 'Бассейн',
    }
    for a, b in replacements.items():
        text = text.replace(a, b)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def translate_texts(tokenizer, model, texts: list[str], batch_size: int = 8) -> list[str]:
    if not texts:
        return []
    out: list[str] = []
    for i in range(0, len(texts), batch_size):
        batch = texts[i:i + batch_size]
        encoded = tokenizer(batch, return_tensors='pt', padding=True, truncation=True, max_length=384)
        generated = model.generate(**encoded, max_new_tokens=180, num_beams=1)
        out.extend(clean_ru(x) for x in tokenizer.batch_decode(generated, skip_special_tokens=True))
    return out


def compact_join(parts: list[str], limit: int) -> str:
    result = ''
    for part in parts:
        candidate = (result + (' ' if result else '') + part).strip()
        if len(candidate) > limit:
            break
        result = candidate
    return result
def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument('--only-code', action='append', default=[])
    args = parser.parse_args()
    only_codes = {str(x).strip() for x in args.only_code if str(x).strip()}
    catalog = json.loads(CATALOG.read_text())
    existing = json.loads(OUTPUT.read_text()) if OUTPUT.exists() else {}
    work: list[tuple[str, str, list[str], list[str]]] = []
    for item in catalog:
        code = str(item.get('code') or item.get('slug') or '')
        if not code:
            continue
        if only_codes and code not in only_codes:
            continue
        fp = fingerprint(item)
        cached = existing.get(code) or {}
        if cached.get('manual') and cached.get('summary_ru'):
            continue
        if cached.get('fingerprint') == fp and cached.get('summary_ru'):
            continue
        summary_src, notes_src = pick_texts(str(item.get('description') or ''))
        work.append((code, fp, summary_src, notes_src))

    if not work:
        print(json.dumps({'updated': 0, 'total': len(existing)}, ensure_ascii=False))
        return
    tokenizer = AutoTokenizer.from_pretrained(MODEL)
    model = AutoModelForSeq2SeqLM.from_pretrained(MODEL)
    source_texts: list[str] = []
    slots: list[tuple[str, str]] = []
    for code, _fp, summary_src, notes_src in work:
        for text in summary_src:
            source_texts.append(text); slots.append((code, 'summary'))
        for text in notes_src:
            source_texts.append(text); slots.append((code, 'note'))

    translated = translate_texts(tokenizer, model, source_texts)
    buckets: dict[str, dict[str, list[str]]] = {}
    for (code, kind), text in zip(slots, translated):
        buckets.setdefault(code, {'summary': [], 'note': []})[kind].append(text)
    for code, fp, _summary_src, _notes_src in work:
        data = buckets.get(code, {'summary': [], 'note': []})
        existing[code] = {
            'fingerprint': fp,
            'summary_ru': compact_join(data['summary'], 650),
            'notes_ru': [x for x in data['note'] if x][:4],
            'translator': MODEL,
        }
    OUTPUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUTPUT.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(existing, ensure_ascii=False, indent=2))
    tmp.replace(OUTPUT)
    print(json.dumps({'updated': len(work), 'total': len(existing)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
