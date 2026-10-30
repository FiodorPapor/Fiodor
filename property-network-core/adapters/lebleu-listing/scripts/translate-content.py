from __future__ import annotations

import argparse
import json
import re
from pathlib import Path

from argostranslate.translate import translate

ROOT = Path('/opt/lebleu-listing-bridge')
CATALOG = ROOT / 'public/data/full/catalog.json'
CACHE = ROOT / 'state/ru-content.json'

IMPORTANT = re.compile(
    r'ingreso|admisi[oó]n|garant[ií]a|expensas|amoblad|equipad|capacidad|seguridad|subte|'
    r'financi|apto cr[eé]dito|amenit|contrato|mascotas|cochera|pileta|piscina|parrilla|'
    r'lavadero|laundry|terraza|balc[oó]n|patio|jard[ií]n|gimnasio|sum|solarium',
    re.I,
)

def choose_text(text: str, limit: int = 1500) -> str:
    text = re.sub(r'\s+', ' ', text or '').strip()
    if not text:
        return ''
    sentences = re.split(r'(?<=[.!?])\s+|(?<=\d)\s+(?=[A-ZÁÉÍÓÚÑ])', text)
    picked: list[str] = []
    size = 0
    for i, sentence in enumerate(sentences):
        sentence = sentence.strip()
        if not sentence:
            continue
        keep = i < 3 or bool(IMPORTANT.search(sentence))
        if keep and sentence not in picked:
            if size + len(sentence) + 1 > limit:
                break
            picked.append(sentence)
            size += len(sentence) + 1
    return ' '.join(picked) or text[:limit]


def postprocess(text: str) -> str:
    fixes = {
        'право на доход': 'вступительный взнос',
        'право на въезд': 'вступительный взнос',
        'барбекю': 'зона барбекю',
        'кинчо': 'крытая зона отдыха (quincho)',
        'СУМ': 'общий зал (SUM)',
    }
    for old, new in fixes.items():
        text = text.replace(old, new)
    text = re.sub(r'\s+', ' ', text).strip()
    return text


def important_notes(src: str) -> list[str]:
    notes: list[str] = []
    m = re.search(r'derecho de ingreso[^\d]{0,50}(?:U\$S|US\$|USD)\s*([\d.]+)', src, re.I)
    if m:
        notes.append(f'Вступительный взнос: USD {m.group(1)}')
    if re.search(r'entrevistas? de admisi[oó]n', src, re.I):
        notes.append('Для вступления требуется собеседование')
    m = re.search(r'capacidad para\s*(\d+)\s*person', src, re.I)
    if m:
        notes.append(f'Рассчитано на {m.group(1)} чел.')
    if re.search(r'totalmente amoblad', src, re.I):
        notes.append('Полностью меблировано')
    if re.search(r'seguridad\s*24', src, re.I):
        notes.append('Охрана 24/7')
    m = re.search(r'(?:aproximadamente\s*)?(\d+)\s*metros?[^.]{0,80}l[ií]nea\s*D', src, re.I)
    if m:
        notes.append(f'Около {m.group(1)} м до метро линии D')
    return notes[:4]


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--codes', default='')
    args = ap.parse_args()
    wanted = {x.strip() for x in args.codes.split(',') if x.strip()}
    items = json.loads(CATALOG.read_text())
    CACHE.parent.mkdir(parents=True, exist_ok=True)
    cache = json.loads(CACHE.read_text()) if CACHE.exists() else {}
    changed = 0
    for item in items:
        code = str(item.get('code') or item.get('slug') or '')
        if wanted and code not in wanted:
            continue
        fingerprint = str(item.get('sourceFingerprint') or '')
        old = cache.get(code) or {}
        if old.get('fingerprint') == fingerprint and old.get('summary_ru'):
            continue
        source = choose_text(str(item.get('description') or ''))
        if not source:
            summary = ''
        else:
            en = translate(source, 'es', 'en')
            summary = postprocess(translate(en, 'en', 'ru'))
        cache[code] = {
            'fingerprint': fingerprint,
            'summary_ru': summary[:1200],
            'notes_ru': important_notes(str(item.get('description') or '')),
        }
        changed += 1
        print('translated', code, flush=True)
        CACHE.write_text(json.dumps(cache, ensure_ascii=False, indent=2))
    print(json.dumps({'changed': changed, 'cached': len(cache)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
