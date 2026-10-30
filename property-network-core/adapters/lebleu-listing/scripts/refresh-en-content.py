from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path

from transformers import MarianMTModel, MarianTokenizer

ROOT = Path('/opt/lebleu-listing-bridge')
CATALOG = ROOT / 'public/data/full/catalog.json'
STATE = ROOT / 'state/en-content.json'
MODEL_NAME = 'Helsinki-NLP/opus-mt-es-en'
VERSION = 'opus-mt-es-en-v1'

TERM_RULES: list[tuple[re.Pattern[str], str]] = [
    (re.compile(r'\ba (?:pocas|unas) cuadras de\b', re.I), 'a few blocks from'),
    (re.compile(r'\ba metros de\b', re.I), 'close to'),
    (re.compile(r'\bliving comedor\b', re.I), 'living/dining room'),
    (re.compile(r'\blosa radiante\b', re.I), 'radiant-floor heating'),
    (re.compile(r'\blocal comercial\b', re.I), 'commercial premises'),
    (re.compile(r'\bdepartamento\b|\bdpto\.?\b', re.I), 'apartment'),
    (re.compile(r'\bambientes\b', re.I), 'rooms'),
    (re.compile(r'\bambiente\b', re.I), 'room'),
    (re.compile(r'\bgalp[oó]n\b', re.I), 'warehouse'),
    (re.compile(r'\bcampo\b', re.I), 'rural property'),
    (re.compile(r'\bplacard(?:es)?\b', re.I), 'built-in closet'),
    (re.compile(r'\btermotanque\b', re.I), 'water heater'),
    (re.compile(r'\bconsultorio\b', re.I), 'professional office'),
    (re.compile(r'\bLobos\b', re.I), 'Lobos'),
    (re.compile(r'\bBelgrano\b', re.I), 'Belgrano'),
    (re.compile(r'\bRecoleta\b', re.I), 'Recoleta'),
    (re.compile(r'\bPalermo\b', re.I), 'Palermo'),
    (re.compile(r'\bColegiales\b', re.I), 'Colegiales'),
    (re.compile(r'\bN[uú][nñ]ez\b', re.I), 'Núñez'),
    (re.compile(r'\bSan Telmo\b', re.I), 'San Telmo'),
    (re.compile(r'\bCaballito\b', re.I), 'Caballito'),
    (re.compile(r'\bBuenos Aires\b', re.I), 'Buenos Aires'),
    (re.compile(r'\bMar del Plata\b', re.I), 'Mar del Plata'),
    (re.compile(r'\bLa Plata\b', re.I), 'La Plata'),
    (re.compile(r'\bVicente L[oó]pez\b', re.I), 'Vicente López'),
    (re.compile(r'\bMart[ií]nez\b', re.I), 'Martínez'),
    (re.compile(r'\bTigre\b', re.I), 'Tigre'),
    (re.compile(r'\bCa[nñ]uelas\b', re.I), 'Cañuelas'),
    (re.compile(r'\bsemipiso\b', re.I), 'semi-private-floor apartment'),
    (re.compile(r'\bmonoambiente\b', re.I), 'studio apartment'),
    (re.compile(r'\bexpensas\b', re.I), 'building fees (expensas)'),
    (re.compile(r'\bapto cr[eé]dito\b', re.I), 'mortgage eligible'),
    (re.compile(r'\bapto profesional\b', re.I), 'suitable for professional use'),
    (re.compile(r'\bal contrafrente\b', re.I), 'rear-facing'),
    (re.compile(r'\bcontrafrente\b', re.I), 'rear-facing'),
    (re.compile(r'\bal frente\b', re.I), 'front-facing'),
    (re.compile(r'\bbaulera\b', re.I), 'storage unit'),
    (re.compile(r'\bparrilla\b', re.I), 'barbecue grill (parrilla)'),
    (re.compile(r'\bquincho\b', re.I), 'covered barbecue and social area (quincho)'),
    (re.compile(r'\bpileta\b|\bpiscina\b', re.I), 'swimming pool'),
    (re.compile(r'\bSUM\b'), 'shared multipurpose room (SUM)'),
    (re.compile(r'\bsubte\b', re.I), 'subway'),
    (re.compile(r'\bcolectivos?\b', re.I), 'bus lines'),
    (re.compile(r'\bcochera\b', re.I), 'parking space'),
    (re.compile(r'\blavadero\b', re.I), 'laundry area'),
    (re.compile(r'\ba estrenar\b', re.I), 'brand new'),
]


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def save_json(path: Path, payload) -> None:
    tmp = path.with_suffix(path.suffix + '.tmp')
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    tmp.replace(path)


def protect(text: str) -> tuple[str, dict[str, str]]:
    restore: dict[str, str] = {}
    out = text
    for rx, replacement in TERM_RULES:
        def repl(_m, value=replacement):
            token = f'ZZTERM{len(restore)}ZZ'
            restore[token] = value
            return token
        out = rx.sub(repl, out)
    return out, restore


def restore(text: str, values: dict[str, str]) -> tuple[str, list[str]]:
    missing = []
    out = text
    for token, value in values.items():
        if token not in out:
            missing.append(token)
        out = out.replace(token, value)
    return re.sub(r'\s+', ' ', out).strip(), missing


def chunks(text: str, max_chars: int = 420) -> list[str]:
    text = re.sub(r'\s+', ' ', text or '').strip()
    if not text:
        return []
    rows = re.split(r'(?<=[.!?])\s+|\s*[•·]\s*', text)
    out: list[str] = []
    buf = ''
    for row in rows:
        row = row.strip()
        if not row:
            continue
        if len(row) > max_chars:
            pieces = [row[i:i + max_chars] for i in range(0, len(row), max_chars)]
        else:
            pieces = [row]
        for part in pieces:
            candidate = (buf + ' ' + part).strip()
            if buf and len(candidate) > max_chars:
                out.append(buf)
                buf = part
            else:
                buf = candidate
    if buf:
        out.append(buf)
    return out


def normalized_numbers(text: str) -> set[str]:
    values: set[str] = set()
    for raw in re.findall(r'(?<![A-Za-z])(?:\d{1,3}(?:[.\s,]\d{3})+(?:[.,]\d+)?|\d+(?:[.,]\d+)?)(?![A-Za-z])', text):
        value = raw.strip()
        # Treat common thousand separators as typography, not numeric changes.
        if re.fullmatch(r'\d{1,3}(?:[.\s,]\d{3})+(?:[.,]\d+)?', value):
            parts = re.split(r'[.\s,]', value)
            if len(parts) > 1 and all(len(x) == 3 for x in parts[1:-1] or parts[1:]):
                value = ''.join(parts)
        value = value.replace(',', '.')
        try:
            number = float(value)
            values.add(str(int(number)) if number.is_integer() else ('%.6f' % number).rstrip('0').rstrip('.'))
        except ValueError:
            pass
    return values


def validate(source: str, translated: str, missing_tokens: list[str]) -> list[str]:
    errors: list[str] = []
    if not translated or len(translated) < 20:
        errors.append('empty_or_too_short')
    ratio = len(translated) / max(1, len(source))
    if ratio < 0.40 or ratio > 2.20:
        errors.append('length_ratio')
    if missing_tokens:
        errors.append('missing_terms:' + ','.join(missing_tokens[:6]))
    missing_numbers = normalized_numbers(source) - normalized_numbers(translated)
    if missing_numbers:
        errors.append('missing_numbers:' + ','.join(sorted(missing_numbers)[:8]))
    alpha = len(re.findall(r'[A-Za-z]', translated))
    letters = len(re.findall(r'[A-Za-zÁÉÍÓÚÑáéíóúñ]', translated)) or 1
    if alpha / letters < 0.85:
        errors.append('too_little_english')
    return errors


def summarize(text: str, limit: int = 520) -> str:
    text = re.sub(r'\s+', ' ', text).strip()
    if len(text) <= limit:
        return text
    rows = re.split(r'(?<=[.!?])\s+', text)
    out = ''
    for row in rows:
        candidate = (out + ' ' + row).strip()
        if out and len(candidate) > limit:
            break
        out = candidate
    return out or text[:limit].rsplit(' ', 1)[0].rstrip(' ,;:') + '…'


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-items', type=int, default=6)
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--only-code', default='')
    args = ap.parse_args()

    catalog = load_json(CATALOG, [])
    state = load_json(STATE, {})
    pending = []
    for item in catalog:
        code = str(item.get('code') or '')
        if args.only_code and code != args.only_code:
            continue
        source = str(item.get('description') or '').strip()
        url = str(item.get('sourceUrl') or '')
        fp = str(item.get('sourceFingerprint') or '')
        if not url:
            continue
        row = state.get(url) or {}
        if len(source) < 20:
            state[url] = {'code': code, 'fingerprint': fp, 'status': 'source_missing', 'updated_at': datetime.now(UTC).isoformat()}
            continue
        if not args.force and row.get('fingerprint') == fp:
            if row.get('status') in {'live_auto','source_missing'}:
                continue
            if row.get('status') == 'needs_review' and row.get('translator') == VERSION:
                continue
        pending.append(item)
    pending = sorted(pending, key=lambda x: len(str(x.get('description') or '')))[:max(0, args.max_items)]
    if not pending:
        save_json(STATE, state)
        print(json.dumps({'attempted':0,'live_auto':0,'needs_review':0,'state_total':len(state)}))
        return

    tokenizer = MarianTokenizer.from_pretrained(MODEL_NAME)
    model = MarianMTModel.from_pretrained(MODEL_NAME)
    attempted = live = review = 0
    for item in pending:
        attempted += 1
        source = str(item.get('description') or '').strip()
        url = str(item.get('sourceUrl') or '')
        fp = str(item.get('sourceFingerprint') or '')
        all_parts: list[str] = []
        missing_terms: list[str] = []
        try:
            for chunk in chunks(source):
                protected, term_map = protect(chunk)
                batch = tokenizer([protected], return_tensors='pt', padding=True, truncation=True, max_length=512)
                generated = model.generate(**batch, max_new_tokens=520, num_beams=4)
                translated = tokenizer.batch_decode(generated, skip_special_tokens=True)[0]
                translated, missing = restore(translated, term_map)
                all_parts.append(translated)
                missing_terms.extend(missing)
            full = re.sub(r'\s+', ' ', ' '.join(all_parts)).strip()
            errors = validate(source, full, missing_terms)
            status = 'live_auto' if not errors else 'needs_review'
            live += int(status == 'live_auto')
            review += int(status != 'live_auto')
            state[url] = {
                'code': item.get('code'),
                'fingerprint': fp,
                'status': status,
                'summary_en': summarize(full),
                'description_en': full,
                'quality_errors': errors,
                'translator': VERSION,
                'updated_at': datetime.now(UTC).isoformat(),
            }
        except Exception as exc:
            review += 1
            state[url] = {
                'code': item.get('code'), 'fingerprint': fp, 'status': 'needs_review',
                'quality_errors': ['translator_error:' + str(exc)[:180]], 'translator': VERSION,
                'updated_at': datetime.now(UTC).isoformat(),
            }
        save_json(STATE, state)
    print(json.dumps({'attempted':attempted,'live_auto':live,'needs_review':review,'state_total':len(state)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
