from __future__ import annotations

import argparse
import json
import os
import re
import time
import urllib.request
from datetime import UTC, datetime
from pathlib import Path
from typing import Callable

ROOT = Path('/opt/lebleu-listing-bridge')
CATALOG = ROOT / 'public/data/full/catalog.json'
STATE = ROOT / 'state/ru-full-translations.json'
ENDPOINT = os.getenv('LEBLEU_TRANSLATION_ENDPOINT', 'http://127.0.0.1:3014/v1/chat/completions')
MODEL = os.getenv('LEBLEU_TRANSLATION_MODEL', 'TranslateGemma-4B')
TRANSLATOR_VERSION = 'translategemma-4b-q4-protected-v3'

BARRIOS = [
    'Palermo','Belgrano','Colegiales','Recoleta','Núñez','Caballito','Chacarita','Villa Crespo',
    'Villa Urquiza','Saavedra','Retiro','Puerto Madero','San Telmo','Barracas','Almagro','Boedo',
    'Flores','Floresta','Villa Devoto','Villa del Parque','San Nicolás','Balvanera','Monserrat',
    'Constitución','Parque Chas','Agronomía','Paternal','Villa Ortúzar','Villa Pueyrredón',
    'San Isidro','Vicente López','Olivos','Martínez','Nordelta','Pilar','Escobar','La Plata',
    'Mar del Plata','Mar de las Pampas','Villa Gesell','Aranzazu','Aránzazu',
]

# Phrases that generic MT regularly mistranslates in Argentine property listings.
# Each phrase is protected as an opaque token and restored directly in Russian.
TERM_RULES: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
    (re.compile(r'\bdepartamento\s+([1-9])\s+ambientes?\b', re.I), lambda m: f'{m.group(1)}-комнатная квартира'),
    (re.compile(r'\bmonoambiente\b', re.I), lambda m: 'студия'),
    (re.compile(r'\bambiente y medio\b', re.I), lambda m: 'полуторакомнатная квартира'),
    (re.compile(r'\b([2-9])\s+ambientes\b', re.I), lambda m: f'{m.group(1)}-комнатная квартира'),
    (re.compile(r'\bdormitorio principal\b', re.I), lambda m: 'основная спальня'),
    (re.compile(r'\bbaño completo\b', re.I), lambda m: 'полноценная ванная комната'),
    (re.compile(r'\btoilette(?: de recepción)?\b', re.I), lambda m: 'гостевой санузел'),
    (re.compile(r'\bal contrafrente\b', re.I), lambda m: 'с окнами во двор'),
    (re.compile(r'\bcontrafrente\b', re.I), lambda m: 'окна во двор'),
    (re.compile(r'\bal frente\b', re.I), lambda m: 'с окнами на улицу'),
    (re.compile(r'\bcocina independiente\b', re.I), lambda m: 'отдельная кухня'),
    (re.compile(r'\bcocina integrada\b', re.I), lambda m: 'кухня, объединённая с гостиной'),
    (re.compile(r'\bconexi[oó]n para lavarropas\b', re.I), lambda m: 'подключение для стиральной машины'),
    (re.compile(r'\bcalefacci[oó]n individual por tiro balanceado(?: a gas)?\b', re.I), lambda m: 'индивидуальное газовое отопление'),
    (re.compile(r'\bcalefacci[oó]n por tiro balanceado(?: a gas)?\b', re.I), lambda m: 'индивидуальное газовое отопление'),
    (re.compile(r'\btiro balanceado(?: a gas)?\b', re.I), lambda m: 'индивидуальное газовое отопление'),
    (re.compile(r'\blosa radiante\b', re.I), lambda m: 'отопление в полу'),
    (re.compile(r'\baire acondicionado\b', re.I), lambda m: 'кондиционер'),
    (re.compile(r'\bfr[ií]o[ -]calor\b', re.I), lambda m: 'режим охлаждения и обогрева'),
    (re.compile(r'\bventilaci[oó]n natural\b', re.I), lambda m: 'естественная вентиляция'),
    (re.compile(r'\bpisos? de parquet\b', re.I), lambda m: 'паркетные полы'),
    (re.compile(r'\bplacard(?:es)?\b', re.I), lambda m: 'встроенный шкаф'),
    (re.compile(r'\btermotanque\b', re.I), lambda m: 'бойлер'),
    (re.compile(r'\bcalef[oó]n\b', re.I), lambda m: 'газовый проточный водонагреватель'),
    (re.compile(r'\bbalc[oó]n aterrazado\b', re.I), lambda m: 'балкон-терраса'),
    (re.compile(r'\bbalc[oó]n corrido\b', re.I), lambda m: 'длинный балкон'),
    (re.compile(r'\bparrilla\b', re.I), lambda m: 'зона барбекю (parrilla)'),
    (re.compile(r'\bquincho\b', re.I), lambda m: 'крытая зона отдыха (quincho)'),
    (re.compile(r'\bpileta\b|\bpiscina\b', re.I), lambda m: 'бассейн'),
    (re.compile(r'\bsolarium\b', re.I), lambda m: 'солярий'),
    (re.compile(r'\blaundry\b', re.I), lambda m: 'общая прачечная'),
    (re.compile(r'\bbaulera\b', re.I), lambda m: 'кладовая'),
    (re.compile(r'\bSUM\b'), lambda m: 'общий зал (SUM)'),
    (re.compile(r'\bgimnasio\b', re.I), lambda m: 'спортзал'),
    (re.compile(r'\bseguridad 24(?:hs| horas)?\b|\bvigilancia 24(?:hs| horas)?\b', re.I), lambda m: 'охрана 24/7'),
    (re.compile(r'\bno apto cr[eé]dito\b', re.I), lambda m: 'не подходит для ипотечного кредита'),
    (re.compile(r'\bapto cr[eé]dito\b', re.I), lambda m: 'подходит для ипотечного кредита'),
    (re.compile(r'\bapto profesional\b', re.I), lambda m: 'разрешено профессиональное использование'),
    (re.compile(r'\ba estrenar\b', re.I), lambda m: 'новый, без проживания'),
    (re.compile(r'\bexpensas\b', re.I), lambda m: 'ежемесячные расходы по дому (expensas)'),
    (re.compile(r'\bsubte\b', re.I), lambda m: 'метро'),
    (re.compile(r'\bcolectivos?\b', re.I), lambda m: 'автобусы'),
]

CONCEPTS = [
    (re.compile(r'\b(?:pileta|piscina)\b', re.I), re.compile(r'бассейн', re.I), 'pool'),
    (re.compile(r'\b(?:cochera|garage|garaje|estacionamiento)\b', re.I), re.compile(r'парков|гараж', re.I), 'parking'),
    (re.compile(r'\bterraza\b', re.I), re.compile(r'террас', re.I), 'terrace'),
    (re.compile(r'\bbalc[oó]n\b', re.I), re.compile(r'балкон', re.I), 'balcony'),
    (re.compile(r'\bgas\b', re.I), re.compile(r'\bгаз', re.I), 'gas'),
    (re.compile(r'\bcr[eé]dito\b', re.I), re.compile(r'ипотек|кредит', re.I), 'credit'),
]


def _token(kind: str, index: int) -> str:
    return f'[[{kind}{index}]]'


def _replace_pattern(text: str, pattern: re.Pattern[str], render: Callable[[re.Match[str]], str], restore: dict[str, str], kind: str) -> str:
    def repl(match: re.Match[str]) -> str:
        token = _token(kind, len(restore))
        restore[token] = render(match)
        return token
    return pattern.sub(repl, text)


def protect(text: str, item: dict) -> tuple[str, dict[str, str]]:
    out = text
    restore: dict[str, str] = {}

    for pattern, render in TERM_RULES:
        out = _replace_pattern(out, pattern, render, restore, 'T')

    # Keep the published street/address and known Argentine place names searchable
    # instead of letting MT invent phonetic Russian variants.
    address = str(item.get('address') or '').strip()
    proper_names = [address] if len(address) >= 4 else []
    proper_names += BARRIOS
    for name in sorted(set(proper_names), key=len, reverse=True):
        if not name:
            continue
        rx = re.compile(re.escape(name), re.I)
        out = _replace_pattern(out, rx, lambda m, n=name: n, restore, 'P')

    # Critical values are not translated at all. Normalize Argentine peso notation
    # so '$ 39.000' can never silently become '39,000 dollars'.
    value_rules: list[tuple[re.Pattern[str], Callable[[re.Match[str]], str]]] = [
        (re.compile(r'\b(?:USD|U\$S|US\$)\s*([\d.]+(?:,\d+)?)', re.I), lambda m: 'USD ' + m.group(1).replace('.', ' ').replace(',', '.')),
        (re.compile(r'\$\s*([\d.]+(?:,\d+)?)'), lambda m: m.group(1).replace('.', ' ').replace(',', '.') + ' ARS'),
        (re.compile(r'([\d.]+(?:,\d+)?)\s*\$'), lambda m: m.group(1).replace('.', ' ').replace(',', '.') + ' ARS'),
        (re.compile(r'\b(\d+(?:[.,]\d+)?)\s*(?:m2|m²)\b', re.I), lambda m: m.group(1).replace('.', ',') + ' м²'),
        (re.compile(r'(?<![A-Za-z])\d+(?:[.,]\d+)?(?![A-Za-z])'), lambda m: m.group(0)),
    ]
    for pattern, render in value_rules:
        out = _replace_pattern(out, pattern, render, restore, 'V')

    return re.sub(r'\s+', ' ', out).strip(), restore


def restore_tokens(text: str, restore: dict[str, str]) -> tuple[str, list[str]]:
    out = text
    missing: list[str] = []
    for token, value in restore.items():
        kind_num = token.strip('[]')
        # TranslateGemma occasionally drops exactly one bracket around a placeholder.
        rx = re.compile(r'\[{1,2}\s*' + re.escape(kind_num) + r'\s*\]{1,2}', re.I)
        out, count = rx.subn(lambda _m, v=value: v, out)
        if count == 0:
            missing.append(token)
    return out, missing


def chunks(text: str, max_chars: int = 360) -> list[str]:
    rows = re.split(r'(?<=[.!?])\s+|\s*[•·]\s*', text)
    rows = [x.strip() for x in rows if x.strip()]
    out: list[str] = []
    current = ''
    for row in rows:
        parts = [row[i:i + max_chars] for i in range(0, len(row), max_chars)] if len(row) > max_chars else [row]
        for part in parts:
            candidate = (current + ' ' + part).strip()
            if current and len(candidate) > max_chars:
                out.append(current)
                current = part
            else:
                current = candidate
    if current:
        out.append(current)
    return out


def translate(text: str, item: dict) -> tuple[str, list[str]]:
    protected, restore = protect(text, item)
    prompt = (
        'You are a professional Spanish (es) to Russian (ru) translator. This is an Argentine real-estate listing. '
        'Preserve every placeholder token such as [[T0]], [[P1]] and [[V2]] exactly, including brackets. '
        'Do not infer, summarize, advertise, omit facts, or add facts. Translate only the surrounding Spanish. '
        'Produce only natural Russian translation without explanations or commentary.\n\n' + protected
    )
    payload = json.dumps({
        'model': MODEL,
        'messages': [{'role': 'user', 'content': prompt}],
        'temperature': 0.0,
        'top_p': 1.0,
        'top_k': 20,
        'repeat_penalty': 1.05,
        'max_tokens': 360,
        'stream': False,
    }, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(ENDPOINT, data=payload, headers={'content-type': 'application/json'})
    with urllib.request.urlopen(req, timeout=300) as response:
        data = json.load(response)
    value = str(data['choices'][0]['message']['content']).strip()
    value = re.sub(r'^```(?:text)?\s*|\s*```$', '', value, flags=re.I)
    value, missing = restore_tokens(value, restore)
    value = re.sub(r'\s+', ' ', value).strip()
    # Small deterministic grammar repairs for patterns induced by protected noun phrases.
    value = re.sub(r'\bИмеет\s+отдельная кухня\b', 'Отдельная кухня', value, flags=re.I)
    value = re.sub(r'\bИмеет\s+полноценная ванная комната\b', 'Полноценная ванная комната', value, flags=re.I)
    value = value.replace(' ,', ',').replace(' .', '.')
    # A currency placeholder must never inherit an area unit from noisy source text.
    value = re.sub(r'\b(ARS|USD)\s*м²\b', r'\1', value)
    return value, missing


def normalized_numbers(text: str) -> set[str]:
    # Compare numeric meaning, not typography: 39.000 (ES) == 39 000 (RU),
    # while 12,5 remains a decimal. This avoids rejecting faithful translations.
    out: set[str] = set()
    pattern = r'(?<![A-Za-zА-Яа-я])(?:\d{1,3}(?:[.\s]\d{3})+(?:,\d+)?|\d+(?:[.,]\d+)?)(?![A-Za-zА-Яа-я])'
    for raw in re.findall(pattern, text):
        value = raw.strip()
        if re.fullmatch(r'\d{1,3}(?:[.\s]\d{3})+(?:,\d+)?', value):
            value = value.replace(' ', '').replace('.', '').replace(',', '.')
        else:
            value = value.replace(',', '.')
        try:
            n = float(value)
            out.add(str(int(n)) if n.is_integer() else ('%.6f' % n).rstrip('0').rstrip('.'))
        except ValueError:
            pass
    return out


def validate(source: str, translated: str, missing_tokens: list[str]) -> list[str]:
    reasons: list[str] = []
    if missing_tokens:
        reasons.append('missing_placeholders:' + ','.join(missing_tokens[:8]))
    if not translated or len(translated) < 25:
        return reasons + ['empty_or_too_short']
    cyr = len(re.findall(r'[А-Яа-яЁё]', translated))
    alpha = len(re.findall(r'[A-Za-zА-Яа-яЁё]', translated)) or 1
    if cyr / alpha < 0.58:
        reasons.append('too_little_russian')
    ratio = len(translated) / max(1, len(source))
    if ratio < 0.40 or ratio > 2.30:
        reasons.append('length_ratio')
    missing_numbers = normalized_numbers(source) - normalized_numbers(translated)
    if missing_numbers:
        reasons.append('missing_numbers:' + ','.join(sorted(missing_numbers)[:8]))
    for src_rx, ru_rx, name in CONCEPTS:
        if not src_rx.search(source) and ru_rx.search(translated):
            reasons.append('added_' + name)
    if '$' in source and not re.search(r'\bARS\b|\bUSD\b', translated):
        reasons.append('currency_not_disambiguated')
    if re.search(r'полностью оборудованн(?:ый|ая) бассейн|ванн\w+.*бассейн', translated, re.I):
        reasons.append('bathroom_pool_confusion')
    if 'общежит' in translated.lower() and not re.search(r'residencia|hostel|dormitorio colectivo', source, re.I):
        reasons.append('invented_hostel')
    if re.search(r'\bпредприятие\b|стирк[аи] белья|шкаф-куполь|естественн\w+ отоплен|паркетн\w+ почв', translated, re.I):
        reasons.append('unnatural_domain_translation')
    return reasons


def load_json(path: Path, default):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return default


def save_state(state: dict) -> None:
    tmp = STATE.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    tmp.replace(STATE)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument('--max-items', type=int, default=1)
    ap.add_argument('--force', action='store_true')
    ap.add_argument('--only-code', default='')
    args = ap.parse_args()

    catalog = load_json(CATALOG, [])
    state = load_json(STATE, {})
    # Short descriptions first: more of the catalogue becomes useful early while
    # the 2-vCPU server backfills longer descriptions in later batches.
    catalog = sorted(catalog, key=lambda x: len(str(x.get('description') or '')) or 10**9)
    attempted = passed = failed = 0
    for item in catalog:
        if args.only_code and str(item.get('code') or '') != args.only_code:
            continue
        source = str(item.get('description') or '').strip()
        url = str(item.get('sourceUrl') or '')
        fp = str(item.get('ruContentFingerprint') or item.get('sourceFingerprint') or '')
        if not url or len(source) < 35:
            if url:
                state[url] = {
                    'code': item.get('code'), 'fingerprint': fp, 'status': 'source_missing',
                    'updated_at': datetime.now(UTC).isoformat(),
                }
            continue
        current = state.get(url) or {}
        if not args.force and current.get('fingerprint') == fp:
            if current.get('status') in {'live_auto', 'source_missing'}:
                continue
            if current.get('status') == 'needs_review' and current.get('translator') == TRANSLATOR_VERSION:
                continue
        if attempted >= args.max_items:
            break
        attempted += 1
        try:
            translated_parts: list[str] = []
            missing_tokens: list[str] = []
            for part in chunks(source):
                translated, missing = translate(part, item)
                translated_parts.append(translated)
                missing_tokens.extend(missing)
            translated = ' '.join(translated_parts).strip()
            errors = validate(source, translated, missing_tokens)
            status = 'live_auto' if not errors else 'needs_review'
            passed += int(status == 'live_auto')
            failed += int(status != 'live_auto')
            state[url] = {
                'code': item.get('code'), 'fingerprint': fp, 'status': status,
                'description_ru': translated, 'quality_errors': errors,
                'translator': TRANSLATOR_VERSION,
                'updated_at': datetime.now(UTC).isoformat(),
            }
        except Exception as exc:
            failed += 1
            state[url] = {
                'code': item.get('code'), 'fingerprint': fp, 'status': 'needs_review',
                'quality_errors': ['translator_error:' + str(exc)[:180]],
                'translator': TRANSLATOR_VERSION,
                'updated_at': datetime.now(UTC).isoformat(),
            }
        save_state(state)
        time.sleep(0.05)
    save_state(state)
    print(json.dumps({'attempted': attempted, 'live_auto': passed, 'needs_review': failed, 'state_total': len(state)}, ensure_ascii=False))


if __name__ == '__main__':
    main()
