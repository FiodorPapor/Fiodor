#!/usr/bin/env python3
"""Read-only Tokko -> Property Network candidate importer. Never publishes.

Requires Python 3.10+, standard library only. Output is a staged candidate and
small audit report, never the production catalog or any Tokko private fields.
"""
import argparse
import hashlib
import json
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from pathlib import Path
from typing import Any

API = 'https://www.tokkobroker.com/api/v1/property/'
PROD_CATALOG = Path('/opt/lebleu-listing-bridge/public/data/full/catalog.json')
ALLOWED_IMG_HOSTS = {'static.tokkobroker.com'}
OPS = {'venta': 'Venta', 'alquiler': 'Alquiler', 'alquiler temporario': 'Alquiler temporario'}
TYPES = {'Local': 'Local Comercial', 'Terreno o Lote': 'Terreno', 'Galpon': 'Galpón'}
FEATURE_NAMES = {
    'balcon': 'Balcón', 'terraza': 'Terraza', 'parrilla': 'Parrilla',
    'piscina': 'Piscina', 'pileta': 'Pileta', 'patio': 'Patio',
    'jardin': 'Jardín', 'sum': 'SUM', 'laundry': 'Laundry',
    'solarium': 'Solarium', 'baulera': 'Baulera', 'quincho': 'Quincho',
    'gimnasio': 'Gimnasio', 'ascensor': 'Ascensor',
    'aire acondicionado individual': 'Aire Acondicionado',
    'aire acondicionado': 'Aire Acondicionado', 'calefaccion': 'Calefacción',
    'seguridad 24 hs': 'Seguridad 24', 'apto credito bancario': 'Apto crédito',
}


def clean(value: Any) -> str:
    return re.sub(r'\s+', ' ', str(value or '')).strip()


def norm(value: Any) -> str:
    s = unicodedata.normalize('NFD', clean(value).lower())
    return re.sub(r'[^a-z0-9]+', ' ', ''.join(x for x in s if unicodedata.category(x) != 'Mn')).strip()


def hashjson(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def integer(v: Any) -> int | None:
    try:
        n = int(float(str(v).replace(',', '.')))
        return n if 0 <= n <= 10000 else None
    except (ValueError, TypeError):
        return None


def positive(v: Any) -> float | None:
    try:
        n = float(str(v).replace(',', '.'))
        return n if 0 < n < 100_000_000_000 else None
    except (ValueError, TypeError):
        return None


def url_if_public(value: Any) -> str | None:
    try:
        p = urllib.parse.urlsplit(str(value))
        if p.scheme == 'https' and p.hostname and p.hostname.lower() in {'ficha.info', 'www.ficha.info'}:
            return urllib.parse.urlunsplit((p.scheme, p.netloc, p.path, '', ''))
    except ValueError:
        pass
    return None


def image_urls(photos: Any) -> list[str]:
    result = []
    for photo in photos if isinstance(photos, list) else []:
        raw = photo.get('image') if isinstance(photo, dict) else None
        if not isinstance(raw, str):
            continue
        p = urllib.parse.urlsplit(raw)
        if p.scheme == 'https' and p.hostname in ALLOWED_IMG_HOSTS and raw not in result:
            result.append(raw)
    return result[:40]


def scrub_description(value: Any) -> str:
    s = str(value or '')
    s = re.sub(r'https?://\S+|www\.\S+', ' ', s, flags=re.I)
    s = re.sub(r'[\w.+-]+@[\w.-]+\.[a-z]{2,}', ' ', s, flags=re.I)
    s = re.sub(r'\+?\d[\d\s()\-]{7,}\d', ' ', s)
    s = re.sub(r'\b(?:Whatsapp|Wsp|Telefono|Teléfono|Celular|Contacto)\s*:?\s*[^.;\n]{0,80}', ' ', s, flags=re.I)
    s = re.sub(r'Le Bleu Negocios Inmobiliarios|COD PROP\s+[A-Z0-9._/-]+', ' ', s, flags=re.I)
    return clean(s)[:4000]


def trusted_secondary_match(old: dict, raw: dict, op_name: str, type_name: str, price: dict, description: str) -> bool:
    # Only salvage legacy site address-parsing errors with strong *independent*
    # Tokko facts. The primary reference_code + operation already matched uniquely.
    if old.get('operation') != op_name or old.get('propertyType') != type_name:
        return False
    if old.get('priceCurrency') != price.get('currency'):
        return False
    a, b = positive(old.get('priceAmount')), positive(price.get('price'))
    old_area = positive((old.get('details') or {}).get('totalAreaM2'))
    new_area = positive(raw.get('total_surface'))
    if a is None or b is None or abs(a-b)>0.01 or old_area is None or new_area is None:
        return False
    if abs(old_area-new_area)>0.05:
        return False
    before, after = norm(old.get('description'))[:1500], norm(description)[:1500]
    return bool(before and after) and SequenceMatcher(None, before, after).ratio() >= 0.92


def verified_features(raw: dict) -> list[str]:
    names = []
    for field in ('tags', 'custom_tags'):
        for x in raw.get(field) if isinstance(raw.get(field), list) else []:
            if isinstance(x, dict):
                label = FEATURE_NAMES.get(norm(x.get('name')))
                if label and label not in names:
                    names.append(label)
    return names


def match_address(old: str, new: str) -> bool:
    a, b = norm(old), norm(new)
    if not a or not b:
        return False
    if a == b:
        return True
    nums_a, nums_b = set(re.findall(r'\b\d{2,5}\b', a)), set(re.findall(r'\b\d{2,5}\b', b))
    street_a = {w for w in a.split() if len(w) > 3 and not w.isdigit()}
    street_b = {w for w in b.split() if len(w) > 3 and not w.isdigit()}
    return bool(nums_a & nums_b) and bool(street_a & street_b) and SequenceMatcher(None, a, b).ratio() >= 0.42


def fetch_all(key: str, limit: int = 20, timeout: int = 18, max_items: int = 3000) -> list[dict]:
    if not key:
        raise ValueError('Tokko key is empty')
    collected: list[dict] = []
    expected = None
    for offset in range(0, max_items, limit):
        # Never log full URL or urllib exception: Tokko includes key in the query.
        query = urllib.parse.urlencode({'format': 'json', 'key': key, 'lang': 'es_ar', 'limit': limit, 'offset': offset})
        req = urllib.request.Request(API + '?' + query, headers={'User-Agent': 'PropertyNetwork-Tokko-ReadOnly/1.0'})
        try:
            with urllib.request.urlopen(req, timeout=timeout) as response:
                if response.status != 200:
                    raise RuntimeError('Tokko HTTP response not 200')
                result = json.load(response)
        except urllib.error.HTTPError as exc:
            raise RuntimeError(f'Tokko HTTP {exc.code}, offset={offset}') from None
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError) as exc:
            raise RuntimeError(f'Tokko request failed ({type(exc).__name__}), offset={offset}') from None
        if not isinstance(result, dict) or not isinstance(result.get('objects'), list):
            raise RuntimeError('Tokko unexpected API response, refusing candidate')
        meta = result.get('meta') or {}
        if not isinstance(meta.get('total_count'), int) or meta['total_count'] > max_items:
            raise RuntimeError('Tokko total count missing/exceeds safe cap')
        if expected is None:
            expected = meta['total_count']
        if expected != meta['total_count'] or meta.get('offset') != offset:
            raise RuntimeError('Tokko pagination drift during sync')
        batch = result['objects']
        if offset + len(batch) > expected or (len(batch) != limit and offset + len(batch) != expected):
            raise RuntimeError('Tokko incomplete page, preserving previous catalog')
        collected.extend(batch)
        if len(collected) == expected:
            break
        if not batch:
            raise RuntimeError('Tokko empty page before end')
        time.sleep(0.12)
    if len(collected) != expected or len({r.get('id') for r in collected}) != len(collected):
        raise RuntimeError('Tokko incomplete/duplicate inventory, refusing candidate')
    return collected


def build_candidate(rows: list[dict], legacy: list[dict]) -> tuple[list[dict], dict]:
    by_codeop = defaultdict(list)
    for old in legacy:
        by_codeop[(norm(old.get('code')), old.get('operation'))].append(old)
    generated: list[dict] = []
    skipped = Counter()
    conflicts = []
    matched_ids = set()
    secondary_matches = []
    for raw in rows:
        if raw.get('status') != 2:
            skipped['not_available_status'] += 1
            continue
        tokko_id = raw.get('id')
        if not clean(tokko_id).isdigit() or int(tokko_id) <= 0:
            skipped['invalid_tokko_id'] += 1
            continue
        code = clean(raw.get('reference_code')) or f'TOKKO{tokko_id}'
        addr = clean(raw.get('address'))
        type_name = TYPES.get(clean((raw.get('type') or {}).get('name')), clean((raw.get('type') or {}).get('name'))) if isinstance(raw.get('type'), dict) else ''
        pictures = image_urls(raw.get('photos'))
        operations = raw.get('operations') if isinstance(raw.get('operations'), list) else []
        for op in operations:
            if not isinstance(op, dict):
                continue
            op_name = OPS.get(norm(op.get('operation_type')))
            if not op_name:
                skipped['unsupported_operation'] += 1
                continue
            prices = op.get('prices') if isinstance(op.get('prices'), list) else []
            valid_prices = [p for p in prices if isinstance(p, dict) and positive(p.get('price')) and p.get('currency') in {'ARS', 'USD'}]
            valid_prices.sort(key=lambda p: bool(p.get('is_promotional')))
            if not valid_prices or not addr or not type_name or not pictures:
                skipped['incomplete_public_facts'] += 1
                continue
            price = valid_prices[0]
            description = scrub_description(raw.get('description'))
            candidates = by_codeop.get((norm(code), op_name), [])
            legacy_item = None
            if len(candidates) == 1:
                if match_address(candidates[0].get('address', ''), addr):
                    legacy_item = candidates[0]
                elif trusted_secondary_match(candidates[0], raw, op_name, type_name, price, description):
                    legacy_item = candidates[0]
                    secondary_matches.append({'code': code, 'type': 'independent_price_area_description_match'})
                else:
                    conflicts.append({'code': code, 'type': 'address_mismatch'})
            elif len(candidates) > 1:
                conflicts.append({'code': code, 'type': 'ambiguous_legacy_code'})
            source_url = legacy_item.get('sourceUrl') if legacy_item else url_if_public(raw.get('public_url'))
            if not source_url:
                skipped['missing_safe_public_url'] += 1
                continue
            d = {}
            for key, remote in [('totalAreaM2', 'total_surface'), ('coveredAreaM2', 'roofed_surface')]:
                n = positive(raw.get(remote))
                if n is not None and n <= 50000:
                    d[key] = n
            for key, remote in [('rooms', 'room_amount'), ('bathrooms', 'bathroom_amount'), ('parkingSpaces', 'parking_lot_amount')]:
                n = integer(raw.get(remote))
                if n is not None and n <= 100 and (n > 0 or key == 'parkingSpaces'):
                    d[key] = n
            features = verified_features(raw)  # Current Tokko feature tags, not legacy guesses.
            item = {
                'title': clean(raw.get('publication_title')) or f'{type_name} · {addr}',
                'address': addr, 'description': description,
                'imageUrls': pictures,
                'priceAmount': str(price['price']), 'priceCurrency': price['currency'],
                'details': d, 'highlightedFeatures': features,
                'additionalInfo': {}, 'services': [], 'environments': [], 'comforts': [],
                'sourceAgency': 'Le Bleu Negocios Inmobiliarios', 'sourceId': 'lebleu',
                'sourceUrl': source_url,
                'slug': f'tokko-{tokko_id}-{norm(op_name).replace(" ", "-")}',
                'code': code, 'operation': op_name, 'propertyType': type_name,
            }
            # Reuse historical identity and reviewed enrichment only after a strong match.
            if legacy_item:
                item['slug'] = legacy_item.get('slug') or item['slug']
                matched_ids.add(legacy_item.get('sourceUrl'))
                if legacy_item.get('latitude') is not None and legacy_item.get('longitude') is not None:
                    item['latitude'] = legacy_item['latitude']
                    item['longitude'] = legacy_item['longitude']
                # Tokko does not expose all website-assembled amenities/labels as
                # direct scalar properties. Preserve already reviewed details while
                # letting nonempty API fields override previous facts.
                item['details'] = {**(legacy_item.get('details') or {}), **item['details']}
                item['highlightedFeatures'] = list(dict.fromkeys(
                    (legacy_item.get('highlightedFeatures') or []) + features
                ))
                for field in ('additionalInfo', 'services', 'environments', 'comforts'):
                    if isinstance(legacy_item.get(field), type(item[field])):
                        item[field] = legacy_item[field]
                if item['propertyType'] == 'Terreno' and legacy_item.get('propertyType') == 'Terreno o Lote':
                    item['propertyType'] = 'Terreno o Lote'
                # Keep previously reviewed punctuation only when prose is
                # semantically near-identical to current Tokko copy.
                before, after = norm(legacy_item.get('description'))[:1500], norm(description)[:1500]
                if before and after and SequenceMatcher(None, before, after).ratio() >= 0.95:
                    item['description'] = legacy_item['description']
            # Tokko has no explicit expensas currency. For an existing reviewed
            # card, preserve its known currency only if the amount matches.
            expenses = positive(raw.get('expenses'))
            if legacy_item and expenses and positive(legacy_item.get('expensesAmount')) == expenses and legacy_item.get('expensesCurrency'):
                item['expensesAmount'] = str(expenses)
                item['expensesCurrency'] = legacy_item['expensesCurrency']
            # New raw Tokko GPS is intentionally not published before geocoding QA.
            # Baseline the first official Tokko snapshot without invalidating all
            # existing RU reviews or forcing 134 false 'changed' notifications.
            # Subsequent Tokko changes produce a new source version/fingerprint.
            tokko_version = hashjson({
                'id': tokko_id, 'operation': op_name, 'price': price,
                'address': addr, 'description': description,
                'photos': pictures, 'features': verified_features(raw),
                'details': d, 'type': type_name,
            })
            item['tokkoSnapshotFingerprint'] = tokko_version
            current_source = hashjson({k: item[k] for k in ('sourceUrl', 'priceAmount', 'priceCurrency', 'address', 'description', 'details', 'imageUrls')})
            current_ru = hashjson({k: item[k] for k in ('operation', 'propertyType', 'address', 'description', 'details', 'highlightedFeatures')})
            same_price = legacy_item and legacy_item.get('priceCurrency') == item['priceCurrency'] and positive(legacy_item.get('priceAmount')) == positive(item['priceAmount'])
            same_version = legacy_item and legacy_item.get('tokkoSnapshotFingerprint') == tokko_version
            first_baseline = legacy_item and not legacy_item.get('tokkoSnapshotFingerprint') and same_price
            item['sourceFingerprint'] = (legacy_item.get('sourceFingerprint') or current_source) if (same_version or first_baseline) else current_source
            item['ruContentFingerprint'] = (legacy_item.get('ruContentFingerprint') or current_ru) if (same_version or first_baseline) else current_ru
            generated.append(item)
    if len({(x['sourceUrl'], x['operation']) for x in generated}) != len(generated):
        raise RuntimeError('Duplicate sourceURL+operation detected')
    tokens = [f"{x['code']}_{hashlib.sha256(x['sourceUrl'].encode()).hexdigest()[:8]}" for x in generated]
    if len(set(tokens)) != len(tokens):
        # A single Tokko property can have sale and rental operations. They
        # must not use identical public listing tokens, even if their URL is equal.
        conflicts.append({'type': 'duplicate_public_listing_tokens', 'count': len(tokens)-len(set(tokens))})
    coverage = len(matched_ids) / len(legacy) if legacy else 1.0
    counts = Counter(x['operation'] for x in generated)
    report = {
        'tokko_properties': len(rows), 'legacy_catalog': len(legacy), 'candidate_rows': len(generated),
        'legacy_matched': len(matched_ids), 'legacy_coverage': round(coverage, 4),
        'unmatched_legacy': len(legacy) - len(matched_ids), 'operation_counts': dict(counts),
        'skipped_reasons': dict(skipped), 'secondary_matches': secondary_matches, 'match_conflicts': conflicts[:25],
        'ready_for_cutover': coverage >= 0.90 and len(generated) >= max(1, (9 * len(legacy) + 9)//10) and not conflicts,
        'policy': 'STAGING ONLY. A separate approved cutover must verify token parity, QA, backup and rollback.',
    }
    return generated, report


def atomic_json(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temp = path.with_suffix(path.suffix + '.tmp')
    temp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding='utf-8')
    temp.replace(path)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--key-file', default='/etc/fiodor/credentials/tokko_api_key')
    parser.add_argument('--fixture', help='Offline JSON fixture with API objects and meta, skips key')
    parser.add_argument('--legacy', default=str(PROD_CATALOG))
    parser.add_argument('--output-dir', default='/opt/property-network-tokko-staging')
    args = parser.parse_args()
    out = Path(args.output_dir).resolve()
    if out == PROD_CATALOG.parent.resolve() or PROD_CATALOG.parent.resolve() in out.parents:
        raise SystemExit('Refusing production catalog output directory')
    legacy = json.loads(Path(args.legacy).read_text(encoding='utf-8'))
    if not isinstance(legacy, list):
        raise SystemExit('Legacy catalog is not an array')
    if args.fixture:
        payload = json.loads(Path(args.fixture).read_text(encoding='utf-8'))
        rows = payload['objects']
    else:
        keyfile = Path(args.key_file)
        if not keyfile.is_file():
            raise SystemExit('Tokko credential unavailable; no catalog changed')
        rows = fetch_all(keyfile.read_text().strip())
    candidate, report = build_candidate(rows, legacy)
    atomic_json(out / 'candidate-catalog.json', candidate)
    atomic_json(out / 'audit.json', report)
    print(json.dumps(report, ensure_ascii=False))
    return 0 if report['ready_for_cutover'] else 2


if __name__ == '__main__':
    try:
        sys.exit(main())
    except Exception as exc:
        # Deliberately never print exceptions with credential-bearing request URLs.
        print(f'Tokko sync aborted safely ({type(exc).__name__}); catalog unchanged', file=sys.stderr)
        sys.exit(3)
