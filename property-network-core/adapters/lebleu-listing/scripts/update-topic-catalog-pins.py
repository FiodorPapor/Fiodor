#!/usr/bin/env python3
import json
import time
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path('/opt/lebleu-listing-bridge')
TOPICS = ROOT / 'state/forum-topics.json'
PUBLISH_STATE = ROOT / 'state/telegram-state.json'
PIN_STATE = ROOT / 'state/topic-catalog-pins.json'
PUBLISHER_ENV = ROOT / 'publisher.env'
CRM_ENV = Path('/opt/fiodor-crm-v2/.env')
GROWTH_ENV = Path('/opt/growth-core/.env')

TOPIC_CONFIG = {
    'rent_apartments': {
        'button': 'Смотреть все квартиры в аренду',
        'filters': {'operation': 'Alquiler', 'propertyTypes': ['Departamento', 'PH']},
    },
    'sale_apartments': {
        'button': 'Смотреть все квартиры на продажу',
        'filters': {'operation': 'Venta', 'propertyTypes': ['Departamento', 'PH']},
    },
    'rent_houses': {
        'button': 'Смотреть все дома в аренду',
        'filters': {'operation': 'Alquiler', 'propertyTypes': ['Casa']},
    },
    'sale_houses': {
        'button': 'Смотреть все дома на продажу',
        'filters': {'operation': 'Venta', 'propertyTypes': ['Casa']},
    },
    'parking': {
        'button': 'Смотреть все парковочные места',
        'filters': {'propertyTypes': ['Cochera']},
    },
    'land': {
        'button': 'Смотреть землю и участки',
        'filters': {'propertyTypes': ['Terreno', 'Terreno o Lote', 'Finca', 'Campo']},
    },
    'commercial': {
        'button': 'Смотреть коммерческую недвижимость',
        'filters': {'propertyTypes': ['Oficina', 'Local Comercial', 'Edificio Comercial', 'Galpón', 'Depósito']},
    },
    'temporary': {
        'button': 'Смотреть временную аренду',
        'filters': {'operation': 'Alquiler'},
    },
}


def env_file(path: Path):
    out = {}
    for raw in path.read_text(encoding='utf-8').splitlines():
        line = raw.strip()
        if not line or line.startswith('#') or '=' not in line:
            continue
        key, value = line.split('=', 1)
        out[key.strip()] = value.strip().strip("'").strip('"')
    return out


def bot_api(token, method, payload):
    data = json.dumps(payload).encode()
    for attempt in range(5):
        req = urllib.request.Request(
            f'https://api.telegram.org/bot{token}/{method}',
            data=data,
            headers={'Content-Type': 'application/json'},
        )
        try:
            with urllib.request.urlopen(req, timeout=12) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            try:
                body = json.loads(exc.read().decode())
            except Exception:
                body = {}
            retry = int((body.get('parameters') or {}).get('retry_after') or 0)
            if retry and attempt < 4:
                time.sleep(retry + 1)
                continue
            raise RuntimeError(body.get('description') or f'HTTP {exc.code}') from exc
        if body.get('ok'):
            return body.get('result')
        retry = int((body.get('parameters') or {}).get('retry_after') or 0)
        if retry and attempt < 4:
            time.sleep(retry + 1)
            continue
        raise RuntimeError(body.get('description') or method)
    raise RuntimeError(f'{method}: retries exhausted')


def ensure_link(growth, bot_username, topic_key, filters, listing_codes):
    key = growth.get('SERVICE_KEY') or ''
    if not key:
        return f'https://t.me/{bot_username}?startapp=section_{topic_key}'
    payload = {
        'tenant': growth.get('DEFAULT_TENANT') or 'lebleu',
        'source': 'telegram_catalog',
        'medium': 'owned',
        'campaign': 'topic_catalog',
        'content': topic_key,
        'placement': 'topic_pin',
        'intent': 'catalog',
        'bot_username': bot_username,
        'metadata': {
            'surface': 'topic_pin',
            'topic_key': topic_key,
            'filters': filters,
            'listing_codes': listing_codes,
        },
    }
    req = urllib.request.Request(
        'http://127.0.0.1:8040/v1/links/ensure',
        data=json.dumps(payload).encode(),
        headers={'Content-Type': 'application/json', 'X-Growth-Key': key},
    )
    try:
        with urllib.request.urlopen(req, timeout=6) as response:
            body = json.load(response)
        token = str(body.get('token') or '')
        if token:
            return f'https://t.me/{bot_username}?startapp=section_{topic_key}__trk_{token}'
    except Exception:
        pass
    return f'https://t.me/{bot_username}?startapp=section_{topic_key}'


def load_json(path, fallback):
    try:
        return json.loads(path.read_text(encoding='utf-8'))
    except Exception:
        return fallback


def object_phrase(count):
    last_two = count % 100
    last = count % 10
    if last == 1 and last_two != 11:
        return 'актуальный объект'
    if 2 <= last <= 4 and not 12 <= last_two <= 14:
        return 'актуальных объекта'
    return 'актуальных объектов'


def save_state(value):
    tmp = PIN_STATE.with_suffix('.json.tmp')
    tmp.write_text(json.dumps(value, ensure_ascii=False, indent=2) + '\n', encoding='utf-8')
    tmp.replace(PIN_STATE)


def main():
    topics = load_json(TOPICS, {})
    publish = load_json(PUBLISH_STATE, {'entries': {}})
    pins = load_json(PIN_STATE, {})
    publisher = env_file(PUBLISHER_ENV)
    crm = env_file(CRM_ENV)
    growth = env_file(GROWTH_ENV)
    channel = publisher.get('TELEGRAM_CHANNEL') or '@lebleu_argentina_ru'
    bot_username = (publisher.get('TELEGRAM_BOT_USERNAME') or 'LeBleuArgentinaBot').lstrip('@')
    token = crm.get('LEBLEU_TELEGRAM_BOT_TOKEN') or crm.get('TELEGRAM_BOT_TOKEN') or ''
    if not token:
        raise RuntimeError('CRM Telegram bot token missing')

    entries = list((publish.get('entries') or {}).values())
    result = {}
    for topic_key, topic in topics.items():
        cfg = TOPIC_CONFIG.get(topic_key)
        if not cfg:
            continue
        thread_id = int(topic.get('message_thread_id') or 0)
        if not thread_id:
            continue
        codes = sorted({
            str(entry.get('code'))
            for entry in entries
            if entry.get('status') == 'active'
            and int(entry.get('threadId') or 0) == thread_id
            and str(entry.get('code') or '').strip()
        })
        url = ensure_link(growth, bot_username, topic_key, cfg['filters'], codes)
        name = str(topic.get('name') or topic_key)
        count = len(codes)
        text = (
            f'🔎 Весь раздел: {name}\n\n'
            f'В каталоге сейчас {count} {object_phrase(count)}. '
            'Там доступны фильтры, карта и полные галереи.'
        )
        markup = {'inline_keyboard': [[{'text': cfg['button'], 'url': url}]]}
        message_id = int((pins.get(topic_key) or {}).get('message_id') or 0)
        if message_id:
            try:
                bot_api(token, 'editMessageText', {
                    'chat_id': channel,
                    'message_id': message_id,
                    'text': text,
                    'reply_markup': markup,
                    'disable_web_page_preview': True,
                })
            except Exception as exc:
                if 'message is not modified' not in str(exc).lower():
                    message_id = 0
        if not message_id:
            sent = bot_api(token, 'sendMessage', {
                'chat_id': channel,
                'message_thread_id': thread_id,
                'text': text,
                'reply_markup': markup,
                'disable_notification': True,
                'disable_web_page_preview': True,
            })
            message_id = int(sent['message_id'])
        try:
            bot_api(token, 'pinChatMessage', {
                'chat_id': channel,
                'message_id': message_id,
                'disable_notification': True,
            })
        except Exception as exc:
            if 'message is not modified' not in str(exc).lower():
                raise
        pins[topic_key] = {
            'message_id': message_id,
            'thread_id': thread_id,
            'name': name,
            'count': count,
            'updated_at': int(time.time()),
        }
        save_state(pins)
        result[topic_key] = {'message_id': message_id, 'count': count}
        time.sleep(0.15)
    print(json.dumps({'ok': True, 'topics': result}, ensure_ascii=False))


if __name__ == '__main__':
    main()
