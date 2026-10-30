#!/usr/bin/env python3
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path

ROOT = Path("/opt/lebleu-listing-bridge")
CATALOG = ROOT / "public/data/full/catalog.json"
STATE = ROOT / "state/category-index.json"
MIGRATION_STATE = ROOT / "state/forum-migration.json"
PUBLISH_STATE = ROOT / "state/telegram-state.json"
TOPICS = ROOT / "state/forum-topics.json"
PUBLISHER_ENV = ROOT / "publisher.env"
CRM_ENV = Path("/opt/fiodor-crm-v2/.env")
GROWTH_ENV = Path("/opt/growth-core/.env")

def env_file(path):
    out = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip("'").strip('"')
    return out

def effective_type(item):
    value = str(item.get("propertyType") or "").strip()
    if value:
        return value
    hay = " ".join(str(item.get(k) or "") for k in ("slug", "description", "sourceUrl")).lower()
    if "finca" in hay:
        return "Finca"
    if "edificio en block" in hay or "edificio comercial" in hay:
        return "Edificio Comercial"
    if "galpón" in hay or "galpon" in hay:
        return "Galpón"
    if "campo" in hay:
        return "Campo"
    return ""

def category(item):
    typ = effective_type(item)
    op = item.get("operation")
    if typ in ("Departamento", "PH"):
        return "#АрендаКвартир" if op == "Alquiler" else "#ПродажаКвартир"
    if typ == "Casa":
        return "#АрендаДомов" if op == "Alquiler" else "#ПродажаДомов"
    if typ == "Cochera":
        return "#Парковки"
    if typ in ("Terreno", "Terreno o Lote", "Finca", "Campo"):
        return "#УчасткиИЗемля"
    if typ in ("Oficina", "Local Comercial", "Edificio Comercial", "Galpón", "Depósito"):
        return "#КоммерческаяНедвижимость"
    return "#ДругиеОбъекты"

def api(token, method, payload):
    for attempt in range(6):
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=15) as response:
                body = json.load(response)
        except urllib.error.HTTPError as exc:
            body = {}
            try:
                body = json.loads(exc.read().decode("utf-8"))
            except Exception:
                pass
            retry = int((body.get("parameters") or {}).get("retry_after") or 0)
            if exc.code == 429 and attempt < 5:
                time.sleep(max(1, retry) + 1)
                continue
            raise RuntimeError(body.get("description") or f"HTTP {exc.code}") from exc
        if body.get("ok"):
            return body.get("result")
        retry = int((body.get("parameters") or {}).get("retry_after") or 0)
        if retry and attempt < 5:
            time.sleep(max(1, retry) + 1)
            continue
        raise RuntimeError(body.get("description") or method)
    raise RuntimeError(f"{method}: retries exhausted")

def ensure_catalog_link(bot_username):
    growth = env_file(GROWTH_ENV)
    key = growth.get("SERVICE_KEY") or ""
    if not key:
        return f"https://t.me/{bot_username}?startapp"
    payload = {
        "tenant": growth.get("DEFAULT_TENANT") or "lebleu",
        "source": "telegram_catalog",
        "medium": "owned",
        "campaign": "full_catalog",
        "content": "catalog_index",
        "placement": "general_pin",
        "intent": "catalog",
        "bot_username": bot_username,
        "metadata": {"surface": "general_pin"},
    }
    req = urllib.request.Request(
        "http://127.0.0.1:8040/v1/links/ensure",
        data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json", "X-Growth-Key": key},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as response:
            body = json.load(response)
        token = str(body.get("token") or "")
        if token:
            return f"https://t.me/{bot_username}?startapp=trk_{token}"
    except Exception:
        pass
    return f"https://t.me/{bot_username}?startapp"


def main():
    items = json.loads(CATALOG.read_text(encoding="utf-8"))
    counts = Counter(category(item) for item in items)
    temporary = sum(
        str(item.get("code") or "") == "LAP9861952"
        and item.get("operation") == "Alquiler"
        for item in items
    )
    # Prefer the publisher state for section counters: this is the inventory users
    # actually see in each Telegram topic after quality gates and topic overrides.
    try:
        published = json.loads(PUBLISH_STATE.read_text(encoding="utf-8"))
        topics = json.loads(TOPICS.read_text(encoding="utf-8"))
        live = Counter()
        thread_to_key = {int(v.get("message_thread_id") or 0): k for k, v in topics.items()}
        for entry in (published.get("entries") or {}).values():
            if entry.get("status") != "active":
                continue
            key = thread_to_key.get(int(entry.get("threadId") or 0))
            if key:
                live[key] += 1
        counts["#АрендаКвартир"] = live["rent_apartments"]
        counts["#ПродажаКвартир"] = live["sale_apartments"]
        counts["#АрендаДомов"] = live["rent_houses"]
        counts["#ПродажаДомов"] = live["sale_houses"]
        counts["#Парковки"] = live["parking"]
        counts["#УчасткиИЗемля"] = live["land"]
        counts["#КоммерческаяНедвижимость"] = live["commercial"]
        temporary = live["temporary"]
    except Exception:
        pass
    lines = [
        "🏠 LE BLEU · НЕДВИЖИМОСТЬ В БУЭНОС-АЙРЕСЕ",
        "",
        "Новые объекты публикуются здесь автоматически по разделам.",
        "",
        "Чтобы не пропускать обновления, присоединитесь к этой витрине Telegram.",
        "Для поиска по району, бюджету, комнатам, карте и полным фото откройте каталог.",
        "",
        f"Сейчас в каталоге: {len(items)} актуальных объектов.",
    ]
    text = "\n".join(lines)
    publisher = env_file(PUBLISHER_ENV)
    crm = env_file(CRM_ENV)
    channel = publisher.get("TELEGRAM_CHANNEL") or "@lebleu_argentina_ru"
    token = crm.get("LEBLEU_TELEGRAM_BOT_TOKEN") or crm.get("TELEGRAM_BOT_TOKEN") or ""
    if not token:
        raise RuntimeError("CRM Telegram bot token missing")
    bot_username = (publisher.get("TELEGRAM_BOT_USERNAME") or "LeBleuArgentinaBot").lstrip("@")
    try:
        api(token, "setChatDescription", {
            "chat_id": channel,
            "description": (
                "🏠 Le Bleu · недвижимость в Буэнос-Айресе. Новые объекты публикуются здесь автоматически. "
                f"🔎 Каталог, карта и фильтры: https://t.me/{bot_username}?startapp"
            ),
        })
    except Exception as exc:
        print(f"description update skipped: {exc}")
    catalog_url = ensure_catalog_link(bot_username)
    reply_markup = {"inline_keyboard": [[{"text": "🔎 Открыть каталог", "url": catalog_url}]]}
    state = {}
    if STATE.exists():
        try:
            state = json.loads(STATE.read_text(encoding="utf-8"))
        except Exception:
            state = {}
    message_id = state.get("message_id")
    if message_id:
        try:
            api(token, "editMessageText", {
                "chat_id": channel, "message_id": message_id, "text": text,
                "disable_web_page_preview": True, "reply_markup": reply_markup,
            })
        except Exception as exc:
            if "message is not modified" not in str(exc).lower():
                message_id = None
    if not message_id:
        sent = api(token, "sendMessage", {
            "chat_id": channel, "text": text,
            "disable_notification": True, "disable_web_page_preview": True, "reply_markup": reply_markup,
        })
        message_id = sent["message_id"]
    api(token, "pinChatMessage", {
        "chat_id": channel, "message_id": message_id, "disable_notification": True,
    })
    STATE.write_text(
        json.dumps({"message_id": message_id, "channel": channel}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    # The forum migration left an older welcome card in General. Once the
    # canonical auto-updated pin is healthy, remove that duplicate permanently.
    try:
        migration = json.loads(MIGRATION_STATE.read_text(encoding="utf-8")) if MIGRATION_STATE.exists() else {}
        legacy_id = int(migration.get("catalog_info_message_id") or 0)
        if legacy_id and legacy_id != int(message_id):
            try:
                api(token, "deleteMessage", {"chat_id": channel, "message_id": legacy_id})
            except Exception as exc:
                if "message to delete not found" not in str(exc).lower():
                    raise
            migration.pop("catalog_info_message_id", None)
            migration["catalog_info_version"] = 5
            MIGRATION_STATE.write_text(json.dumps(migration, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    except Exception as exc:
        print(f"legacy welcome cleanup skipped: {exc}")
    print(json.dumps({"message_id": message_id, "items": len(items), "counts": counts}, ensure_ascii=False, default=dict))

if __name__ == "__main__":
    main()
