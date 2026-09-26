import asyncio
import json
import os
import sqlite3
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from telethon import TelegramClient, events, functions, types
from telethon.errors import FloodWaitError
from telethon.tl.types import User

from scoring import score_message

import sys
sys.path.insert(0, "/opt/intent-radar")
from opportunity_state import ingest_live_signal
from intelligence import ingest_raw_message

API_ID = int(os.environ["TG_API_ID"])
API_HASH = os.environ["TG_API_HASH"]
SESSION = os.environ.get("TG_SESSION", "/opt/intent-radar/data/fiodor")
CONFIG_PATH = os.environ.get("RADAR_CONFIG", "/opt/intent-radar/config.json")
DB_PATH = os.environ.get("RADAR_DB", "/opt/intent-radar/data/signals.sqlite3")
BOT_TOKEN = os.environ.get("RADAR_BOT_TOKEN", "")
BOT_CHAT_ID = os.environ.get("RADAR_BOT_CHAT_ID", "")
DYNAMIC_SOURCES_PATH = Path("/opt/intent-radar/data/dynamic_public_sources.json")
LEGACY_ALERTS = os.environ.get("RADAR_LEGACY_ALERTS", "0") == "1"

with open(CONFIG_PATH, "r", encoding="utf-8") as fh:
    CFG = json.load(fh)

Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
DB = sqlite3.connect(DB_PATH)
DB.execute("""
CREATE TABLE IF NOT EXISTS signals (
  chat_id INTEGER, message_id INTEGER, created_at TEXT, chat_title TEXT,
  sender_id INTEGER, sender_name TEXT, sender_username TEXT, score INTEGER,
  capital INTEGER, text TEXT, link TEXT, reasons TEXT,
  PRIMARY KEY (chat_id, message_id)
)
""")
DB.execute("""
CREATE TABLE IF NOT EXISTS watch_cursors (
  source_key TEXT PRIMARY KEY, last_message_id INTEGER NOT NULL DEFAULT 0, updated_at TEXT
)
""")
DB.commit()

def get_watch_cursor(source_key):
    row = DB.execute("SELECT last_message_id FROM watch_cursors WHERE source_key=?", (source_key,)).fetchone()
    return int(row[0]) if row else 0

def set_watch_cursor(source_key, message_id):
    DB.execute("""INSERT INTO watch_cursors(source_key,last_message_id,updated_at) VALUES(?,?,?)
                  ON CONFLICT(source_key) DO UPDATE SET last_message_id=excluded.last_message_id, updated_at=excluded.updated_at""",
               (source_key, int(message_id), datetime.now(timezone.utc).isoformat()))
    DB.commit()

def message_link(chat, chat_id, message_id):
    username = getattr(chat, "username", None)
    if username:
        return f"https://t.me/{username}/{message_id}"
    raw = str(chat_id)
    if raw.startswith("-100"):
        return f"https://t.me/c/{raw[4:]}/{message_id}"
    return ""


def insert_signal(row):
    cur = DB.execute("INSERT OR IGNORE INTO signals VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", row)
    DB.commit()
    return cur.rowcount == 1


def compact(text, limit=700):
    clean = " ".join((text or "").split())
    return clean if len(clean) <= limit else clean[:limit] + "…"


def _bot_send_sync(text, link="", copy_text=""):
    if not BOT_TOKEN or not BOT_CHAT_ID:
        return False
    keyboard = []
    row = []
    if link:
        row.append({"text": "Открыть сообщение", "url": link})
    if copy_text:
        row.append({"text": "Скопировать для ChatGPT", "copy_text": {"text": copy_text[:256]}})
    if row:
        keyboard.append(row)
    payload = {
        "chat_id": BOT_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as resp:
        result = json.loads(resp.read().decode("utf-8"))
    return bool(result.get("ok"))


async def send_operator_alert(text, link="", copy_text=""):
    try:
        if await asyncio.to_thread(_bot_send_sync, text, link, copy_text):
            return
    except Exception as exc:
        print(f"Bot alert failed: {type(exc).__name__}: {str(exc)[:120]}", flush=True)
    await client.send_message("me", text, link_preview=False)


client = TelegramClient(SESSION, API_ID, API_HASH)


async def process_candidate(chat, chat_id, message_id, text, date, sender):
    if not isinstance(sender, User) or getattr(sender, "bot", False):
        return
    chat_title = getattr(chat, "title", "Telegram group")
    try:
        ingest_raw_message(
            chat_id=int(chat_id),
            message_id=int(message_id),
            created_at=(date or datetime.now(timezone.utc)).isoformat(),
            chat_title=chat_title,
            sender_id=int(sender.id),
            sender_name=" ".join(filter(None, [sender.first_name, sender.last_name])).strip(),
            sender_username=sender.username or "",
            text=text,
            link=message_link(chat, chat_id, message_id),
        )
    except Exception as exc:
        print(
            f"Intelligence shadow ingest failed: {type(exc).__name__}: {str(exc)[:120]}",
            flush=True,
        )
    result = score_message(text, CFG, chat_title)
    if result["score"] < CFG["min_score"]:
        return

    sender_name = " ".join(filter(None, [sender.first_name, sender.last_name])).strip()
    link = message_link(chat, chat_id, message_id)
    created = (date or datetime.now(timezone.utc)).isoformat()
    row = (
        int(chat_id), int(message_id), created, chat_title,
        int(sender.id), sender_name, sender.username or "", int(result["score"]),
        result["capital"], text, link, json.dumps(result["reasons"], ensure_ascii=False),
    )
    if not insert_signal(row):
        return
    try:
        ingest_live_signal(
            platform="telegram", platform_user_id=str(sender.id), username=sender.username or "",
            name=sender_name, occurred_at=created, source_title=chat_title,
            category=result["category"], score=int(result["score"]), text=text, link=link,
            reasons=result["reasons"],
        )
    except Exception as exc:
        print(f"Opportunity state ingest failed: {type(exc).__name__}: {str(exc)[:120]}", flush=True)

    if not LEGACY_ALERTS:
        return

    tier = "🔥 HOT" if result["score"] >= CFG["hot_score"] else "🟡 WARM"
    who = f"@{sender.username}" if sender.username else sender_name or f"user:{sender.id}"
    reasons = " · ".join(result["reasons"][:5])
    alert = (
        f"{tier} · {result['category']} · {result['score']}/100\n"
        f"{chat_title}\n{who}\n\n{compact(text)}\n\n"
        f"Why: {reasons}\n{link or 'Открой группу в Telegram и найди сообщение по времени.'}"
    )
    copy_prompt = (
        "Оцени этот сигнал как потенциального клиента для недвижимости/инвестиций в Аргентине. "
        f"Нужен вывод: подходит/не подходит, почему и следующий шаг. Сообщение: {compact(text, 120)}"
    )
    await send_operator_alert(alert, link, copy_prompt)


@client.on(events.NewMessage)
async def on_new_message(event):
    if not event.is_group or event.out or not event.raw_text or event.message.fwd_from:
        return
    sender = await event.get_sender()
    chat = await event.get_chat()
    await process_candidate(chat, event.chat_id, event.id, event.raw_text, event.date, sender)


DISCOVERY_QUERIES = [
    "Аргентина недвижимость", "Буэнос-Айрес квартира", "ищу квартиру Буэнос-Айрес",
    "купить квартиру Аргентина", "инвестиции Аргентина", "аренда Буэнос-Айрес",
    "escritura Argentina", "seguro de caucion Argentina", "ипотека Аргентина",
    "dueño directo Buenos Aires", "русские Аргентина", "релокация Аргентина"
]

def load_dynamic_sources():
    try:
        data = json.loads(DYNAMIC_SOURCES_PATH.read_text(encoding="utf-8"))
        return [x.get("username") for x in data.get("sources", []) if x.get("username")]
    except Exception:
        return []

async def discover_public_sources():
    await asyncio.sleep(20)
    while True:
        found = {}
        min_date = int((datetime.now(timezone.utc) - timedelta(days=30)).timestamp())
        for query in DISCOVERY_QUERIES:
            try:
                result = await client(functions.messages.SearchGlobalRequest(
                    q=query, filter=types.InputMessagesFilterEmpty(), min_date=min_date, max_date=0,
                    offset_rate=0, offset_peer=types.InputPeerEmpty(), offset_id=0, limit=50, groups_only=True))
                for chat in result.chats:
                    username = getattr(chat, "username", None)
                    if not username:
                        continue
                    item = found.setdefault(username, {"username":username,"title":getattr(chat,"title","") or "",
                                                       "participants":getattr(chat,"participants_count",0) or 0,"hits":0})
                    item["hits"] += 1
            except FloodWaitError as exc:
                await asyncio.sleep(min(exc.seconds + 2, 600))
            except Exception as exc:
                print(f"Source discovery failed for {query}: {type(exc).__name__}: {str(exc)[:100]}", flush=True)
            await asyncio.sleep(0.4)
        rows = sorted(found.values(), key=lambda x:(x["hits"],x["participants"]), reverse=True)[:80]
        DYNAMIC_SOURCES_PATH.write_text(json.dumps({"updated_at":datetime.now(timezone.utc).isoformat(),"sources":rows}, ensure_ascii=False, indent=2), encoding="utf-8")
        print(f"Dynamic source discovery complete: {len(rows)} public groups", flush=True)
        await asyncio.sleep(6 * 3600)

async def poll_public_groups():
    if not CFG.get("public_watch_groups", []):
        return
    interval = max(120, int(CFG.get("poll_interval_seconds", 300)))
    limit = max(10, min(80, int(CFG.get("public_poll_limit", 30))))
    max_age = timedelta(days=7)
    cache = {}
    await asyncio.sleep(5)
    while True:
        groups = list(dict.fromkeys(CFG.get("public_watch_groups", []) + load_dynamic_sources()))[:100]
        cycle_started = datetime.now(timezone.utc)
        for username in groups:
            try:
                entity = cache.get(username)
                if entity is None:
                    entity = await client.get_entity(username)
                    cache[username] = entity
                last_id = get_watch_cursor(username)
                max_seen = last_id
                if last_id:
                    iterator = client.iter_messages(entity, min_id=last_id, reverse=True, limit=limit)
                else:
                    iterator = client.iter_messages(entity, limit=limit)
                async for msg in iterator:
                    max_seen = max(max_seen, int(msg.id))
                    if not msg.raw_text or msg.out or msg.fwd_from:
                        continue
                    if not last_id and msg.date and cycle_started - msg.date > max_age:
                        break
                    sender = msg.sender or await msg.get_sender()
                    await process_candidate(entity, msg.chat_id, msg.id, msg.raw_text, msg.date, sender)
                if max_seen > last_id:
                    set_watch_cursor(username, max_seen)
            except FloodWaitError as exc:
                print(f"Public watch flood wait {exc.seconds}s", flush=True)
                await asyncio.sleep(min(exc.seconds + 2, 600))
            except Exception as exc:
                print(f"Public watch @{username} failed: {type(exc).__name__}: {str(exc)[:120]}", flush=True)
            await asyncio.sleep(0.15)
        print(f"Public watch cycle complete: {len(groups)} groups", flush=True)
        await asyncio.sleep(interval)


async def main():
    await client.start()
    me = await client.get_me()
    print(f"Buyer Radar online as @{me.username or me.id}", flush=True)
    print("Listening to joined groups + polling selected public groups. No outreach is automated.", flush=True)
    watcher = asyncio.create_task(poll_public_groups())
    discovery = asyncio.create_task(discover_public_sources())
    try:
        await client.run_until_disconnected()
    finally:
        watcher.cancel()
        discovery.cancel()


if __name__ == "__main__":
    asyncio.run(main())
