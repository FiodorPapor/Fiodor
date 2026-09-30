#!/usr/bin/env python3
import asyncio, json, os, time, urllib.request, urllib.error
from pathlib import Path

ROOT = Path("/opt/lebleu-listing-bridge")
STATE = ROOT / "state/forum-migration.json"
TOPICS = ROOT / "state/forum-topics.json"
OLD_USERNAME = "lebleu_argentina_ru"
NEW_TITLE = "Аренда и продажа квартир | Le Bleu"
ARCHIVE_TITLE = "Аренда квартир • Продажа квартир | Буэнос-Айрес 🇦🇷 | Le Bleu"

TOPIC_SPECS = [
    ("rent_apartments", "Аренда квартир", 0x6FB9F0, "5309929258443874898"),
    ("sale_apartments", "Продажа квартир", 0xFFD67E, "5350452584119279096"),
    ("rent_houses", "Аренда домов", 0x8EEE98, "5312486108309757006"),
    ("sale_houses", "Продажа домов", 0xCB86DB, "5309958691854754293"),
    ("parking", "Парковочные места", 0x6FB9F0, "5312322066328853156"),
    ("land", "Земля и участки", 0x8EEE98, "5418196338774907917"),
    ("commercial", "Коммерческая недвижимость", 0xFFD67E, "5348227245599105972"),
    ("temporary", "Временная аренда", 0xFF93B2, "5357120306097956843"),
]

def load_env(path):
    out = {}
    for raw in Path(path).read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip("'").strip('"')
    return out

def load_state():
    if STATE.exists():
        return json.loads(STATE.read_text(encoding="utf-8"))
    return {}

def save_state(state):
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(STATE)

def bot_api(token, method, payload):
    for attempt in range(6):
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/{method}",
            data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
            headers={"Content-Type":"application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                body = json.load(resp)
        except urllib.error.HTTPError as exc:
            body = {}
            try: body = json.loads(exc.read().decode())
            except Exception: pass
            retry = int((body.get("parameters") or {}).get("retry_after") or 0)
            if exc.code == 429 and attempt < 5:
                time.sleep(max(1,retry)+1); continue
            raise RuntimeError(body.get("description") or f"HTTP {exc.code}") from exc
        if body.get("ok"):
            return body.get("result")
        retry = int((body.get("parameters") or {}).get("retry_after") or 0)
        if retry and attempt < 5:
            time.sleep(max(1,retry)+1); continue
        raise RuntimeError(body.get("description") or method)
    raise RuntimeError(f"{method}: retries exhausted")
async def main():
    from telethon import TelegramClient, functions, types, utils
    from telethon.errors import UserNotParticipantError

    tg = load_env("/opt/intent-radar/.env")
    crm = load_env("/opt/fiodor-crm-v2/.env")
    token = crm.get("LEBLEU_TELEGRAM_BOT_TOKEN") or crm["TELEGRAM_BOT_TOKEN"]
    bot_username = crm.get("LEBLEU_TELEGRAM_BOT_USERNAME") or "LeBleuArgentinaBot"
    state = load_state()

    client = TelegramClient(tg["TG_SESSION"], int(tg["TG_API_ID"]), tg["TG_API_HASH"])
    await client.start()

    # Resolve the original public channel before username transfer.
    old = None
    old_id = state.get("old_channel_id")
    if old_id:
        try:
            old = await client.get_entity(int(old_id))
        except Exception:
            old = None
    if old is None:
        old = await client.get_entity(OLD_USERNAME)
        state["old_channel_id"] = old.id
        state["old_title"] = getattr(old, "title", "")
        save_state(state)

    # Create exactly one forum supergroup.
    new = None
    new_id = state.get("new_group_id")
    if new_id:
        try:
            new = await client.get_entity(int(new_id))
        except Exception:
            new = None
    if new is None:
        res = await client(functions.channels.CreateChannelRequest(
            title=NEW_TITLE,
            about="Русскоязычный каталог объектов Le Bleu. Выберите раздел и откройте карточку объекта.",
            megagroup=True,
            forum=True,
        ))
        new = res.chats[0]
        state["new_group_id"] = new.id
        save_state(state)
        print("created forum", new.id, flush=True)

    # Force the list-based Topics UI, matching the reference screenshot.
    if not state.get("forum_enabled"):
        try:
            await client(functions.channels.ToggleForumRequest(channel=new, enabled=True, tabs=False))
        except Exception as exc:
            if "CHAT_NOT_MODIFIED" not in str(exc):
                raise
        state["forum_enabled"] = True
        save_state(state)

    # Copy the existing Le Bleu avatar if available.
    if not state.get("photo_copied"):
        try:
            photo_path = await client.download_profile_photo(old, file="/tmp/lebleu-forum-avatar.jpg")
            if photo_path:
                uploaded = await client.upload_file(photo_path)
                await client(functions.channels.EditPhotoRequest(
                    channel=new, photo=types.InputChatUploadedPhoto(file=uploaded)
                ))
            state["photo_copied"] = True
            save_state(state)
        except Exception as exc:
            print("photo copy skipped", type(exc).__name__, str(exc)[:120], flush=True)

    # Make the CRM bot an admin and topic manager.
    if not state.get("bot_admin"):
        bot = await client.get_entity(bot_username)
        try:
            await client(functions.channels.InviteToChannelRequest(channel=new, users=[bot]))
        except Exception as exc:
            if "USER_ALREADY_PARTICIPANT" not in str(exc):
                print("bot invite", type(exc).__name__, str(exc)[:120], flush=True)
        rights = types.ChatAdminRights(
            change_info=True, delete_messages=True, ban_users=True, invite_users=True,
            pin_messages=True, manage_topics=True, other=True,
        )
        await client(functions.channels.EditAdminRequest(
            channel=new, user_id=bot, admin_rights=rights, rank="Le Bleu"
        ))
        state["bot_admin"] = True
        save_state(state)

    # Read-only catalog for ordinary members. CTA goes to the CRM bot.
    if not state.get("read_only"):
        banned = types.ChatBannedRights(
            until_date=None, send_messages=True, send_media=True, send_stickers=True,
            send_gifs=True, send_games=True, send_inline=True, embed_links=True,
            send_polls=True, change_info=True, pin_messages=True, manage_topics=True,
            send_photos=True, send_videos=True, send_roundvideos=True, send_audios=True,
            send_voices=True, send_docs=True, send_plain=True,
        )
        try:
            await client(functions.messages.EditChatDefaultBannedRightsRequest(peer=new, banned_rights=banned))
        except Exception as exc:
            if "CHAT_NOT_MODIFIED" not in str(exc):
                raise
        state["read_only"] = True
        save_state(state)
    # Transfer the established public username atomically with rollback.
    if not state.get("username_transferred"):
        current_new = getattr(new, "username", None)
        if current_new != OLD_USERNAME:
            try:
                await client(functions.channels.UpdateUsernameRequest(channel=old, username=""))
                try:
                    await client(functions.channels.UpdateUsernameRequest(channel=new, username=OLD_USERNAME))
                except Exception:
                    await client(functions.channels.UpdateUsernameRequest(channel=old, username=OLD_USERNAME))
                    raise
            finally:
                pass
        state["username_transferred"] = True
        save_state(state)
        print("username transferred", flush=True)

    # Rename the old channel, but keep it as an archive/rollback source.
    try:
        await client(functions.channels.EditTitleRequest(channel=old, title=ARCHIVE_TITLE))
    except Exception as exc:
        if "CHAT_NOT_MODIFIED" not in str(exc):
            print("archive title", type(exc).__name__, str(exc)[:120], flush=True)
    state["old_archived"] = True
    save_state(state)

    bot_chat_id = utils.get_peer_id(new)
    state["bot_api_chat_id"] = bot_chat_id
    save_state(state)
    await client.disconnect()

    # Topic management via official Bot API.
    try:
        bot_api(token, "editGeneralForumTopic", {
            "chat_id": bot_chat_id, "name": "О каталоге"
        })
    except Exception as exc:
        print("general topic rename", str(exc)[:120], flush=True)

    existing = {}
    if TOPICS.exists():
        try: existing = json.loads(TOPICS.read_text(encoding="utf-8"))
        except Exception: existing = {}
    for key, name, color, icon_id in TOPIC_SPECS:
        if key in existing and existing[key].get("message_thread_id"):
            continue
        topic = bot_api(token, "createForumTopic", {
            "chat_id": bot_chat_id, "name": name, "icon_color": color, "icon_custom_emoji_id": icon_id
        })
        existing[key] = {
            "name": name,
            "message_thread_id": topic["message_thread_id"],
        }
        TOPICS.write_text(json.dumps(existing,ensure_ascii=False,indent=2),encoding="utf-8")
        print("topic", key, topic["message_thread_id"], flush=True)
        time.sleep(0.6)

    # Keep General short: explain the two modes (browse vs. search) and lead
    # with the measurable Mini App funnel instead of a concierge-style CTA.
    info_text = (
        "Каталог Le Bleu в Telegram.\n\n"
        "• Хотите просто посмотреть объекты — выберите нужный раздел.\n"
        "• Нужен поиск по району, бюджету, комнатам и полная галерея — откройте каталог.\n"
        "• Ничего не подошло — сохраните поиск, и новые совпадения не потеряются."
    )
    info_markup = {"inline_keyboard": [
        [{"text": "🔎 Открыть каталог", "url": "https://t.me/LeBleuArgentinaBot?start=trk_94ocnclUKkVi"}],
        [
            {"text": "🌐 Сайт Le Bleu", "url": "https://www.lebleu.com.ar/"},
            {"text": "📷 Instagram", "url": "https://www.instagram.com/lebleu.inmobiliaria/"},
        ],
    ]}
    try:
        bot_api(token, "setChatDescription", {
            "chat_id": bot_chat_id,
            "description": (
                "Недвижимость в Буэнос-Айресе от Le Bleu: актуальные объекты для покупки, аренды "
                "и инвестиций. Выберите раздел и найдите подходящий вариант. "
                "🌐 lebleu.com.ar · 📷 @lebleu.inmobiliaria"
            ),
        })
    except Exception as exc:
        print("description update", str(exc)[:120], flush=True)

    info_id = state.get("catalog_info_message_id")
    if info_id:
        try:
            bot_api(token, "editMessageText", {
                "chat_id": bot_chat_id, "message_id": info_id,
                "text": info_text, "reply_markup": info_markup,
                "disable_web_page_preview": True,
            })
        except Exception:
            info_id = None
    if not info_id:
        sent = bot_api(token, "sendMessage", {
            "chat_id": bot_chat_id, "text": info_text,
            "reply_markup": info_markup, "disable_web_page_preview": True,
            "disable_notification": True,
        })
        state["catalog_info_message_id"] = sent["message_id"]
    state["catalog_info_version"] = 4
    state["welcome_sent"] = True
    state.pop("legacy_133_notice_id", None)
    save_state(state)

    print(json.dumps({
        "old_channel_id": state["old_channel_id"],
        "new_group_id": state["new_group_id"],
        "bot_api_chat_id": state["bot_api_chat_id"],
        "username": OLD_USERNAME,
        "topics": existing,
    }, ensure_ascii=False, indent=2))

if __name__ == "__main__":
    asyncio.run(main())
