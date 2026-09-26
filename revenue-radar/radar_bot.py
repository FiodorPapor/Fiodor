#!/usr/bin/env python3
import json, os, time, urllib.request, urllib.parse
from datetime import datetime, timezone, timedelta

from broad_radar import connect, render_candidate, iso
from opportunity_state import connect as opp_connect, upsert_person, add_signal, add_or_update_opportunity

TOKEN = os.environ["RADAR_ALERT_BOT_TOKEN"]
ALLOWED_CHAT_ID = str(os.environ["RADAR_ALERT_CHAT_ID"])
API = f"https://api.telegram.org/bot{TOKEN}/"

def api(method, payload=None, timeout=35):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    req = urllib.request.Request(API + method, data=data, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.load(resp)

def send(text, keyboard=None, chat_id=None):
    payload = {
        "chat_id": chat_id or ALLOWED_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    return api("sendMessage", payload)

def candidate_keyboard(row):
    buttons = [[
        {"text":"✅ Лид","callback_data":f"lead:{row['id']}"},
        {"text":"👀 Просмотрено","callback_data":f"review:{row['id']}"},
        {"text":"🗑 Шум","callback_data":f"noise:{row['id']}"},
        {"text":"⏰ Потом","callback_data":f"later:{row['id']}"}
    ]]
    if row["link"]:
        buttons.append([{"text":"Открыть оригинал","url":row["link"]}])
    return buttons

def send_candidate(con, row, mark_shown=True):
    send(render_candidate(con, row), candidate_keyboard(row))
    if mark_shown:
        con.execute("UPDATE candidates SET shown_at=COALESCE(shown_at,?) WHERE id=?", (iso(), row["id"]))
        con.commit()

def queue_rows(con, where="state='NEW'", params=(), limit=8):
    return con.execute(
        f"""SELECT * FROM candidates WHERE {where}
            ORDER BY score DESC, occurred_at DESC, id DESC LIMIT ?""",
        (*params, limit)
    ).fetchall()

def send_rows(con, rows, empty_text="Новых непросмотренных сигналов нет."):
    if not rows:
        send(empty_text)
        return
    for row in rows:
        send_candidate(con, row)
        time.sleep(0.08)

def stats_text(con):
    total = con.execute("SELECT COUNT(*) c FROM candidates").fetchone()["c"]
    states = con.execute(
        "SELECT state,COUNT(*) c FROM candidates GROUP BY state ORDER BY c DESC"
    ).fetchall()
    cats = con.execute(
        """SELECT category,COUNT(*) c FROM candidates
           WHERE region='argentina' AND occurred_at>=? GROUP BY category ORDER BY c DESC""",
        ((datetime.now(timezone.utc)-timedelta(days=7)).isoformat(),)
    ).fetchall()
    cursor = con.execute("SELECT value FROM meta WHERE key='raw_cursor'").fetchone()
    state_txt = ", ".join(f"{x['state']}={x['c']}" for x in states) or "—"
    cat_txt = ", ".join(f"{x['category']}={x['c']}" for x in cats) or "—"
    return (
        f"📡 Revenue Radar\nВсего кандидатов: {total}\n"
        f"Очередь: {state_txt}\nЗа 7 дней: {cat_txt}\n"
        f"Raw cursor: {(cursor['value'] if cursor else '0')}"
    )

HELP = """📡 Revenue Radar

/new — только ещё не показанные сигналы
/unreviewed — всё, что ещё не разобрано
/today — новые за 24 часа
/buyers — покупатели и pre-intent
/renters — арендаторы и rental friction
/owners — прямые владельцы
/investors — инвесторы
/potential — слабые/косвенные сигналы для ручной проверки
/search текст — поиск по локальной базе
/stats — состояние радара

Кнопки под сигналом фиксируют решение. Просмотренные и шум больше не возвращаются в /new."""

def handle_command(con, text):
    parts = (text or "").strip().split(maxsplit=1)
    cmd = parts[0].split("@")[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""
    if cmd in ("/start", "/help"):
        send(HELP)
    elif cmd == "/stats":
        send(stats_text(con))
    elif cmd == "/new":
        since = (datetime.now(timezone.utc)-timedelta(days=14)).isoformat()
        rows = queue_rows(con, "state='NEW' AND shown_at IS NULL AND region='argentina' AND occurred_at>=?", (since,))
        send_rows(con, rows)
    elif cmd == "/unreviewed":
        since = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Неразобранных сигналов нет.")
    elif cmd == "/today":
        since = (datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "За последние 24 часа новых неразобранных сигналов нет.")
    elif cmd == "/buyers":
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND category IN ('PROPERTY_BUYER','PRE_INTENT')", limit=10)
        send_rows(con, rows, "Новых buyer/pre-intent сигналов нет.")
    elif cmd == "/renters":
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND category='RENTER'", limit=10)
        send_rows(con, rows, "Новых renter-сигналов нет.")
    elif cmd == "/owners":
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND category IN ('OWNER_DIRECT','OWNER_RENTAL')", limit=10)
        send_rows(con, rows, "Новых прямых владельцев нет.")
    elif cmd == "/investors":
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND category='INVESTOR'", limit=10)
        send_rows(con, rows, "Новых investor-сигналов нет.")
    elif cmd == "/potential":
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND score<58", limit=10)
        send_rows(con, rows, "Новых косвенных сигналов нет.")
    elif cmd == "/search":
        if not arg:
            send("Использование: /search квартира Палермо")
            return
        like = "%" + arg.lower() + "%"
        rows = con.execute(
            """SELECT * FROM candidates
               WHERE lower(text) LIKE ? OR lower(COALESCE(sender_username,'')) LIKE ?
                  OR lower(COALESCE(chat_title,'')) LIKE ?
               ORDER BY occurred_at DESC, score DESC LIMIT 10""",
            (like, like, like)
        ).fetchall()
        send_rows(con, rows, "Совпадений в локальной базе нет.")
    else:
        send("Не понял команду. /help")

CATEGORY_KIND = {
    "PROPERTY_BUYER":"BUYER",
    "PRE_INTENT":"PRE_INTENT",
    "INVESTOR":"INVESTOR",
    "RENTER":"RENTER",
    "OWNER_DIRECT":"OWNER_DIRECT",
    "OWNER_RENTAL":"OWNER_RENTAL",
    "SUPPLY":"SUPPLY",
    "PARTNER":"PARTNER",
    "POTENTIAL":"OTHER",
}

def promote_to_opportunity(row):
    con = opp_connect()
    pid = upsert_person(
        con, "telegram", row["sender_username"] or row["sender_name"] or row["person_key"],
        str(row["sender_id"]) if row["sender_id"] else None,
        row["sender_username"], row["sender_name"]
    )
    reasons = json.loads(row["reasons_json"] or "[]")
    sid, _ = add_signal(
        con, pid, "telegram", row["occurred_at"], row["chat_title"], row["category"],
        int(row["score"]), None, row["text"], row["link"], reasons
    )
    kind = CATEGORY_KIND.get(row["category"], "OTHER")
    label = ("@" + row["sender_username"]) if row["sender_username"] else (row["sender_name"] or row["person_key"])
    priority = "HIGH" if int(row["score"]) >= 80 else "MEDIUM"
    confidence = "HIGH" if int(row["score"]) >= 80 else "MEDIUM"
    summary = " ".join((row["text"] or "").split())[:700]
    return add_or_update_opportunity(
        con, pid, kind, f"{kind} · {label}", "REVIEW", priority,
        confidence, summary, sid
    )

def disposition_text(action):
    return {
        "lead":"QUALIFIED",
        "review":"REVIEWED",
        "noise":"NOISE",
        "later":"NURTURE"
    }.get(action)

def handle_callback(con, cq):
    data = cq.get("data", "")
    try:
        action, sid = data.split(":", 1)
        cid = int(sid)
    except Exception:
        api("answerCallbackQuery", {"callback_query_id": cq["id"], "text":"Некорректная команда"})
        return
    state = disposition_text(action)
    if not state:
        api("answerCallbackQuery", {"callback_query_id": cq["id"], "text":"Неизвестное действие"})
        return
    row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
    if not row:
        api("answerCallbackQuery", {"callback_query_id": cq["id"], "text":"Сигнал не найден"})
        return
    con.execute(
        """UPDATE candidates SET state=?, reviewed_at=?, disposition=? WHERE id=?""",
        (state, iso(), action, cid)
    )
    con.commit()
    opportunity_id = None
    if action == "lead":
        try:
            opportunity_id = promote_to_opportunity(row)
        except Exception as exc:
            print(f"Opportunity promotion failed: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
    labels = {
        "lead":("Сохранено как лид" + (f" · opportunity #{opportunity_id}" if opportunity_id else "")),
        "review":"Отмечено просмотренным",
        "noise":"Отмечено как шум",
        "later":"Отложено"
    }
    api("answerCallbackQuery", {"callback_query_id": cq["id"], "text":labels[action]})
    msg = cq.get("message") or {}
    try:
        api("editMessageReplyMarkup", {
            "chat_id": msg.get("chat",{}).get("id"),
            "message_id": msg.get("message_id"),
            "reply_markup": {"inline_keyboard": (
                [[{"text":"Открыть оригинал","url":row["link"]}]] if row["link"] else []
            )}
        })
    except Exception:
        pass

def set_commands():
    commands = [
        {"command":"new","description":"Новые, ещё не показанные сигналы"},
        {"command":"unreviewed","description":"Все неразобранные"},
        {"command":"today","description":"Сигналы за 24 часа"},
        {"command":"buyers","description":"Покупатели и pre-intent"},
        {"command":"renters","description":"Арендаторы и rental friction"},
        {"command":"owners","description":"Прямые владельцы"},
        {"command":"investors","description":"Инвесторы"},
        {"command":"potential","description":"Косвенные сигналы"},
        {"command":"search","description":"Поиск по базе"},
        {"command":"stats","description":"Статус радара"},
        {"command":"help","description":"Команды"}
    ]
    try:
        api("setMyCommands", {"commands":commands})
    except Exception as exc:
        print("setMyCommands failed", type(exc).__name__, flush=True)

def main():
    con = connect()
    set_commands()
    offset = int(
        (con.execute("SELECT value FROM meta WHERE key='bot_update_offset'").fetchone() or {"value":"0"})["value"]
    )
    print(f"Revenue Radar bot online · offset={offset}", flush=True)
    while True:
        try:
            result = api("getUpdates", {
                "offset": offset,
                "timeout": 25,
                "allowed_updates": ["message","callback_query"]
            }, timeout=35)
            for upd in result.get("result", []):
                offset = max(offset, upd["update_id"] + 1)
                con.execute(
                    """INSERT INTO meta(key,value) VALUES('bot_update_offset',?)
                       ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
                    (str(offset),)
                )
                con.commit()
                if "message" in upd:
                    msg = upd["message"]
                    if str(msg.get("chat",{}).get("id")) != ALLOWED_CHAT_ID:
                        continue
                    if msg.get("text","").startswith("/"):
                        handle_command(con, msg["text"])
                elif "callback_query" in upd:
                    cq = upd["callback_query"]
                    if str((cq.get("message") or {}).get("chat",{}).get("id")) != ALLOWED_CHAT_ID:
                        continue
                    handle_callback(con, cq)
        except Exception as exc:
            print(f"Bot loop error: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
            time.sleep(3)

if __name__ == "__main__":
    main()
