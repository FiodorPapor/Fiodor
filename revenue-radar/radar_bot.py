#!/usr/bin/env python3
import json, os, time, urllib.request, urllib.parse, urllib.error, subprocess, re, threading
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone, timedelta

from broad_radar import connect, render_candidate, iso
from opportunity_state import connect as opp_connect, upsert_person, add_signal, add_or_update_opportunity
from question_lane import list_questions, get_question, mark_question
from lebleu_matcher import (
    search as lebleu_search, match_signal, brief as lebleu_brief,
    public_post_url, draft_dm, draft_public, dm_link, get_by_code, parse_query
)

TOKEN = os.environ["RADAR_ALERT_BOT_TOKEN"]
ALLOWED_CHAT_ID = str(os.environ["RADAR_ALERT_CHAT_ID"])
API = f"https://api.telegram.org/bot{TOKEN}/"

def api(method, payload=None, timeout=15):
    data = None
    headers = {}
    if payload is not None:
        data = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        headers["Content-Type"] = "application/json"
    last = None
    for attempt in range(2):
        req = urllib.request.Request(API + method, data=data, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.load(resp)
        except urllib.error.HTTPError as exc:
            detail_raw = exc.read().decode("utf-8", "ignore")[:2000]
            last = RuntimeError(f"Telegram {method} HTTP {exc.code}: {detail_raw[:500]}")
            if exc.code == 429 and attempt == 0:
                retry_after = 1
                try:
                    body = json.loads(detail_raw)
                    retry_after = int((body.get("parameters") or {}).get("retry_after") or 1)
                except Exception:
                    pass
                wait = max(1, min(30, retry_after))
                print(f"BOT_RATE_LIMIT method={method} retry_after={wait}s", flush=True)
                time.sleep(wait + 0.15)
                continue
            raise last from exc
    raise last or RuntimeError(f"Telegram {method} failed")

def send(text, keyboard=None, chat_id=None):
    payload = {
        "chat_id": chat_id or ALLOWED_CHAT_ID,
        "text": text,
        "disable_web_page_preview": True
    }
    if keyboard is not None:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    return api("sendMessage", payload)


def safe_answer_callback(cqid, text="Принято"):
    if not cqid:
        return False
    try:
        api("answerCallbackQuery", {"callback_query_id": cqid, "text": text}, timeout=8)
        return True
    except Exception as exc:
        # Callback answers are time-limited by Telegram. A stale answer must never
        # abort processing of the action itself or the rest of the update batch.
        print(f"Callback ack skipped: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
        return False

def callback_ack_text(data):
    if data.startswith("matches:"):
        return "Ищу совпадения Le Bleu…"
    if data.startswith("catalogreply:"):
        return "Готовлю шаблон каталога…"
    if data.startswith("catalogdraft:"):
        return "Сохраняю черновик в исходном чате…"
    if data.startswith("reply:") or data.startswith("savedraft"):
        return "Готовлю черновик…"
    if data.startswith("card:") or data.startswith("carddm:"):
        return "Проверяю карточку…"
    if data.startswith("replymatch:"):
        return "Готовлю ответ…"
    return {
        "lead": "Сохраняю как лид…",
        "review": "Отмечаю просмотренным…",
        "noise": "Отмечаю как шум…",
        "later": "Откладываю…",
        "qdone": "Отмечаю: ответил",
        "qskip": "Убираю вопрос",
        "qlater": "Откладываю вопрос",
    }.get(data.split(":",1)[0], "Принято")

MATCH_CATEGORIES = ("PROPERTY_BUYER", "INVESTOR", "RENTER", "PRE_INTENT")
CATALOG_REPLY_CATEGORIES = MATCH_CATEGORIES + ("POTENTIAL",)
LEBLEU_CATALOG_URL = "https://t.me/lebleu_argentina_ru"
FIODOR_TELEGRAM = "@paporotskiy"

# Some communities explicitly prohibit commercial replies, links or service offers.
# Keep those sources useful for lead discovery, but never create outbound group drafts.
READ_ONLY_OUTREACH_CHATS = {
    -1001745734197: "Аргентина 🇦🇷 Чат TravelAsk",
}

WRITE_BLOCK_ERRORS = ("ChatWriteForbiddenError", "ChannelPrivateError", "UserBannedInChannelError")

def _row_chat_id(row):
    try:
        return int(row["chat_id"])
    except Exception:
        return None

def latest_draft_write_blocked(row):
    chat_id = _row_chat_id(row)
    if chat_id is None:
        return False
    con = None
    try:
        con = connect()
        latest = con.execute(
            "SELECT status,error FROM draft_jobs WHERE chat_id=? ORDER BY id DESC LIMIT 1",
            (chat_id,)
        ).fetchone()
        if not latest or latest["status"] != "ERROR":
            return False
        error = latest["error"] or ""
        return any(marker in error for marker in WRITE_BLOCK_ERRORS)
    except Exception:
        return False
    finally:
        if con is not None:
            con.close()

def outreach_read_only(row):
    chat_id = _row_chat_id(row)
    return (chat_id in READ_ONLY_OUTREACH_CHATS) or latest_draft_write_blocked(row)

def outreach_read_only_note(row):
    try:
        name = READ_ONLY_OUTREACH_CHATS.get(int(row["chat_id"]))
    except Exception:
        name = None
    if name:
        return (
            f"⚠️ {name}: коммерческие объявления, продажи и ссылки могут привести к бану. "
            "Для этого чата Revenue Radar не создаёт групповые черновики и не предлагает каталог. "
            "Допустим только нейтральный полезный ответ без саморекламы и CTA."
        )
    if latest_draft_write_blocked(row):
        return (
            "⚠️ Telegram уже возвращал запрет записи для этого чата. Revenue Radar отключил групповые черновики, "
            "чтобы не повторять попытки до восстановления доступа."
        )
    return None

def response_keyboard(row):
    # Reply tools stay available even after the signal is marked reviewed/lead/noise/later.
    # Restricted communities stay useful for discovery, but commercial group actions are hidden.
    first = [{"text":"✍️ Ответить","callback_data":f"reply:{row['id']}"}]
    if row["category"] in CATALOG_REPLY_CATEGORIES and not outreach_read_only(row):
        first.append({"text":"📚 Каталог-шаблон","callback_data":f"catalogreply:{row['id']}"})
    buttons = [first]
    if row["category"] in MATCH_CATEGORIES:
        buttons.append([{"text":"🏠 Совпадения Le Bleu","callback_data":f"matches:{row['id']}"}])
    if row["link"]:
        buttons.append([{"text":"Открыть оригинал","url":row["link"]}])
    return buttons

def candidate_keyboard(row):
    return [[
        {"text":"✅ Лид","callback_data":f"lead:{row['id']}"},
        {"text":"👀 Просмотрено","callback_data":f"review:{row['id']}"},
        {"text":"🗑 Шум","callback_data":f"noise:{row['id']}"},
        {"text":"⏰ Потом","callback_data":f"later:{row['id']}"}
    ]] + response_keyboard(row)


def send_candidate(con, row, mark_shown=True):
    send(render_candidate(con, row), candidate_keyboard(row))
    if mark_shown:
        con.execute("UPDATE candidates SET shown_at=COALESCE(shown_at,?) WHERE id=?", (iso(), row["id"]))
        con.commit()

def _short(text, limit=250):
    clean = " ".join((text or "").split())
    return clean if len(clean) <= limit else clean[:limit-1] + "…"

def _reply_flags(row):
    text = " ".join((row["text"] or "").lower().replace("ё","е").split())
    rental_friction = any(x in text for x in (
        "без подтверждения доход", "иностранный доход", "неофициальный доход",
        "recibo de sueldo", "sin recibo", "seguro de cauc", "без гарант", "garantia", "garantía"
    ))
    direct_only = any(x in text for x in (
        "без агент", "без риелтор", "без риэлтор", "без посредник",
        "напрямую от хозя", "напрямую от собственника", "dueño directo", "dueno directo", "sin inmobiliaria"
    ))
    research = any(x in text for x in (
        "закон", "юрист", "адвокат", "escritura", "escribano", "налог", "impuesto",
        "ипотек", "hipoteca", "оккуп", "ocupa", "миграц", "residencia", "гражданств",
        "ciudadania", "ciudadanía", "внж", "днж", "bienes personales", "arca", "afip"
    ))
    return text, rental_friction, direct_only, research

def catalog_public_template():
    return (
        f"Если запрос ещё актуален, вот каталог Le Bleu с текущими объектами: {LEBLEU_CATALOG_URL}\n\n"
        f"Если там ничего подходящего нет, напишите мне в личку {FIODOR_TELEGRAM} и коротко опишите, "
        "что ищете. Посмотрю ваш запрос отдельно."
    )

def catalog_dm_template():
    return (
        f"Привет! Увидел ваш запрос. Вот каталог Le Bleu с текущими объектами: {LEBLEU_CATALOG_URL}\n\n"
        "Если там ничего подходящего нет, напишите, что ищете: аренда или покупка, район, бюджет и основные пожелания. "
        "Посмотрю ваш запрос отдельно."
    )

def send_catalog_reply_kit(row=None):
    if row is not None and outreach_read_only(row):
        send((outreach_read_only_note(row) or "⚠️ Для этого чата отключён коммерческий outreach.") +
             "\n\nКаталог-шаблон для исходной группы здесь не предлагаю. Сначала нужно согласовать рекламу/экспертное размещение с администраторами чата.")
        return
    public = catalog_public_template()
    dm = catalog_dm_template()
    buttons = []
    if row is not None:
        buttons.append([{"text":"💬 Черновик в группе","callback_data":f"catalogdraft:{row['id']}"}])
    buttons.append([{"text":"📋 Скопировать для группы","copy_text":{"text":_short(public,256)}}])
    if row is not None and row["sender_username"]:
        link = dm_link(row["sender_username"], dm)
        if link:
            buttons.append([{"text":"✉️ Открыть личку с текстом","url":link}])
    buttons.append([{"text":"📋 Скопировать для лички","copy_text":{"text":_short(dm,256)}}])
    buttons.append([{"text":"📚 Открыть каталог Le Bleu","url":LEBLEU_CATALOG_URL}])
    if row is not None and row["link"]:
        buttons.append([{"text":"↩️ Открыть исходное сообщение","url":row["link"]}])
    send("📚 Шаблон каталога. Ничего не отправляется автоматически.\n\nВ группу:\n" + public + "\n\nВ личку:\n" + dm, buttons)

def generic_dm(row):
    _text, rental_friction, direct_only, _research = _reply_flags(row)
    if row["category"] == "RENTER" and rental_friction:
        return ("Привет! Увидел ваш вопрос по аренде без стандартного подтверждения дохода. "
                "У меня есть контакт PAS, который рассматривает в том числе нестандартный/иностранный доход, "
                "но заранее обещать одобрение нельзя. Если актуально, напишите ваш тип дохода, какие документы есть и бюджет — я быстро уточню, реалистичен ли вариант через seguro de caución.")
    if row["category"] == "RENTER" and direct_only:
        return ("Привет! Увидел ваш запрос. Понял, что вам принципиально напрямую от собственника, поэтому агентские варианты навязывать не буду. "
                "Если найдёте конкретный объект и захотите быстро проверить условия/договор перед оплатой, можете написать.")
    if row["category"] == "RENTER":
        return "Привет! Увидел ваш запрос по аренде в Буэнос-Айресе. Я Фёдор, занимаюсь недвижимостью здесь. Если запрос ещё актуален, могу быстро посмотреть подходящие варианты и условия."
    if row["category"] in ("PROPERTY_BUYER", "INVESTOR", "PRE_INTENT"):
        return "Привет! Увидел ваш вопрос по недвижимости в Буэнос-Айресе. Я Фёдор, занимаюсь подбором и сопровождением сделок здесь. Если ещё актуально, напишите — постараюсь быстро подсказать по делу."
    return "Привет! Увидел ваш вопрос. Я Фёдор, работаю с недвижимостью в Буэнос-Айресе. Если ещё актуально, напишите — постараюсь быстро сориентировать."

def generic_public(row):
    # Public-group replies are answer-first by default. No self-promotion, links or
    # "write me in DM" CTA: those patterns are frequently treated as advertising.
    _text, rental_friction, direct_only, _research = _reply_flags(row)
    if row["category"] == "RENTER" and rental_friction:
        return ("Если проблема именно в подтверждении дохода/garantía, иногда используют seguro de caución, "
                "но требования зависят от компании, собственника и документов. Лучше заранее уточнить, какие подтверждения дохода принимают именно в вашем случае.")
    if row["category"] == "RENTER" and direct_only:
        return ("Если принципиально нужен dueño directo, это лучше сразу указывать в запросе и отдельно уточнять, "
                "кто подписывает договор и какие комиссии/гарантии действительно обязательны по конкретному объекту.")
    if row["category"] == "RENTER":
        return ("По аренде цена и условия сильно зависят от района, срока, меблировки и требований по garantía/ingresos. "
                "Если напишете эти параметры, участникам будет проще дать релевантный ориентир.")
    if row["category"] in ("PROPERTY_BUYER", "INVESTOR", "PRE_INTENT"):
        return ("По покупке лучше сначала зафиксировать район, бюджет, формат объекта и цель покупки. "
                "Тогда можно сравнивать не только цену объявления, но и expensas, состояние, документы и реальные расходы сделки.")
    return "Чтобы ответить по делу, лучше уточнить район, бюджет и ключевые ограничения запроса."

def research_prompt(row):
    return ("Проверь на текущую дату по официальным и надёжным источникам этот вопрос из Telegram. "
            "Дай короткий фактический ответ человеку, отдельно укажи, что точно известно, где есть неопределённость, и источники. "
            "Не продавай услугу в лоб. Вопрос: " + _short(row["text"], 500))

def queue_reply_draft(row, text):
    con = connect()
    con.execute("""CREATE TABLE IF NOT EXISTS draft_jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
      text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
      error TEXT, created_at TEXT NOT NULL, processed_at TEXT
    )""")
    cur = con.execute(
        "INSERT INTO draft_jobs(candidate_id,chat_id,message_id,text,status,created_at) VALUES(?,?,?,?, 'PENDING', ?)",
        (row["id"], row["chat_id"], row["message_id"], text, iso())
    )
    con.commit()
    return cur.lastrowid

def wait_reply_draft(job_id, seconds=5):
    con = connect()
    deadline = time.time() + seconds
    while time.time() < deadline:
        row = con.execute("SELECT * FROM draft_jobs WHERE id=?", (job_id,)).fetchone()
        if row and row["status"] in ("DONE", "ERROR"):
            return row
        time.sleep(0.35)
    return con.execute("SELECT * FROM draft_jobs WHERE id=?", (job_id,)).fetchone()

def ensure_public_card(code):
    item = get_by_code(code)
    if not item:
        return None, "Объект уже не найден в текущем каталоге Le Bleu."
    existing = public_post_url(item)
    if existing:
        return existing, None
    try:
        proc = subprocess.run(
            ["npx", "tsx", "scripts/telegram-publisher.ts", "--apply", "--only-codes", code, "--limit-new", "1"],
            cwd="/opt/lebleu-listing-bridge", capture_output=True, text=True, timeout=90
        )
    except Exception as exc:
        return None, f"Не удалось создать карточку: {type(exc).__name__}"
    url = public_post_url(item)
    if url:
        return url, None
    detail = _short((proc.stderr or proc.stdout or "неизвестная ошибка"), 300)
    return None, "Карточка не опубликована. Возможно, объект не прошёл quality gate: " + detail

def send_reply_kit(row, result=None, post_url=None):
    _text, _friction, _direct, needs_research = _reply_flags(row)
    if result is None and needs_research:
        prompt = research_prompt(row)
        buttons = [[{"text":"📋 Скопировать research prompt","copy_text":{"text":_short(prompt,256)}}]]
        if row["link"]:
            buttons.append([{"text":"↩️ Открыть исходное сообщение","url":row["link"]}])
        send("🔎 Здесь не стоит отвечать шаблоном: тема требует проверки актуальных фактов.\n\n" + prompt, buttons)
        return
    public = draft_public(dict(row), result) if result else generic_public(row)
    dm = draft_dm(dict(row), result, post_url) if result else generic_dm(row)
    if outreach_read_only(row):
        # Do not help bypass a community restriction by switching to unsolicited DM.
        # Keep only a neutral, non-commercial public answer for manual review.
        safe_public = generic_public(row)
        buttons = [[{"text":"📋 Скопировать нейтральный ответ","copy_text":{"text":_short(safe_public, 256)}}]]
        if row["link"]:
            buttons.append([{"text":"↩️ Открыть исходное сообщение","url":row["link"]}])
        send((outreach_read_only_note(row) or "⚠️ Для этого чата отключён коммерческий outreach.") +
             "\n\nНейтральный вариант без рекламы:\n" + safe_public, buttons)
        return
    code = str(result["item"].get("code") or "").strip() if result else ""
    draft_cb = f"savedraftmatch:{row['id']}:{code}" if code else f"savedraft:{row['id']}"
    buttons = [[{"text":"💬 Черновик в группе","callback_data":draft_cb}],
               [{"text":"📋 Скопировать ответ в группу","copy_text":{"text":_short(public, 256)}}],
               [{"text":"📋 Скопировать для лички","copy_text":{"text":_short(dm, 256)}}]]
    if row["sender_username"]:
        link = dm_link(row["sender_username"], dm)
        if link:
            buttons.append([{"text":"✉️ Открыть личку с текстом","url":link}])
    if row["link"]:
        buttons.append([{"text":"↩️ Открыть исходное сообщение","url":row["link"]}])
    send("✍️ Черновик, ничего не отправлено автоматически:\n\n" + public + ("\n\nЛичное:\n" + dm if row["sender_username"] else ""), buttons)

def send_match_result(candidate, result):
    item = result["item"]
    code = str(item.get("code") or "").strip()
    if not code:
        return
    buttons = [[
        {"text":"📣 Карточка + DM","callback_data":f"carddm:{candidate['id']}:{code}"},
        {"text":"💬 Ответ без карточки","callback_data":f"replymatch:{candidate['id']}:{code}"}
    ]]
    if item.get("sourceUrl"):
        buttons.append([{"text":"🌐 Оригинал Le Bleu","url":item["sourceUrl"]}])
    send("🏠 Возможный match Le Bleu\n\n" + lebleu_brief(result), buttons)

def show_candidate_matches(con, row):
    q = parse_query(row["text"], "Alquiler" if row["category"] == "RENTER" else "Venta" if row["category"] in ("PROPERTY_BUYER","INVESTOR") else None)
    if q.get("direct_owner_only"):
        send("🚫 Le Bleu не предлагаю: в запросе явно указано только напрямую от собственника / без посредников. Сигнал сохранён, но агентский inventory здесь будет плохим контактом.")
        return
    matches = match_signal(row["text"], row["category"], 3)
    if not matches:
        send("Le Bleu: надёжного совпадения по текущему каталогу не нашёл. Лучше не отправлять человеку случайный объект.")
        return
    send(f"Нашёл {len(matches)} совпадени{'е' if len(matches)==1 else 'я'} в текущем каталоге Le Bleu. Это shortlist, не обещание fit:")
    for result in matches:
        time.sleep(1.05)
        send_match_result(row, result)

def handle_property_search(text):
    results = lebleu_search(text, limit=5)
    if not results:
        send("В текущем каталоге Le Bleu подходящего варианта не нашёл. Можно писать свободно, например: «аренда 2 ambientes Palermo до 900 USD с балконом» или «купить 2 ambientes Núñez до 120000 USD». ")
        return
    send(f"🏠 Le Bleu: нашёл {len(results)} вариантов по запросу «{_short(text,120)}». Показываю только текущий каталог:")
    for result in results:
        item = result["item"]
        code = str(item.get("code") or "").strip()
        buttons = [[{"text":"📣 Опубликовать русскую карточку","callback_data":f"card:{code}"}]]
        if item.get("sourceUrl"):
            buttons.append([{"text":"🌐 Оригинал Le Bleu","url":item["sourceUrl"]}])
        time.sleep(1.05)
        send(lebleu_brief(result), buttons)

def search_signal_rows(con, query, limit=10):
    stop = {"ищу","ищем","квартиру","квартира","квартиры","нужно","нужна","хочу","аренда","купить","продажа","в","на","и","до","для","the","and"}
    tokens = []
    for t in re.findall(r"[A-Za-zА-Яа-яЁёÁÉÍÓÚáéíóúÑñ0-9_]+", (query or "").lower().replace("ё","е")):
        if len(t) >= 3 and t not in stop and t not in tokens:
            tokens.append(t)
    if not tokens:
        return []
    rows = con.execute("SELECT * FROM candidates WHERE region='argentina' ORDER BY occurred_at DESC,id DESC LIMIT 5000").fetchall()
    ranked = []
    for row in rows:
        blob = " ".join([row["text"] or "", row["sender_username"] or "", row["sender_name"] or "", row["chat_title"] or ""]).lower().replace("ё","е")
        hits = 0
        for t in tokens:
            stem = t[:5] if len(t) >= 6 else t
            if t in blob or stem in blob:
                hits += 1
        if hits:
            ranked.append((hits, int(row["score"] or 0), row["occurred_at"] or "", row))
    ranked.sort(key=lambda x:(x[0],x[1],x[2]), reverse=True)
    return [x[3] for x in ranked[:limit]]

def queue_rows(con, where="state='NEW'", params=(), limit=8):
    return con.execute(
        f"""SELECT * FROM candidates WHERE {where}
            ORDER BY score DESC, occurred_at DESC, id DESC LIMIT ?""",
        (*params, limit)
    ).fetchall()


def queue_people(con, where="state='NEW'", params=(), limit=8, scan_limit=500):
    # One person, one card. Prefer the latest signal from that person, then rank
    # people by the strength of that latest signal. This avoids a Felix-style
    # history flooding the operator with several messages from one buyer.
    rows = con.execute(
        f"""SELECT * FROM candidates WHERE {where}
            ORDER BY occurred_at DESC, score DESC, id DESC LIMIT ?""",
        (*params, scan_limit)
    ).fetchall()
    latest, seen = [], set()
    for row in rows:
        key = row["person_key"] or f"row:{row['id']}"
        if key in seen:
            continue
        seen.add(key); latest.append(row)
    latest.sort(key=lambda r:(int(r["score"] or 0), r["occurred_at"] or "", int(r["id"])), reverse=True)
    return latest[:limit]

def send_rows(con, rows, empty_text="Новых непросмотренных сигналов нет."):
    if not rows:
        send(empty_text)
        return
    for i, row in enumerate(rows):
        if i:
            time.sleep(1.05)
        send_candidate(con, row)

def question_research_prompt(row):
    return ("Проверь на текущую дату по официальным и надёжным источникам вопрос из Telegram по недвижимости в Аргентине. "
            "Дай короткий человеческий ответ для публичного чата, без продажи в лоб. Отдели подтверждённые факты от неопределённости. "
            "Вопрос: " + _short(row.get("text"), 500))

def send_questions(limit=8):
    rows = list_questions(limit=limit, days=7)
    if not rows:
        send("💬 За последние 7 дней хороших свежих вопросов по недвижимости не нашёл. Лучше ноль, чем шум.")
        return
    send(f"💬 Вопросы · {len(rows)} лучших свежих\nОтдельная очередь для полезных публичных ответов. Это не список лидов.")
    for i, row in enumerate(rows):
        if i:
            time.sleep(1.05)
        who = ("@" + row["sender_username"]) if row.get("sender_username") else (row.get("sender_name") or "без имени")
        research = "Да — сначала проверить актуальные факты." if row.get("needs_research") else "Нет — можно отвечать из устойчивой практики."
        text = (
            f"💬 {row['score']}/100 · {row['why']}\n"
            f"{who} · {row.get('chat_title') or 'Telegram'}\n\n"
            f"{_short(row.get('text'), 900)}\n\n"
            f"Почему стоит ответить: свежий публичный вопрос по теме «{row['why']}».\n"
            f"Research: {research}\n\n"
            f"Черновик:\n{row.get('draft') or '—'}"
        )
        buttons = [[
            {"text":"✅ Ответил","callback_data":f"qdone:{row['raw_message_id']}"},
            {"text":"🗑 Неинтересно","callback_data":f"qskip:{row['raw_message_id']}"},
            {"text":"⏰ Потом","callback_data":f"qlater:{row['raw_message_id']}"}
        ]]
        if row.get("draft"):
            buttons.append([{"text":"📋 Скопировать черновик","copy_text":{"text":_short(row["draft"],256)}}])
        if row.get("needs_research"):
            prompt = question_research_prompt(row)
            buttons.append([{"text":"🔎 Скопировать research prompt","copy_text":{"text":_short(prompt,256)}}])
        if row.get("link"):
            buttons.append([{"text":"↩️ Открыть вопрос","url":row["link"]}])
        send(text, buttons)

def growth_text(days=30):
    try:
        days = max(1, min(365, int(days)))
    except Exception:
        days = 30
    try:
        proc = subprocess.run(
            ["/usr/local/bin/growthctl", "report", "--days", str(days)],
            capture_output=True,
            text=True,
            timeout=12,
            check=False,
        )
        body = (proc.stdout or proc.stderr or "").strip()
        if proc.returncode != 0:
            return "📈 Le Bleu Growth\n\nНе удалось получить отчёт: " + _short(body, 800)
        return f"📈 Le Bleu Growth · {days} дн.\n\n" + (body or "Нет данных.")
    except Exception as exc:
        return f"📈 Le Bleu Growth\n\nОшибка отчёта: {type(exc).__name__}"


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
/buyers — только подтверждённые buyer-сигналы покупки недвижимости
/preintent — косвенные сигналы перед покупкой
/renters — арендаторы и rental friction
/owners — прямые владельцы
/investors — инвесторы
/questions — свежие вопросы по недвижимости для полезных публичных ответов
/potential — слабые/косвенные сигналы для ручной проверки
/search текст — поиск среди сигналов Radar
/find запрос — поиск объектов Le Bleu; можно просто написать запрос обычным текстом
/catalog — готовый шаблон с каталогом Le Bleu для группы и лички
/stats — состояние радара
/growth [дни] — измеримая воронка Le Bleu по источникам

Кнопки под сигналом фиксируют решение. Просмотренные и шум больше не возвращаются в /new."""

def handle_command(con, text):
    parts = (text or "").strip().split(maxsplit=1)
    cmd = parts[0].split("@")[0].lower() if parts else ""
    arg = parts[1].strip() if len(parts) > 1 else ""
    if cmd in ("/start", "/help"):
        send(HELP)
    elif cmd == "/stats":
        send(stats_text(con))
    elif cmd == "/growth":
        days = arg if arg.isdigit() else 30
        send(growth_text(days))
    elif cmd == "/new":
        since = (datetime.now(timezone.utc)-timedelta(days=14)).isoformat()
        rows = queue_rows(con, "state='NEW' AND shown_at IS NULL AND region='argentina' AND category IN ('PROPERTY_BUYER','INVESTOR','RENTER','PRE_INTENT','OWNER_DIRECT','OWNER_RENTAL','PARTNER') AND score>=55 AND occurred_at>=?", (since,))
        send_rows(con, rows)
    elif cmd == "/unreviewed":
        since = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND category IN ('PROPERTY_BUYER','INVESTOR','RENTER','PRE_INTENT','OWNER_DIRECT','OWNER_RENTAL','PARTNER') AND score>=55 AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Неразобранных сигналов нет.")
    elif cmd == "/today":
        since = (datetime.now(timezone.utc)-timedelta(hours=24)).isoformat()
        rows = queue_rows(con, "state='NEW' AND region='argentina' AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "За последние 24 часа новых неразобранных сигналов нет.")
    elif cmd == "/buyers":
        since = (datetime.now(timezone.utc)-timedelta(days=90)).isoformat()
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category='PROPERTY_BUYER' AND score>=55 AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Новых подтверждённых buyer-сигналов покупки недвижимости нет.")
    elif cmd == "/preintent":
        since = (datetime.now(timezone.utc)-timedelta(days=90)).isoformat()
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category='PRE_INTENT' AND score>=45 AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Новых property pre-intent сигналов нет.")
    elif cmd == "/renters":
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category='RENTER'", limit=10)
        send_rows(con, rows, "Новых renter-сигналов нет.")
    elif cmd == "/owners":
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category IN ('OWNER_DIRECT','OWNER_RENTAL')", limit=10)
        send_rows(con, rows, "Новых прямых владельцев нет.")
    elif cmd == "/investors":
        since = (datetime.now(timezone.utc)-timedelta(days=90)).isoformat()
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category='INVESTOR' AND score>=45 AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Новых подтверждённых investor-сигналов нет.")
    elif cmd == "/questions":
        send_questions(8)
    elif cmd == "/catalog":
        send_catalog_reply_kit()
    elif cmd == "/potential":
        since = (datetime.now(timezone.utc)-timedelta(days=30)).isoformat()
        rows = queue_people(con, "state='NEW' AND region='argentina' AND category='POTENTIAL' AND score BETWEEN 40 AND 57 AND occurred_at>=?", (since,), 10)
        send_rows(con, rows, "Новых коммерчески осмысленных косвенных сигналов нет.")
    elif cmd == "/find":
        if not arg:
            send("Напиши после /find обычный запрос, например: /find аренда 2 ambientes Palermo до 900 USD")
            return
        handle_property_search(arg)
    elif cmd == "/search":
        if not arg:
            send("Использование: /search текст из сигнала")
            return
        rows = search_signal_rows(con, arg, 10)
        send_rows(con, rows, "Совпадений среди сигналов нет. Поиск понимает набор параметров, а не только точную фразу.")
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

def handle_callback(con, cq, acknowledged=False):
    data = cq.get("data", "")
    cqid = cq.get("id")
    def ack(text):
        if not acknowledged:
            safe_answer_callback(cqid, text)

    # Question-lane actions are intentionally separate from commercial lead state.
    if data.startswith(("qdone:", "qskip:", "qlater:")):
        try:
            action, raw_id_s = data.split(":", 1)
            raw_id = int(raw_id_s)
        except Exception:
            ack("Некорректная команда")
            return
        status = {"qdone":"DONE", "qskip":"SKIP", "qlater":"LATER"}[action]
        mark_question(raw_id, status)
        row = get_question(raw_id)
        msg = cq.get("message") or {}
        keep = []
        if row and row.get("link"):
            keep = [[{"text":"↩️ Открыть вопрос","url":row["link"]}]]
        try:
            api("editMessageReplyMarkup", {
                "chat_id": msg.get("chat",{}).get("id"),
                "message_id": msg.get("message_id"),
                "reply_markup": {"inline_keyboard": keep}
            })
        except Exception:
            pass
        return

    # Non-destructive action helpers. They never contact a lead automatically.
    if data.startswith("matches:"):
        try: cid = int(data.split(":",1)[1])
        except Exception: cid = 0
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        ack("Ищу совпадения в Le Bleu…")
        if row: show_candidate_matches(con, row)
        else: send("Сигнал уже не найден.")
        return

    if data.startswith("reply:"):
        try: cid = int(data.split(":",1)[1])
        except Exception: cid = 0
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        ack("Готовлю черновик")
        if row: send_reply_kit(row)
        return

    if data.startswith("catalogreply:"):
        try: cid = int(data.split(":",1)[1])
        except Exception: cid = 0
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        ack("Готовлю шаблон каталога")
        if row: send_catalog_reply_kit(row)
        else: send("Сигнал уже не найден.")
        return

    if data.startswith("catalogdraft:"):
        try: cid = int(data.split(":",1)[1])
        except Exception: cid = 0
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        if not row:
            ack("Сигнал уже не найден")
            return
        if outreach_read_only(row):
            ack("Групповой outreach отключён")
            send(outreach_read_only_note(row) or "⚠️ Для этого чата групповой outreach отключён.")
            return
        job_id = queue_reply_draft(row, catalog_public_template())
        ack("Сохраняю черновик в исходном чате…")
        job = wait_reply_draft(job_id, 6)
        if job and job["status"] == "DONE":
            send("✅ Шаблон каталога сохранён черновиком-ответом в исходной группе. Ничего не отправлено.")
        elif job and job["status"] == "ERROR":
            send("⚠️ Не удалось сохранить черновик: " + _short(job["error"] or "неизвестная ошибка", 300))
        else:
            send("⏳ Черновик поставлен в очередь и будет сохранён watcher-ом при следующем цикле.")
        return

    if data.startswith("savedraftmatch:") or data.startswith("savedraft:"):
        try:
            parts = data.split(":")
            cid = int(parts[1])
            code = parts[2] if len(parts) > 2 else ""
        except Exception:
            ack("Некорректная команда")
            return
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        if not row:
            ack("Сигнал уже не найден")
            return
        if outreach_read_only(row):
            ack("Групповой outreach отключён")
            send(outreach_read_only_note(row) or "⚠️ Для этого чата групповой outreach отключён.")
            return
        result = None
        if code:
            item = get_by_code(code)
            if item:
                result = {"item":item, "score":0, "reasons":[]}
        draft = draft_public(dict(row), result)
        job_id = queue_reply_draft(row, draft)
        ack("Сохраняю reply-draft в Telegram…")
        job = wait_reply_draft(job_id, 6)
        if job and job["status"] == "DONE":
            send("✅ Черновик сохранён прямо в исходном Telegram-чате как reply. Ничего не отправлено. Открой сообщение, проверь текст и нажми Send сам.")
        elif job and job["status"] == "ERROR":
            send("⚠️ Не удалось сохранить Telegram draft: " + _short(job["error"] or "неизвестная ошибка", 300))
        else:
            send("⏳ Черновик поставлен в очередь. Если Telegram session занята, watcher сохранит его при следующем цикле.")
        return

    if data.startswith("replymatch:") or data.startswith("carddm:"):
        try:
            action, cid_s, code = data.split(":", 2)
            cid = int(cid_s)
        except Exception:
            ack("Некорректная команда")
            return
        row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
        item = get_by_code(code)
        if not row or not item:
            ack("Сигнал или объект уже неактуален")
            return
        result = {"item":item, "score":0, "reasons":[]}
        if action == "replymatch":
            ack("Черновик готов")
            send_reply_kit(row, result)
            return
        ack("Создаю русскую карточку…")
        url, error = ensure_public_card(code)
        if error:
            send("⚠️ " + error)
            return
        send("✅ Карточка готова: " + url, [[{"text":"Открыть карточку","url":url}]])
        send_reply_kit(row, result, url)
        return

    if data.startswith("card:"):
        code = data.split(":",1)[1]
        ack("Создаю русскую карточку…")
        url, error = ensure_public_card(code)
        if error:
            send("⚠️ " + error)
        else:
            send("✅ Карточка готова: " + url, [[{"text":"Открыть карточку","url":url}]])
        return

    try:
        action, sid = data.split(":", 1)
        cid = int(sid)
    except Exception:
        ack("Некорректная команда")
        return
    state = disposition_text(action)
    if not state:
        ack("Неизвестное действие")
        return
    row = con.execute("SELECT * FROM candidates WHERE id=?", (cid,)).fetchone()
    if not row:
        ack("Сигнал не найден")
        return
    con.execute(
        "UPDATE candidates SET state=?, reviewed_at=?, disposition=? WHERE id=?",
        (state, iso(), action, cid)
    )
    con.commit()
    opportunity_id = None
    crm_result = None
    if action == "lead":
        try:
            opportunity_id = promote_to_opportunity(row)
        except Exception as exc:
            print(f"Opportunity promotion failed: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
        try:
            crm_result = sync_candidate_to_crm(row)
        except Exception as exc:
            print(f"CRM promotion failed: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
    labels = {
        "lead":("Сохранено как лид" + (f" · Radar #{opportunity_id}" if opportunity_id else "") + (" · CRM ✓" if crm_result else " · CRM ⚠️")),
        "review":"Отмечено просмотренным",
        "noise":"Отмечено как шум",
        "later":"Отложено"
    }
    ack(labels[action])
    msg = cq.get("message") or {}
    try:
        api("editMessageReplyMarkup", {
            "chat_id": msg.get("chat",{}).get("id"),
            "message_id": msg.get("message_id"),
            "reply_markup": {"inline_keyboard": response_keyboard(row)}
        })
    except Exception:
        pass

def set_commands():
    commands = [
        {"command":"new","description":"Новые, ещё не показанные сигналы"},
        {"command":"unreviewed","description":"Все неразобранные"},
        {"command":"today","description":"Сигналы за 24 часа"},
        {"command":"buyers","description":"Покупатели недвижимости"},
        {"command":"preintent","description":"Косвенный pre-intent перед покупкой"},
        {"command":"renters","description":"Арендаторы и rental friction"},
        {"command":"owners","description":"Прямые владельцы"},
        {"command":"investors","description":"Инвесторы"},
        {"command":"questions","description":"Свежие вопросы по недвижимости"},
        {"command":"potential","description":"Косвенные сигналы"},
        {"command":"find","description":"Свободный поиск объектов Le Bleu"},
        {"command":"catalog","description":"Шаблон каталога для группы/лички"},
        {"command":"search","description":"Поиск среди сигналов"},
        {"command":"stats","description":"Статус радара"},
        {"command":"growth","description":"Воронка Le Bleu по источникам"},
        {"command":"help","description":"Команды"}
    ]
    try:
        api("setMyCommands", {"commands":commands})
    except Exception as exc:
        print("setMyCommands failed", type(exc).__name__, flush=True)

BOT_WORKERS = int(os.environ.get("RR_BOT_WORKERS", "4"))
EXECUTOR = ThreadPoolExecutor(max_workers=max(2, min(8, BOT_WORKERS)), thread_name_prefix="rrbot")

def _run_message_job(msg, update_id):
    started = time.monotonic()
    con = connect()
    try:
        text = (msg.get("text") or "").strip()
        if not text:
            return
        if text.startswith("/"):
            handle_command(con, text)
        else:
            handle_property_search(text)
        print(f"BOT_JOB message update={update_id} ok duration={time.monotonic()-started:.2f}s text={_short(text,80)!r}", flush=True)
    except Exception as exc:
        print(f"BOT_JOB message update={update_id} error={type(exc).__name__}: {str(exc)[:240]}", flush=True)
        try:
            send("⚠️ Не удалось выполнить эту команду. Ошибка записана; остальные команды продолжают работать.")
        except Exception:
            pass
    finally:
        try: con.close()
        except Exception: pass

def _run_callback_job(cq, update_id):
    started = time.monotonic()
    con = connect()
    data = cq.get("data", "")
    try:
        handle_callback(con, cq, acknowledged=True)
        print(f"BOT_JOB callback update={update_id} ok duration={time.monotonic()-started:.2f}s data={data!r}", flush=True)
    except Exception as exc:
        print(f"BOT_JOB callback update={update_id} error={type(exc).__name__}: {str(exc)[:240]} data={data!r}", flush=True)
        try:
            send("⚠️ Действие по кнопке не завершилось. Ошибка записана; бот продолжает работать.")
        except Exception:
            pass
    finally:
        try: con.close()
        except Exception: pass

def _store_offset(con, offset):
    con.execute(
        """INSERT INTO meta(key,value) VALUES('bot_update_offset',?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value""",
        (str(offset),)
    )
    con.commit()

def main():
    con = connect()
    set_commands()
    offset = int(
        (con.execute("SELECT value FROM meta WHERE key='bot_update_offset'").fetchone() or {"value":"0"})["value"]
    )
    print(f"Revenue Radar bot online · offset={offset} · workers={BOT_WORKERS}", flush=True)
    while True:
        try:
            result = api("getUpdates", {
                "offset": offset,
                "timeout": 25,
                "allowed_updates": ["message","callback_query"]
            }, timeout=35)
            for upd in result.get("result", []):
                update_id = int(upd["update_id"])
                next_offset = max(offset, update_id + 1)
                try:
                    if "message" in upd:
                        msg = upd["message"]
                        if str(msg.get("chat",{}).get("id")) == ALLOWED_CHAT_ID:
                            text = (msg.get("text") or "").strip()
                            if text:
                                sent_at = float(msg.get("date") or 0)
                                lag = max(0.0, time.time() - sent_at) if sent_at else 0.0
                                print(f"BOT_DISPATCH message update={update_id} lag={lag:.1f}s text={_short(text,80)!r}", flush=True)
                                EXECUTOR.submit(_run_message_job, msg, update_id)
                    elif "callback_query" in upd:
                        cq = upd["callback_query"]
                        if str((cq.get("message") or {}).get("chat",{}).get("id")) == ALLOWED_CHAT_ID:
                            data = cq.get("data", "")
                            # Acknowledge before any DB/search/publisher work. This removes the
                            # Telegram spinner immediately and prevents query-too-old failures.
                            safe_answer_callback(cq.get("id"), callback_ack_text(data))
                            print(f"BOT_DISPATCH callback update={update_id} data={data!r}", flush=True)
                            EXECUTOR.submit(_run_callback_job, cq, update_id)
                except Exception as exc:
                    # One malformed/failed update must not discard the rest of the Telegram batch.
                    print(f"BOT_DISPATCH update={update_id} error={type(exc).__name__}: {str(exc)[:220]}", flush=True)
                offset = next_offset
                _store_offset(con, offset)
        except (TimeoutError, OSError, urllib.error.URLError) as exc:
            # Telegram getUpdates is a long poll; transient transport churn is routine.
            print(f"Bot transport retry: {type(exc).__name__}: {str(exc)[:120]}", flush=True)
            time.sleep(0.5)
        except Exception as exc:
            print(f"Bot poll error: {type(exc).__name__}: {str(exc)[:220]}", flush=True)
            time.sleep(2)

if __name__ == "__main__":
    main()
