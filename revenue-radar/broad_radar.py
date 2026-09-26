#!/usr/bin/env python3
import json, os, re, sqlite3, time, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

RAW_DB = os.getenv("RR_INTELLIGENCE_DB", "/opt/intent-radar/data/intelligence.sqlite3")
DB_PATH = os.getenv("RR_BROAD_DB", "/opt/intent-radar/data/broad_radar.sqlite3")
BOT_TOKEN = os.getenv("RADAR_ALERT_BOT_TOKEN", "")
BOT_CHAT_ID = os.getenv("RADAR_ALERT_CHAT_ID", "")
POLL_SECONDS = int(os.getenv("RR_BROAD_POLL_SECONDS", "10"))
ALERT_MIN_SCORE = int(os.getenv("RR_BROAD_ALERT_MIN_SCORE", "58"))
ALERT_MAX_AGE_HOURS = int(os.getenv("RR_BROAD_ALERT_MAX_AGE_HOURS", "72"))

ARG_SOURCE = (
    "argentin", "аргент", "buenos", "буэнос", "ciudadania", "гражданств",
    "monotribut", "caba", "b-g", "travelask"
)
ARG_GEO = (
    "argentina", "аргентина", "buenos aires", "буэнос-айрес", "буэнос айрес", "caba",
    "palermo", "recoleta", "belgrano", "nuñez", "nunez", "colegiales", "saavedra",
    "caballito", "villa urquiza", "villa crespo", "almagro", "puerto madero", "san telmo"
)
PROPERTY = (
    "квартир", "жиль", "студи", "апартамент", "недвиж", "дом ", "дом,", "дом.",
    "departamento", "depto", "dpto", "propiedad", "inmueble", "monoambiente", "ambiente"
)
NEED = (
    "ищу", "ищем", "нужен", "нужна", "нужно", "хочу", "хотим", "планирую", "планируем",
    "собираюсь", "собираемся", "подскаж", "посовет", "кто знает", "как лучше",
    "busco", "necesito", "quiero", "queremos", "alguien sabe", "cómo", "como "
)
BUY = (
    "купить квартир", "купить недвиж", "купить дом", "покупка недвиж", "покупку недвиж",
    "покупать недвиж", "приобрести недвиж", "comprar departamento", "comprar propiedad",
    "comprar casa", "buy apartment", "buy property"
)
RENT = (
    "снять квартир", "снять жиль", "арендовать квартир", "арендовать жиль", "ищу квартир",
    "ищем квартир", "ищу жиль", "ищем жиль", "ищу студ", "ищем студ", "alquilar",
    "alquiler", "busco departamento", "busco depto", "rentar"
)
INVEST = (
    "инвестир", "куда влож", "во что влож", "капитал", "доходност", "рентабельност",
    "сохранить деньги", "сохранить капитал", "rentabilidad", "rendimiento", "invertir",
    "inversión", "inversion", "investment", "пассивный доход"
)
PREINTENT = (
    "escritura", "escribano", "boleto de compraventa", "происхождени средств",
    "происхождени денег", "source of funds", "origen de fondos", "swift", "ипотек",
    "hipoteca", "apto crédito", "apto credito", "комисси", "расходы при покуп",
    "налог при покуп", "налоги при покуп", "bienes personales", "expensas",
    "перевести деньги", "завести деньги", "перевод денег", "перевод средств",
    "деньги из россии", "деньги в аргентин", "usdt", "крипт", "crypto"
)
RENT_FRICTION = (
    "без подтверждения доход", "иностранный доход", "неофициальный доход", "garantía",
    "garantia", "seguro de caución", "seguro de caucion", "без гаранти", "гарантия для арен",
    "не могу снять", "не получается снять", "recibo de sueldo", "нет recibo de sueldo"
)
RELOCATION = (
    "переехать в аргент", "переезд в аргент", "релокац", "лечу в буэнос", "прилетаю в буэнос",
    "переезжаем", "переезжаю", "mudarme a argentina", "vivir en argentina"
)
OWNER_DIRECT = (
    "от собственника", "напрямую от хозя", "напрямую от собственника", "я собственник",
    "собственник напрямую", "dueño directo", "dueno directo", "soy dueño", "soy dueno",
    "soy propietario", "propietario directo"
)
SALE = ("продаю", "продается", "продаётся", "продам", "vendo", "se vende", "en venta")
RENT_SUPPLY = ("сдаю", "сдается", "сдаётся", "сдам", "se alquila", "alquilo")
PARTNER = (
    "риэлтор", "риелтор", "broker", "corredor", "inmobiliaria", "escribano", "abogado",
    "contador", "arquitect", "seguro de cauc", "gestor", "tasador", "administrador"
)
PROMO = (
    "наша компания", "предлагаем услуги", "оказываю услуги", "пишите в личку", "обращайтесь",
    "скидка", "акция", "в наличии", "#продажа", "#аренда", "подписывайтесь"
)

def norm(value):
    return " ".join((value or "").lower().replace("ё", "е").split())

def has_any(text, cues):
    return any(x in text for x in cues)

def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH, timeout=30)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA journal_mode=WAL")
    init_db(con)
    return con

def init_db(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS meta(
      key TEXT PRIMARY KEY, value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS candidates(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      raw_message_id INTEGER NOT NULL UNIQUE,
      chat_id INTEGER, message_id INTEGER, person_key TEXT NOT NULL,
      occurred_at TEXT, chat_title TEXT, sender_id INTEGER,
      sender_name TEXT, sender_username TEXT,
      category TEXT NOT NULL, score INTEGER NOT NULL, region TEXT NOT NULL DEFAULT 'other',
      tags_json TEXT NOT NULL, reasons_json TEXT NOT NULL,
      text TEXT NOT NULL, link TEXT, fingerprint TEXT,
      state TEXT NOT NULL DEFAULT 'NEW',
      alerted_at TEXT, shown_at TEXT, reviewed_at TEXT,
      disposition TEXT, created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_candidates_queue
      ON candidates(state, alerted_at, score DESC, occurred_at DESC);
    CREATE INDEX IF NOT EXISTS idx_candidates_person
      ON candidates(person_key, occurred_at DESC);
    CREATE TABLE IF NOT EXISTS source_cursors(
      source_key TEXT PRIMARY KEY, last_message_id INTEGER NOT NULL DEFAULT 0,
      updated_at TEXT NOT NULL
    );
    """)
    cols = {r[1] for r in con.execute("PRAGMA table_info(candidates)")}
    if "region" not in cols:
        con.execute("ALTER TABLE candidates ADD COLUMN region TEXT NOT NULL DEFAULT 'other'")
        con.execute("UPDATE candidates SET region='argentina' WHERE reasons_json LIKE '%Argentina context%'")
    con.commit()

def utcnow():
    return datetime.now(timezone.utc)

def iso(dt=None):
    return (dt or utcnow()).isoformat(timespec="seconds")

def get_meta(con, key, default="0"):
    row = con.execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default

def set_meta(con, key, value):
    con.execute("INSERT INTO meta(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                (key, str(value)))
    con.commit()

def person_key(row):
    if row["sender_id"]:
        return f"telegram:id:{row['sender_id']}"
    if row["sender_username"]:
        return "telegram:user:" + row["sender_username"].lower()
    return f"telegram:anon:{row['chat_id']}:{row['message_id']}"

def classify(row):
    text = norm(row["text"])
    source = norm(row["chat_title"])
    arg_context = has_any(source, ARG_SOURCE) or has_any(text, ARG_GEO)
    prop = has_any(text, PROPERTY)
    need = has_any(text, NEED) or "?" in text
    buy = has_any(text, BUY)
    rent = has_any(text, RENT)
    self_signal = bool(re.search(r"(?:^|\s)(?:я|мы)(?:\s|$)|у меня|у нас|мне |нам |мой |моя |наши |продал|продала|продаем|перевожу|переводим|получил|получила|собираюсь|планирую", text))
    invest_raw = has_any(text, INVEST)
    pre_raw = has_any(text, PREINTENT)
    friction = has_any(text, RENT_FRICTION) and (need or "?" in text)
    relocation = has_any(text, RELOCATION)
    owner = has_any(text, OWNER_DIRECT)
    sale = has_any(text, SALE) and prop
    rent_supply = (has_any(text, RENT_SUPPLY) and prop) or (owner and prop and not sale and not buy and has_any(text, ("в месяц", "месяц аренды", "аренда", "депозит")))
    invest = invest_raw and (need or self_signal)
    pre = pre_raw and (need or self_signal) and not (sale or rent_supply)
    partner = has_any(text, PARTNER)
    promo = has_any(text, PROMO)

    tags, reasons, score = [], [], 0
    if arg_context:
        score += 15; reasons.append("Argentina context")
    if prop:
        score += 12; tags.append("property")
    if need:
        score += 12; reasons.append("personal need/question")
    if buy:
        score += 28; tags.append("buyer"); reasons.append("purchase intent")
    if rent and (need or not rent_supply):
        score += 25; tags.append("rental_demand"); reasons.append("rental demand")
    if invest:
        score += 24; tags.append("investor"); reasons.append("capital/investment intent")
    if pre:
        score += 18; tags.append("pre_intent"); reasons.append("transaction-readiness topic")
    if friction:
        score += 20; tags.append("rental_friction"); reasons.append("rental eligibility/friction")
    if relocation:
        score += 14; tags.append("relocation"); reasons.append("relocation intent")
    if owner and sale:
        score += 35; tags.append("owner_sale"); reasons.append("direct owner sale")
    elif sale:
        score += 14; tags.append("seller_supply"); reasons.append("sale supply")
    if owner and rent_supply:
        score += 30; tags.append("owner_rental"); reasons.append("direct owner rental")
    elif rent_supply:
        score += 10; tags.append("rental_supply")
    if partner and (need or owner or "рекоменд" in text or "контакт" in text):
        score += 12; tags.append("partner"); reasons.append("transaction partner signal")

    if promo and not owner:
        score -= 18
    if not arg_context and not (buy or invest or pre):
        score -= 20
    if not (prop or invest or pre or friction or relocation or owner):
        return None
    if not tags:
        tags.append("potential")

    if "owner_sale" in tags:
        category = "OWNER_DIRECT"
    elif "buyer" in tags:
        category = "PROPERTY_BUYER"
    elif "investor" in tags:
        category = "INVESTOR"
    elif "rental_demand" in tags or "rental_friction" in tags:
        category = "RENTER"
    elif "owner_rental" in tags:
        category = "OWNER_RENTAL"
    elif "pre_intent" in tags:
        category = "PRE_INTENT"
    elif "seller_supply" in tags or "rental_supply" in tags:
        category = "SUPPLY"
    elif "partner" in tags:
        category = "PARTNER"
    else:
        category = "POTENTIAL"

    score = max(0, min(100, score))
    if score < 24:
        return None
    return category, score, sorted(set(tags)), reasons

def fingerprint(text):
    low = re.sub(r"https?://\S+|@[A-Za-z0-9_]{4,32}", " ", norm(text))
    low = re.sub(r"\d+", "#", low)
    return " ".join(re.findall(r"[a-záéíóúñüа-я0-9#]{2,}", low, re.I))[:500]

def insert_candidate(con, row, result):
    category, score, tags, reasons = result
    pk = person_key(row)
    prior = con.execute(
        "SELECT COUNT(*) c FROM candidates WHERE person_key=? AND occurred_at>=?",
        (pk, (utcnow()-timedelta(days=30)).isoformat())
    ).fetchone()["c"]
    if prior and ("personal need/question" in reasons or category in {"OWNER_DIRECT","OWNER_RENTAL"}):
        bonus = min(12, prior * 4)
        score = min(100, score + bonus)
        reasons = reasons + [f"repeat person signal +{bonus}"]
    cur = con.execute("""
      INSERT OR IGNORE INTO candidates(
        raw_message_id,chat_id,message_id,person_key,occurred_at,chat_title,
        sender_id,sender_name,sender_username,category,score,region,tags_json,reasons_json,
        text,link,fingerprint,created_at
      ) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        row["id"], row["chat_id"], row["message_id"], pk, row["created_at"], row["chat_title"],
        row["sender_id"], row["sender_name"], row["sender_username"], category, score,
        ("argentina" if "Argentina context" in reasons else "other"), json.dumps(tags, ensure_ascii=False), json.dumps(reasons, ensure_ascii=False),
        row["text"], row["link"], fingerprint(row["text"]), iso()
    ))
    con.commit()
    if cur.rowcount != 1:
        return None
    return con.execute("SELECT * FROM candidates WHERE raw_message_id=?", (row["id"],)).fetchone()

def bot_send(text, keyboard=None):
    if not BOT_TOKEN or not BOT_CHAT_ID:
        return False
    payload = {"chat_id": BOT_CHAT_ID, "text": text, "disable_web_page_preview": True}
    if keyboard:
        payload["reply_markup"] = {"inline_keyboard": keyboard}
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"}
    )
    with urllib.request.urlopen(req, timeout=12) as resp:
        return bool(json.load(resp).get("ok"))

def render_candidate(con, row):
    who = ("@" + row["sender_username"]) if row["sender_username"] else (row["sender_name"] or row["person_key"])
    tags = ", ".join(json.loads(row["tags_json"]))
    reasons = " · ".join(json.loads(row["reasons_json"])[:5])
    text = " ".join((row["text"] or "").split())
    if len(text) > 700:
        text = text[:700] + "…"
    history = con.execute(
        "SELECT COUNT(*) c FROM candidates WHERE person_key=? AND id<>?",
        (row["person_key"], row["id"])
    ).fetchone()["c"]
    return (
        f"📡 {row['category']} · {row['score']}/100\n"
        f"{who} · {row['chat_title']}\n"
        f"Повторных сигналов автора: {history}\n\n{text}\n\n"
        f"Tags: {tags}\nWhy: {reasons}"
    )

def alert_candidate(con, row):
    try:
        occurred = datetime.fromisoformat((row["occurred_at"] or "").replace("Z","+00:00"))
        if occurred.tzinfo is None:
            occurred = occurred.replace(tzinfo=timezone.utc)
    except Exception:
        occurred = utcnow()
    age = utcnow() - occurred
    if row["score"] < ALERT_MIN_SCORE or age > timedelta(hours=ALERT_MAX_AGE_HOURS):
        return
    keyboard = [[
        {"text":"✅ Лид","callback_data":f"lead:{row['id']}"},
        {"text":"👀 Просмотрено","callback_data":f"review:{row['id']}"},
        {"text":"🗑 Шум","callback_data":f"noise:{row['id']}"},
        {"text":"⏰ Потом","callback_data":f"later:{row['id']}"}
    ]]
    if row["link"]:
        keyboard.append([{"text":"Открыть оригинал","url":row["link"]}])
    if bot_send(render_candidate(con, row), keyboard):
        con.execute("UPDATE candidates SET alerted_at=? WHERE id=?", (iso(), row["id"]))
        con.commit()

def process_batch(con, raw, after_id, limit=1000):
    rows = raw.execute(
        "SELECT * FROM raw_messages WHERE id>? ORDER BY id LIMIT ?", (after_id, limit)
    ).fetchall()
    last = after_id
    for row in rows:
        last = row["id"]
        result = classify(row)
        if not result:
            continue
        cand = insert_candidate(con, row, result)
        if cand is not None:
            alert_candidate(con, cand)
    return last, len(rows)

def main():
    con = connect()
    raw = sqlite3.connect(RAW_DB, timeout=30)
    raw.row_factory = sqlite3.Row
    cursor = int(get_meta(con, "raw_cursor", "0"))
    print(f"Broad Radar online · cursor={cursor} · raw={RAW_DB}", flush=True)
    while True:
        try:
            last, count = process_batch(con, raw, cursor)
            if last != cursor:
                cursor = last
                set_meta(con, "raw_cursor", cursor)
            if count == 0:
                time.sleep(POLL_SECONDS)
        except KeyboardInterrupt:
            break
        except Exception as exc:
            print(f"Broad Radar error: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
            time.sleep(5)

if __name__ == "__main__":
    main()
