#!/usr/bin/env python3
import os, re, sqlite3
from datetime import datetime, timezone, timedelta
from pathlib import Path

INTELLIGENCE_DB = os.getenv("RR_INTELLIGENCE_DB", "/opt/intent-radar/data/intelligence.sqlite3")
STATE_DB = os.getenv("RR_BROAD_DB", "/opt/intent-radar/data/broad_radar.sqlite3")

RELEVANT_TOPICS = {
    "real_estate_purchase", "rental", "property_legal_process", "property_management",
    "valuation", "mortgage", "cross_border_funds", "investment_capital",
    "renovation_redevelopment", "permits", "taxes"
}
RESEARCH_TOPICS = {"property_legal_process", "mortgage", "cross_border_funds", "permits", "taxes"}
QUESTION_CUES = (
    "?", "как ", "где ", "кто ", "сколько", "можно ли", "подскаж", "посовет",
    "какие ", "какой ", "какая ", "что делать", "нужен ли", "нужна ли", "кто-нибудь"
)
PROPERTY_CUES = (
    "квартир", "недвиж", "жиль", "комнат", "студи", "апартамент", "departamento", "vivienda",
    "expensas", "consorcio", "escrit", "reserva", "ипотек", "hipoteca", "dueño", "dueno",
    "собственник", "риелтор", "риэлтор", "inmobiliaria", "alquiler temporario",
    "rentabilidad", "доходност", "ликвидност", "seguro de cauc", "garantía", "garantia"
)

def _norm(text):
    return " ".join((text or "").lower().replace("ё", "е").split())

def _dt(value):
    if not value:
        return datetime.now(timezone.utc)
    x = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return x if x.tzinfo else x.replace(tzinfo=timezone.utc)

def _state_con():
    Path(STATE_DB).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(STATE_DB)
    con.row_factory = sqlite3.Row
    con.execute("""CREATE TABLE IF NOT EXISTS question_state(
        raw_message_id INTEGER PRIMARY KEY,
        status TEXT NOT NULL,
        updated_at TEXT NOT NULL
    )""")
    return con

def mark_question(raw_message_id, status):
    con = _state_con()
    con.execute("""INSERT INTO question_state(raw_message_id,status,updated_at)
        VALUES(?,?,?) ON CONFLICT(raw_message_id) DO UPDATE SET
        status=excluded.status, updated_at=excluded.updated_at""",
        (int(raw_message_id), status, datetime.now(timezone.utc).isoformat(timespec="seconds")))
    con.commit()
    con.close()

def _argentina_context(row):
    blob = _norm((row["chat_title"] or "") + " " + (row["text"] or ""))
    return any(x in blob for x in (
        "аргент", "buenos aires", "буэнос-айрес", "буэнос айрес", "caba",
        "palermo", "recoleta", "belgrano", "nunez", "núñez", "expensas",
        "escriban", "consorcio", "monotributo"
    ))

def _relevant(row):
    text = _norm(row["text"])
    if len(text) < 24:
        return False
    if not any(x in text for x in QUESTION_CUES):
        return False
    property_hit = any(x in text for x in PROPERTY_CUES)
    direct_ask = any(x in text for x in (
        "подскаж", "как ", "где ", "можно ли", "правильно понимаю", "ищу ", "ищем ",
        "кто-нибудь", "кто нибудь", "у кого", "кто-то сда", "кто сдает", "кто сдаёт"
    ))
    hard_promo = any(x in text for x in (
        "приглашаю", "мои уроки", "мои занятия", "оказываю услуги", "мастер-инструктор",
        "маникюр", "педикюр", "хатха йог", "йоги "
    ))
    supply_promo = any(x in text for x in (
        "предлагаю", "свободна с ", "свободен с ", "сдается ", "сдаётся ", "продается ", "продаётся "
    ))
    if hard_promo or (supply_promo and not direct_ask):
        return False
    topic = row["topic"]
    if topic.startswith("emerging:") and "?" not in text and not direct_ask:
        return False
    if topic in {"rental", "real_estate_purchase", "property_sale"}:
        return property_hit
    if topic in RELEVANT_TOPICS:
        return property_hit or topic in {"property_legal_process", "mortgage", "valuation", "property_management"}
    return property_hit

def _research_needed(row):
    text = _norm(row["text"])
    return row["topic"] in RESEARCH_TOPICS or any(x in text for x in (
        "закон", "налог", "договор", "нотариус", "escrib", "ипотек", "миграц",
        "внж", "гражданств", "arca", "afip", "bienes personales"
    ))

def _score(row):
    text = _norm(row["text"])
    age_h = max(0, (datetime.now(timezone.utc) - _dt(row["created_at"])).total_seconds() / 3600)
    score = 50
    score += 26 if age_h <= 6 else 20 if age_h <= 24 else 12 if age_h <= 72 else 5
    chat = _norm(row["chat_title"])
    if "все русские в аргентине" in chat:
        score += 14
    elif "аргент" in chat or "буэнос" in chat or "buenos" in chat:
        score += 8
    if row["link"]:
        score += 4
    if row["topic"] in {"real_estate_purchase", "rental", "property_legal_process", "mortgage"}:
        score += 10
    if any(x in text for x in ("купить", "покупк", "снять", "аренд", "инвест", "доходност", "ипотек")):
        score += 10
    if len(text) < 45:
        score -= 12
    if len(text) > 1400:
        score -= 4
    return score

def _why(row):
    topic = row["topic"]
    labels = {
        "real_estate_purchase": "покупка недвижимости",
        "rental": "аренда",
        "property_legal_process": "оформление сделки",
        "property_management": "управление недвижимостью",
        "valuation": "оценка недвижимости",
        "mortgage": "ипотека",
        "cross_border_funds": "деньги на сделку",
        "investment_capital": "инвестиции",
        "renovation_redevelopment": "ремонт/реконструкция",
        "permits": "разрешения",
        "taxes": "налоги",
    }
    return labels.get(topic, "недвижимость")

def _draft(row):
    text = _norm(row["text"])
    if row["topic"] == "rental":
        return ("Если хотите, напишите район, срок аренды и ориентир по бюджету. "
                "Тогда можно быстро понять, какие варианты и условия вообще реалистичны сейчас.")
    if row["topic"] == "real_estate_purchase":
        return ("Тут многое зависит от цели покупки и бюджета. Если напишете район, формат объекта "
                "и для себя это или под инвестицию, можно уже предметно сориентироваться.")
    if "инвест" in text or row["topic"] == "investment_capital":
        return ("Я бы сначала разделил цель: доходность, сохранение капитала или покупка для себя. "
                "От этого очень сильно меняется и сам объект, и то, что нужно проверять.")
    if _research_needed(row):
        return ("На такой вопрос лучше отвечать только после проверки актуальных правил и документов, "
                "потому что здесь детали меняются и по памяти легко дать устаревший совет.")
    return "Тут есть несколько нюансов. Если вопрос ещё актуален, можно быстро разобрать его по конкретной ситуации."

def list_questions(limit=8, days=7):
    icon = sqlite3.connect(INTELLIGENCE_DB)
    icon.row_factory = sqlite3.Row
    since = (datetime.now(timezone.utc) - timedelta(days=days)).isoformat()
    rows = icon.execute("""SELECT a.raw_message_id,a.classification,a.topic,a.confidence,
        r.chat_title,r.sender_name,r.sender_username,r.text,r.link,r.created_at
        FROM message_analysis a JOIN raw_messages r ON r.id=a.raw_message_id
        WHERE a.classification='QUESTION' AND r.created_at>=?
        ORDER BY r.created_at DESC LIMIT 1200""", (since,)).fetchall()
    icon.close()
    scon = _state_con()
    statuses = {r["raw_message_id"]: r["status"] for r in scon.execute("SELECT * FROM question_state")}
    scon.close()
    out = []
    seen = set()
    for row in rows:
        if statuses.get(row["raw_message_id"]) in {"DONE", "SKIP"}:
            continue
        if not _argentina_context(row) or not _relevant(row):
            continue
        fp = re.sub(r"\W+", " ", _norm(row["text"]))[:180]
        if fp in seen:
            continue
        seen.add(fp)
        item = dict(row)
        item["score"] = _score(row) - (8 if statuses.get(row["raw_message_id"]) == "LATER" else 0)
        item["why"] = _why(row)
        item["needs_research"] = _research_needed(row)
        item["draft"] = _draft(row)
        out.append(item)
    out.sort(key=lambda x: (x["score"], x["created_at"]), reverse=True)
    return out[:max(1, min(10, int(limit)))]

def get_question(raw_message_id):
    icon = sqlite3.connect(INTELLIGENCE_DB)
    icon.row_factory = sqlite3.Row
    row = icon.execute("""SELECT a.raw_message_id,a.classification,a.topic,a.confidence,
        r.chat_title,r.sender_name,r.sender_username,r.text,r.link,r.created_at
        FROM message_analysis a JOIN raw_messages r ON r.id=a.raw_message_id
        WHERE a.raw_message_id=?""", (int(raw_message_id),)).fetchone()
    icon.close()
    if not row:
        return None
    item = dict(row)
    item["score"] = _score(row)
    item["why"] = _why(row)
    item["needs_research"] = _research_needed(row)
    item["draft"] = _draft(row)
    return item
