#!/usr/bin/env python3
import json, os, re, sqlite3, time, urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path
from lebleu_matcher import match_signal, brief as lebleu_brief, parse_query

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
    "квартир", "жиль", "апартамент", "недвиж", "дом ", "дом,", "дом.",
    "departamento", "depto", "dpto", "propiedad", "inmueble", "monoambiente", "ambiente",
    "объект недвиж", "земел", "участ", "terreno", "lote", "local comercial", "oficina", "cochera", "campo"
)
NEED = (
    "ищу", "ищем", "нужен", "нужна", "нужно", "хочу", "хотим", "планирую", "планируем",
    "собираюсь", "собираемся", "подскаж", "посовет", "кто знает", "как лучше",
    "busco", "necesito", "quiero", "queremos", "alguien sabe", "cómo", "como "
)
BUY = (
    "купить квартир", "купить недвиж", "купить дом", "покупка недвиж", "покупку недвиж",
    "покупать недвиж", "приобрести недвиж", "comprar departamento", "comprar propiedad",
    "comprar casa", "quiero comprar", "queremos comprar", "busco comprar",
    "хочу купить", "хотим купить", "планирую купить", "планируем купить",
    "buy apartment", "buy property"
)
BUY_STAGE = (
    "покупка квартиры", "покупка недвижимости", "приобретение квартиры", "приобретение недвижимости",
    "покупаю квартиру", "покупаю недвижимость", "куплю квартиру", "куплю недвижимость",
    "варианты покупки квартиры", "варианты покупки недвижимости", "варианты на покупку",
    "кто покупал квартиру", "кто покупал недвижимость", "покупал квартиру в аргентине", "покупал недвижимость в аргентине",
    "смотрю квартиры на продажу", "смотрю недвижимость на продажу", "выбираю квартиру для покупки",
    "для покупки квартиры", "для покупки недвижимости", "перед покупкой квартиры", "перед покупкой недвижимости",
    "после покупки квартиры", "после покупки недвижимости", "резерв квартиры", "резерв объекта",
    "reserva de compra", "seña de compra", "sena de compra", "boleto de compraventa",
    "compra de departamento", "compra de propiedad", "estoy comprando departamento", "estoy comprando propiedad",
    "adquisición de propiedad", "adquisicion de propiedad"
)
RENT = (
    "снять квартир", "снять жиль", "сниму ", "сниму квартир", "сниму жиль", "сниму дом", "арендовать квартир", "арендовать жиль", "ищу квартир",
    "ищем квартир", "ищу жиль", "ищем жиль", "ищу студ", "ищем студ", "alquilar",
    "alquiler", "busco departamento", "busco depto", "rentar"
)
INVEST = (
    "хочу инвест", "хотим инвест", "планирую инвест", "куда влож", "во что влож",
    "разместить капитал", "инвестировать деньги", "инвестировать в", "инвестиции в недвиж",
    "инвестиционную недвиж", "инвестиционный объект", "доходность недвиж", "рентабельность недвиж",
    "сохранить капитал", "rentabilidad inmobiliaria", "rentabilidad propiedad",
    "quiero invertir", "queremos invertir", "invertir en propiedad", "invertir en inmueble",
    "inversión inmobiliaria", "inversion inmobiliaria", "investment property", "пассивный доход от недвиж"
)
INVEST_STAGE = (
    "сумма инвестиций", "размер инвестиций", "объем инвестиций", "объём инвестиций",
    "бизнес план", "бизнес-план", "инвестиционная программа", "программа инвестиций",
    "внж за инвестиции", "внж через инвестиции", "гражданство за инвестиции", "гражданство через инвестиции",
    "residencia por inversión", "residencia por inversion", "ciudadanía por inversión", "ciudadania por inversion",
    "monto de inversión", "monto de inversion", "programa de inversión", "programa de inversion",
    "plan de negocio", "investment program", "investment amount",
    "открыть бизнес в аргентине", "открыть компанию в аргентине", "бизнес в аргентине"
)
PREINTENT = (
    "escritura", "escribano", "boleto de compraventa", "происхождени средств",
    "происхождени денег", "source of funds", "origen de fondos", "swift", "ипотек",
    "hipoteca", "apto crédito", "apto credito", "комиссия при покуп", "комиссии при покуп",
    "комиссия риелтор", "комиссия риэлтор", "расходы при покуп",
    "налог при покуп", "налоги при покуп", "bienes personales", "expensas",
    "перевести деньги", "завести деньги", "перевод денег", "перевод средств",
    "деньги из россии", "деньги в аргентин", "продажа квартиры в россии",
    "какой район", "какие районы", "где лучше жить", "что выбрать палермо",
    "gastos de compra", "gastos escritura", "honorarios escribano",
    "comisión inmobiliaria", "comision inmobiliaria", "impuestos compra",
    "impuesto inmobiliario", "comprar siendo extranjero", "extranjero comprar",
    "transferir fondos", "transferencia internacional", "origen fondos",
    "qué barrio", "que barrio", "zonas para vivir", "barrio para vivir",
    "residencia por inversión", "residencia por inversion", "ciudadanía por inversión",
    "ciudadania por inversion", "внж через покуп", "гражданство через инвест",
    "бизнес план", "бизнес-план", "business plan", "plan de negocio", "сумма инвестиц",
    "reserva de compra", "seña", "sena", "informe de dominio", "escribanía", "escribania",
    "tasación", "tasacion", "título de propiedad", "titulo de propiedad"
)
RENT_FRICTION = (
    "без подтверждения доход", "иностранный доход", "неофициальный доход", "garantía",
    "garantia", "seguro de caución", "seguro de caucion", "без гаранти", "гарантия для арен",
    "не могу снять", "не получается снять", "recibo de sueldo", "нет recibo de sueldo",
    "sin recibo de sueldo", "sin garantía propietaria", "sin garantia propietaria",
    "ingresos del exterior", "ingresos extranjeros", "monotributo"
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
    "скидка", "акция", "в наличии", "#продажа", "#аренда", "подписывайтесь",
    "для новых клиентов", "записаться", "заказать", "стоимость услуги", "наши услуги",
    "оказываем", "оказываю", "наша команда", "написать нам", "оставить заявку",
    "к вашим услугам", "выполняем", "выполняю", "предлагаю", "предлагаем",
    "помогаю", "поможем", "научу", "консультации", "услуга ", "запись в", "запись:",
    "индивидуальный подбор", "напишите ваши пожелания", "наша база", "подберем квартиру", "подберём квартиру"
)

def norm(value):
    return " ".join((value or "").lower().replace("ё", "е").split())

def has_any(text, cues):
    return any(x in text for x in cues)

PROPERTY_RE = re.compile(
    r"(?<![\wа-яё])(?:квартир\w*|жиль\w*|апартамент\w*|недвиж\w*|"
    r"дом(?:а|ом|у|е|ы|ов)?|земел\w*|участ(?:ок|ка|ке|ки|ков|ку|ком)|"
    r"departamento\w*|depto\w*|dpto\w*|propiedad(?:es)?|inmueble(?:s)?|"
    r"monoambiente\w*|ambiente(?:s)?|terreno(?:s)?|lote(?:s)?|casa(?:s)?|"
    r"local comercial|oficina(?:s)?|cochera(?:s)?|campo(?:s)?)(?![\wа-яё])", re.I
)

def has_property_context(text):
    return bool(PROPERTY_RE.search(text or ""))

def has_personal_need(text):
    head = (text or "")[:500]
    strong = r"(?:ищу|ищем|хочу|хотим|планирую|планируем|собираюсь|собираемся|busco|necesito|quiero|queremos)"
    if re.search(r"(?<![\wа-яё])" + strong + r"(?![\wа-яё])", head, re.I):
        return True
    weak = r"(?:нужен|нужна|нужно)"
    weak_target = r"(?:квартир\w*|жиль\w*|дом(?:\s|$)|риелтор\w*|риэлтор\w*|broker\w*|escriban\w*|нотариус\w*|адвокат\w*)"
    if re.search(r"(?<![\wа-яё])" + weak + r".{0,25}" + weak_target, head[:260], re.I):
        return True
    if re.search(r"(?:мне|нам|у меня|у нас).{0,25}" + weak + r".{0,35}" + weak_target, head[:300], re.I):
        return True
    # Important: do not use the stem "подскаж" here. It also matches promo
    # wording such as "подскажу", which previously turned service ads into leads.
    if re.search(r"(?<![\wа-яё])(?:подскажите|посоветуйте)(?![\wа-яё])", head[:300], re.I):
        return True
    if re.search(r"(?<![\wа-яё])кто\s+знает(?![\wа-яё])", head[:300], re.I):
        return True
    if re.search(r"(?<![\wа-яё])как\s+лучше(?![\wа-яё])", head[:300], re.I):
        return True
    if re.search(r"\b(?:alguien sabe|cómo|como)\b", head[:300], re.I) and ("?" in head or re.search(r"\b(?:comprar|alquilar|invertir)\b", head, re.I)):
        return True
    return False

def has_question_intent(text):
    head = (text or "")[:420]
    patterns = (
        r"\bподскажите\b", r"\bпосоветуйте\b", r"\bкто\s+знает\b", r"\bкак\s+лучше\b",
        r"\bгде\s+(?:снять|купить)\b", r"\bкак\s+(?:купить|снять)\b",
        r"\bгде\s+(?:можно\s+)?(?:посмотреть|найти).{0,35}покупк\w*\s+(?:квартир|недвиж)\w*",
        r"\balguien\s+sabe\b", r"\bc[oó]mo\s+(?:comprar|alquilar)\b", r"\bd[oó]nde\s+comprar\b",
    )
    return any(re.search(p, head, re.I) for p in patterns)

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
    CREATE TABLE IF NOT EXISTS draft_jobs(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      candidate_id INTEGER, chat_id INTEGER NOT NULL, message_id INTEGER NOT NULL,
      text TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'PENDING',
      error TEXT, created_at TEXT NOT NULL, processed_at TEXT
    );
    CREATE INDEX IF NOT EXISTS idx_draft_jobs_status ON draft_jobs(status,id);
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
    prop = has_property_context(text)
    studio_listing = "студи" in text and (has_any(text, RENT_SUPPLY) or has_any(text, SALE))
    prop = prop or studio_listing
    need = has_personal_need(text)
    question_intent = has_question_intent(text)
    buy = has_any(text, BUY)
    buyer_stage = has_any(text, BUY_STAGE) or bool(re.search(r"\bкто(?:-?то)?\s+покупал\w*.{0,45}(?:квартир\w*|недвиж\w*|дом(?:а|ов)?)", text, re.I))
    rent = has_any(text, RENT)
    self_signal = bool(re.search(r"(?:^|\s)(?:я|мы)(?:\s|$)|у меня|у нас|мне |нам |мой |моя |наши |продал|продала|продаем|перевожу|переводим|получил|получила|собираюсь|планирую", text))
    invest_stage = has_any(text, INVEST_STAGE)
    invest_raw = has_any(text, INVEST) or invest_stage
    crypto_personal = has_any(text, ("usdt", "крипт", "crypto", "binance", "bybit")) and (need or question_intent)
    pre_terms_raw = has_any(text, PREINTENT)
    # Generic crypto/cash/transfer questions are not property pre-intent by themselves.
    # Keep them out of buyer funnels unless the same message has real-estate/purchase/investment context.
    pre_raw = pre_terms_raw and (prop or buy or buyer_stage or invest_raw or has_any(text, (
        "escritura", "escribano", "boleto de compraventa", "reserva de compra", "informe de dominio",
        "hipoteca", "apto crédito", "apto credito", "gastos de compra", "comisión inmobiliaria",
        "comision inmobiliaria", "comprar siendo extranjero", "extranjero comprar"
    )))
    if crypto_personal and (buy or buyer_stage or invest_raw):
        pre_raw = True
    friction = has_any(text, RENT_FRICTION) and (need or question_intent) and (prop or rent)
    relocation = has_any(text, RELOCATION)
    owner = has_any(text, OWNER_DIRECT)
    sale = has_any(text, SALE) and prop
    head = text[:500]
    strong_intent_word = r"(?:ищу|ищем|хочу|хотим|сниму|busco|quiero|queremos)"
    weak_intent_word = r"(?:нужна|нужно|нужен)"
    residential_noun = r"(?:квартир\w*|жиль\w*|апартамент\w*|departamento\w*|depto\w*|monoambiente\w*)"
    explicit_rent_need = bool(re.search(strong_intent_word + r".{0,38}" + residential_noun, head, re.I))
    explicit_rent_need = explicit_rent_need or bool(re.search(weak_intent_word + r".{0,14}" + residential_noun, head, re.I))
    house_need = bool(re.search(strong_intent_word + r".{0,28}дом(?:\s|$|[,.;])", head, re.I)) and not bool(re.search(r"ищу\s+в\s+дом", head, re.I))
    house_need = house_need or bool(re.search(weak_intent_word + r".{0,12}дом(?:\s|$|[,.;])", head, re.I))
    studio_need = bool(re.search(strong_intent_word + r".{0,38}студи\w*", head, re.I)) or bool(re.search(weak_intent_word + r".{0,14}студи\w*", head, re.I))
    studio_need = studio_need and not has_any(head, ("студию танц", "студия танц", "студию масс", "студия масс", "педагог", "хореограф", "салон красоты", "рабочее место"))
    rental_question = bool(re.search(r"(?:как|где|площадк\w*).{0,55}(?:снять|арендовать|alquilar).{0,45}" + residential_noun, head, re.I)) or has_any(head, ("как лучше снять жиль", "где снять квартир", "где снять жиль", "арендовать квартиру", "арендовать жилье", "арендовать жильё"))
    explicit_rent_need = explicit_rent_need or house_need or studio_need or rental_question
    explicit_rent_word = has_any(text, ("снять", "сниму", "арендовать", "аренда", "долгосроч", "alquiler", "alquilar", "rentar", "por mes"))
    # “Хочу купить квартиру” must never also become rental demand merely because
    # “хочу ... квартира” matches the generic residential-need pattern.
    if (buy or buyer_stage) and not explicit_rent_word:
        explicit_rent_need = False
    prop = prop or studio_need
    rent = rent or explicit_rent_need
    listing_terms = has_any(text, ("/месяц", "в месяц", "usd/месяц", "ars в месяц", "депозит", "expensas", "alquiler temporario"))
    listing_heading = bool(re.search(r"^(?:квартиры? в аренду|аренда в |alquiler |лот#?\d*\s+аренда)", text, re.I))
    rent_price_listing = bool(re.search(r"(?:аренда|alquiler).{0,60}(?:usd|ars|usdt|\$)\s*[0-9]|(?:аренда|alquiler).{0,60}[0-9][0-9., ]*\s*(?:usd|ars|usdt)", text, re.I))
    promo = has_any(text, PROMO)
    other_person_question = bool(re.search(r"(?<![\wа-яё])(?:вам|вас|вы)(?![\wа-яё])", head, re.I)) and not (need or self_signal)
    buyer_active_self = bool(re.search(
        r"(?:покупаю|покупаем|куплю|купим|хочу купить|хотим купить|планирую купить|планируем купить|"
        r"собираюсь купить|собираемся купить|ищу.{0,30}(?:для покупки|купить)|ищем.{0,30}(?:для покупки|купить)|"
        r"смотрю.{0,35}(?:на продажу|для покупки)|смотрим.{0,35}(?:на продажу|для покупки)|"
        r"выбираю.{0,35}для покупки|потом покупка|следующ(?:ий|ая) этап.{0,35}покупк|"
        r"estoy comprando|estamos comprando|quiero comprar|queremos comprar|busco.{0,30}para comprar)", text, re.I
    ))
    buyer_demand = (buy or buyer_stage) and (need or question_intent or buyer_active_self or (("?" in head) and not promo and not other_person_question))
    partner = has_any(text, PARTNER)
    agent_rental_need = partner and need and has_any(text, ("аренд", "снять", "alquiler", "alquilar"))
    explicit_rent_need = explicit_rent_need or agent_rental_need
    service_listing = listing_heading or (rent_price_listing and has_any(text, ("комиссия", "комиссии", "подбор", "напишите", "контракт")))
    rent_supply = (has_any(text, RENT_SUPPLY) and prop) or (listing_heading and prop) or (rent_price_listing and prop and not explicit_rent_need) or (owner and prop and not sale and not buyer_demand and listing_terms)
    if rent_supply and (service_listing or promo) and not bool(re.search(r"^(?:всем привет[!, ]*)?(?:мы |я |ищу|ищем|хочу|хотим|нужна|нужно|сниму)", head, re.I)):
        explicit_rent_need = False
    moving_job_noise = has_any(head, ("разовая подработка", "перенести вещи", "перевезти вещи", "грузчик", "помочь с переездом", "оплата каждому"))
    if moving_job_noise and not has_any(head, ("ищу квартиру", "ищем квартиру", "ищу жиль", "ищем жиль", "хочу снять", "сниму квартиру", "арендовать квартиру")):
        return None
    animal_home_noise = has_any(head, ("кот", "кош", "собак", "щен", "питомц", "приют", "мохнат"))
    if animal_home_noise and not (buy or buyer_stage or explicit_rent_word or sale or rent_supply):
        return None
    active_invest_process = bool(re.search(
        r"(?:мне дали ответ.{0,80}(?:консульств|миграц)|по моему вопросу.{0,80}(?:инвест|бизнес)|"
        r"готов(?:а|ы)?\s+(?:подать|предоставить|инвестировать)|подаю.{0,40}(?:инвест|бизнес)|"
        r"хочу попробовать.{0,50}(?:путь|инвест|программ)|готовлю.{0,40}(?:бизнес[- ]?план|документ)|"
        r"presentar documentos.{0,60}(?:inversi[oó]n|plan de negocio))", text, re.I
    ))
    invest = invest_raw and (need or question_intent or active_invest_process)
    transaction_self = bool(re.search(
        r"(?:покупаю|купил(?:а)?|приобретаю|оформляю|перевожу деньги|переводим деньги|"
        r"продал(?:а)? недвиж|продал(?:а)? квартир|моя покупка|наша покупка|"
        r"estoy comprando|estamos comprando|compré|compre|estoy escriturando)", text, re.I
    ))
    pre = pre_raw and (need or question_intent or transaction_self) and not (sale or rent_supply)
    job_noise = has_any(head, ("ищем педагог", "ищем модератор", "ищем сотрудник", "вакансия", "подработка", "ищем помощник", "ищу заказы", "работа из дома"))
    if job_noise and not re.search(residential_noun, head, re.I):
        return None

    money_signal = bool(re.search(r"(?:usd|usdt|u\$s|\$|eur|€)\s*\d|\d[\d., ]*\s*(?:usd|usdt|u\$s|eur|€)", text, re.I))

    tags, reasons, score = [], [], 0
    if arg_context:
        score += 15; reasons.append("Argentina context")
    if prop:
        score += 12; tags.append("property")
    if need or question_intent:
        score += 12; reasons.append("personal need/question")
    if self_signal and (prop or invest_raw or pre_raw or relocation):
        score += 8; reasons.append("first-person context")
    if money_signal and (need or question_intent or self_signal):
        score += 8; tags.append("money"); reasons.append("budget/capital amount")
    # Time-economics: keep low-budget direct-owner rental demand in the database,
    # but do not let it crowd the operator inbox unless a strong exact fit exists later.
    direct_only_request = has_any(text, ("без агент", "без риелтор", "без риэлтор", "без посредник", "напрямую от хозя", "напрямую от собственника", "dueño directo", "dueno directo", "sin inmobiliaria"))
    rental_budget_usd = None
    m_budget = re.search(r"(?:до|бюджет(?:ом)?(?:\s+до)?)?\s*(?:usd|usdt|u\$s|\$)\s*([0-9]{3,5})|(?:до|бюджет(?:ом)?(?:\s+до)?)?\s*([0-9]{3,5})\s*(?:usd|usdt|доллар)", text, re.I)
    if m_budget:
        try: rental_budget_usd = float(m_budget.group(1) or m_budget.group(2))
        except Exception: rental_budget_usd = None
    if buyer_demand:
        score += 28; tags.append("buyer"); reasons.append("purchase intent" if buy else "purchase-stage intent")
    if explicit_rent_need:
        score += 25; tags.append("rental_demand"); reasons.append("rental demand")
    if invest:
        score += 24; tags.append("investor"); reasons.append("investment-stage intent" if invest_stage else "capital/investment intent")
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
    if partner and (need or question_intent or owner or "рекоменд" in text or "контакт" in text):
        score += 12; tags.append("partner"); reasons.append("transaction partner signal")

    if (rent and explicit_rent_need) and direct_only_request and rental_budget_usd is not None and rental_budget_usd <= 600:
        score -= 24; reasons.append("low-economics direct-owner rental")
    if relocation and not (prop or invest or pre or friction or buyer_demand or explicit_rent_need):
        score = min(score, 45); reasons.append("relocation only: low commercial specificity")
    if promo and not owner:
        score -= 30; reasons.append("publisher/service promo")
    if not arg_context and not (buy or invest or pre):
        score -= 20
    if not (prop or invest or pre or friction or relocation or owner or (partner and need)):
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
    fp = fingerprint(row["text"])
    duplicate = con.execute("SELECT id FROM candidates WHERE person_key=? AND fingerprint=? ORDER BY id DESC LIMIT 1", (pk, fp)).fetchone()
    if duplicate:
        return None
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
        row["text"], row["link"], fp, iso()
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
    try:
        with urllib.request.urlopen(req, timeout=8) as resp:
            return bool(json.load(resp).get("ok"))
    except Exception as exc:
        print(f"Broad alert delivery skipped: {type(exc).__name__}: {str(exc)[:160]}", flush=True)
        return False

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
    actionable_push = {"PROPERTY_BUYER","INVESTOR","RENTER","PRE_INTENT","OWNER_DIRECT","OWNER_RENTAL","PARTNER"}
    if (row["region"] != "argentina" or row["category"] not in actionable_push
            or row["score"] < ALERT_MIN_SCORE or age > timedelta(hours=ALERT_MAX_AGE_HOURS)):
        return
    keyboard = [[
        {"text":"✅ Лид","callback_data":f"lead:{row['id']}"},
        {"text":"👀 Просмотрено","callback_data":f"review:{row['id']}"},
        {"text":"🗑 Шум","callback_data":f"noise:{row['id']}"},
        {"text":"⏰ Потом","callback_data":f"later:{row['id']}"}
    ]]
    demand_categories = ("PROPERTY_BUYER", "INVESTOR", "RENTER", "PRE_INTENT")
    restricted_outreach = int(row["chat_id"]) == -1001745734197
    try:
        latest_draft = con.execute(
            "SELECT status,error FROM draft_jobs WHERE chat_id=? ORDER BY id DESC LIMIT 1",
            (int(row["chat_id"]),)
        ).fetchone()
        if latest_draft and latest_draft["status"] == "ERROR":
            err = latest_draft["error"] or ""
            restricted_outreach = restricted_outreach or any(
                marker in err for marker in ("ChatWriteForbiddenError", "ChannelPrivateError", "UserBannedInChannelError")
            )
    except Exception:
        pass
    reply_row = [{"text":"✍️ Ответить","callback_data":f"reply:{row['id']}"}]
    if row["category"] in demand_categories and not restricted_outreach:
        reply_row.append({"text":"📚 Каталог-шаблон","callback_data":f"catalogreply:{row['id']}"})
    keyboard.append(reply_row)
    alert_text = render_candidate(con, row)
    if restricted_outreach:
        alert_text += "\n\n⚠️ Outreach guard: в этом чате не использовать рекламу, каталог, ссылки или CTA в личку. Только нейтральный полезный ответ после ручной проверки."
    if row["category"] in demand_categories:
        keyboard.append([{"text":"🏠 Совпадения Le Bleu","callback_data":f"matches:{row['id']}"}])
        try:
            q = parse_query(row["text"], "Alquiler" if row["category"] == "RENTER" else "Venta" if row["category"] in ("PROPERTY_BUYER","INVESTOR") else None)
            if q.get("direct_owner_only"):
                alert_text += "\n\n🚫 Le Bleu: не предлагать — человек явно просит напрямую/без посредника."
            else:
                lb = match_signal(row["text"], row["category"], 3)
                if lb:
                    top = lb[0]
                    alert_text += f"\n\n🏠 Le Bleu: {len(lb)} возможн. match. Лучший:\n" + lebleu_brief(top)
                else:
                    alert_text += "\n\n🏠 Le Bleu: надёжного match сейчас нет."
        except Exception as exc:
            print(f"Le Bleu match hint failed: {type(exc).__name__}: {str(exc)[:120]}", flush=True)
    if row["link"]:
        keyboard.append([{"text":"Открыть оригинал","url":row["link"]}])
    if bot_send(alert_text, keyboard):
        ts = iso()
        con.execute("UPDATE candidates SET alerted_at=?, shown_at=COALESCE(shown_at,?) WHERE id=?", (ts, ts, row["id"]))
        con.commit()

def process_batch(con, raw, after_id, limit=1000):
    rows = raw.execute(
        "SELECT * FROM raw_messages WHERE id>? ORDER BY id LIMIT ?", (after_id, limit)
    ).fetchall()
    last = after_id
    for row in rows:
        last = row["id"]
        try:
            result = classify(row)
            if not result:
                continue
            cand = insert_candidate(con, row, result)
            if cand is not None:
                alert_candidate(con, cand)
        except Exception as exc:
            # Poison-row isolation: one malformed message, DB edge case or alert
            # failure must not freeze the raw cursor for the rest of the batch.
            print(f"Broad row {row['id']} skipped: {type(exc).__name__}: {str(exc)[:180]}", flush=True)
            continue
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
