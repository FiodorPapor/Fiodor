#!/usr/bin/env python3
import json, os, re, time, urllib.request
from pathlib import Path
from urllib.parse import quote

CATALOG = os.getenv("LEBLEU_CATALOG", "/opt/lebleu-listing-bridge/public/data/full/catalog.json")
QUALITY_CONTENT = os.getenv("LEBLEU_QUALITY_CONTENT", "/opt/lebleu-listing-bridge/state/ru-content-quality.json")
TG_STATE = os.getenv("LEBLEU_TG_STATE", "/opt/lebleu-listing-bridge/state/telegram-state.json")
FX_CACHE = Path(os.getenv("RR_FX_CACHE", "/opt/intent-radar/data/bna_fx.json"))
BNA_URL = "https://www.bna.com.ar/Personas"
FALLBACK_USD_ARS = float(os.getenv("RR_USD_ARS_FALLBACK", "1545"))

NEIGHBORHOODS = {
    "palermo": ["palermo", "палермо", "botanico", "botánico", "ботанико", "las cañitas", "las canitas", "каньитас"],
    "recoleta": ["recoleta", "реколета", "реколетта"],
    "belgrano": ["belgrano", "бельграно"],
    "nunez": ["núñez", "nunez", "nuñez", "нуньес", "нуньез"],
    "colegiales": ["colegiales", "колегиалес", "колехиалес"],
    "villa urquiza": ["villa urquiza", "вилья уркиса", "вилла уркиса"],
    "caballito": ["caballito", "кабальито"],
    "chacarita": ["chacarita", "чакарита"],
    "villa crespo": ["villa crespo", "вилья креспо"],
    "barracas": ["barracas", "барракас"],
    "balvanera": ["balvanera", "бальванера"],
    "san nicolas": ["san nicolás", "san nicolas", "сан николас"],
    "retiro": ["retiro", "ретиро"],    "puerto madero": ["puerto madero", "пуэрто мадеро"],
    "almagro": ["almagro", "альмагро"],
    "san telmo": ["san telmo", "сан тельмо"],
    "parque chas": ["parque chas", "парке час"],
    "saavedra": ["saavedra", "сааведра"],
    "microcentro": ["microcentro", "микроцентро"],
    "la plata": ["la plata", "ла плата"],
    "city bell": ["city bell", "сити бель"],
    "parque centenario": ["parque centenario", "парк сентенарио", "парке сентенарио", "сентенарио"],
    "villa devoto": ["villa devoto", "вилья девото", "вилла девото"],
    "villa del parque": ["villa del parque", "вилья дель парке", "вилла дель парке"],
    "flores": ["flores", "флорес"],
    "floresta": ["floresta", "флореста"],
    "boedo": ["boedo", "боэдо"],
    "san cristobal": ["san cristóbal", "san cristobal", "сан кристобаль"],
}
FEATURES = {
    "balcon": ["балкон", "balcon", "balcón"],
    "pileta": ["бассейн", "pileta", "piscina"],
    "parrilla": ["парилья", "париша", "parrilla", "барбекю"],
    "cochera": ["парковк", "гараж", "cochera"],
    "amoblado": ["меблир", "amoblado", "мебель"],
    "laundry": ["стирал", "прачеч", "laundry"],
    "aire": ["кондиционер", "aire acondicionado"],
    "terraza": ["терраса", "terraza"],
}
DIRECT_OWNER_ONLY = (
    "только от собственника", "напрямую от хозя", "напрямую от собственника",
    "без риелтор", "без риэлтор", "без агентств", "без посредник",
    "dueño directo", "dueno directo", "sin inmobiliaria", "sin comisión", "sin comision"
)

def norm(text):
    return " ".join((text or "").lower().replace("ё", "е").split())

def load_json(path, fallback):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return fallback

QUALITY_CACHE = None

def quality_map():
    global QUALITY_CACHE
    if QUALITY_CACHE is None:
        QUALITY_CACHE = load_json(QUALITY_CONTENT, {})
    return QUALITY_CACHE

def quality_for(item):
    q = quality_map().get(item.get("sourceUrl")) or {}
    if q.get("sourceFingerprint") and q.get("sourceFingerprint") != item.get("sourceFingerprint"):
        return {}
    return q

def effective_type(item):
    return quality_for(item).get("property_type_override") or item.get("propertyType")

def effective_details(item):
    d = dict(item.get("details") or {})
    d.update(quality_for(item).get("details_override") or {})
    return d

def suspicious_price(item):
    try:
        price = float(item.get("priceAmount") or 0)
    except Exception:
        return True
    return bool(item.get("operation") == "Venta" and item.get("priceCurrency") == "USD" and 0 < price < 5000 and effective_type(item) != "Cochera")
def get_usd_ars():
    now = time.time()
    try:
        if FX_CACHE.exists():
            cached = json.loads(FX_CACHE.read_text(encoding="utf-8"))
            if now - float(cached.get("ts", 0)) < 21600 and float(cached.get("sell", 0)) > 0:
                return float(cached["sell"]), cached.get("date", ""), "BNA"
    except Exception:
        pass
    try:
        req = urllib.request.Request(BNA_URL, headers={"User-Agent":"Mozilla/5.0"})
        html = urllib.request.urlopen(req, timeout=12).read().decode("utf-8", "ignore")
        m = re.search(r"Dolar U\.S\.A.{0,500}?(\d+[,.]\d+).{0,220}?(\d+[,.]\d+)", html, re.I|re.S)
        date_m = re.search(r"(\d{1,2}/\d{1,2}/\d{4})", html)
        if m:
            sell = float(m.group(2).replace(".", "").replace(",", "."))
            FX_CACHE.parent.mkdir(parents=True, exist_ok=True)
            FX_CACHE.write_text(json.dumps({"ts":now,"sell":sell,"date":date_m.group(1) if date_m else ""}), encoding="utf-8")
            return sell, date_m.group(1) if date_m else "", "BNA"
    except Exception:
        pass
    return FALLBACK_USD_ARS, "", "fallback"

def extract_money(text):
    low = norm(text)
    out = []
    patterns = [
        (r"(?:до|max(?:imum)?|бюджет(?:ом)?\s*(?:до)?)?\s*(?:usd|us\$|u\$s|\$)\s*([\d.,]+)\s*([kmк]?)", "USD"),
        (r"(?:до|max(?:imum)?|бюджет(?:ом)?\s*(?:до)?)?\s*([\d.,]+)\s*([kmк]?)\s*(?:usd|usdt|доллар)", "USD"),
        (r"(?:до|бюджет(?:ом)?\s*(?:до)?)?\s*\$\s*([\d.,]+)", "USD"),
        (r"(?:до|max(?:imum)?|бюджет(?:ом)?\s*(?:до)?)?\s*([\d.,]+)\s*([kmк]?)\s*\$", "USD"),
        (r"(?:до|бюджет(?:ом)?\s*(?:до)?)?\s*([\d.,]+)\s*(?:ars|песо|pesos)", "ARS"),
    ]
    for pat, cur in patterns:
        for m in re.finditer(pat, low, re.I):
            raw = m.group(1).replace(" ", "")
            suffix = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            try:
                # Telegram budgets commonly use 1,500 or 1.500 as thousands separators.
                if re.fullmatch(r"\d{1,3}[.,]\d{3}", raw):
                    val = float(raw.replace(",", "").replace(".", ""))
                elif raw.count(",") == 1 and len(raw.split(",")[-1]) <= 2:
                    val = float(raw.replace(".", "").replace(",", "."))
                else:
                    val = float(raw.replace(",", "").replace(".", ""))
            except Exception:
                continue
            if suffix.lower() in ("k","m","к"):
                val *= 1000 if suffix.lower() != "m" else 1_000_000
            if val > 0:
                out.append((cur, val))
    return out

def parse_query(text, forced_operation=None):
    low = norm(text)
    q = {
        "operation": forced_operation,
        "neighborhoods": [],
        "max_budget": None,
        "budget_currency": None,
        "rooms": None,
        "bedrooms": None,
        "features": [],
        "direct_owner_only": any(x in low for x in DIRECT_OWNER_ONLY),
        "residential_only": bool(re.search(r"(?:квартир|трешк|трёшк|двушк|однушк|departamento|depto)", low, re.I)),
    }
    if not q["operation"]:
        if any(x in low for x in ["снять","аренд","alquiler","alquilar","rent "]):
            q["operation"] = "Alquiler"
        elif any(x in low for x in ["купить","покуп","продажа","venta","comprar","инвест"]):
            q["operation"] = "Venta"
    for canonical, aliases in NEIGHBORHOODS.items():
        if any(a in low for a in aliases):
            q["neighborhoods"].append(canonical)
    money = extract_money(low)
    if money:
        cur, val = max(money, key=lambda x: x[1])
        q["budget_currency"], q["max_budget"] = cur, val
    m = re.search(r"\b(\d+)\s*[- ]?(?:комнат|комн\.|amb(?:iente)?s?)", low)
    if m:
        q["rooms"] = int(m.group(1))
    elif any(x in low for x in ["трешка","трешку","трёшка","трёшку"]):
        q["rooms"] = 3
    elif any(x in low for x in ["двушка","двушку","двухкомнат"]):
        q["rooms"] = 2
    elif any(x in low for x in ["однушка","однушку","студия","студио","monoambiente","1 ambiente","1 amb"]):
        q["rooms"] = 1
    m = re.search(r"\b(\d+)\s*(?:спальн|dorm(?:itorio)?s?|bedroom)", low)
    if m:
        q["bedrooms"] = int(m.group(1))
    for key, aliases in FEATURES.items():
        if any(a in low for a in aliases):
            q["features"].append(key)
    return q

def listing_blob(item):
    q = quality_for(item)
    return norm(" ".join([
        item.get("title",""), item.get("address",""), item.get("slug",""),
        item.get("description",""), q.get("summary_ru", ""), " ".join(q.get("notes_ru") or []),
        " ".join(item.get("highlightedFeatures") or [])
    ]))

def listing_neighborhoods(item):
    # Neighborhood is a hard constraint: never infer it from marketing prose,
    # which often mentions nearby barrios and creates false matches.
    location_blob = norm(" ".join([
        item.get("title", ""), item.get("address", ""), item.get("slug", "")
    ]))
    found = []
    for canonical, aliases in NEIGHBORHOODS.items():
        if any(a in location_blob for a in aliases):
            found.append(canonical)
    return found

def listing_price_in(item, currency):
    try:
        price = float(item.get("priceAmount") or 0)
    except Exception:
        return None, None
    cur = item.get("priceCurrency") or ""
    if not price or not cur:
        return None, None
    if cur == currency:
        return price, cur
    fx, fx_date, fx_src = get_usd_ars()
    if cur == "ARS" and currency == "USD":
        return price / fx, f"USD≈ (BNA {fx:g})"
    if cur == "USD" and currency == "ARS":
        return price * fx, f"ARS≈ (BNA {fx:g})"
    return None, None

def score_item(item, q):
    reasons = []
    score = 0
    op = item.get("operation")
    ptype = effective_type(item)
    if q.get("residential_only") and ptype not in {"Departamento", "PH", "Casa"}:
        return None
    if suspicious_price(item):
        return None
    if q["operation"]:
        if op != q["operation"]:
            return None
        score += 30
        reasons.append("операция совпадает")
    if q["direct_owner_only"]:
        return None
    req_hoods = set(q["neighborhoods"])
    item_hoods = set(listing_neighborhoods(item))
    if req_hoods:
        overlap = req_hoods & item_hoods
        if not overlap:
            return None
        score += 28
        reasons.append("район: " + ", ".join(sorted(overlap)))
    if q["max_budget"]:
        price, label = listing_price_in(item, q["budget_currency"])
        if price is None:
            score -= 8
            reasons.append("бюджет нельзя сопоставить")
        else:
            ratio = price / q["max_budget"]
            if ratio <= 1.00:
                score += 24
                reasons.append(f"в бюджете ({label or q['budget_currency']})")
            elif ratio <= 1.10:
                score += 8
                reasons.append("до 10% выше бюджета")
            else:
                return None
    d = effective_details(item)
    if q["rooms"]:
        rooms = int(d.get("rooms") or 0)
        if rooms == q["rooms"]:
            score += 15; reasons.append("комнаты совпадают")
        elif rooms and abs(rooms-q["rooms"]) == 1:
            score += 3; reasons.append("комнаты близко")
        else:
            return None
    if q["bedrooms"]:
        bedrooms = int(d.get("bedrooms") or 0)
        if bedrooms == q["bedrooms"]:
            score += 15; reasons.append("спальни совпадают")
        elif bedrooms and abs(bedrooms-q["bedrooms"]) == 1:
            score += 3; reasons.append("спальни близко")
        else:
            return None
    blob = listing_blob(item)
    for feat in q["features"]:
        aliases = FEATURES[feat]
        if any(a in blob for a in aliases):
            score += 6
            reasons.append("есть " + feat)
        else:
            score -= 2
    if not any([q["neighborhoods"], q["max_budget"], q["rooms"], q["bedrooms"], q["features"]]):
        # Free text fallback. This is deliberately simple and deterministic.
        tokens = [t for t in re.findall(r"[a-záéíóúñüа-я0-9]{4,}", norm(q.get("raw","")), re.I)
                  if t not in {"квартир","аренда","продажа","недвижимость","ищу","ищем","хочу","купить"}]
        hits = sum(1 for t in set(tokens) if t in blob)
        score += min(30, hits*6)
        if hits:
            reasons.append(f"текстовых совпадений: {hits}")
    if score < 25:
        return None
    return min(100, score), reasons

def search(text, forced_operation=None, limit=5):
    q = parse_query(text, forced_operation)
    q["raw"] = text
    items = load_json(CATALOG, [])
    results = []
    for item in items:
        scored = score_item(item, q)
        if not scored:
            continue
        score, reasons = scored
        results.append({"score":score,"reasons":reasons,"item":item,"query":q})
    results.sort(key=lambda x:(-x["score"], float(x["item"].get("priceAmount") or 0)))
    return results[:limit]

def match_signal(text, category, limit=3):
    forced = "Alquiler" if category == "RENTER" else "Venta" if category in {"PROPERTY_BUYER","INVESTOR"} else None
    q = parse_query(text, forced)
    # An operation alone is not a meaningful property match. Require evidence
    # from the person's own message before putting inventory in front of them.
    # Neighborhood alone is meaningful; a budget alone is too broad and
    # would produce arbitrary inventory. Without a neighborhood, require
    # budget plus another property criterion.
    specific = bool(
        q["neighborhoods"]
        or (q["max_budget"] and (q["rooms"] or q["bedrooms"] or q["features"]))
        or (q["rooms"] and q["features"])
        or (category == "RENTER" and q["max_budget"])
    )
    if not specific or q.get("direct_owner_only"):
        return []
    return search(text, forced, limit)

def get_by_code(code):
    target = norm(code)
    for item in load_json(CATALOG, []):
        if norm(item.get("code", "")) == target:
            return item
    return None

def public_post_url(item):
    state = load_json(TG_STATE, {"channel":"@lebleu_argentina_ru","entries":{}})
    entry = (state.get("entries") or {}).get(item.get("sourceUrl"))
    if not entry or entry.get("status") != "active" or not entry.get("messageIds"):
        return None
    channel = (state.get("channel") or "@lebleu_argentina_ru").lstrip("@")
    return f"https://t.me/{channel}/{entry['messageIds'][0]}"

def human_price(item):
    cur = item.get("priceCurrency") or ""
    try:
        n = float(item.get("priceAmount") or 0)
        return f"{cur} {n:,.0f}".replace(",", " ")
    except Exception:
        return f"{cur} {item.get('priceAmount') or ''}".strip()

def brief(result):
    item = result["item"]
    d = effective_details(item)
    hoods = listing_neighborhoods(item)
    specs = []
    if d.get("rooms"): specs.append(f"{int(d['rooms'])} amb")
    if d.get("bedrooms"): specs.append(f"{int(d['bedrooms'])} dorm")
    if d.get("totalAreaM2"): specs.append(f"{d['totalAreaM2']:g} m²")
    where = ", ".join(hoods[:2]) or item.get("address") or "CABA"
    return (
        f"{item.get('code')} · {result['score']}/100\n"
        f"{where} · {human_price(item)}"
        + (f" · {' · '.join(specs)}" if specs else "")
        + f"\nПочему: {'; '.join(result['reasons'][:4])}"
    )

def draft_dm(candidate, result, post_url=None):
    item = result["item"]
    category = candidate.get("category","") if isinstance(candidate, dict) else candidate["category"]
    text = norm(candidate.get("text","") if isinstance(candidate, dict) else candidate["text"])
    if category == "RENTER":
        intro = "Привет! Увидел ваш запрос по аренде в Буэнос-Айресе. Я Фёдор, занимаюсь недвижимостью здесь."
    else:
        intro = "Привет! Увидел ваш запрос по недвижимости в Буэнос-Айресе. Я Фёдор, занимаюсь подбором и сопровождением сделок здесь."
    msg = f"{intro} Есть вариант, который по основным параметрам похож: {human_price(item)}, {item.get('address') or ''}."
    if post_url:
        msg += f" Вот карточка на русском: {post_url}"
    msg += " Если запрос ещё актуален, могу быстро проверить детали и подобрать ещё несколько вариантов без лишней рассылки."
    return msg

def draft_public(candidate, result=None):
    category = candidate.get("category","") if isinstance(candidate, dict) else candidate["category"]
    if result:
        item = result["item"]
        return (
            "Вижу ваш запрос. Я Фёдор, занимаюсь недвижимостью в Буэнос-Айресе. "
            f"Есть вариант, который по основным параметрам может подойти: {human_price(item)}, {item.get('address') or ''}. "
            "Если ещё актуально, напишите в личку — пришлю детали и проверю актуальность."
        )
    if category == "RENTER":
        return "Вижу ваш запрос. Я Фёдор, занимаюсь недвижимостью в Буэнос-Айресе. Если ещё актуально, напишите в личку — попробую быстро сориентировать по вариантам и условиям."
    return "Вижу ваш вопрос. Я Фёдор, занимаюсь недвижимостью и сделками в Буэнос-Айресе. Если актуально, напишите в личку — постараюсь быстро подсказать по делу."

def dm_link(username, draft):
    if not username:
        return None
    return "https://t.me/" + username.lstrip("@") + "?text=" + quote(draft, safe="")

if __name__ == "__main__":
    import sys
    query = " ".join(sys.argv[1:]) or "аренда студия Палермо до 700 USD"
    for r in search(query, limit=10):
        print(brief(r))
        print(r["item"].get("sourceUrl"))
        print()
