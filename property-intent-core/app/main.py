from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import unicodedata
from datetime import UTC, datetime
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode
from uuid import UUID, uuid4

import httpx
from fastapi import Depends, FastAPI, Header, HTTPException, Query
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import BigInteger, Boolean, DateTime, ForeignKey, Index, JSON, String, UniqueConstraint, create_engine, select, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str
    service_key: str
    telegram_bot_token: str
    telegram_bot_username: str = "LeBleuArgentinaBot"
    operator_chat_id: str = ""
    growth_core_url: str = "http://growth-core-api:8080"
    growth_core_key: str
    growth_tenant: str = "lebleu"
    brand_name: str = "Le Bleu"
    crm_source: str = "lebleu_miniapp"
    crm_saved_search_type: str = "property_saved_search"
    miniapp_url: str = "https://lebleu-app.srv1636153.hstgr.cloud"
    crm_base_url: str = ""
    crm_api_key: str = ""
    catalog_path: str = "/data/catalog.json"
    quality_path: str = "/data/quality.json"
    geo_enrichment_path: str = "/data/geo-enrichment.json"
    caba_barrios_path: str = "/srv/data/reference/caba-barrios.geojson"
    init_data_max_age_seconds: int = 86400
    test_telegram_ids: str = ""


settings = Settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class SavedSearch(Base):
    __tablename__ = "saved_searches"
    __table_args__ = (
        UniqueConstraint("tenant", "telegram_user_id", "fingerprint", name="uq_saved_search_identity"),
        Index("ix_saved_search_active", "tenant", "active", "notify"),
    )
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    telegram_user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(64))
    tracking_token: Mapped[str | None] = mapped_column(String(24), nullable=True)
    label: Mapped[str] = mapped_column(String(255))
    criteria_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    notify: Mapped[bool] = mapped_column(Boolean, default=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    crm_contact_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    crm_opportunity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)


class SavedSearchMatch(Base):
    __tablename__ = "saved_search_matches"
    __table_args__ = (
        UniqueConstraint("search_id", "listing_code", "source_fingerprint", name="uq_saved_match_version"),
        Index("ix_saved_match_search", "search_id", "first_seen_at"),
    )
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    search_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("saved_searches.id", ondelete="CASCADE"), index=True)
    listing_code: Mapped[str] = mapped_column(String(120))
    source_fingerprint: Mapped[str] = mapped_column(String(80))
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


# Text aliases are a fallback. When coordinates fall inside CABA, the official
# Buenos Aires Data barrio polygon is authoritative and these hints are ignored.
CABA_TEXT_ALIASES = {
    "palermo": ["palermo", "botanico", "botánico", "las cañitas", "las canitas"],
    "recoleta": ["recoleta", "barrio norte"],
    "belgrano": ["belgrano"],
    "nunez": ["núñez", "nunez", "nuñez"],
    "colegiales": ["colegiales", "coleiales"],
    "villa urquiza": ["villa urquiza"],
    "caballito": ["caballito"],
    "chacarita": ["chacarita"],
    "villa crespo": ["villa crespo"],
    "barracas": ["barracas"],
    "balvanera": ["balvanera", "congreso"],
    "san nicolas": ["san nicolás", "san nicolas", "microcentro"],
    "retiro": ["retiro"],
    "puerto madero": ["puerto madero"],
    "almagro": ["almagro"],
    "san telmo": ["san telmo"],
    "saavedra": ["saavedra"],
    "parque chas": ["parque chas"],
    "villa devoto": ["villa devoto"],
    "villa del parque": ["villa del parque"],
    "villa santa rita": ["villa santa rita"],
    "monte castro": ["monte castro"],
    "flores": ["flores"],
    "floresta": ["floresta"],
    "boedo": ["boedo"],
    "san cristobal": ["san cristóbal", "san cristobal"],
}

# Explicit non-CABA locality/project names. Avoid generic street names here:
# zero location is better than assigning a property to the wrong market.
OUTSIDE_LOCATION_ALIASES = {
    "la plata": ["la plata"],
    "city bell": ["city bell"],
    "olivos": ["olivos"],
    "martinez": ["martínez", "martinez"],
    "la martona": ["la martona"],
    "canuelas": ["cañuelas", "canuelas"],
    "carabassa": ["carabassa"],
    "ingeniero maschwitz": ["ingeniero maschwitz"],
    "pilar": ["pilar centro", " pilar ", "duplex en pilar"],
    "escobar": ["escobar", "puertos de escobar"],
    "aranzazu": ["aranzazu"],
    "nordelta": ["nordelta"],
    "san isidro": ["san isidro"],
    "lomas de zamora": ["lomas de zamora"],
    "longchamps": ["longchamps"],
    "general rodriguez": ["general rodriguez", "general rodríguez"],
    "florida": ["florida v lopez", "florida vicente lopez", "florida vicente lópez"],
    "mar del plata": ["mar del plata"],
    "mar de las pampas": ["mar de las pampas"],
    "villa gesell": ["villa gesell"],
    "lobos": ["lobos"],
    "dolores": ["dolores provincia", "dolores"],
    "navarro": ["navarro"],
}
DESCRIPTION_LOCATION_ALIASES = {
    # High-specificity names that are safe to accept from the listing prose.
    "martinez": ["martínez", "martinez"],
    "la martona": ["la martona"],
    "canuelas": ["cañuelas", "canuelas"],
    "carabassa": ["carabassa"],
    "ingeniero maschwitz": ["ingeniero maschwitz"],
}

# Verified parent-market relationships for named projects/localities. These make
# specific searches useful while preventing a bad source-map pin from inventing
# a contradictory municipality.
LOCATION_PARENT = {
    "olivos": "vicente lopez",
    "martinez": "san isidro",
    "la martona": "canuelas",
    "carabassa": "pilar",
    "ingeniero maschwitz": "escobar",
    "aranzazu": "escobar",
    "city bell": "la plata",
    "mar de las pampas": "villa gesell",
    "longchamps": "almirante brown",
    "florida": "vicente lopez",
    "nordelta": "tigre",
}

FEATURE_ALIASES = {
    "balcon": ["balcón", "balcon"],
    "pileta": ["pileta", "piscina"],
    "parrilla": ["parrilla"],
    "cochera": ["cochera", "garage", "garaje"],
    "amoblado": ["amoblado", "amueblado"],
    "laundry": ["laundry", "lavadero"],
    "aire": ["aire acondicionado"],
    "terraza": ["terraza"],
}


class SessionIn(BaseModel):
    init_data: str


class SavedSearchIn(BaseModel):
    init_data: str
    criteria: dict[str, Any]
    label: str | None = Field(default=None, max_length=255)
    notify: bool = False
    link_token: str | None = Field(default=None, max_length=24)


class EventIn(BaseModel):
    init_data: str
    event_name: str
    listing_code: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    link_token: str | None = Field(default=None, max_length=24)


class ActionIn(BaseModel):
    init_data: str
    listing_code: str
    action: str
    link_token: str | None = Field(default=None, max_length=24)


def db():
    with SessionLocal() as session:
        yield session


def _norm(value: Any) -> str:
    value = str(value or "").lower().replace("ё", "е")
    # Slugs and source URLs encode neighbourhoods with hyphens. Normalize all
    # punctuation to spaces so "villa-crespo" and "Villa Crespo" match identically.
    value = re.sub(r"[^a-záéíóúñüа-я0-9]+", " ", value)
    return " ".join(value.split())


def _canonical_location(value: str) -> str:
    normalized = unicodedata.normalize("NFKD", value)
    asciiish = "".join(ch for ch in normalized if not unicodedata.combining(ch))
    asciiish = re.sub(r"[^a-zA-Z0-9]+", " ", asciiish).lower()
    return " ".join(asciiish.split())


@lru_cache(maxsize=1)
def _caba_features() -> list[dict[str, Any]]:
    data = _load_json(settings.caba_barrios_path, {})
    features = data.get("features") if isinstance(data, dict) else []
    return features if isinstance(features, list) else []


def _point_in_ring(longitude: float, latitude: float, ring: list[list[float]]) -> bool:
    inside = False
    if len(ring) < 3:
        return False
    j = len(ring) - 1
    for i, point in enumerate(ring):
        xi, yi = float(point[0]), float(point[1])
        xj, yj = float(ring[j][0]), float(ring[j][1])
        crosses = (yi > latitude) != (yj > latitude)
        if crosses:
            x_at_lat = (xj - xi) * (latitude - yi) / (yj - yi) + xi
            if longitude < x_at_lat:
                inside = not inside
        j = i
    return inside


def _point_in_polygon(longitude: float, latitude: float, coordinates: list[Any]) -> bool:
    if not coordinates or not _point_in_ring(longitude, latitude, coordinates[0]):
        return False
    return not any(_point_in_ring(longitude, latitude, hole) for hole in coordinates[1:])


def _caba_barrio(longitude: float, latitude: float) -> str | None:
    # Cheap bounding box first: avoids polygon work for GBA / Provincia inventory.
    if not (-58.55 <= longitude <= -58.33 and -34.71 <= latitude <= -34.52):
        return None
    for feature in _caba_features():
        geometry = feature.get("geometry") or {}
        coordinates = geometry.get("coordinates") or []
        kind = geometry.get("type")
        hit = False
        if kind == "Polygon":
            hit = _point_in_polygon(longitude, latitude, coordinates)
        elif kind == "MultiPolygon":
            hit = any(_point_in_polygon(longitude, latitude, polygon) for polygon in coordinates)
        if hit:
            name = str((feature.get("properties") or {}).get("nombre") or "").strip()
            return _canonical_location(name) if name else None
    return None


def _alias_matches(blob: str, aliases_by_name: dict[str, list[str]]) -> list[str]:
    padded = f" {blob} "
    matches: list[str] = []
    for name, aliases in aliases_by_name.items():
        if any(f" {_norm(alias)} " in padded for alias in aliases):
            matches.append(name)
    return matches


def _load_json(path: str, fallback: Any):
    try:
        return json.loads(Path(path).read_text(encoding="utf-8"))
    except Exception:
        return fallback


_catalog_cache: dict[str, Any] = {
    "mtime": 0.0,
    "quality_mtime": 0.0,
    "geo_mtime": 0.0,
    "items": [],
}


def _catalog() -> list[dict[str, Any]]:
    try:
        mtime = os.path.getmtime(settings.catalog_path)
        qtime = os.path.getmtime(settings.quality_path)
    except OSError:
        return []
    try:
        gtime = os.path.getmtime(settings.geo_enrichment_path)
    except OSError:
        gtime = 0.0
    if (
        _catalog_cache["items"]
        and _catalog_cache["mtime"] == mtime
        and _catalog_cache["quality_mtime"] == qtime
        and _catalog_cache["geo_mtime"] == gtime
    ):
        return _catalog_cache["items"]
    raw = _load_json(settings.catalog_path, [])
    quality = _load_json(settings.quality_path, {})
    geo_payload = _load_json(settings.geo_enrichment_path, {})
    geo_entries = geo_payload.get("entries", {}) if isinstance(geo_payload, dict) else {}
    items: list[dict[str, Any]] = []
    for src in raw:
        q = quality.get(src.get("sourceUrl")) or {}
        current = not q.get("sourceFingerprint") or q.get("sourceFingerprint") == src.get("sourceFingerprint")
        details = dict(src.get("details") or {})
        if current:
            details.update(q.get("details_override") or {})
        ptype = (q.get("property_type_override") if current else None) or src.get("propertyType")
        item = {
            "code": src.get("code"),
            "operation": src.get("operation"),
            "propertyType": ptype,
            "address": src.get("address"),
            "priceAmount": src.get("priceAmount"),
            "priceCurrency": src.get("priceCurrency"),
            "details": details,
            "highlightedFeatures": src.get("highlightedFeatures") or [],
            "description": (q.get("summary_ru") if current else None) or src.get("description") or "",
            "notes": (q.get("notes_ru") if current else []) or [],
            # Keep the complete source gallery for the detail endpoint. The
            # catalogue summary below still returns only the first image, so list
            # payloads stay light while “all photos” really means all photos.
            "images": src.get("imageUrls") or [],
            "sourceUrl": src.get("sourceUrl"),
            "slug": src.get("slug"),
            "latitude": src.get("latitude"),
            "longitude": src.get("longitude"),
            "geo": geo_entries.get(src.get("sourceUrl")) or {},
            "sourceFingerprint": src.get("sourceFingerprint") or "",
        }
        item["neighborhoods"] = _listing_neighborhoods(item)
        item["listingToken"] = _listing_token(item)
        items.append(item)
    _catalog_cache.update({
        "mtime": mtime,
        "quality_mtime": qtime,
        "geo_mtime": gtime,
        "items": items,
    })
    return items


def _listing_token(item: dict[str, Any]) -> str:
    source = str(item.get("sourceUrl") or "")
    suffix = hashlib.sha256(source.encode()).hexdigest()[:8]
    return f"{item.get('code')}_{suffix}"


def _listing_neighborhoods(item: dict[str, Any]) -> list[str]:
    primary_blob = _norm(" ".join([
        str(item.get("address") or ""),
        str(item.get("slug") or ""),
    ]))
    prose_blob = _norm(" ".join([
        primary_blob,
        str(item.get("description") or ""),
    ]))
    latitude = _safe_num(item.get("latitude"))
    longitude = _safe_num(item.get("longitude"))

    if latitude is not None and longitude is not None:
        official = _caba_barrio(longitude, latitude)
        if official:
            return [official]

        # Coordinates prove the listing is outside CABA. Preserve a specific
        # project/locality hint (Nordelta, Aranzazu, etc.) and add the official
        # Georef local government so broader searches still find the property.
        locations = list(dict.fromkeys(
            _alias_matches(primary_blob, OUTSIDE_LOCATION_ALIASES)
            + _alias_matches(prose_blob, DESCRIPTION_LOCATION_ALIASES)
        ))
        expected_parents = {
            LOCATION_PARENT[name]
            for name in locations
            if name in LOCATION_PARENT
        }
        locations.extend(sorted(expected_parents))

        geo = item.get("geo") or {}
        government = str(geo.get("localGovernment") or geo.get("department") or "").strip()
        if government:
            canonical = _canonical_location(government)
            if canonical and not canonical.startswith("comuna "):
                # If a named project/locality has a verified parent market, reject
                # a conflicting map pin instead of showing a false municipality.
                if not expected_parents or canonical in expected_parents:
                    locations.append(canonical)
        return list(dict.fromkeys(locations))

    # Legacy/source pages without coordinates: conservative textual fallback.
    return list(dict.fromkeys(
        _alias_matches(primary_blob, CABA_TEXT_ALIASES)
        + _alias_matches(primary_blob, OUTSIDE_LOCATION_ALIASES)
        + _alias_matches(prose_blob, DESCRIPTION_LOCATION_ALIASES)
    ))


def _listing_blob(item: dict[str, Any]) -> str:
    return _norm(" ".join([
        str(item.get("address") or ""),
        str(item.get("description") or ""),
        " ".join(item.get("highlightedFeatures") or []),
        str(item.get("slug") or ""),
    ]))


def _safe_num(value: Any) -> float | None:
    try:
        return float(value)
    except Exception:
        return None


def _match(item: dict[str, Any], criteria: dict[str, Any]) -> bool:
    op = criteria.get("operation")
    if op and item.get("operation") != op:
        return False
    ptypes = set(criteria.get("propertyTypes") or [])
    if ptypes and item.get("propertyType") not in ptypes:
        return False
    hoods = set(criteria.get("neighborhoods") or [])
    if hoods and not hoods.intersection(item.get("neighborhoods") or []):
        return False
    d = item.get("details") or {}
    rooms = criteria.get("rooms")
    if rooms and int(d.get("rooms") or 0) != int(rooms):
        return False
    bedrooms = criteria.get("bedrooms")
    if bedrooms and int(d.get("bedrooms") or 0) != int(bedrooms):
        return False
    min_area = _safe_num(criteria.get("minArea"))
    if min_area and _safe_num(d.get("totalAreaM2") or d.get("coveredAreaM2") or 0) < min_area:
        return False
    max_area = _safe_num(criteria.get("maxArea"))
    if max_area and _safe_num(d.get("totalAreaM2") or d.get("coveredAreaM2") or 0) > max_area:
        return False
    budget = _safe_num(criteria.get("maxBudget"))
    currency = criteria.get("budgetCurrency")
    if budget:
        price = _safe_num(item.get("priceAmount"))
        if not price or item.get("priceCurrency") != currency or price > budget:
            return False
    blob = _listing_blob(item)
    for feature in criteria.get("features") or []:
        aliases = FEATURE_ALIASES.get(feature, [feature])
        if not any(alias in blob for alias in aliases):
            return False
    query = _norm(criteria.get("query"))
    if query:
        tokens = [x for x in re.findall(r"[a-záéíóúñüа-я0-9]{3,}", query) if x not in {"квартира", "квартиру", "дом", "ищу", "нужна"}]
        if tokens and not any(token in blob for token in tokens):
            return False
    return True


def _search(criteria: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [item for item in _catalog() if _match(item, criteria)]
    rows.sort(key=lambda item: (_safe_num(item.get("priceAmount")) or 10**18, item.get("code") or ""))
    return rows


def _validate_init_data(raw: str) -> dict[str, Any]:
    if not raw:
        raise HTTPException(status_code=401, detail="Telegram authorization required")
    pairs = dict(parse_qsl(raw, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")
    pairs.pop("signature", None)
    if not received_hash:
        raise HTTPException(status_code=401, detail="Missing Telegram hash")
    data_check = "\n".join(f"{key}={value}" for key, value in sorted(pairs.items()))
    secret = hmac.new(b"WebAppData", settings.telegram_bot_token.encode(), hashlib.sha256).digest()
    calculated = hmac.new(secret, data_check.encode(), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(calculated, received_hash):
        raise HTTPException(status_code=401, detail="Invalid Telegram signature")
    try:
        auth_date = int(pairs.get("auth_date") or "0")
    except ValueError:
        auth_date = 0
    now = int(datetime.now(UTC).timestamp())
    if not auth_date or now - auth_date > settings.init_data_max_age_seconds or auth_date > now + 60:
        raise HTTPException(status_code=401, detail="Expired Telegram authorization")
    try:
        user = json.loads(pairs.get("user") or "{}")
    except json.JSONDecodeError:
        user = {}
    if not user.get("id"):
        raise HTTPException(status_code=401, detail="Telegram user missing")
    return {"user": user, "start_param": pairs.get("start_param"), "raw": pairs}


def _is_test_user(user_id: int) -> bool:
    values = {
        int(part.strip())
        for part in settings.test_telegram_ids.split(",")
        if part.strip().lstrip("-").isdigit()
    }
    return user_id in values


def _growth_event(user_id: int, event_name: str, *, listing_token: str | None = None, properties: dict[str, Any] | None = None, link_token: str | None = None):
    payload = {
        "tenant": settings.growth_tenant,
        "event_name": event_name,
        "actor_external_id": user_id,
        "link_token": link_token,
        "listing_code": listing_token,
        "source": None if link_token else "telegram_miniapp",
        "medium": None if link_token else "owned",
        "campaign": None if link_token else "miniapp_catalog",
        "content": None if link_token else "app",
        "placement": None if link_token else "miniapp",
        "properties": properties or {},
        "is_test": _is_test_user(user_id),
    }
    try:
        httpx.post(
            f"{settings.growth_core_url.rstrip('/')}/v1/events",
            json=payload,
            headers={"X-Growth-Key": settings.growth_core_key},
            timeout=3.0,
        ).raise_for_status()
    except Exception:
        pass


@lru_cache(maxsize=4096)
def _growth_link(token: str | None) -> dict[str, Any] | None:
    if not token:
        return None
    try:
        response = httpx.get(
            f"{settings.growth_core_url.rstrip('/')}/v1/links/{token}",
            params={"tenant": settings.growth_tenant},
            headers={"X-Growth-Key": settings.growth_core_key},
            timeout=3.0,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _tracking_token(explicit: str | None, ctx: dict[str, Any]) -> str | None:
    start_param = str(ctx.get("start_param") or "")
    candidate = explicit or (start_param[4:] if start_param.startswith("trk_") else None)
    return candidate if candidate and _growth_link(candidate) else None


def _ensure_link(item: dict[str, Any], *, source: str, medium: str, campaign: str, content: str, placement: str) -> dict[str, Any] | None:
    try:
        response = httpx.post(
            f"{settings.growth_core_url.rstrip('/')}/v1/links/ensure",
            json={
                "tenant": settings.growth_tenant,
                "source": source,
                "medium": medium,
                "campaign": campaign,
                "content": content,
                "placement": placement,
                "listing_code": item["listingToken"],
                "intent": "listing",
                "bot_username": settings.telegram_bot_username,
                "metadata": {"code": item.get("code"), "source_url": item.get("sourceUrl")},
            },
            headers={"X-Growth-Key": settings.growth_core_key},
            timeout=3.0,
        )
        response.raise_for_status()
        return response.json()
    except Exception:
        return None


def _ensure_intent_link(
    *,
    source: str,
    medium: str,
    campaign: str,
    content: str,
    placement: str,
    intent: str,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any] | None:
    try:
        response = httpx.post(
            f"{settings.growth_core_url.rstrip('/')}/v1/links/ensure",
            json={
                "tenant": settings.growth_tenant,
                "source": source,
                "medium": medium,
                "campaign": campaign,
                "content": content,
                "placement": placement,
                "intent": intent,
                "bot_username": settings.telegram_bot_username,
                "metadata": metadata or {},
            },
            headers={"X-Growth-Key": settings.growth_core_key},
            timeout=3.0,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _bot_send(chat_id: int | str, text: str, reply_markup: dict[str, Any] | None = None) -> bool:
    try:
        response = httpx.post(
            f"https://api.telegram.org/bot{settings.telegram_bot_token}/sendMessage",
            json={
                "chat_id": chat_id,
                "text": text,
                "parse_mode": "HTML",
                "disable_web_page_preview": True,
                **({"reply_markup": reply_markup} if reply_markup else {}),
            },
            timeout=8.0,
        )
        response.raise_for_status()
        return bool(response.json().get("ok"))
    except Exception:
        return False


def _crm_post(path: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    base = settings.crm_base_url.rstrip("/")
    if not base or not settings.crm_api_key:
        return None
    try:
        response = httpx.post(
            f"{base}{path}",
            json=payload,
            headers={"X-API-Key": settings.crm_api_key},
            timeout=5.0,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _crm_sync_saved_search(row: SavedSearch, user: dict[str, Any], matches_now: int) -> None:
    if not settings.crm_base_url or not settings.crm_api_key:
        return
    user_id = int(user["id"])
    attribution = _growth_link(row.tracking_token) or {}
    display_name = " ".join(
        part for part in [user.get("first_name"), user.get("last_name")] if part
    ) or user.get("username") or f"Telegram {user_id}"
    if not row.crm_contact_id:
        contact = _crm_post(
            "/v1/contacts/upsert",
            {
                "display_name": display_name,
                "identity": {
                    "channel": "telegram",
                    "value": str(user_id),
                    "external_id": str(user_id),
                    "verified": True,
                    "is_primary": True,
                },
                "preferred_language": "ru",
                "relationship_stage": "lead",
                "priority": "medium",
                "summary_current": f"{settings.brand_name} Mini App. Сохранённый поиск: {row.label}",
            },
        )
        if contact and contact.get("id"):
            row.crm_contact_id = str(contact["id"])
    if row.crm_contact_id and not row.crm_opportunity_id:
        opportunity = _crm_post(
            "/v1/opportunities",
            {
                "name": f"{settings.brand_name} · сохранённый поиск · {row.label}"[:255],
                "type": settings.crm_saved_search_type,
                "stage": "qualifying",
                "contact_id": row.crm_contact_id,
                "probability": 60,
                "source": settings.crm_source,
                "next_action": "Просмотреть критерии сохранённого поиска и реагировать на новые совпадения",
                "summary_current": f"{row.label}. Совпадений сейчас: {matches_now}. Уведомления: {'да' if row.notify else 'нет'}.",
                "extra_json": {
                    "saved_search_id": str(row.id),
                    "criteria": row.criteria_json,
                    "telegram_user_id": user_id,
                    "telegram_username": user.get("username"),
                    "notification_opt_in": row.notify,
                    "source": settings.crm_source,
                    "tracking_token": row.tracking_token,
                    "tracking_source": attribution.get("source"),
                    "tracking_medium": attribution.get("medium"),
                    "tracking_campaign": attribution.get("campaign"),
                    "tracking_content": attribution.get("content"),
                    "tracking_placement": attribution.get("placement"),
                },
            },
        )
        if opportunity and opportunity.get("id"):
            row.crm_opportunity_id = str(opportunity["id"])


def _label(criteria: dict[str, Any]) -> str:
    bits = []
    if criteria.get("operation"):
        bits.append("Покупка" if criteria["operation"] == "Venta" else "Аренда")
    hoods = criteria.get("neighborhoods") or []
    if hoods:
        bits.append(", ".join(x.title() for x in hoods[:3]))
    if criteria.get("rooms"):
        bits.append(f"{criteria['rooms']} комн.")
    if criteria.get("maxBudget"):
        cur = criteria.get("budgetCurrency") or "USD"
        bits.append(f"до {cur} {criteria['maxBudget']}")
    return " · ".join(bits) or "Мой поиск"


def _criteria_fingerprint(criteria: dict[str, Any]) -> str:
    normalized = json.dumps(criteria, sort_keys=True, ensure_ascii=False, separators=(",", ":"))
    return hashlib.sha256(normalized.encode()).hexdigest()


app = FastAPI(title="Property Intent Core", version="0.1.0")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    # Tiny additive migrations keep the pilot deployable without destructive resets.
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS crm_contact_id VARCHAR(80)"))
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS crm_opportunity_id VARCHAR(80)"))
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS tracking_token VARCHAR(24)"))


@app.get("/health")
def health():
    return {"status": "ok", "service": "property-intent-core", "version": "0.1.0"}


def _catalog_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "code": item.get("code"),
        "operation": item.get("operation"),
        "propertyType": item.get("propertyType"),
        "address": item.get("address"),
        "priceAmount": item.get("priceAmount"),
        "priceCurrency": item.get("priceCurrency"),
        "details": item.get("details") or {},
        "highlightedFeatures": (item.get("highlightedFeatures") or [])[:5],
        "description": "",
        "notes": [],
        "images": (item.get("images") or [])[:1],
        "photoCount": len(item.get("images") or []),
        "sourceUrl": item.get("sourceUrl"),
        "neighborhoods": item.get("neighborhoods") or [],
        "listingToken": item.get("listingToken"),
    }


@app.get("/v1/catalog")
def catalog():
    items = _catalog()
    return {
        "generatedAt": datetime.now(UTC).isoformat(),
        "count": len(items),
        "operations": {
            "Venta": sum(1 for x in items if x.get("operation") == "Venta"),
            "Alquiler": sum(1 for x in items if x.get("operation") == "Alquiler"),
        },
        "neighborhoods": sorted({hood for x in items for hood in x.get("neighborhoods", [])}),
        "items": [_catalog_summary(item) for item in items],
    }


@app.get("/v1/catalog/{code}")
def catalog_detail(code: str):
    item = next((x for x in _catalog() if x.get("code") == code), None)
    if not item:
        raise HTTPException(status_code=404, detail="Listing not found")
    return {**item, "photoCount": len(item.get("images") or [])}


@app.post("/v1/session")
def session(body: SessionIn):
    ctx = _validate_init_data(body.init_data)
    user = ctx["user"]
    return {"ok": True, "user": {"id": user["id"], "first_name": user.get("first_name"), "username": user.get("username")}}


@app.post("/v1/events")
def capture_event(body: EventIn):
    allowed = {
        "catalog_opened",
        "listing_opened",
        "gallery_opened",
        "search_started",
        "search_submitted",
        "share_clicked",
        "notification_clicked",
    }
    if body.event_name not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported event")
    ctx = _validate_init_data(body.init_data)
    item = next((x for x in _catalog() if x.get("code") == body.listing_code), None) if body.listing_code else None
    link_token = _tracking_token(body.link_token, ctx)
    user_id = int(ctx["user"]["id"])
    _growth_event(
        user_id,
        body.event_name,
        listing_token=item.get("listingToken") if item else None,
        properties=body.properties,
        link_token=link_token,
    )
    if body.event_name == "catalog_opened" and link_token:
        attribution = _growth_link(link_token) or {}
        if attribution.get("source") == "saved_search":
            _growth_event(
                user_id,
                "notification_clicked",
                listing_token=item.get("listingToken") if item else None,
                properties={"via": "miniapp"},
                link_token=link_token,
            )
    return {"ok": True}


@app.post("/v1/actions")
def action(body: ActionIn):
    ctx = _validate_init_data(body.init_data)
    item = next((x for x in _catalog() if x.get("code") == body.listing_code), None)
    if not item:
        raise HTTPException(status_code=404, detail="Listing not found")
    event_map = {
        "availability": "availability_requested",
        "viewing": "viewing_requested",
        "question": "question_submitted",
        "similar": "search_started",
    }
    event = event_map.get(body.action)
    if not event:
        raise HTTPException(status_code=422, detail="Unsupported action")
    acquisition_token = _tracking_token(body.link_token, ctx)
    attribution = _growth_link(acquisition_token) if acquisition_token else None
    link = _ensure_link(
        item,
        source=str((attribution or {}).get("source") or "telegram_miniapp"),
        medium=str((attribution or {}).get("medium") or "owned"),
        campaign=str((attribution or {}).get("campaign") or "miniapp_catalog"),
        content=body.action,
        placement="miniapp_listing_detail",
    )
    _growth_event(
        int(ctx["user"]["id"]),
        event,
        listing_token=item["listingToken"],
        properties={"action": body.action},
        link_token=(link or {}).get("token"),
    )
    fallback = f"https://t.me/{settings.telegram_bot_username}?start=lb_{item['listingToken']}"
    return {"ok": True, "telegram_url": (link or {}).get("telegram_url") or fallback}


@app.get("/v1/saved-searches")
def list_saved_searches(init_data: str = Query(...), session: Session = Depends(db)):
    ctx = _validate_init_data(init_data)
    user_id = int(ctx["user"]["id"])
    rows = list(session.scalars(select(SavedSearch).where(
        SavedSearch.tenant == settings.growth_tenant,
        SavedSearch.telegram_user_id == user_id,
        SavedSearch.active.is_(True),
    ).order_by(SavedSearch.created_at.desc())))
    return {"items": [{
        "id": str(row.id),
        "label": row.label,
        "criteria": row.criteria_json,
        "notify": row.notify,
        "createdAt": row.created_at.isoformat(),
    } for row in rows]}


@app.post("/v1/saved-searches")
def save_search(body: SavedSearchIn, session: Session = Depends(db)):
    ctx = _validate_init_data(body.init_data)
    user = ctx["user"]
    user_id = int(user["id"])
    tracking_token = _tracking_token(body.link_token, ctx)
    criteria = body.criteria
    if not any([
        criteria.get("neighborhoods"),
        criteria.get("maxBudget"),
        criteria.get("rooms"),
        criteria.get("bedrooms"),
        criteria.get("propertyTypes"),
        criteria.get("features"),
        criteria.get("query"),
    ]):
        raise HTTPException(status_code=422, detail="Add at least one search criterion")
    fp = _criteria_fingerprint(criteria)
    row = session.scalar(select(SavedSearch).where(
        SavedSearch.tenant == settings.growth_tenant,
        SavedSearch.telegram_user_id == user_id,
        SavedSearch.fingerprint == fp,
    ))
    now = datetime.now(UTC)
    if row is None:
        row = SavedSearch(
            tenant=settings.growth_tenant,
            telegram_user_id=user_id,
            username=user.get("username"),
            display_name=" ".join(x for x in [user.get("first_name"), user.get("last_name")] if x) or user.get("username"),
            fingerprint=fp,
            tracking_token=tracking_token,
            label=(body.label or _label(criteria))[:255],
            criteria_json=criteria,
            notify=body.notify,
            active=True,
        )
        session.add(row)
        session.flush()
        # Existing inventory is the baseline. Only future listing versions can trigger a notification.
        for item in _search(criteria):
            session.add(SavedSearchMatch(
                search_id=row.id,
                listing_code=item.get("code") or "",
                source_fingerprint=item.get("sourceFingerprint") or "",
                first_seen_at=now,
                notified_at=now,
            ))
    else:
        row.notify = body.notify
        row.active = True
        row.updated_at = now
        row.label = (body.label or row.label)[:255]
        if not row.tracking_token and tracking_token:
            row.tracking_token = tracking_token
    matches_now = len(_search(criteria))
    session.flush()
    if not _is_test_user(user_id):
        _crm_sync_saved_search(row, user, matches_now)
    session.commit()
    _growth_event(
        user_id,
        "search_submitted",
        properties={"saved_search_id": str(row.id), "matches_now": matches_now},
        link_token=row.tracking_token,
    )
    if body.notify:
        _growth_event(
            user_id,
            "notification_opt_in",
            properties={"saved_search_id": str(row.id)},
            link_token=row.tracking_token,
        )
    _growth_event(
        user_id,
        "lead_qualified",
        properties={"lead_kind": "saved_search", "saved_search_id": str(row.id)},
        link_token=row.tracking_token,
    )
    if settings.operator_chat_id and not _is_test_user(user_id):
        who = f"@{user.get('username')}" if user.get("username") else (row.display_name or str(user_id))
        _bot_send(
            settings.operator_chat_id,
            f"🔎 <b>Сохранённый поиск {settings.brand_name}</b>\n"
            f"{who}\n{row.label}\n"
            f"Сейчас в каталоге: {matches_now}\n"
            f"Уведомления: {'да' if body.notify else 'нет'}",
        )
    return {"ok": True, "id": str(row.id), "label": row.label, "matches_now": matches_now, "notify": row.notify}


@app.delete("/v1/saved-searches/{search_id}")
def disable_search(search_id: UUID, init_data: str = Query(...), session: Session = Depends(db)):
    ctx = _validate_init_data(init_data)
    user_id = int(ctx["user"]["id"])
    row = session.scalar(select(SavedSearch).where(
        SavedSearch.id == search_id,
        SavedSearch.tenant == settings.growth_tenant,
        SavedSearch.telegram_user_id == user_id,
    ))
    if not row:
        raise HTTPException(status_code=404, detail="Saved search not found")
    row.active = False
    row.updated_at = datetime.now(UTC)
    session.commit()
    return {"ok": True}


@app.post("/v1/internal/rematch")
def rematch(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    if not x_intent_key or not hmac.compare_digest(x_intent_key, settings.service_key):
        raise HTTPException(status_code=401, detail="Invalid intent key")
    searches = list(session.scalars(select(SavedSearch).where(
        SavedSearch.tenant == settings.growth_tenant,
        SavedSearch.active.is_(True),
        SavedSearch.notify.is_(True),
    )))
    notifications = 0
    new_matches = 0
    delivery_attempts = 0
    delivery_failures = 0
    for search in searches:
        pending: list[tuple[dict[str, Any], SavedSearchMatch]] = []
        for item in _search(search.criteria_json):
            # Notify once per listing code. A photo/text/source-fingerprint refresh must
            # not look like a new property. If Telegram delivery fails, keep the match
            # pending and retry on the next catalogue sync instead of silently losing it.
            match = session.scalar(select(SavedSearchMatch).where(
                SavedSearchMatch.search_id == search.id,
                SavedSearchMatch.listing_code == item.get("code"),
            ))
            if match and match.notified_at is not None:
                continue
            if match is None:
                match = SavedSearchMatch(
                    search_id=search.id,
                    listing_code=item.get("code") or "",
                    source_fingerprint=item.get("sourceFingerprint") or "",
                )
                session.add(match)
                session.flush()
                new_matches += 1
            pending.append((item, match))
        if not pending:
            continue
        chosen = [item for item, _ in pending[:3]]
        lines = ["✨ <b>Появились новые варианты по вашему поиску</b>", search.label, ""]
        keyboard = []
        catalog_link = _ensure_intent_link(
            source="saved_search",
            medium="owned",
            campaign="reactivation",
            content="saved_search",
            placement="telegram_notification",
            intent="saved_search",
            metadata={"saved_search_id": str(search.id)},
        )
        catalog_token = str((catalog_link or {}).get("token") or "")
        for item in chosen:
            price = f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}".strip()
            lines.append(f"• {item.get('address') or item.get('code')} · {price}")
            link = _ensure_link(
                item,
                source="saved_search",
                medium="owned",
                campaign="reactivation",
                content="new_match",
                placement="telegram_notification",
            )
            item_token = str((link or {}).get("token") or "")
            params = {"listing": str(item.get("code") or "")}
            if item_token:
                params["trk"] = item_token
            url = f"{settings.miniapp_url.rstrip('/')}?{urlencode(params)}"
            keyboard.append([{
                "text": f"Открыть {item.get('code')}",
                "web_app": {"url": url},
            }])
        if len(pending) > 3:
            lines.append(f"\nИ ещё {len(pending) - 3} новых.")
        catalog_params = {"saved": str(search.id)}
        if catalog_token:
            catalog_params["trk"] = catalog_token
        catalog_url = f"{settings.miniapp_url.rstrip('/')}?{urlencode(catalog_params)}"
        keyboard.append([{"text": "Открыть мой поиск", "web_app": {"url": catalog_url}}])
        delivery_attempts += 1
        sent = _bot_send(search.telegram_user_id, "\n".join(lines), {"inline_keyboard": keyboard})
        now = datetime.now(UTC)
        if sent:
            notifications += 1
            search.last_notified_at = now
            for _, match in pending:
                match.notified_at = now
            _growth_event(
                search.telegram_user_id,
                "notification_sent",
                properties={"saved_search_id": str(search.id), "new_matches": len(pending)},
                link_token=catalog_token or None,
            )
        else:
            delivery_failures += 1
    session.commit()
    return {
        "ok": True,
        "active_searches": len(searches),
        "new_matches": new_matches,
        "notifications": notifications,
        "delivery_attempts": delivery_attempts,
        "delivery_failures": delivery_failures,
    }
