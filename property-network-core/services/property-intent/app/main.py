from __future__ import annotations

import base64
import hashlib
import hmac
import html
import json
import os
import re
import secrets
import unicodedata
from datetime import UTC, datetime, timedelta
from functools import lru_cache
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlparse, urlsplit, urlunsplit
from uuid import UUID, uuid4

import httpx
from fastapi import BackgroundTasks, Depends, FastAPI, Header, HTTPException, Query, Request, Response
from fastapi.responses import RedirectResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import BigInteger, Boolean, DateTime, Float, ForeignKey, Index, Integer, JSON, String, UniqueConstraint, create_engine, func, select, text
from sqlalchemy.dialects.postgresql import UUID as PgUUID
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str
    service_key: str
    telegram_bot_token: str
    telegram_bot_username: str = "AgencyCatalogBot"
    operator_chat_id: str = ""
    # Customer messages use telegram_bot_token. Operator alerts use the private Revenue Radar bot when configured.
    operator_bot_token: str = ""
    operator_sla_minutes: int = 30
    operator_crm_url: str = "https://app.fiodor.ar/telegram-crm"
    operator_crm_tab: str = ""
    smoke_username: str = "property_network_smoke"
    growth_core_url: str = "http://growth-core-api:8080"
    growth_core_key: str
    growth_tenant: str = "default"
    brand_name: str = "Agency"
    brand_tagline: str = ""
    brand_logo_url: str = "/brand-logo.jpg"
    public_language_default: str = "ru"
    telegram_channel_url: str = ""
    attribution_campaign: str = "property_catalog"
    source_label: str = "original_source"
    share_footer: str = ""
    crm_source: str = "property_miniapp"
    crm_saved_search_type: str = "property_saved_search"
    miniapp_url: str = "https://catalog.example.com"
    marketplace_enabled: bool = False
    telegram_webhook_secret: str = ""
    deepl_api_key: str = ""
    libretranslate_url: str = ""
    libretranslate_api_key: str = ""
    vapid_public_key: str = ""
    vapid_private_key: str = ""
    vapid_subject: str = "mailto:admin@example.com"
    resend_api_key: str = ""
    auth_email_from: str = "Где жить <acceso@alqi.fiodor.ar>"
    auth_email_reply_to: str = "contact@fiodor.ar"
    person_auth_secret: str = ""
    crm_base_url: str = ""
    crm_api_key: str = ""
    crm_webhook_url: str = ""
    crm_webhook_secret: str = ""
    catalog_path: str = "/data/catalog.json"
    catalog_alias_path: str = "/data/catalog-aliases.json"
    source_registry_path: str = "/data/source-registry.json"
    quality_path: str = "/data/quality.json"
    geo_enrichment_path: str = "/data/geo-enrichment.json"
    ru_translations_path: str = "/data/state/ru-full-translations.json"
    en_translations_path: str = "/data/state/en-content.json"
    caba_barrios_path: str = "/srv/data/reference/caba-barrios.geojson"
    init_data_max_age_seconds: int = 86400
    test_telegram_ids: str = ""
    # Staff/operator accounts use the real product without becoming leads or polluting acquisition KPIs.
    internal_telegram_ids: str = ""
    # Optional human-workspace projection. Disabled until a separate Chatwoot host exists.
    chatwoot_enabled: bool = False
    chatwoot_base_url: str = ""
    chatwoot_account_id: int = 0
    chatwoot_api_inbox_id: int = 0
    chatwoot_api_token: str = ""
    chatwoot_webhook_secret: str = ""
    chatwoot_webhook_max_age_seconds: int = 300
    partner_handoff_ttl_minutes: int = 120
    rescue_warning_minutes: int = 10
    rescue_escalation_minutes: int = 30
    rescue_required_minutes: int = 60
    # Lightweight first-party browser workspace for human agents. Business state remains canonical here.
    agent_inbox_password: str = ""
    agent_session_hours: int = 12


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
    person_profile_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True, index=True)
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
    crm_webhook_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    crm_webhook_attempts: Mapped[int] = mapped_column(Integer, default=0)


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
    price_amount: Mapped[float | None] = mapped_column(Float, nullable=True)
    price_currency: Mapped[str | None] = mapped_column(String(8), nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)


class ListingAction(Base):
    __tablename__ = "listing_actions"
    __table_args__ = (
        Index("ix_listing_actions_inbox", "tenant", "is_test", "status", "created_at"),
        Index("ix_listing_actions_actor", "tenant", "telegram_user_id", "created_at"),
        Index("ix_listing_actions_listing", "tenant", "listing_token", "created_at"),
        Index("ix_listing_actions_routing", "tenant", "inventory_owner_tenant", "routing_mode", "created_at"),
    )
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    telegram_user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    person_profile_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), nullable=True, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    listing_token: Mapped[str] = mapped_column(String(120), index=True)
    listing_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    inventory_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inventory_owner_tenant: Mapped[str | None] = mapped_column(String(64), nullable=True)
    routing_mode: Mapped[str | None] = mapped_column(String(32), nullable=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    message: Mapped[str | None] = mapped_column(String(2000), nullable=True)
    tracking_token: Mapped[str | None] = mapped_column(String(24), nullable=True)
    listing_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    crm_opportunity_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    operator_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    user_confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    delivery_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class OutboundClick(Base):
    __tablename__ = "outbound_clicks"
    __table_args__ = (
        UniqueConstraint("tenant", "click_id", name="uq_outbound_click_tenant_click"),
        Index("ix_outbound_click_delivery", "tenant", "is_test", "status", "created_at"),
        Index("ix_outbound_click_actor", "tenant", "telegram_user_id", "created_at"),
        Index("ix_outbound_click_listing", "tenant", "listing_token", "created_at"),
    )
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    click_id: Mapped[str] = mapped_column(String(96))
    telegram_user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    listing_token: Mapped[str] = mapped_column(String(120), index=True)
    listing_code: Mapped[str | None] = mapped_column(String(120), nullable=True)
    inventory_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inventory_owner_tenant: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tracking_token: Mapped[str | None] = mapped_column(String(24), nullable=True)
    listing_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    status: Mapped[str] = mapped_column(String(32), default="new", index=True)
    growth_delivered_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    crm_fact_id: Mapped[str | None] = mapped_column(String(80), nullable=True)
    delivery_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


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

PROPERTY_TYPE_RU = {
    "Departamento": "Квартира",
    "Casa": "Дом",
    "PH": "PH",
    "Cochera": "Парковочное место",
    "Local Comercial": "Коммерческое помещение",
    "Local": "Коммерческое помещение",
    "Terreno o Lote": "Участок",
    "Terreno": "Участок",
    "Oficina": "Офис",
    "Depósito": "Склад",
}

FEATURE_RU = {
    "balcón": "балкон",
    "balcon": "балкон",
    "pileta": "бассейн",
    "piscina": "бассейн",
    "parrilla": "зона барбекю",
    "cochera": "парковочное место",
    "amoblado": "меблировка",
    "laundry": "прачечная",
    "aire acondicionado": "кондиционер",
    "terraza": "терраса",
    "jardín": "сад",
    "jardin": "сад",
    "gimnasio": "спортзал",
    "patio": "патио",
    "sum": "общий зал",
    "solarium": "солярий",
    "baulera": "кладовая",
    "quincho": "крытая зона барбекю",
    "apto crédito": "подходит под ипотеку",
    "apto credito": "подходит под ипотеку",
    "apto profesional": "подходит для профессионального использования",
    "calefacción": "отопление",
    "calefaccion": "отопление",
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
    "jardin": ["jardín", "jardin"],
    "gimnasio": ["gimnasio", "gym"],
    "patio": ["patio"],
    "sum": ["sum"],
    "solarium": ["solarium"],
    "baulera": ["baulera"],
    "quincho": ["quincho"],
    "apto_credito": ["apto crédito", "apto credito"],
    "apto_profesional": ["apto profesional"],
    "calefaccion": ["calefacción", "calefaccion"],
    "ascensor": ["ascensor"],
    "seguridad": ["seguridad 24", "seguridad las 24"],
    "a_estrenar": ["a estrenar"],
}


class SessionIn(BaseModel):
    init_data: str


class SavedSearchIn(BaseModel):
    init_data: str = ""
    session_token: str = ""
    criteria: dict[str, Any]
    label: str | None = Field(default=None, max_length=255)
    notify: bool = False
    link_token: str | None = Field(default=None, max_length=24)

class SavedSearchStateIn(BaseModel):
    init_data: str = ""
    session_token: str = ""
    notify: bool | None = None
    active: bool | None = None


class PushSubscriptionIn(BaseModel):
    init_data: str = ""
    session_token: str = ""
    subscription: dict[str, Any]

class EventIn(BaseModel):
    init_data: str
    event_name: str
    listing_code: str | None = None
    properties: dict[str, Any] = Field(default_factory=dict)
    link_token: str | None = Field(default=None, max_length=24)


class ActionIn(BaseModel):
    init_data: str = ""
    session_token: str = ""
    listing_code: str
    action: str
    message: str | None = Field(default=None, max_length=2000)
    link_token: str | None = Field(default=None, max_length=24)
    web_contact: dict[str, str] = Field(default_factory=dict)


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


def _structured_ru_fallback(src: dict[str, Any], details: dict[str, Any], property_type: str | None) -> str:
    title = PROPERTY_TYPE_RU.get(str(property_type or ""), "Объект недвижимости")
    operation = str(src.get("operation") or "")
    address = str(src.get("address") or "").strip()
    if operation == "Venta":
        opening = f"{title} на продажу"
    elif operation == "Alquiler":
        opening = f"{title} в аренду"
    else:
        opening = title
    if address:
        opening += f" по адресу {address}"
    parts = [opening + "."]

    def ru_count(value: Any, one: str, few: str, many: str) -> str:
        try:
            n = int(value)
        except (TypeError, ValueError):
            return ""
        n10, n100 = n % 10, n % 100
        word = many if 11 <= n100 <= 14 else one if n10 == 1 else few if 2 <= n10 <= 4 else many
        return f"{n} {word}"

    area = details.get("totalAreaM2") or details.get("coveredAreaM2")
    facts: list[str] = []
    if area:
        rendered = f"{area:g}" if isinstance(area, (int, float)) else str(area)
        facts.append(f"площадь {rendered} м²")
    if details.get("rooms"):
        facts.append(ru_count(details["rooms"], "комната", "комнаты", "комнат"))
    if details.get("bedrooms"):
        facts.append(ru_count(details["bedrooms"], "спальня", "спальни", "спален"))
    if details.get("bathrooms"):
        facts.append(ru_count(details["bathrooms"], "ванная", "ванные", "ванных"))
    if details.get("parkingSpaces"):
        facts.append(ru_count(details["parkingSpaces"], "парковочное место", "парковочных места", "парковочных мест"))
    facts = [x for x in facts if x]
    if facts:
        if len(facts) == 1:
            parts.append(f"Основной параметр: {facts[0]}.")
        else:
            parts.append("Параметры: " + ", ".join(facts[:-1]) + " и " + facts[-1] + ".")

    feature_names: list[str] = []
    for raw in src.get("highlightedFeatures") or []:
        translated = FEATURE_RU.get(str(raw).strip().lower())
        if translated and translated not in feature_names:
            feature_names.append(translated)
    if feature_names:
        selected = feature_names[:6]
        if len(selected) == 1:
            parts.append(f"Есть {selected[0].lower()}.")
        else:
            parts.append("Есть " + ", ".join(x.lower() for x in selected[:-1]) + " и " + selected[-1].lower() + ".")
    return " ".join(parts)


SOURCE_ID_RE = re.compile(r"^[a-z0-9][a-z0-9_-]{0,63}$")
SOURCE_TOKEN_STRATEGIES = {"legacy_source_url_v1", "source_local_v1"}
_source_registry_cache: dict[str, Any] = {"mtime": 0.0, "sources": {}}


def _source_registry() -> dict[str, dict[str, Any]]:
    try:
        mtime = os.path.getmtime(settings.source_registry_path)
    except OSError as exc:
        raise RuntimeError(f"Source registry unavailable: {settings.source_registry_path}") from exc
    if _source_registry_cache["sources"] and _source_registry_cache["mtime"] == mtime:
        return _source_registry_cache["sources"]
    payload = _load_json(settings.source_registry_path, {})
    raw_sources = payload.get("sources") if isinstance(payload, dict) else None
    if not isinstance(raw_sources, list) or not raw_sources:
        raise RuntimeError("Source registry must contain a non-empty sources array")
    sources: dict[str, dict[str, Any]] = {}
    slugs: set[str] = set()
    legacy_defaults = 0
    for raw in raw_sources:
        if not isinstance(raw, dict):
            raise RuntimeError("Every source registry entry must be an object")
        source_id = str(raw.get("sourceId") or "").strip()
        source_slug = str(raw.get("sourceSlug") or source_id).strip()
        owner_tenant = str(raw.get("ownerTenant") or "").strip()
        adapter_type = str(raw.get("adapterType") or "").strip()
        display_name = str(raw.get("displayName") or source_slug or source_id).strip()
        token_strategy = str(raw.get("listingTokenStrategy") or "source_local_v1").strip()
        lead_routing = str(raw.get("leadRouting") or "inventory_owner").strip()
        if not SOURCE_ID_RE.fullmatch(source_id):
            raise RuntimeError(f"Invalid sourceId: {source_id!r}")
        if not SOURCE_ID_RE.fullmatch(source_slug):
            raise RuntimeError(f"Invalid sourceSlug: {source_slug!r}")
        if not owner_tenant or not SOURCE_ID_RE.fullmatch(owner_tenant):
            raise RuntimeError(f"Invalid ownerTenant for source {source_id}")
        if not adapter_type:
            raise RuntimeError(f"adapterType is required for source {source_id}")
        if token_strategy not in SOURCE_TOKEN_STRATEGIES:
            raise RuntimeError(f"Unsupported listingTokenStrategy for source {source_id}: {token_strategy}")
        if lead_routing != "inventory_owner":
            raise RuntimeError(f"Unsupported leadRouting for source {source_id}: {lead_routing}")
        if source_id in sources or source_slug in slugs:
            raise RuntimeError(f"Duplicate source identity: {source_id}/{source_slug}")
        legacy_default = bool(raw.get("legacyDefault"))
        legacy_defaults += int(legacy_default)
        record = {
            "sourceId": source_id,
            "sourceSlug": source_slug,
            "displayName": display_name,
            "ownerTenant": owner_tenant,
            "adapterType": adapter_type,
            "active": bool(raw.get("active", True)),
            "leadRouting": lead_routing,
            "listingTokenStrategy": token_strategy,
            "legacyDefault": legacy_default,
            "websiteUrl": str(raw.get("websiteUrl") or "").strip(),
            "baseUrl": str(raw.get("baseUrl") or "").strip(),
            "importMode": str(raw.get("importMode") or "").strip(),
        }
        sources[source_id] = record
        slugs.add(source_slug)
    if legacy_defaults > 1:
        raise RuntimeError("Source registry may define at most one legacyDefault source")
    _source_registry_cache.update({"mtime": mtime, "sources": sources})
    return sources


def _public_source(source: dict[str, Any]) -> dict[str, Any]:
    return {
        "sourceId": source["sourceId"],
        "sourceSlug": source["sourceSlug"],
        "displayName": source["displayName"],
        "ownerTenant": source["ownerTenant"],
        "adapterType": source["adapterType"],
        "importMode": source.get("importMode") or "",
        "active": bool(source["active"]),
    }


def _source_for_raw_listing(src: dict[str, Any]) -> dict[str, Any]:
    sources = _source_registry()
    explicit = str(src.get("sourceId") or "").strip()
    if explicit:
        source = sources.get(explicit)
        if source is None:
            raise RuntimeError(f"Unknown sourceId in catalog: {explicit}")
        if not source.get("active"):
            raise RuntimeError(f"Inactive sourceId in catalog: {explicit}")
    else:
        defaults = [source for source in sources.values() if source.get("legacyDefault")]
        if len(defaults) != 1:
            raise RuntimeError("Catalog listing without sourceId requires exactly one legacyDefault source")
        source = defaults[0]
    if not source.get("active"):
        raise RuntimeError(f"Catalog references inactive source: {source['sourceId']}")
    return source


def _source_local_id(src: dict[str, Any], source: dict[str, Any]) -> str:
    explicit = str(src.get("sourceLocalId") or "").strip()
    if explicit:
        return explicit
    code = str(src.get("code") or "").strip()
    if not code:
        return ""
    # Legacy catalogs can reuse the same agency code for sale and rent. Their
    # already-published URL-bound token supplies a stable per-listing suffix.
    if source["listingTokenStrategy"] == "legacy_source_url_v1":
        legacy_suffix = hashlib.sha256(str(src.get("sourceUrl") or "").encode()).hexdigest()[:8]
        return f"{code}_{legacy_suffix}"
    return code


def _global_listing_id(source_id: str, local_id: str) -> str:
    identity = f"{source_id}:{local_id}"
    return "listing_" + hashlib.sha256(identity.encode()).hexdigest()[:24]


def _routing_context(item: dict[str, Any], demand_tenant: str | None = None) -> dict[str, str]:
    demand = str(demand_tenant or settings.growth_tenant).strip()
    owner = str(item.get("inventoryOwnerTenant") or "").strip()
    source_id = str(item.get("sourceId") or "").strip()
    source_slug = str(item.get("sourceSlug") or "").strip()
    if not demand or not owner or not source_id:
        raise RuntimeError("Listing provenance is incomplete for routing")
    return {
        "demandTenant": demand,
        "relationshipOwnerTenant": demand,
        "inventorySourceId": source_id,
        "inventorySourceSlug": source_slug,
        "inventoryOwnerTenant": owner,
        "routingMode": "direct_inventory_owner" if demand == owner else "collaboration_required",
    }


def _listing_snapshot(item: dict[str, Any], demand_tenant: str | None = None) -> dict[str, Any]:
    snapshot = dict(item)
    snapshot["networkProvenance"] = _routing_context(item, demand_tenant)
    return snapshot


def _listing_from_snapshot(
    snapshot: dict[str, Any] | None,
    *,
    listing_token: str | None = None,
    listing_code: str | None = None,
) -> dict[str, Any] | None:
    """Rehydrate safe source provenance for inventory no longer in the live catalog.

    Source ownership comes from the registry. `sourceUrl` is used only by a legacy
    token strategy to reproduce the already-published local identity; its domain
    is never used to choose an owner.
    """
    if not isinstance(snapshot, dict) or not snapshot:
        return None
    item = dict(snapshot)
    if listing_code and not item.get("code"):
        item["code"] = listing_code
    try:
        source = _source_for_raw_listing(item)
    except RuntimeError:
        return None
    source_local_id = _source_local_id(item, source)
    if not source_local_id:
        return None
    item["sourceId"] = source["sourceId"]
    item["sourceSlug"] = source["sourceSlug"]
    item["sourceLocalId"] = source_local_id
    item["globalListingId"] = _global_listing_id(source["sourceId"], source_local_id)
    item["inventoryOwnerTenant"] = source["ownerTenant"]
    item["source"] = _public_source(source)
    item["listingToken"] = str(listing_token or item.get("listingToken") or _listing_token(item, source))
    return item


def _event_provenance(item: dict[str, Any]) -> dict[str, Any]:
    route = _routing_context(item)
    return {
        "global_listing_id": item.get("globalListingId"),
        "source_id": route["inventorySourceId"],
        "source_local_id": item.get("sourceLocalId"),
        "demand_tenant": route["demandTenant"],
        "relationship_owner_tenant": route["relationshipOwnerTenant"],
        "inventory_owner_tenant": route["inventoryOwnerTenant"],
        "routing_mode": route["routingMode"],
    }


_catalog_cache: dict[str, Any] = {
    "registry_mtime": 0.0,
    "mtime": 0.0,
    "quality_mtime": 0.0,
    "geo_mtime": 0.0,
    "translation_mtime": 0.0,
    "en_translation_mtime": 0.0,
    "items": [],
}


def _catalog() -> list[dict[str, Any]]:
    try:
        mtime = os.path.getmtime(settings.catalog_path)
        qtime = os.path.getmtime(settings.quality_path)
        registry_mtime = os.path.getmtime(settings.source_registry_path)
    except OSError:
        return []
    try:
        gtime = os.path.getmtime(settings.geo_enrichment_path)
    except OSError:
        gtime = 0.0
    try:
        ttime = os.path.getmtime(settings.ru_translations_path)
    except OSError:
        ttime = 0.0
    try:
        entime = os.path.getmtime(settings.en_translations_path)
    except OSError:
        entime = 0.0
    if (
        _catalog_cache["items"]
        and _catalog_cache["registry_mtime"] == registry_mtime
        and _catalog_cache["mtime"] == mtime
        and _catalog_cache["quality_mtime"] == qtime
        and _catalog_cache["geo_mtime"] == gtime
        and _catalog_cache["translation_mtime"] == ttime
        and _catalog_cache["en_translation_mtime"] == entime
    ):
        return _catalog_cache["items"]
    raw = _load_json(settings.catalog_path, [])
    quality = _load_json(settings.quality_path, {})
    translations = _load_json(settings.ru_translations_path, {})
    en_translations = _load_json(settings.en_translations_path, {})
    geo_payload = _load_json(settings.geo_enrichment_path, {})
    geo_entries = geo_payload.get("entries", {}) if isinstance(geo_payload, dict) else {}
    items: list[dict[str, Any]] = []
    for src in raw:
        source = _source_for_raw_listing(src)
        source_local_id = _source_local_id(src, source)
        if not source_local_id:
            raise RuntimeError(f"Listing from source {source['sourceId']} is missing sourceLocalId/code")
        q = quality.get(src.get("sourceUrl")) or {}
        reviewed_fp = q.get("ruContentFingerprint") or q.get("sourceFingerprint")
        current_fp = src.get("ruContentFingerprint") or src.get("sourceFingerprint")
        current = not reviewed_fp or reviewed_fp == current_fp
        source_description = str(src.get("description") or "").strip()
        translation = translations.get(src.get("sourceUrl")) or {}
        en_translation = en_translations.get(src.get("sourceUrl")) or {}
        translated_current = (
            translation.get("status") == "live_auto"
            and translation.get("fingerprint") == current_fp
            and str(translation.get("description_ru") or "").strip()
        )
        reviewed_summary = str(q.get("summary_ru") or "").strip() if current else ""
        en_current = (
            en_translation.get("status") == "live_auto"
            and en_translation.get("fingerprint") == str(src.get("sourceFingerprint") or "")
        )
        en_summary = str(en_translation.get("summary_en") or "").strip() if en_current else ""
        en_description = str(en_translation.get("description_en") or "").strip() if en_current else ""
        # Keep two concepts separate:
        # 1) reviewed Russian summary (editorial, source-derived), and
        # 2) full source-description translation (only when explicitly approved/live).
        # Never present a summary as if it were a complete translation of the listing.
        if translated_current:
            description = str(translation.get("description_ru") or "").strip()
            description_kind = "source_translation"
        else:
            description = ""
            description_kind = "source_missing" if not source_description else "translation_pending"
        summary = reviewed_summary or _structured_ru_fallback(src, dict(src.get("details") or {}), src.get("propertyType"))
        summary_kind = "reviewed_summary" if reviewed_summary else "structured_fallback"
        details = dict(src.get("details") or {})
        if current:
            details.update(q.get("details_override") or {})
        ptype = (q.get("property_type_override") if current else None) or src.get("propertyType")
        item = {
            "code": src.get("code"),
            "sourceId": source["sourceId"],
            "sourceSlug": source["sourceSlug"],
            "sourceLocalId": source_local_id,
            "globalListingId": _global_listing_id(source["sourceId"], source_local_id),
            "inventoryOwnerTenant": source["ownerTenant"],
            "source": _public_source(source),
            "operation": src.get("operation"),
            "propertyType": ptype,
            "address": src.get("address"),
            "priceAmount": src.get("priceAmount"),
            "priceCurrency": src.get("priceCurrency"),
            "details": details,
            "highlightedFeatures": src.get("highlightedFeatures") or [],
            "description": description,
            "descriptionKind": description_kind,
            "sourceDescriptionAvailable": bool(source_description),
            "summary": summary,
            "summaryKind": summary_kind,
            "localized": {
                "ru": {"summary": summary, "description": description},
                "es": {"summary": "", "description": source_description},
                "en": {"summary": en_summary, "description": en_description},
            },
            "additionalInfo": src.get("additionalInfo") or {},
            "services": src.get("services") or [],
            "environments": src.get("environments") or [],
            "comforts": src.get("comforts") or [],
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
        item["listingToken"] = _listing_token(item, source)
        items.append(item)
    _catalog_cache.update({
        "registry_mtime": registry_mtime,
        "mtime": mtime,
        "quality_mtime": qtime,
        "geo_mtime": gtime,
        "translation_mtime": ttime,
        "en_translation_mtime": entime,
        "items": items,
    })
    return items


def _listing_token(item: dict[str, Any], source: dict[str, Any] | None = None) -> str:
    source = source or _source_registry().get(str(item.get("sourceId") or ""))
    if not source:
        raise RuntimeError("Listing source unavailable for token generation")
    local_id = str(item.get("sourceLocalId") or item.get("code") or "").strip()
    if source["listingTokenStrategy"] == "legacy_source_url_v1":
        identity = str(item.get("sourceUrl") or "")
        token_prefix = str(item.get("code") or "").strip()
    else:
        identity = f"{source['sourceId']}:{local_id}"
        token_prefix = local_id
    suffix = hashlib.sha256(identity.encode()).hexdigest()[:8]
    return f"{token_prefix}_{suffix}"


def _listing_by_key(key: str | None) -> dict[str, Any] | None:
    lookup = str(key or "")
    if not lookup:
        return None
    items = _catalog()
    # Unique source-bound token is authoritative.
    item = next((x for x in items if x.get("listingToken") == lookup), None)
    if item:
        return item
    alias_payload = _load_json(settings.catalog_alias_path, {})
    aliases = alias_payload.get("aliases", {}) if isinstance(alias_payload, dict) else {}
    canonical = aliases.get(lookup) if isinstance(aliases, dict) else None
    if canonical:
        item = next((x for x in items if x.get("listingToken") == canonical), None)
        if item:
            return item
    # Plain code remains a backwards-compatible fallback only while unambiguous.
    # Cross-source collisions must never silently select the first inventory owner.
    code_matches = [x for x in items if str(x.get("code") or "") == lookup or str(x.get("sourceLocalId") or "") == lookup]
    if len(code_matches) == 1:
        return code_matches[0]
    # Preserve the historical first-match plain-code fallback inside the one
    # legacy source, but never apply it across different inventory sources.
    source_ids = {str(x.get("sourceId") or "") for x in code_matches}
    if len(source_ids) == 1 and code_matches:
        source = _source_registry().get(next(iter(source_ids)))
        if source and source.get("legacyDefault"):
            return code_matches[0]
    return None


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
    min_bedrooms = criteria.get("minBedrooms")
    if min_bedrooms and int(d.get("bedrooms") or 0) < int(min_bedrooms):
        return False
    min_bathrooms = criteria.get("minBathrooms")
    if min_bathrooms and int(d.get("bathrooms") or 0) < int(min_bathrooms):
        return False
    if criteria.get("parking") and int(d.get("parkingSpaces") or 0) < 1:
        return False
    min_area = _safe_num(criteria.get("minArea"))
    if min_area and _safe_num(d.get("totalAreaM2") or d.get("coveredAreaM2") or 0) < min_area:
        return False
    max_area = _safe_num(criteria.get("maxArea"))
    if max_area and _safe_num(d.get("totalAreaM2") or d.get("coveredAreaM2") or 0) > max_area:
        return False
    min_budget = _safe_num(criteria.get("minBudget"))
    max_budget = _safe_num(criteria.get("maxBudget"))
    currency = criteria.get("budgetCurrency")
    if min_budget or max_budget:
        price = _safe_num(item.get("priceAmount"))
        if not price or item.get("priceCurrency") != currency:
            return False
        if min_budget and price < min_budget:
            return False
        if max_budget and price > max_budget:
            return False
    blob = _listing_blob(item)
    for feature in criteria.get("features") or []:
        aliases = FEATURE_ALIASES.get(feature, [feature])
        if not any(alias in blob for alias in aliases):
            return False
    query = _norm(criteria.get("query"))
    if query:
        tokens = [x for x in re.findall(r"[a-záéíóúñüа-я0-9]{3,}", query) if x not in {"квартира", "квартиру", "дом", "ищу", "нужна"}]
        if tokens and not all(token in blob for token in tokens):
            return False
    return True


def _search(criteria: dict[str, Any]) -> list[dict[str, Any]]:
    rows = [item for item in _catalog() if str(item.get("status") or "active").lower() not in {"paused","unavailable","reserved","rented","sold","removed"} and _match(item, criteria)]
    rows.sort(key=lambda item: (_safe_num(item.get("priceAmount")) or 10**18, item.get("code") or ""))
    return rows


def _validate_init_data(raw: str) -> dict[str, Any]:
    if not raw:
        raise HTTPException(status_code=401, detail="Telegram authorization required")
    pairs = dict(parse_qsl(raw, keep_blank_values=True))
    received_hash = pairs.pop("hash", "")
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


def _telegram_ids(value: str) -> set[int]:
    return {
        int(part.strip())
        for part in value.split(",")
        if part.strip().lstrip("-").isdigit()
    }


def _is_test_user(user_id: int) -> bool:
    return user_id in _telegram_ids(settings.test_telegram_ids)


def _is_internal_user(user_id: int) -> bool:
    return user_id in _telegram_ids(settings.internal_telegram_ids)


def _exclude_from_production(user_id: int) -> bool:
    # Synthetic QA and staff activity must never inflate acquisition or create self-leads.
    return _is_test_user(user_id) or _is_internal_user(user_id)


def _growth_event(user_id: int, event_name: str, *, listing_token: str | None = None, properties: dict[str, Any] | None = None, link_token: str | None = None) -> bool:
    web_actor = user_id < 0
    payload = {
        "tenant": settings.growth_tenant,
        "event_name": event_name,
        "actor_external_id": user_id,
        "link_token": link_token,
        "listing_code": listing_token,
        "source": None if link_token else ("web_app" if web_actor else "telegram_miniapp"),
        "medium": None if link_token else "owned",
        "campaign": None if link_token else ("web_catalog" if web_actor else "miniapp_catalog"),
        "content": None if link_token else "app",
        "placement": None if link_token else ("web_app" if web_actor else "miniapp"),
        "properties": properties or {},
        "is_test": _exclude_from_production(user_id),
    }
    try:
        httpx.post(
            f"{settings.growth_core_url.rstrip('/')}/v1/events",
            json=payload,
            headers={"X-Growth-Key": settings.growth_core_key},
            timeout=3.0,
        ).raise_for_status()
        return True
    except Exception:
        return False


def _outbound_click_token(user: dict[str, Any]) -> str:
    payload = {
        "id": int(user["id"]),
        "username": user.get("username"),
        "first_name": user.get("first_name"),
        "last_name": user.get("last_name"),
        "exp": int(datetime.now(UTC).timestamp()) + settings.init_data_max_age_seconds,
    }
    raw = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode()
    encoded = base64.urlsafe_b64encode(raw).decode().rstrip("=")
    sig = hmac.new(settings.service_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
    return f"{encoded}.{sig}"


def _outbound_click_user(token: str) -> dict[str, Any]:
    try:
        encoded, sig = token.rsplit(".", 1)
        expected = hmac.new(settings.service_key.encode(), encoded.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(expected, sig):
            raise ValueError("bad signature")
        padded = encoded + "=" * (-len(encoded) % 4)
        payload = json.loads(base64.urlsafe_b64decode(padded.encode()).decode())
        if int(payload.get("exp") or 0) < int(datetime.now(UTC).timestamp()):
            raise ValueError("expired")
        if not payload.get("id"):
            raise ValueError("missing user")
        return payload
    except Exception as exc:
        raise HTTPException(status_code=401, detail="Invalid outbound click token") from exc


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


def _ensure_link(
    item: dict[str, Any],
    *,
    source: str,
    medium: str,
    campaign: str,
    content: str,
    placement: str,
    metadata_extra: dict[str, Any] | None = None,
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
                "listing_code": item["listingToken"],
                "intent": "listing",
                "bot_username": settings.telegram_bot_username,
                "metadata": {
                    "code": item.get("code"),
                    "source_url": item.get("sourceUrl"),
                    "source_id": item.get("sourceId"),
                    "source_local_id": item.get("sourceLocalId"),
                    "global_listing_id": item.get("globalListingId"),
                    "inventory_owner_tenant": item.get("inventoryOwnerTenant"),
                    **(metadata_extra or {}),
                },
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


def _bot_api(method: str, payload: dict[str, Any], timeout: float = 8.0) -> dict[str, Any] | None:
    try:
        response = httpx.post(
            f"https://api.telegram.org/bot{settings.telegram_bot_token}/{method}",
            json=payload,
            timeout=timeout,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) and data.get("ok") else None
    except Exception:
        return None


def _bot_send(
    chat_id: int | str,
    text: str,
    reply_markup: dict[str, Any] | None = None,
    *,
    message_thread_id: int | None = None,
    bot_token: str | None = None,
) -> bool:
    try:
        payload: dict[str, Any] = {
            "chat_id": chat_id,
            "text": text,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
            **({"reply_markup": reply_markup} if reply_markup else {}),
        }
        if message_thread_id:
            payload["message_thread_id"] = message_thread_id
        token = bot_token or settings.telegram_bot_token
        response = httpx.post(
            f"https://api.telegram.org/bot{token}/sendMessage",
            json=payload,
            timeout=8.0,
        )
        response.raise_for_status()
        return bool(response.json().get("ok"))
    except Exception:
        return False


def _prepared_share_message(
    user_id: int,
    item: dict[str, Any],
    share_target: str,
) -> str | None:
    price = f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}".strip()
    address = str(item.get("address") or item.get("code") or f"Объект {settings.brand_name}")
    details = item.get("details") or {}
    specs = []
    if details.get("rooms"):
        specs.append(f"{details['rooms']} комн.")
    area = details.get("totalAreaM2") or details.get("coveredAreaM2")
    if area:
        specs.append(f"{area} м²")
    caption = f"<b>{html.escape(address)}</b>\n{html.escape(price)}"
    if specs:
        caption += "\n" + html.escape(" · ".join(specs))
    footer = settings.share_footer.strip() or settings.brand_name
    caption += "\n\n" + html.escape(footer)

    images = item.get("images") or []
    result_id = hashlib.sha256(
        f"share|{item.get('listingToken')}|{share_target}".encode()
    ).hexdigest()[:32]
    reply_markup = {
        "inline_keyboard": [[{"text": "Открыть объект", "url": share_target}]]
    }
    if images:
        result: dict[str, Any] = {
            "type": "photo",
            "id": result_id,
            "photo_url": images[0],
            "thumbnail_url": images[0],
            "caption": caption,
            "parse_mode": "HTML",
            "reply_markup": reply_markup,
        }
    else:
        result = {
            "type": "article",
            "id": result_id,
            "title": address,
            "description": price,
            "input_message_content": {
                "message_text": caption,
                "parse_mode": "HTML",
            },
            "reply_markup": reply_markup,
        }
    data = _bot_api(
        "savePreparedInlineMessage",
        {
            "user_id": user_id,
            "result": result,
            "allow_user_chats": True,
            "allow_group_chats": True,
            "allow_channel_chats": True,
        },
    )
    prepared = (data or {}).get("result") or {}
    return str(prepared.get("id") or "") or None


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


def _crm_get(path: str) -> dict[str, Any] | None:
    base = settings.crm_base_url.rstrip("/")
    if not base or not settings.crm_api_key:
        return None
    try:
        response = httpx.get(
            f"{base}{path}",
            headers={"X-API-Key": settings.crm_api_key},
            timeout=5.0,
        )
        response.raise_for_status()
        data = response.json()
        return data if isinstance(data, dict) else None
    except Exception:
        return None


def _crm_patch(path: str, payload: dict[str, Any]) -> dict[str, Any] | None:
    base = settings.crm_base_url.rstrip("/")
    if not base or not settings.crm_api_key:
        return None
    try:
        response = httpx.patch(
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
    attribution = _growth_link(row.tracking_token) or {
        "source": "telegram_miniapp",
        "medium": "owned",
        "campaign": "miniapp_catalog",
        "content": "saved_search",
        "placement": "miniapp_saved_search",
    }
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
                "stage": "identified",
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
                    "acquisition_tracking_token": row.tracking_token,
                    "acquisition_source": attribution.get("source"),
                    "acquisition_medium": attribution.get("medium"),
                    "acquisition_campaign": attribution.get("campaign"),
                    "acquisition_content": attribution.get("content"),
                    "acquisition_placement": attribution.get("placement"),
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


def _crm_sync_listing_action(
    user: dict[str, Any],
    item: dict[str, Any],
    action: str,
    message: str | None,
    tracking_token: str | None,
) -> str | None:
    if not settings.crm_base_url or not settings.crm_api_key:
        return None
    user_id = int(user["id"])
    display_name = " ".join(
        part for part in [user.get("first_name"), user.get("last_name")] if part
    ) or user.get("username") or f"Telegram {user_id}"
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
            "priority": "high" if action == "viewing" else "medium",
            "summary_current": (
                f"{settings.brand_name} Mini App. Интерес к объекту "
                f"{item.get('address') or item.get('code')}"
            ),
        },
    )
    if not contact or not contact.get("id"):
        return None
    contact_id = str(contact["id"])
    attribution = _growth_link(tracking_token) or {
        "source": "telegram_miniapp",
        "medium": "owned",
        "campaign": "miniapp_catalog",
        "content": action,
        "placement": "miniapp_listing_detail",
    }
    action_label = {
        "availability": "Проверить актуальность",
        "viewing": "Запрос просмотра",
        "question": "Вопрос по объекту",
    }.get(action, action)
    next_action = {
        "availability": "Проверить актуальность объекта и ответить клиенту в Telegram",
        "viewing": "Связаться с клиентом и согласовать просмотр",
        "question": "Ответить на вопрос клиента по объекту",
    }.get(action, "Связаться с клиентом")
    probability = {"availability": 70, "viewing": 85, "question": 65}.get(action, 60)
    clean_message = (message or "").strip()
    summary = (
        f"{action_label}: {item.get('address') or item.get('code')} · "
        f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}"
    )
    if clean_message:
        summary += f". Вопрос: {clean_message}"
    route = _routing_context(item)
    extra = {
        "listing_token": item.get("listingToken"),
        "listing_code": item.get("code"),
        "listing_source_url": item.get("sourceUrl"),
        "global_listing_id": item.get("globalListingId"),
        "source_id": item.get("sourceId"),
        "source_local_id": item.get("sourceLocalId"),
        "demand_tenant": route["demandTenant"],
        "relationship_owner_tenant": route["relationshipOwnerTenant"],
        "inventory_owner_tenant": route["inventoryOwnerTenant"],
        "routing_mode": route["routingMode"],
        "action": action,
        "message": clean_message or None,
        "telegram_user_id": user_id,
        "telegram_username": user.get("username"),
        # Immutable first-touch acquisition fields. They answer "who did this
        # channel/catalog acquire?" even if the same person returns later directly.
        "acquisition_tracking_token": tracking_token,
        "acquisition_source": attribution.get("source"),
        "acquisition_medium": attribution.get("medium"),
        "acquisition_campaign": attribution.get("campaign"),
        "acquisition_content": attribution.get("content"),
        "acquisition_placement": attribution.get("placement"),
        # Legacy lifecycle attribution remains stable for existing integrations.
        "tracking_token": tracking_token,
        "tracking_source": attribution.get("source"),
        "tracking_medium": attribution.get("medium"),
        "tracking_campaign": attribution.get("campaign"),
        "tracking_content": attribution.get("content"),
        "tracking_placement": attribution.get("placement"),
        # Latest interaction is deliberately separate from acquisition.
        "latest_tracking_token": tracking_token,
        "latest_tracking_source": attribution.get("source"),
        "latest_tracking_medium": attribution.get("medium"),
        "latest_tracking_campaign": attribution.get("campaign"),
        "latest_tracking_content": attribution.get("content"),
        "latest_tracking_placement": attribution.get("placement"),
    }

    existing_payload = _crm_get(
        "/v1/opportunities?"
        + urlencode({"contact_id": contact_id, "limit": 200, "offset": 0})
    ) or {}
    existing = next(
        (
            row for row in existing_payload.get("items", [])
            if row.get("source") == settings.crm_source
            and (row.get("extra_json") or {}).get("listing_token") == item.get("listingToken")
            and row.get("stage") not in {"won", "lost"}
        ),
        None,
    )
    if existing and existing.get("id"):
        merged_extra = dict(existing.get("extra_json") or {})
        # Never overwrite original acquisition with a later return visit. Only the
        # latest-touch fields move forward after first creation.
        immutable_keys = {
            "acquisition_tracking_token", "acquisition_source", "acquisition_medium",
            "acquisition_campaign", "acquisition_content", "acquisition_placement",
            "tracking_token", "tracking_source", "tracking_medium", "tracking_campaign",
            "tracking_content", "tracking_placement",
        }
        for key, value in extra.items():
            if key in immutable_keys and merged_extra.get(key) not in {None, ""}:
                continue
            merged_extra[key] = value
        updated = _crm_patch(
            f"/v1/opportunities/{existing['id']}",
            {
                "probability": max(int(existing.get("probability") or 0), probability),
                "next_action": next_action,
                "summary_current": summary,
                "extra_json": merged_extra,
            },
        )
        return str((updated or existing).get("id") or "") or None

    opportunity = _crm_post(
        "/v1/opportunities",
        {
            "name": f"{settings.brand_name} · {action_label} · {item.get('address') or item.get('code')}"[:255],
            "type": "real_estate_lead",
            "stage": "identified",
            "contact_id": contact_id,
            "probability": probability,
            "source": settings.crm_source,
            "next_action": next_action,
            "summary_current": summary,
            "extra_json": extra,
        },
    )
    return str((opportunity or {}).get("id") or "") or None



def _crm_record_original_click(
    user: dict[str, Any],
    item: dict[str, Any],
    tracking_token: str | None,
    click_id: str | None,
) -> str | None:
    """Record a low-intent external-site click without creating a CRM opportunity."""
    if not settings.crm_base_url or not settings.crm_api_key:
        return None
    user_id = int(user["id"])
    display_name = " ".join(
        part for part in [user.get("first_name"), user.get("last_name")] if part
    ) or user.get("username") or f"Telegram {user_id}"
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
        },
    )
    if not contact or not contact.get("id"):
        return None
    attribution = _growth_link(tracking_token) or {}
    clicked_at = datetime.now(UTC).isoformat()
    fact = _crm_post(
        "/v1/facts",
        {
            "subject_type": "contact",
            "subject_id": str(contact["id"]),
            "predicate": "catalog.original_opened",
            "value": {
                "click_id": click_id,
                "clicked_at": clicked_at,
                "listing_token": item.get("listingToken"),
                "listing_code": item.get("code"),
                "global_listing_id": item.get("globalListingId"),
                "source_id": item.get("sourceId"),
                "source_local_id": item.get("sourceLocalId"),
                "inventory_owner_tenant": item.get("inventoryOwnerTenant"),
                "demand_tenant": settings.growth_tenant,
                "address": item.get("address"),
                "price_amount": item.get("priceAmount"),
                "price_currency": item.get("priceCurrency"),
                "tracking_token": tracking_token,
                "tracking_source": attribution.get("source"),
                "tracking_medium": attribution.get("medium"),
                "tracking_campaign": attribution.get("campaign"),
                "tracking_content": attribution.get("content"),
                "tracking_placement": attribution.get("placement"),
            },
            "confidence": 1.0,
            "source_url": item.get("sourceUrl") or settings.miniapp_url,
            "source_excerpt": f"Открыл оригинал {settings.brand_name} из Telegram-каталога",
        },
    )
    return str((fact or {}).get("id") or "") or None


def _tagged_original_url(item: dict[str, Any], click_id: str) -> str:
    source = str(item.get("sourceUrl") or "").strip()
    if not source.startswith(("http://", "https://")):
        raise HTTPException(status_code=404, detail="Listing source URL unavailable")
    parts = urlsplit(source)
    managed = {"utm_source", "utm_medium", "utm_campaign", "utm_content", "lb_click"}
    query = [(k, v) for k, v in parse_qsl(parts.query, keep_blank_values=True) if k not in managed]
    query.extend([
        ("utm_source", "telegram"),
        ("utm_medium", "miniapp"),
        ("utm_campaign", settings.attribution_campaign),
        ("utm_content", str(item.get("listingToken") or item.get("code") or "listing")),
        ("lb_click", click_id),
    ])
    return urlunsplit((parts.scheme, parts.netloc, parts.path, urlencode(query), parts.fragment))


def _deliver_outbound_click(row: OutboundClick, item: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    errors: list[str] = []
    if row.growth_delivered_at is None:
        if _growth_event(
            row.telegram_user_id,
            "original_opened",
            listing_token=row.listing_token,
            properties={
                "click_id": row.click_id,
                "destination": settings.source_label,
                "via": "server_redirect",
                **_event_provenance(item),
            },
            link_token=row.tracking_token,
        ):
            row.growth_delivered_at = now
        else:
            errors.append("growth")
    needs_crm = bool(not row.is_test and settings.crm_base_url and settings.crm_api_key)
    if needs_crm and not row.crm_fact_id:
        user = {
            "id": row.telegram_user_id,
            "username": row.username,
            "first_name": row.display_name,
        }
        fact_id = _crm_record_original_click(user, item, row.tracking_token, row.click_id)
        if fact_id:
            row.crm_fact_id = fact_id
        else:
            errors.append("crm_fact")
    complete = row.growth_delivered_at is not None and (not needs_crm or bool(row.crm_fact_id))
    row.status = "delivered" if complete else "retry"
    row.delivery_error = ",".join(errors)[:500] or None
    row.updated_at = now


def _deliver_outbound_click_by_id(click_row_id: UUID) -> None:
    with SessionLocal() as session:
        row = session.get(OutboundClick, click_row_id)
        if not row or row.status == "delivered":
            return
        item = dict(row.listing_snapshot_json or {})
        if not item:
            item = _listing_by_key(row.listing_token) or {}
        _deliver_outbound_click(row, item)
        session.commit()


def _listing_action_confirmation(action: str) -> str:
    return {
        "availability": "Запрос получили. Проверим актуальность объекта и свяжемся с вами в Telegram.",
        "viewing": "Запрос на просмотр получили. Свяжемся с вами в Telegram, чтобы согласовать время.",
        "question": "Вопрос получили. Ответим вам в Telegram.",
    }.get(action, "Запрос получили. Свяжемся с вами в Telegram.")


def _listing_action_operator_payload(
    row: ListingAction,
    item: dict[str, Any],
) -> tuple[str, dict[str, Any]]:
    action_label = {
        "availability": "АКТУАЛЬНОСТЬ",
        "viewing": "ПРОСМОТР",
        "question": "ВОПРОС",
    }.get(row.action, row.action.upper())
    synthetic_test = _is_test_user(row.telegram_user_id)
    prefix = "🧰 TEST · ТОЛЬКО ОПЕРАТОР · " if synthetic_test else "🔥 "
    username = (row.username or "").strip().lstrip("@")
    who = row.display_name or (f"@{username}" if username else f"Telegram {row.telegram_user_id}")
    if username:
        who += f" · @{username}" if f"@{username}" not in who else ""
    price = f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}".strip()
    lines = [
        f"{prefix}<b>{html.escape(settings.brand_name)} · {html.escape(action_label)}</b>",
        f"Клиент: <b>{html.escape(str(who))}</b>",
        f"Telegram ID: <code>{row.telegram_user_id}</code>",
        f"Объект: {html.escape(str(item.get('address') or item.get('code') or row.listing_code or row.listing_token))}",
        f"Цена: {html.escape(price)}" if price else "",
        f"Заявка: <code>{row.id}</code>",
    ]
    if row.message:
        lines.extend(["", html.escape(row.message)])
    route = _routing_context(item, row.tenant)
    if route["routingMode"] == "collaboration_required":
        lines.extend([
            "",
            f"Inventory owner: <code>{html.escape(route['inventoryOwnerTenant'])}</code>",
            "Routing: требуется collaboration с владельцем инвентаря; прямой owner-side CRM route не выполняется.",
        ])
    if row.crm_opportunity_id:
        lines.extend(["", f"CRM: <code>{html.escape(row.crm_opportunity_id)}</code>"])
    elif _is_test_user(row.telegram_user_id):
        lines.extend(["", "CRM: синтетический QA, production не изменяется"])
    elif _is_internal_user(row.telegram_user_id):
        lines.extend(["", "CRM: внутренний аккаунт, лид на самого оператора не создаётся"])
    elif route["routingMode"] != "collaboration_required":
        lines.extend(["", "⚠️ CRM пока не синхронизирована, заявка сохранена локально и будет повторена автоматически."])
    web_client = row.telegram_user_id < 0 and not username
    keyboard: list[list[dict[str, str]]] = []
    if not web_client:
        chat_url = f"https://t.me/{username}" if username else f"tg://user?id={row.telegram_user_id}"
        keyboard.append([{"text": "💬 Открыть диалог", "url": chat_url}])
    listing_token = str(item.get("listingToken") or row.listing_token or "").strip()
    if listing_token:
        telegram_card_url = f"https://t.me/{settings.telegram_bot_username}?startapp=listing_{listing_token}"
        keyboard.append([{"text": "🏠 Карточка объекта", "url": telegram_card_url}])
    if settings.operator_crm_url:
        sep = "&" if "?" in settings.operator_crm_url else "?"
        crm_tab = settings.operator_crm_tab.strip() or settings.growth_tenant
        crm_url = f"{settings.operator_crm_url}{sep}{urlencode({'tab': crm_tab})}"
        keyboard.append([{"text": f"📥 {settings.brand_name} CRM", "web_app": {"url": crm_url}}])
    return "\n".join(lines), {"inline_keyboard": keyboard}


def _deliver_listing_action(row: ListingAction, item: dict[str, Any]) -> None:
    now = datetime.now(UTC)
    user = {
        "id": row.telegram_user_id,
        "username": row.username,
        "first_name": row.display_name,
    }
    errors: list[str] = []
    synthetic_test = _is_test_user(row.telegram_user_id)
    internal_user = _is_internal_user(row.telegram_user_id)
    web_client = row.telegram_user_id < 0 and not (row.username or "").strip()
    excluded = synthetic_test or internal_user
    route = _routing_context(item, row.tenant)
    collaboration_required = route["routingMode"] == "collaboration_required"
    row.inventory_source_id = row.inventory_source_id or route["inventorySourceId"]
    row.inventory_owner_tenant = row.inventory_owner_tenant or route["inventoryOwnerTenant"]
    row.routing_mode = row.routing_mode or route["routingMode"]

    if not excluded and not collaboration_required and not row.crm_opportunity_id:
        opportunity_id = _crm_sync_listing_action(
            user,
            item,
            row.action,
            row.message,
            row.tracking_token,
        )
        if opportunity_id:
            row.crm_opportunity_id = opportunity_id
        else:
            errors.append("crm_sync")

    silent_smoke = bool(synthetic_test and (row.username or "").strip().lower() == settings.smoke_username.strip().lower())
    # An operator testing from their own Telegram account must not receive an
    # "operator alert" about themselves. Real-client alerts still go to the operator.
    if internal_user:
        row.operator_notified_at = row.operator_notified_at or now
        row.user_confirmed_at = row.user_confirmed_at or now
    else:
        if row.operator_notified_at is None and settings.operator_chat_id and not silent_smoke:
            operator_text, markup = _listing_action_operator_payload(row, item)
            if _bot_send(settings.operator_chat_id, operator_text, markup, bot_token=settings.operator_bot_token or None):
                row.operator_notified_at = now
            else:
                errors.append("operator_notify")
        # Browser/PWA contacts are acknowledged in the HTTP/UI response. Their generated
        # negative pseudo-ID is not a Telegram user and must never be retried as a DM.
        if web_client:
            row.user_confirmed_at = row.user_confirmed_at or now
        elif row.user_confirmed_at is None and not silent_smoke:
            confirmation = _listing_action_confirmation(row.action)
            if synthetic_test:
                confirmation = "🧪 QA · " + confirmation
            if _bot_send(row.telegram_user_id, confirmation):
                row.user_confirmed_at = now
            else:
                errors.append("user_confirm")

    if silent_smoke:
        row.operator_notified_at = row.operator_notified_at or now
        row.user_confirmed_at = row.user_confirmed_at or now
    row.delivery_error = ",".join(errors)[:500] or None
    if synthetic_test:
        row.status = "test_delivered" if not errors else "test_partial"
    elif internal_user:
        row.status = "internal_delivered" if not errors else "internal_partial"
    else:
        notifications_complete = (
            (not settings.operator_chat_id or row.operator_notified_at is not None)
            and row.user_confirmed_at is not None
        )
        if collaboration_required:
            row.status = "collaboration_required" if notifications_complete and not errors else "retry"
        else:
            complete = bool(row.crm_opportunity_id) and notifications_complete
            row.status = "delivered" if complete else "retry"
    row.updated_at = now

def _saved_search_webhook_payload(
    row: SavedSearch,
    user: dict[str, Any],
    matches_now: int,
) -> dict[str, Any]:
    attribution = _growth_link(row.tracking_token) or {}
    display_name = " ".join(
        part for part in [user.get("first_name"), user.get("last_name")] if part
    ) or user.get("username") or row.display_name or f"Telegram {row.telegram_user_id}"
    return {
        "schema_version": "1.0",
        "event": "lead.saved_search",
        "tenant": settings.growth_tenant,
        "idempotency_key": f"saved_search:{row.id}",
        "occurred_at": row.created_at.isoformat(),
        "contact": {
            "channel": "telegram",
            "external_id": str(row.telegram_user_id),
            "username": user.get("username") or row.username,
            "display_name": display_name,
            "language": "ru",
        },
        "lead": {
            "external_id": str(row.id),
            "type": "property_saved_search",
            "label": row.label,
            "criteria": row.criteria_json,
            "notification_opt_in": row.notify,
            "matches_now": matches_now,
        },
        "attribution": {
            "token": row.tracking_token,
            "source": attribution.get("source"),
            "medium": attribution.get("medium"),
            "campaign": attribution.get("campaign"),
            "content": attribution.get("content"),
            "placement": attribution.get("placement"),
        },
    }


def _crm_webhook_sync(row: SavedSearch, user: dict[str, Any], matches_now: int) -> bool | None:
    url = settings.crm_webhook_url.strip()
    secret = settings.crm_webhook_secret
    if not url or not secret:
        return None
    payload = _saved_search_webhook_payload(row, user, matches_now)
    body = json.dumps(
        payload,
        ensure_ascii=False,
        sort_keys=True,
        separators=(",", ":"),
    ).encode("utf-8")
    signature = hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    row.crm_webhook_attempts = int(row.crm_webhook_attempts or 0) + 1
    try:
        response = httpx.post(
            url,
            content=body,
            headers={
                "Content-Type": "application/json",
                "X-Revenue-Event": "lead.saved_search",
                "X-Revenue-Signature": f"sha256={signature}",
                "Idempotency-Key": payload["idempotency_key"],
            },
            timeout=5.0,
        )
        response.raise_for_status()
        row.crm_webhook_delivered_at = datetime.now(UTC)
        return True
    except Exception:
        return False


def _label(criteria: dict[str, Any]) -> str:
    bits = []
    if criteria.get("operation"):
        bits.append("Покупка" if criteria["operation"] == "Venta" else "Аренда")
    types = criteria.get("propertyTypes") or []
    if types:
        bits.append(", ".join(str(x) for x in types[:2]))
    hoods = criteria.get("neighborhoods") or []
    if hoods:
        bits.append(", ".join(x.title() for x in hoods[:3]))
    if criteria.get("rooms"):
        bits.append(f"{criteria['rooms']} комн.")
    elif criteria.get("minBedrooms"):
        bits.append(f"от {criteria['minBedrooms']} спальн.")
    if criteria.get("minArea"):
        bits.append(f"от {criteria['minArea']} м²")
    if criteria.get("maxBudget"):
        cur = criteria.get("budgetCurrency") or "USD"
        if criteria.get("minBudget"):
            bits.append(f"{cur} {criteria['minBudget']}–{criteria['maxBudget']}")
        else:
            bits.append(f"до {cur} {criteria['maxBudget']}")
    elif criteria.get("minBudget"):
        cur = criteria.get("budgetCurrency") or "USD"
        bits.append(f"от {cur} {criteria['minBudget']}")
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
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS crm_webhook_delivered_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS crm_webhook_attempts INTEGER NOT NULL DEFAULT 0"))
        conn.execute(text("ALTER TABLE listing_actions ADD COLUMN IF NOT EXISTS inventory_source_id VARCHAR(64)"))
        conn.execute(text("ALTER TABLE listing_actions ADD COLUMN IF NOT EXISTS inventory_owner_tenant VARCHAR(64)"))
        conn.execute(text("ALTER TABLE listing_actions ADD COLUMN IF NOT EXISTS routing_mode VARCHAR(32)"))
        conn.execute(text("ALTER TABLE listing_actions ADD COLUMN IF NOT EXISTS person_profile_id UUID"))
        conn.execute(text("ALTER TABLE outbound_clicks ADD COLUMN IF NOT EXISTS inventory_source_id VARCHAR(64)"))
        conn.execute(text("ALTER TABLE outbound_clicks ADD COLUMN IF NOT EXISTS inventory_owner_tenant VARCHAR(64)"))
        conn.execute(text("ALTER TABLE saved_search_matches ADD COLUMN IF NOT EXISTS price_amount DOUBLE PRECISION"))
        conn.execute(text("ALTER TABLE saved_search_matches ADD COLUMN IF NOT EXISTS price_currency VARCHAR(8)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_saved_match_listing ON saved_search_matches (search_id, listing_code)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_listing_actions_routing ON listing_actions (tenant, inventory_owner_tenant, routing_mode, created_at)"))
    _source_registry()
    _backfill_listing_provenance()


def _backfill_listing_provenance() -> None:
    with SessionLocal() as session:
        changed = False
        for row in session.scalars(select(ListingAction).where(ListingAction.inventory_source_id.is_(None)).limit(1000)):
            item = _listing_by_key(row.listing_token) or _listing_from_snapshot(
                row.listing_snapshot_json,
                listing_token=row.listing_token,
                listing_code=row.listing_code,
            )
            if not item:
                continue
            route = _routing_context(item, row.tenant)
            row.inventory_source_id = route["inventorySourceId"]
            row.inventory_owner_tenant = route["inventoryOwnerTenant"]
            row.routing_mode = route["routingMode"]
            row.listing_snapshot_json = _listing_snapshot(item, row.tenant)
            changed = True
        for row in session.scalars(select(OutboundClick).where(OutboundClick.inventory_source_id.is_(None)).limit(1000)):
            item = _listing_by_key(row.listing_token) or _listing_from_snapshot(
                row.listing_snapshot_json,
                listing_token=row.listing_token,
                listing_code=row.listing_code,
            )
            if not item:
                continue
            route = _routing_context(item, row.tenant)
            row.inventory_source_id = route["inventorySourceId"]
            row.inventory_owner_tenant = route["inventoryOwnerTenant"]
            row.listing_snapshot_json = _listing_snapshot(item, row.tenant)
            changed = True
        if changed:
            session.commit()


@app.get("/health")
def health():
    sources = _source_registry()
    return {"status": "ok", "service": "property-intent-core", "version": "0.1.0", "marketplaceVersion":"20261031-first-party-agent-inbox-r8", "marketplaceEnabled":settings.marketplace_enabled, "sourceRegistry": len(sources)}


@app.get("/v1/sources")
def public_sources():
    sources = [_public_source(source) for source in _source_registry().values() if source.get("active")]
    return {"count": len(sources), "sources": sources}


@app.get("/v1/config")
def public_config():
    return {
        "tenantSlug": settings.growth_tenant,
        "brandName": settings.brand_name,
        "brandTagline": settings.brand_tagline,
        "brandLogoUrl": settings.brand_logo_url,
        "botUsername": settings.telegram_bot_username,
        "defaultLanguage": settings.public_language_default,
        "telegramChannelUrl": settings.telegram_channel_url,
        "attributionCampaign": settings.attribution_campaign,
        "sourceLabel": settings.source_label,
        "marketplaceEnabled": settings.marketplace_enabled,
        "webAuthEnabled": bool(settings.resend_api_key.strip()),
        "vapidPublicKey": settings.vapid_public_key.strip(),
        "webPushEnabled": bool(settings.vapid_public_key.strip() and settings.vapid_private_key.strip()),
        "marketplaceVersion": "20261031-first-party-agent-inbox-r8",
    }


def _catalog_summary(item: dict[str, Any]) -> dict[str, Any]:
    return {
        "code": item.get("code"),
        "sourceId": item.get("sourceId"),
        "sourceSlug": item.get("sourceSlug"),
        "sourceLocalId": item.get("sourceLocalId"),
        "globalListingId": item.get("globalListingId"),
        "inventoryOwnerTenant": item.get("inventoryOwnerTenant"),
        "source": item.get("source") or {},
        "operation": item.get("operation"),
        "status": item.get("status") or "active",
        "propertyType": item.get("propertyType"),
        "address": item.get("address"),
        "priceAmount": item.get("priceAmount"),
        "priceCurrency": item.get("priceCurrency"),
        "details": item.get("details") or {},
        "highlightedFeatures": (item.get("highlightedFeatures") or [])[:8],
        "description": str(item.get("description") or "")[:480],
        "descriptionKind": item.get("descriptionKind"),
        "sourceDescriptionAvailable": bool(item.get("sourceDescriptionAvailable")),
        "summary": str(item.get("summary") or "")[:480],
        "summaryKind": item.get("summaryKind"),
        "localized": {
            lang: {
                "summary": str((payload or {}).get("summary") or "")[:480],
                "description": str((payload or {}).get("description") or "")[:480],
            }
            for lang, payload in (item.get("localized") or {}).items()
        },
        "notes": [],
        "images": (item.get("images") or [])[:5],
        "photoCount": len(item.get("images") or []),
        "sourceUrl": item.get("sourceUrl"),
        "neighborhoods": item.get("neighborhoods") or [],
        "latitude": item.get("latitude"),
        "longitude": item.get("longitude"),
        "listingToken": item.get("listingToken"),
        "inventoryOwnerTenant": item.get("inventoryOwnerTenant"),
        "routingMode": _routing_context(item).get("routingMode"),
    }


@app.get("/v1/catalog")
def catalog():
    items = [x for x in _catalog() if str(x.get("status") or "active").lower() not in {"paused","unavailable","reserved","rented","sold","removed"}]
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
    item = _listing_by_key(code)
    if not item:
        raise HTTPException(status_code=404, detail="Listing not found")
    return {**item, "photoCount": len(item.get("images") or [])}


@app.get("/v1/launch-context")
def launch_context(token: str = Query(..., min_length=6, max_length=24)):
    # Direct Mini App links carry only an opaque Growth token. Resolve it server-side
    # and return the smallest safe navigation context needed by the client.
    link = _growth_link(token)
    if not link:
        raise HTTPException(status_code=404, detail="Launch context not found")
    metadata = link.get("metadata") if isinstance(link.get("metadata"), dict) else {}
    filters = metadata.get("filters") if isinstance(metadata.get("filters"), dict) else {}
    raw_codes = metadata.get("listing_codes") if isinstance(metadata.get("listing_codes"), list) else []
    listing_codes = [str(x) for x in raw_codes if str(x).strip()][:250]
    return {
        "listing": link.get("listing_code"),
        "intent": link.get("intent"),
        "filters": filters,
        "listingCodes": listing_codes,
    }


@app.post("/v1/session")
def session(body: SessionIn):
    ctx = _validate_init_data(body.init_data)
    user = ctx["user"]
    return {
        "ok": True,
        "user": {"id": user["id"], "first_name": user.get("first_name"), "username": user.get("username")},
        "outbound_click_token": _outbound_click_token(user),
    }


@app.get("/v1/out/original")
def outbound_original(
    background_tasks: BackgroundTasks,
    listing_code: str = Query(...),
    click_token: str = Query(...),
    click_id: str = Query(..., min_length=8, max_length=96),
    trk: str | None = Query(default=None, max_length=24),
    session: Session = Depends(db),
):
    user = _outbound_click_user(click_token)
    user_id = int(user["id"])
    item = _listing_by_key(listing_code)
    if not item:
        raise HTTPException(status_code=404, detail="Listing not found")
    listing_token = str(item.get("listingToken") or listing_code)
    tracking_token = trk if trk and _growth_link(trk) else None
    route = _routing_context(item)
    snapshot = _listing_snapshot(item)
    row = session.scalar(select(OutboundClick).where(
        OutboundClick.tenant == settings.growth_tenant,
        OutboundClick.click_id == click_id,
    ))
    if row is None:
        display_name = " ".join(
            part for part in [user.get("first_name"), user.get("last_name")] if part
        ) or user.get("username") or f"Telegram {user_id}"
        row = OutboundClick(
            tenant=settings.growth_tenant,
            click_id=click_id,
            telegram_user_id=user_id,
            username=user.get("username"),
            display_name=display_name,
            listing_token=listing_token,
            listing_code=str(item.get("code") or "") or None,
            inventory_source_id=route["inventorySourceId"],
            inventory_owner_tenant=route["inventoryOwnerTenant"],
            tracking_token=tracking_token,
            listing_snapshot_json=snapshot,
            is_test=_exclude_from_production(user_id),
            status="new",
        )
        session.add(row)
        session.commit()
        session.refresh(row)
    elif row.telegram_user_id != user_id or row.listing_token != listing_token:
        raise HTTPException(status_code=409, detail="Click id already used")
    background_tasks.add_task(_deliver_outbound_click_by_id, row.id)
    destination = _tagged_original_url(item, click_id)
    return RedirectResponse(
        destination,
        status_code=302,
        headers={"Cache-Control": "no-store", "Referrer-Policy": "no-referrer"},
    )


@app.post("/v1/events")
def capture_event(body: EventIn):
    allowed = {
        "catalog_opened",
        "listing_opened",
        "gallery_opened",
        "original_opened",
        "search_started",
        "search_submitted",
        "share_clicked",
        "share_sent",
        "notification_clicked",
        "saved_search_opened",
    }
    if body.event_name not in allowed:
        raise HTTPException(status_code=422, detail="Unsupported event")
    ctx = _validate_init_data(body.init_data)
    item = _listing_by_key(body.listing_code) if body.listing_code else None
    link_token = _tracking_token(body.link_token, ctx)
    user_id = int(ctx["user"]["id"])
    event_properties = dict(body.properties or {})
    if item:
        event_properties.update(_event_provenance(item))
    _growth_event(
        user_id,
        body.event_name,
        listing_token=item.get("listingToken") if item else None,
        properties=event_properties,
        link_token=link_token,
    )
    crm_fact_id = None
    if body.event_name == "original_opened" and item and not _exclude_from_production(user_id):
        crm_fact_id = _crm_record_original_click(
            ctx["user"],
            item,
            link_token,
            str((body.properties or {}).get("click_id") or "") or None,
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
    return {"ok": True, "crm_fact_id": crm_fact_id}


@app.post("/v1/actions")
def action(body: ActionIn, session: Session = Depends(db)):
    if body.init_data:
        ctx = _validate_init_data(body.init_data)
        person = _person_for_telegram(session, ctx["user"])
        ctx["person_profile_id"] = person.id
    elif body.session_token:
        person = _person_from_session(session, body.session_token)
        if not person:
            raise HTTPException(status_code=401, detail="Сессия истекла. Войдите снова")
        pseudo = -int.from_bytes(person.id.bytes[:7], 'big')
        ctx = {'user': {'id': pseudo, 'username': None, 'first_name': person.display_name or 'Пользователь', 'language_code': person.preferred_language or settings.public_language_default}, 'person_profile_id': person.id}
    else:
        contact = {k: str(v or '').strip() for k, v in (body.web_contact or {}).items()}
        identity = contact.get('email') or contact.get('phone')
        if not identity:
            raise HTTPException(status_code=401, detail='Войдите или укажите контакт для ответа')
        person = _person_for_web_contact(session, contact)
        pseudo = -int.from_bytes(person.id.bytes[:7], 'big')
        ctx = {'user': {'id': pseudo, 'username': None, 'first_name': person.display_name or identity, 'language_code': person.preferred_language or settings.public_language_default}, 'web_contact': contact, 'person_profile_id': person.id}
    item = _listing_by_key(body.listing_code)
    if not item:
        raise HTTPException(status_code=404, detail="Listing not found")
    if body.action != "share" and str(item.get("status") or "active").lower() in {"paused","unavailable","reserved","rented","sold","removed"}: raise HTTPException(status_code=409,detail="Listing is not currently available")
    acquisition_token = _tracking_token(body.link_token, ctx)
    user_id = int(ctx["user"]["id"])

    if body.action == "share":
        _growth_event(
            user_id,
            "share_clicked",
            listing_token=item["listingToken"],
            properties={"via": "miniapp", **_event_provenance(item)},
            link_token=acquisition_token,
        )
        share_link = _ensure_link(
            item,
            source="telegram_share",
            medium="earned",
            campaign="property_share",
            content="listing",
            placement="miniapp_share_button",
            metadata_extra={"parent_tracking_token": acquisition_token},
        )
        share_target = (share_link or {}).get("telegram_url") or (
            f"https://t.me/{settings.telegram_bot_username}?start=lb_{item['listingToken']}"
        )
        share_text = (
            f"{item.get('address') or item.get('code')} · "
            f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}"
        ).strip()
        prepared_message_id = _prepared_share_message(user_id, item, share_target)
        return {
            "ok": True,
            "telegram_url": share_target,
            "share_url": "https://t.me/share/url?" + urlencode(
                {"url": share_target, "text": share_text}
            ),
            "prepared_message_id": prepared_message_id,
        }

    event_map = {
        "availability": "availability_requested",
        "viewing": "viewing_requested",
        "question": "question_submitted",
    }
    event = event_map.get(body.action)
    if not event:
        raise HTTPException(status_code=422, detail="Unsupported action")
    if body.init_data and settings.marketplace_enabled and body.action in {"availability","viewing"} and _routing_context(item).get("routingMode")=="collaboration_required":
        raise HTTPException(status_code=409, detail="Partner inventory requires the marketplace conversation flow")
    clean_message = (body.message or "").strip()
    if not body.init_data and body.web_contact:
        contact_bits = [f"{k}: {str(v).strip()}" for k, v in body.web_contact.items() if str(v or '').strip() and k in {'name','email','phone'}]
        if contact_bits:
            clean_message = (clean_message + "\n\nWeb contact: " + " · ".join(contact_bits)).strip()
    if body.action == "question" and not clean_message:
        raise HTTPException(status_code=422, detail="Напишите вопрос")

    # Persist the intent before any external side effect. This makes the UI promise
    # "request saved" true even if CRM or Telegram is temporarily unavailable.
    now = datetime.now(UTC)
    listing_token = str(item.get("listingToken") or body.listing_code)
    duplicate = session.scalar(
        select(ListingAction)
        .where(
            ListingAction.tenant == settings.growth_tenant,
            ListingAction.telegram_user_id == user_id,
            ListingAction.listing_token == listing_token,
            ListingAction.action == body.action,
            ListingAction.message == (clean_message or None),
            ListingAction.created_at >= now - timedelta(minutes=2),
        )
        .order_by(ListingAction.created_at.desc())
        .limit(1)
    )
    if duplicate:
        _deliver_listing_action(duplicate, dict(duplicate.listing_snapshot_json or item))
        session.commit()
        return {
            "ok": True,
            "status": duplicate.status,
            "action_id": str(duplicate.id),
            "opportunity_id": duplicate.crm_opportunity_id,
            "duplicate": True,
            "message": "Запрос уже получен",
            "delivery_message": "Мы уже получили такой запрос. Повторную заявку не создавали.",
            "test_mode": _is_test_user(user_id),
            "internal_mode": _is_internal_user(user_id),
        }

    display_name = " ".join(
        part for part in [ctx["user"].get("first_name"), ctx["user"].get("last_name")] if part
    ) or ctx["user"].get("username") or f"Telegram {user_id}"
    route = _routing_context(item)
    snapshot = _listing_snapshot(item)
    row = ListingAction(
        tenant=settings.growth_tenant,
        telegram_user_id=user_id,
        person_profile_id=ctx.get("person_profile_id"),
        username=ctx["user"].get("username"),
        display_name=display_name,
        listing_token=listing_token,
        listing_code=str(item.get("code") or "") or None,
        inventory_source_id=route["inventorySourceId"],
        inventory_owner_tenant=route["inventoryOwnerTenant"],
        routing_mode=route["routingMode"],
        action=body.action,
        message=clean_message or None,
        tracking_token=acquisition_token,
        listing_snapshot_json=snapshot,
        is_test=_exclude_from_production(user_id),
        status="new",
    )
    session.add(row)
    session.commit()
    session.refresh(row)

    attribution = _growth_link(acquisition_token) if acquisition_token else None
    link = _ensure_link(
        item,
        source=str((attribution or {}).get("source") or "telegram_miniapp"),
        medium=str((attribution or {}).get("medium") or "owned"),
        campaign=str((attribution or {}).get("campaign") or "miniapp_catalog"),
        content=body.action,
        placement="miniapp_listing_detail",
    )
    action_link_token = (link or {}).get("token")
    _growth_event(
        user_id,
        event,
        listing_token=listing_token,
        properties={"action": body.action, "action_id": str(row.id), **_event_provenance(item)},
        link_token=action_link_token,
    )
    _growth_event(
        user_id,
        "lead_qualified",
        listing_token=listing_token,
        properties={
            "lead_kind": "listing_action",
            "action": body.action,
            "action_id": str(row.id),
            **_event_provenance(item),
        },
        link_token=action_link_token,
    )

    _deliver_listing_action(row, item)
    session.commit()

    title = {
        "availability": "Запрос на проверку актуальности отправлен",
        "viewing": "Запрос на просмотр отправлен",
        "question": "Вопрос отправлен",
    }[body.action]
    if _is_test_user(user_id) or _is_internal_user(user_id):
        delivery_message = "Готово. Запрос сохранён в ваших обращениях."
    elif row.status == "delivered":
        delivery_message = "Заявка сохранена. Мы свяжемся с вами в Telegram."
    elif row.status == "collaboration_required":
        delivery_message = "Заявка сохранена. Мы согласуем запрос с владельцем объекта и свяжемся с вами в Telegram."
    else:
        delivery_message = (
            "Запрос отправлен. Мы получили вашу заявку."
        )
    return {
        "ok": True,
        "status": row.status,
        "action_id": str(row.id),
        "opportunity_id": row.crm_opportunity_id,
        "duplicate": False,
        "test_mode": _is_test_user(user_id),
        "internal_mode": _is_internal_user(user_id),
        "message": title,
        "delivery_message": delivery_message,
    }


@app.get("/v1/saved-searches")
def list_saved_searches(init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы открыть сохранённые поиски")
    if mode=="telegram":
        rows = list(session.scalars(select(SavedSearch).where(SavedSearch.tenant==settings.growth_tenant,((SavedSearch.person_profile_id==person.id)|(SavedSearch.telegram_user_id==int(user["id"])))).order_by(SavedSearch.created_at.desc())))
        for row in rows:
            if row.person_profile_id is None: row.person_profile_id=person.id
    else:
        rows = list(session.scalars(select(SavedSearch).where(SavedSearch.tenant==settings.growth_tenant,SavedSearch.person_profile_id==person.id).order_by(SavedSearch.created_at.desc())))
    return {"items": [{
        "id": str(row.id),
        "label": row.label,
        "criteria": row.criteria_json,
        "notify": row.notify,
        "active": row.active,
        "createdAt": row.created_at.isoformat(),
    } for row in rows]}


@app.post("/v1/saved-searches")
def save_search(body: SavedSearchIn, session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,body.init_data,body.session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы сохранить поиск")
    user=user or {"id":-int.from_bytes(person.id.bytes[:7],"big"),"username":None,"first_name":person.display_name}
    user_id=int(user["id"]); ctx={"user":user}
    tracking_token = _tracking_token(body.link_token, ctx)
    criteria = body.criteria
    if not criteria.get("operation") and not criteria.get("all"):
        raise HTTPException(status_code=422, detail="Choose rent or buy before saving")
    if not criteria.get("all") and not any([
        criteria.get("neighborhoods"),
        criteria.get("minBudget"),
        criteria.get("maxBudget"),
        criteria.get("rooms"),
        criteria.get("bedrooms"),
        criteria.get("minBedrooms"),
        criteria.get("minBathrooms"),
        criteria.get("parking"),
        criteria.get("minArea"),
        criteria.get("maxArea"),
        criteria.get("propertyTypes"),
        criteria.get("features"),
        criteria.get("query"),
    ]):
        raise HTTPException(status_code=422, detail="Add at least one search criterion")
    fp = _criteria_fingerprint(criteria)
    row = session.scalar(select(SavedSearch).where(
        SavedSearch.tenant == settings.growth_tenant,
        SavedSearch.person_profile_id == person.id,
        SavedSearch.fingerprint == fp,
    ))
    now = datetime.now(UTC)
    if row is None:
        row = SavedSearch(
            tenant=settings.growth_tenant,
            telegram_user_id=user_id,
            person_profile_id=person.id,
            username=user.get("username"),
            display_name=" ".join(x for x in [user.get("first_name"), user.get("last_name")] if x) or user.get("username"),
            fingerprint=fp,
            tracking_token=tracking_token,
            label=(body.label or _label(criteria))[:255],
            criteria_json=criteria,
            notify=bool(body.notify),
            active=True,
        )
        session.add(row)
        session.flush()
        # Existing inventory is the baseline. Only future listing versions can trigger a notification.
        for item in _search(criteria):
            session.add(SavedSearchMatch(
                search_id=row.id,
                listing_code=item.get("listingToken") or item.get("code") or "",
                source_fingerprint=item.get("sourceFingerprint") or hashlib.sha256((item.get("listingToken") or item.get("code") or "").encode()).hexdigest(),
                price_amount=_safe_num(item.get("priceAmount")),
                price_currency=item.get("priceCurrency") or None,
                first_seen_at=now,
                notified_at=now,
            ))
    else:
        row.notify = bool(body.notify)
        row.active = True
        row.updated_at = now
        row.label = (body.label or row.label)[:255]
        if not row.tracking_token and tracking_token:
            row.tracking_token = tracking_token
    matches_now = len(_search(criteria))
    session.flush()
    if not _exclude_from_production(user_id):
        _crm_sync_saved_search(row, user, matches_now)
        if row.crm_webhook_delivered_at is None:
            _crm_webhook_sync(row, user, matches_now)
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
    if settings.operator_chat_id and not _exclude_from_production(user_id):
        who = f"@{user.get('username')}" if user.get("username") else (row.display_name or str(user_id))
        _bot_send(
            settings.operator_chat_id,
            f"🔎 <b>Сохранённый поиск {settings.brand_name}</b>\n"
            f"{who}\n{row.label}\n"
            f"Сейчас в каталоге: {matches_now}\n"
            f"Уведомления: {'да' if body.notify else 'нет'}",
            bot_token=settings.operator_bot_token or None,
        )
    return {"ok": True, "id": str(row.id), "label": row.label, "matches_now": matches_now, "notify": row.notify, "active": row.active}


@app.patch("/v1/saved-searches/{search_id}")
def update_saved_search_state(search_id: UUID, body: SavedSearchStateIn, session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,body.init_data,body.session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите")
    row = session.scalar(select(SavedSearch).where(SavedSearch.id==search_id,SavedSearch.tenant==settings.growth_tenant,SavedSearch.person_profile_id==person.id))
    if not row:
        raise HTTPException(status_code=404, detail="Saved search not found")
    if body.notify is not None:
        row.notify = body.notify
    if body.active is not None:
        row.active = body.active
    row.updated_at = datetime.now(UTC)
    session.commit()
    return {"ok": True, "id": str(row.id), "notify": row.notify, "active": row.active}


@app.delete("/v1/saved-searches/{search_id}")
def disable_search(search_id: UUID, init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите")
    row = session.scalar(select(SavedSearch).where(SavedSearch.id==search_id,SavedSearch.tenant==settings.growth_tenant,SavedSearch.person_profile_id==person.id))
    if not row:
        raise HTTPException(status_code=404, detail="Saved search not found")
    row.active = False
    row.updated_at = datetime.now(UTC)
    session.commit()
    return {"ok": True}


@app.post("/v1/internal/reconcile-integrations")
def reconcile_integrations(
    x_intent_key: str | None = Header(default=None),
    session: Session = Depends(db),
):
    if not x_intent_key or not hmac.compare_digest(x_intent_key, settings.service_key):
        raise HTTPException(status_code=401, detail="Invalid intent key")
    rows = list(session.scalars(
        select(SavedSearch)
        .where(SavedSearch.tenant == settings.growth_tenant)
        .order_by(SavedSearch.created_at.asc())
        .limit(200)
    ))
    attempted = 0
    delivered = 0
    failed = 0
    for row in rows:
        if _is_test_user(row.telegram_user_id):
            continue
        needs_direct = bool(
            settings.crm_base_url
            and settings.crm_api_key
            and not row.crm_opportunity_id
        )
        needs_webhook = bool(
            settings.crm_webhook_url
            and settings.crm_webhook_secret
            and row.crm_webhook_delivered_at is None
        )
        if not needs_direct and not needs_webhook:
            continue
        attempted += 1
        user = {
            "id": row.telegram_user_id,
            "username": row.username,
            "first_name": row.display_name,
        }
        matches_now = len(_search(row.criteria_json))
        if needs_direct:
            _crm_sync_saved_search(row, user, matches_now)
        webhook_ok: bool | None = None
        if needs_webhook:
            webhook_ok = _crm_webhook_sync(row, user, matches_now)
        direct_ok = (not needs_direct) or bool(row.crm_opportunity_id)
        webhook_done = (not needs_webhook) or webhook_ok is True
        if direct_ok and webhook_done:
            delivered += 1
        else:
            failed += 1

    listing_action_attempted = 0
    listing_action_delivered = 0
    listing_action_failed = 0
    action_rows = list(session.scalars(
        select(ListingAction)
        .where(
            ListingAction.tenant == settings.growth_tenant,
            ListingAction.is_test.is_(False),
            ListingAction.status.in_(["new", "retry"]),
        )
        .order_by(ListingAction.created_at.asc())
        .limit(200)
    ))
    for action_row in action_rows:
        listing_action_attempted += 1
        item = dict(action_row.listing_snapshot_json or {})
        if not item:
            item = _listing_by_key(action_row.listing_token) or {}
        if not item:
            action_row.delivery_error = "listing_snapshot_missing"
            action_row.status = "retry"
            action_row.updated_at = datetime.now(UTC)
            listing_action_failed += 1
            continue
        _deliver_listing_action(action_row, item)
        if action_row.status == "delivered":
            listing_action_delivered += 1
        else:
            listing_action_failed += 1
    outbound_attempted = 0
    outbound_delivered = 0
    outbound_failed = 0
    outbound_rows = list(session.scalars(
        select(OutboundClick)
        .where(
            OutboundClick.tenant == settings.growth_tenant,
            OutboundClick.status.in_(["new", "retry"]),
        )
        .order_by(OutboundClick.created_at.asc())
        .limit(200)
    ))
    for click_row in outbound_rows:
        outbound_attempted += 1
        item = dict(click_row.listing_snapshot_json or {})
        if not item:
            item = _listing_by_key(click_row.listing_token) or {}
        if not item:
            click_row.delivery_error = "listing_snapshot_missing"
            click_row.status = "retry"
            click_row.updated_at = datetime.now(UTC)
            outbound_failed += 1
            continue
        _deliver_outbound_click(click_row, item)
        if click_row.status == "delivered":
            outbound_delivered += 1
        else:
            outbound_failed += 1

    session.commit()
    return {
        "ok": True,
        "attempted": attempted,
        "delivered": delivered,
        "failed": failed,
        "listing_actions": {
            "attempted": listing_action_attempted,
            "delivered": listing_action_delivered,
            "failed": listing_action_failed,
        },
        "outbound_clicks": {
            "attempted": outbound_attempted,
            "delivered": outbound_delivered,
            "failed": outbound_failed,
        },
    }


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
    price_drop_matches = 0
    delivery_attempts = 0
    delivery_failures = 0
    for search in searches:
        pending: list[tuple[dict[str, Any], SavedSearchMatch]] = []
        for item in _search(search.criteria_json):
            # Notify once per listing code. A photo/text/source-fingerprint refresh must
            # not look like a new property. If Telegram delivery fails, keep the match
            # pending and retry on the next catalogue sync instead of silently losing it.
            item_key = item.get("listingToken") or item.get("code") or ""
            match = session.scalar(select(SavedSearchMatch).where(
                SavedSearchMatch.search_id == search.id,
                SavedSearchMatch.listing_code == item_key,
            ))
            current_price=_safe_num(item.get("priceAmount"))
            current_currency=item.get("priceCurrency") or None
            if match and match.notified_at is not None:
                # A meaningful price change is a new commercial signal, but photo/text refreshes are not.
                old_price=match.price_amount
                same_currency=bool(old_price and current_price and match.price_currency==current_currency)
                significant_price_change=same_currency and current_price < old_price and (old_price-current_price)/old_price >= 0.03
                if not significant_price_change:
                    continue
                match.price_amount=current_price; match.price_currency=current_currency; match.source_fingerprint=item.get("sourceFingerprint") or hashlib.sha256((item.get("listingToken") or item.get("code") or "").encode()).hexdigest(); match.notified_at=None; new_matches += 1; price_drop_matches += 1
            if match is None:
                match = SavedSearchMatch(
                    search_id=search.id,
                    listing_code=item_key,
                    source_fingerprint=item.get("sourceFingerprint") or hashlib.sha256((item.get("listingToken") or item.get("code") or "").encode()).hexdigest(),
                    price_amount=current_price,
                    price_currency=current_currency,
                )
                session.add(match)
                session.flush()
                new_matches += 1
            pending.append((item, match))
        if not pending:
            continue
        chosen = [item for item, _ in pending[:3]]
        lines = ["✨ <b>Есть обновления по вашему поиску</b>", search.label, ""]
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
            params = {"listing": str(item.get("listingToken") or item.get("code") or "")}
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
        sent = False
        delivery_channel = "none"
        if search.telegram_user_id and search.telegram_user_id > 0:
            sent = _bot_send(search.telegram_user_id, "\n".join(lines), {"inline_keyboard": keyboard})
            delivery_channel = "telegram" if sent else "none"
        if not sent and search.person_profile_id and settings.vapid_private_key.strip():
            pushes=list(session.scalars(select(PersonPushSubscription).where(PersonPushSubscription.tenant==settings.growth_tenant,PersonPushSubscription.person_profile_id==search.person_profile_id,PersonPushSubscription.active.is_(True))))
            payload={"title":f"Новые варианты · {settings.brand_name}","body":search.label,"url":catalog_url,"tag":f"saved-search-{search.id}"}
            for push in pushes:
                if _webpush_send(push.subscription_json,payload): sent=True; delivery_channel="web_push"
                else: push.active=False; push.updated_at=datetime.now(UTC)
        if not sent and search.person_profile_id:
            person = session.get(PersonProfile, search.person_profile_id)
            email = _normalize_email(str((person.facts_json or {}).get("email") or "")) if person else ""
            ident = session.scalar(select(PersonIdentity).where(PersonIdentity.tenant==settings.growth_tenant,PersonIdentity.person_profile_id==search.person_profile_id,PersonIdentity.provider=="email",PersonIdentity.provider_key==email,PersonIdentity.verified_at.is_not(None))) if email else None
            if ident and settings.resend_api_key.strip():
                plain = ["Есть обновления по вашему поиску", search.label, ""]
                for item in chosen:
                    price = f"{item.get('priceCurrency') or ''} {item.get('priceAmount') or ''}".strip()
                    params = {"listing": str(item.get("listingToken") or item.get("code") or "")}
                    plain.append(f"• {item.get('address') or item.get('code')} · {price} · {settings.miniapp_url.rstrip('/')}?{urlencode(params)}")
                plain.append(f"\nОткрыть поиск: {catalog_url}")
                try:
                    r=httpx.post("https://api.resend.com/emails",headers={"Authorization":f"Bearer {settings.resend_api_key}"},json={"from":settings.auth_email_from,"to":[email],"reply_to":settings.auth_email_reply_to,"subject":f"Новые варианты · {settings.brand_name}","text":"\n".join(plain)},timeout=10)
                    sent = 200 <= r.status_code < 300
                    delivery_channel = "email" if sent else "none"
                except Exception:
                    sent = False
        now = datetime.now(UTC)
        if sent:
            notifications += 1
            search.last_notified_at = now
            for item, match in pending:
                match.notified_at = now
                match.price_amount = _safe_num(item.get("priceAmount"))
                match.price_currency = item.get("priceCurrency") or None
            _growth_event(
                search.telegram_user_id,
                "notification_sent",
                properties={"saved_search_id": str(search.id), "new_matches": len(pending), "channel": delivery_channel},
                link_token=catalog_token or None,
            )
        else:
            delivery_failures += 1
    session.commit()
    return {
        "ok": True,
        "active_searches": len(searches),
        "new_matches": new_matches,
        "price_drop_matches": price_drop_matches,
        "notifications": notifications,
        "delivery_attempts": delivery_attempts,
        "delivery_failures": delivery_failures,
    }

# --- Le Bleu Telegram Marketplace domain (2026-10-28) ---
# Additive implementation. Existing SavedSearch remains the canonical SearchProfile storage.
class PersonProfile(Base):
    __tablename__ = "person_profiles"
    __table_args__ = (UniqueConstraint("tenant", "telegram_user_id", name="uq_person_tenant_telegram"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    telegram_user_id: Mapped[int | None] = mapped_column(BigInteger, index=True, nullable=True)
    username: Mapped[str | None] = mapped_column(String(128), nullable=True)
    display_name: Mapped[str | None] = mapped_column(String(255), nullable=True)
    preferred_language: Mapped[str] = mapped_column(String(8), default="ru")
    facts_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class PersonIdentity(Base):
    __tablename__ = "person_identities"
    __table_args__ = (UniqueConstraint("tenant", "provider", "provider_key", name="uq_person_identity_provider"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    person_profile_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="CASCADE"), index=True)
    provider: Mapped[str] = mapped_column(String(24), index=True)
    provider_key: Mapped[str] = mapped_column(String(320))
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class PersonSession(Base):
    __tablename__ = "person_sessions"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    person_profile_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="CASCADE"), index=True)
    token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    last_used_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    revoked_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class PersonEmailChallenge(Base):
    __tablename__ = "person_email_challenges"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    challenge_key: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    email: Mapped[str] = mapped_column(String(254), index=True)
    code_hash: Mapped[str] = mapped_column(String(64))
    person_profile_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="SET NULL"), nullable=True)
    language: Mapped[str] = mapped_column(String(8), default="ru")
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    consumed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class PersonPushSubscription(Base):
    __tablename__ = "person_push_subscriptions"
    __table_args__ = (UniqueConstraint("tenant", "endpoint_hash", name="uq_person_push_endpoint"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    person_profile_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="CASCADE"), index=True)
    endpoint_hash: Mapped[str] = mapped_column(String(64), index=True)
    subscription_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class SearchCandidate(Base):
    __tablename__ = "search_candidates"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    telegram_user_id: Mapped[int] = mapped_column(BigInteger, index=True)
    raw_text: Mapped[str] = mapped_column(String(4000))
    criteria_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    person_facts_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="candidate", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    confirmed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)

class PartnerAgency(Base):
    __tablename__ = "partner_agencies"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    name: Mapped[str] = mapped_column(String(255))
    website_url: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    responsible_professional: Mapped[str | None] = mapped_column(String(255), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    terms_version: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class ListingResponsibility(Base):
    __tablename__ = "listing_responsibilities"
    __table_args__ = (UniqueConstraint("tenant","inventory_source_id","listing_key",name="uq_listing_responsibility"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    inventory_source_id: Mapped[str] = mapped_column(String(64), index=True)
    listing_key: Mapped[str] = mapped_column(String(120), default="*", index=True)
    operation: Mapped[str | None] = mapped_column(String(24), nullable=True)
    actor_type: Mapped[str] = mapped_column(String(24))
    actor_id: Mapped[str] = mapped_column(String(128))
    fallback_actor_type: Mapped[str | None] = mapped_column(String(24), nullable=True)
    fallback_actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    active: Mapped[bool] = mapped_column(Boolean, default=True, index=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class MarketplaceConversation(Base):
    __tablename__ = "marketplace_conversations"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    person_profile_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="CASCADE"), index=True)
    search_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("saved_searches.id", ondelete="SET NULL"), nullable=True, index=True)
    listing_code: Mapped[str] = mapped_column(String(120), index=True)
    inventory_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inventory_owner_tenant: Mapped[str | None] = mapped_column(String(64), nullable=True)
    partner_agency_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("partner_agencies.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="open", index=True)
    primary_intent: Mapped[str] = mapped_column(String(24), default="question", index=True)
    workflow_status: Mapped[str] = mapped_column(String(24), default="new", index=True)
    assigned_actor_type: Mapped[str | None] = mapped_column(String(24), nullable=True)
    assigned_actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    next_action_type: Mapped[str | None] = mapped_column(String(48), nullable=True, index=True)
    next_action_due_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    first_response_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_client_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    last_operator_activity_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    closed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    close_reason: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source_channel: Mapped[str] = mapped_column(String(24), default="legacy", index=True)
    preferred_outbound_channel: Mapped[str | None] = mapped_column(String(24), nullable=True)
    assigned_queue: Mapped[str | None] = mapped_column(String(64), nullable=True, index=True)
    routing_decision_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    escalation_level: Mapped[int] = mapped_column(Integer, default=0, index=True)
    rescue_reason: Mapped[str | None] = mapped_column(String(128), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    client_last_read_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    qualification_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

class MarketplaceMessage(Base):
    __tablename__ = "marketplace_messages"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    conversation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), index=True)
    sender_role: Mapped[str] = mapped_column(String(24))
    source_language: Mapped[str] = mapped_column(String(8), default="ru")
    body: Mapped[str] = mapped_column(String(4000))
    translated_body: Mapped[str | None] = mapped_column(String(4000), nullable=True)
    translation_status: Mapped[str] = mapped_column(String(24), default="not_needed")
    translation_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    delivery_status: Mapped[str | None] = mapped_column(String(24), nullable=True, default="stored")
    source_channel: Mapped[str] = mapped_column(String(24), default="legacy", index=True)
    external_provider: Mapped[str | None] = mapped_column(String(32), nullable=True)
    external_message_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    reply_to_message_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_messages.id", ondelete="SET NULL"), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class MarketplaceViewingRequest(Base):
    __tablename__ = "marketplace_viewing_requests"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    conversation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), index=True)
    preferred_windows_json: Mapped[list[str]] = mapped_column(JSON, default=list)
    note: Mapped[str | None] = mapped_column(String(1000), nullable=True)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class PartnerHandoff(Base):
    __tablename__ = "partner_handoffs"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    conversation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), index=True)
    partner_agency_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("partner_agencies.id", ondelete="SET NULL"), nullable=True, index=True)
    transport: Mapped[str] = mapped_column(String(24), default="manual")
    recipient_ref: Mapped[str | None] = mapped_column(String(320), nullable=True)
    sanitized_snapshot_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    claim_token_hash: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    claimed_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    sent_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    claimed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), index=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class CommunicationProjection(Base):
    __tablename__ = "communication_projections"
    __table_args__ = (UniqueConstraint("provider","conversation_id",name="uq_communication_projection_case"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    conversation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), index=True)
    external_contact_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    external_conversation_id: Mapped[str | None] = mapped_column(String(128), nullable=True, index=True)
    external_inbox_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    sync_status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class CommunicationOutbox(Base):
    __tablename__ = "communication_outbox"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    kind: Mapped[str] = mapped_column(String(48), index=True)
    conversation_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), nullable=True, index=True)
    message_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_messages.id", ondelete="CASCADE"), nullable=True, index=True)
    payload_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    status: Mapped[str] = mapped_column(String(24), default="pending", index=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    next_attempt_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True, index=True)
    external_delivery_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    last_error: Mapped[str | None] = mapped_column(String(500), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class IntegrationDelivery(Base):
    __tablename__ = "integration_deliveries"
    __table_args__ = (UniqueConstraint("provider","delivery_id",name="uq_integration_delivery"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    provider: Mapped[str] = mapped_column(String(32), index=True)
    delivery_id: Mapped[str] = mapped_column(String(128))
    event_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class MarketplaceViewing(Base):
    __tablename__ = "marketplace_viewings"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    conversation_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("marketplace_conversations.id", ondelete="CASCADE"), index=True)
    proposed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    status: Mapped[str] = mapped_column(String(24), default="proposed", index=True)
    proposed_by: Mapped[str] = mapped_column(String(24), default="partner")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class CollaborationAgreement(Base):
    __tablename__ = "collaboration_agreements"
    __table_args__ = (UniqueConstraint("tenant","partner_agency_id","version",name="uq_collaboration_agreement_version"),)
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    partner_agency_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("partner_agencies.id", ondelete="CASCADE"), index=True)
    version: Mapped[str] = mapped_column(String(64))
    status: Mapped[str] = mapped_column(String(24), default="draft")
    terms_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    accepted_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

class MarketplaceMetric(Base):
    __tablename__ = "marketplace_metrics"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    event_name: Mapped[str] = mapped_column(String(64), index=True)
    actor_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    object_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    properties_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC), index=True)

class CollaborationCase(Base):
    __tablename__ = "collaboration_cases"
    id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), primary_key=True, default=uuid4)
    tenant: Mapped[str] = mapped_column(String(64), index=True)
    person_profile_id: Mapped[UUID] = mapped_column(PgUUID(as_uuid=True), ForeignKey("person_profiles.id", ondelete="RESTRICT"), index=True)
    search_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("saved_searches.id", ondelete="SET NULL"), nullable=True)
    listing_code: Mapped[str] = mapped_column(String(120), index=True)
    buyer_origin_tenant: Mapped[str] = mapped_column(String(64), index=True)
    inventory_source_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    inventory_owner_tenant: Mapped[str] = mapped_column(String(64), index=True)
    agreement_id: Mapped[UUID | None] = mapped_column(PgUUID(as_uuid=True), ForeignKey("collaboration_agreements.id", ondelete="SET NULL"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), default="requested", index=True)
    pii_released_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    introduction_evidence_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))

@app.on_event("startup")
def startup_marketplace_schema():
    # Marketplace ORM models are declared after the legacy startup hook. A second
    # idempotent create_all makes those additive tables available on deployment.
    Base.metadata.create_all(engine)
    with engine.begin() as conn:
        conn.execute(text("ALTER TABLE marketplace_messages ADD COLUMN IF NOT EXISTS delivery_status VARCHAR(24)"))
        conn.execute(text("ALTER TABLE saved_searches ADD COLUMN IF NOT EXISTS person_profile_id UUID"))
        conn.execute(text("ALTER TABLE person_profiles ALTER COLUMN telegram_user_id DROP NOT NULL"))
        conn.execute(text("ALTER TABLE listing_actions ADD COLUMN IF NOT EXISTS person_profile_id UUID"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS client_last_read_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS qualification_snapshot_json JSON DEFAULT '{}'::json"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS primary_intent VARCHAR(24) DEFAULT 'question'"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS workflow_status VARCHAR(24) DEFAULT 'new'"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS assigned_actor_type VARCHAR(24)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS assigned_actor_id VARCHAR(128)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS next_action_type VARCHAR(48)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS next_action_due_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS first_response_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS last_client_activity_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS last_operator_activity_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS closed_at TIMESTAMPTZ"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS close_reason VARCHAR(64)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS source_channel VARCHAR(24) DEFAULT 'legacy'"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS preferred_outbound_channel VARCHAR(24)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS assigned_queue VARCHAR(64)"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS routing_decision_json JSON DEFAULT '{}'::json"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS escalation_level INTEGER DEFAULT 0"))
        conn.execute(text("ALTER TABLE marketplace_conversations ADD COLUMN IF NOT EXISTS rescue_reason VARCHAR(128)"))
        conn.execute(text("ALTER TABLE marketplace_messages ADD COLUMN IF NOT EXISTS source_channel VARCHAR(24) DEFAULT 'legacy'"))
        conn.execute(text("ALTER TABLE marketplace_messages ADD COLUMN IF NOT EXISTS external_provider VARCHAR(32)"))
        conn.execute(text("ALTER TABLE marketplace_messages ADD COLUMN IF NOT EXISTS external_message_id VARCHAR(128)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_marketplace_conversations_workflow_status ON marketplace_conversations (workflow_status)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_marketplace_conversations_next_action_due_at ON marketplace_conversations (next_action_due_at)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_marketplace_conversations_assigned_queue ON marketplace_conversations (assigned_queue)"))
        conn.execute(text("CREATE INDEX IF NOT EXISTS ix_marketplace_messages_external_message_id ON marketplace_messages (external_message_id)"))

class AgentLoginIn(BaseModel):
    password: str = Field(min_length=8, max_length=256)

class EmailAuthStartIn(BaseModel):
    email: str = Field(min_length=5, max_length=254)
    language: str = Field(default="ru", pattern="^(ru|es|en)$")
    init_data: str = ""

class EmailAuthVerifyIn(BaseModel):
    challenge_id: str = Field(min_length=8, max_length=64)
    code: str = Field(min_length=6, max_length=6)
    init_data: str = ""

class PartnerIn(BaseModel):
    name: str = Field(min_length=2, max_length=255)
    website_url: str | None = Field(default=None, max_length=1000)
    responsible_professional: str | None = Field(default=None, max_length=255)
    metadata: dict[str, Any] = Field(default_factory=dict)

class ConversationIn(BaseModel):
    init_data: str = ""
    listing_code: str
    search_id: UUID | None = None
    intent: str = Field(default="question", pattern="^(question|viewing)$")
    message: str = Field(default="", max_length=4000)
    viewing_windows: list[str] = Field(default_factory=list, max_length=6)
    source_language: str = Field(default="ru", pattern="^(ru|es|en)$")
    source_channel: str = Field(default="web", pattern="^(web|telegram|whatsapp|email)$")

class ClientMessageIn(BaseModel):
    init_data: str = ""
    body: str = Field(min_length=1, max_length=4000)
    source_language: str = Field(default="ru", pattern="^(ru|es|en)$")
    source_channel: str = Field(default="web", pattern="^(web|telegram|whatsapp|email)$")
    reply_to_message_id: UUID | None = None

class ProfileIn(BaseModel):
    init_data: str = ""
    session_token: str = ""
    preferred_language: str = Field(default="ru", pattern="^(ru|es|en)$")
    facts: dict[str, Any] = Field(default_factory=dict)

class MessageIn(BaseModel):
    body: str = Field(min_length=1, max_length=4000)
    source_language: str = Field(default="es", pattern="^(ru|es|en)$")
    reply_to_message_id: UUID | None = None

class ViewingIn(BaseModel):
    proposed_at: datetime

class CollaborationIn(BaseModel):
    init_data: str = ""
    listing_code: str
    search_id: UUID | None = None

class PartnerStateIn(BaseModel):
    status: str = Field(pattern="^(pending|active|paused|rejected)$")
    verified: bool = False

class PartnerSourceIn(BaseModel):
    source_id: str = Field(min_length=2, max_length=64)

class PartnerListingImportIn(BaseModel):
    source_id: str = Field(min_length=2, max_length=64)
    url: str = Field(min_length=8, max_length=2000)

class AgreementIn(BaseModel):
    partner_agency_id: UUID
    version: str = Field(min_length=1, max_length=64)
    terms: dict[str, Any] = Field(default_factory=dict)

class AgreementAcceptIn(BaseModel):
    accepted: bool = True
    partner_confirmed: bool = False

class CollaborationDecisionIn(BaseModel):
    agreement_id: UUID
    accept: bool = True

class CollaborationOutcomeIn(BaseModel):
    outcome: str = Field(pattern="^(offer|reserved|closed_won|closed_lost)$")
    note: str | None = Field(default=None, max_length=1000)

class PartnerHandoffIn(BaseModel):
    conversation_id: UUID
    partner_agency_id: UUID | None = None
    transport: str = Field(default="manual", pattern="^(manual|whatsapp|email|api)$")
    recipient_ref: str | None = Field(default=None, max_length=320)

class PartnerHandoffClaimIn(BaseModel):
    token: str = Field(min_length=24, max_length=256)
    claimant: str = Field(min_length=2, max_length=255)
    accept: bool = True

class ListingResponsibilityIn(BaseModel):
    inventory_source_id: str = Field(min_length=1, max_length=64)
    listing_key: str = Field(default="*", min_length=1, max_length=120)
    operation: str | None = Field(default=None, pattern="^(Alquiler|Venta)$")
    actor_type: str = Field(pattern="^(internal_agent|team|partner_agent|partner_team|owner|queue)$")
    actor_id: str = Field(min_length=1, max_length=128)
    fallback_actor_type: str | None = Field(default=None, max_length=24)
    fallback_actor_id: str | None = Field(default=None, max_length=128)
    metadata: dict[str, Any] = Field(default_factory=dict)

_CABA_HOODS = ["Agronomía","Almagro","Balvanera","Barracas","Belgrano","Boedo","Caballito","Chacarita","Coghlan","Colegiales","Constitución","Flores","Floresta","La Boca","La Paternal","Liniers","Mataderos","Monte Castro","Monserrat","Nueva Pompeya","Núñez","Palermo","Parque Avellaneda","Parque Chacabuco","Parque Chas","Parque Patricios","Puerto Madero","Recoleta","Retiro","Saavedra","San Cristóbal","San Nicolás","San Telmo","Vélez Sarsfield","Versalles","Villa Crespo","Villa del Parque","Villa Devoto","Villa General Mitre","Villa Lugano","Villa Luro","Villa Ortúzar","Villa Pueyrredón","Villa Real","Villa Riachuelo","Villa Santa Rita","Villa Soldati","Villa Urquiza"]

def _marketplace_service_auth(key: str | None) -> None:
    if not key or not hmac.compare_digest(key, settings.service_key):
        raise HTTPException(status_code=401, detail="Invalid intent key")

def _safe_qualification_snapshot(facts: dict[str, Any] | None, *, operation: str | None = None, search: SavedSearch | None = None) -> dict[str, Any]:
    facts=facts or {}
    allowed=("occupants","pets","guarantee","moveIn","termMonths","incomeType","purchaseTiming","financingType")
    snapshot={k:facts[k] for k in allowed if k in facts and facts.get(k) not in (None,"")}
    criteria=(search.criteria_json or {}) if search else {}
    for src,dst in (("moveIn","moveIn"),("termMonths","termMonths"),("purchaseTiming","purchaseTiming")):
        if dst not in snapshot and criteria.get(src) not in (None,""): snapshot[dst]=criteria[src]
    if operation: snapshot["operation"]=operation
    return snapshot

def _readiness_for(person: PersonProfile, item: dict[str, Any], search: SavedSearch | None = None) -> dict[str, Any]:
    operation=str(item.get("operation") or "")
    facts=person.facts_json or {}
    if operation=="Alquiler":
        required=("occupants","pets","incomeType","guarantee")
    elif operation=="Venta":
        required=("purchaseTiming","financingType")
    else:
        required=()
    missing=[key for key in required if key not in facts or facts.get(key) in (None,"")]
    snapshot=_safe_qualification_snapshot(facts,operation=operation,search=search)
    return {"operation":operation,"ready":not missing,"state":"ready" if not missing else "incomplete","missing":missing,"snapshot":snapshot,"warnings":[],"verification":facts.get("verification") if isinstance(facts.get("verification"),dict) else {}}

def _effective_channel(mode: str, requested: str | None = None) -> str:
    if mode=="telegram": return "telegram"
    return requested if requested in {"web","email","whatsapp"} else "web"

def _preferred_channel(person: PersonProfile, source_channel: str) -> str:
    preferred=str((person.facts_json or {}).get("preferredChannel") or "")
    return preferred if preferred in {"web","telegram","email","whatsapp"} else source_channel

def _resolve_case_assignment(session: Session, item: dict[str, Any], partner: PartnerAgency | None = None) -> dict[str, Any]:
    source_id=str(item.get("sourceId") or item.get("inventorySourceId") or "")
    listing_key=str(item.get("listingToken") or item.get("code") or "")
    operation=str(item.get("operation") or "")
    responsibility=None
    if source_id:
        responsibility=session.scalar(select(ListingResponsibility).where(ListingResponsibility.tenant==settings.growth_tenant,ListingResponsibility.inventory_source_id==source_id,ListingResponsibility.listing_key==listing_key,ListingResponsibility.active.is_(True)))
        if responsibility is None:
            responsibility=session.scalar(select(ListingResponsibility).where(ListingResponsibility.tenant==settings.growth_tenant,ListingResponsibility.inventory_source_id==source_id,ListingResponsibility.listing_key=="*",ListingResponsibility.active.is_(True)))
    if operation=="Venta":
        return {"actorType":"queue","actorId":"lebleu_sales","queue":"lebleu_sales","reason":"buyer_origin_protected","listingResponsibilityId":str(responsibility.id) if responsibility else None}
    if responsibility:
        return {"actorType":responsibility.actor_type,"actorId":responsibility.actor_id,"queue":responsibility.actor_id if responsibility.actor_type in {"team","queue","partner_team"} else None,"reason":"listing_responsibility","responsibilityId":str(responsibility.id)}
    if partner:
        return {"actorType":"partner_agency","actorId":str(partner.id),"queue":f"partner:{partner.id}","reason":"verified_partner_inventory"}
    return {"actorType":"queue","actorId":"lebleu_rental" if operation=="Alquiler" else "central_operator","queue":"lebleu_rental" if operation=="Alquiler" else "central_operator","reason":"operation_fallback"}

def _queue_communication_projection(session: Session, conversation_id: UUID, kind: str, *, message_id: UUID | None = None, payload: dict[str, Any] | None = None) -> None:
    if not settings.chatwoot_enabled: return
    session.add(CommunicationOutbox(provider="chatwoot",kind=kind,conversation_id=conversation_id,message_id=message_id,payload_json=payload or {},status="pending",next_attempt_at=datetime.now(UTC)))

def _workflow_label(status: str | None) -> str:
    return {
        "new":"Запрос отправлен",
        "in_progress":"Согласовываем",
        "waiting_partner":"Согласовываем",
        "waiting_client":"Ждём вашего ответа",
        "scheduled":"Просмотр подтверждён",
        "unavailable":"Объект недоступен",
        "closed":"Обращение завершено",
    }.get(status or "new","Согласовываем")

def _conversation_listing(row: MarketplaceConversation) -> dict[str, Any] | None:
    return _listing_by_key(row.listing_code)

def _operator_inquiry_notification(session: Session, row: MarketplaceConversation, *, message: str | None = None) -> None:
    if not settings.operator_chat_id:
        return
    item=_conversation_listing(row) or {}
    person=session.get(PersonProfile,row.person_profile_id)
    facts=(person.facts_json or {}) if person else {}
    who=(f"@{person.username}" if person and person.username else (person.display_name if person and person.display_name else "Клиент"))
    qualification=row.qualification_snapshot_json or {}
    lines=[f"🔥 <b>Где жить · {'запрос на просмотр' if row.primary_intent=='viewing' else 'новое обращение'}</b>",html.escape(str(item.get('address') or item.get('code') or row.listing_code)),f"Клиент: <b>{html.escape(str(who))}</b>"]
    contact=" · ".join(str(x) for x in (facts.get("phone"),facts.get("email")) if x)
    if contact: lines.append("Контакт: "+html.escape(contact))
    if row.primary_intent=="viewing": lines.append("Готовность: <b>✓ данные для запроса собраны</b>")
    if qualification:
        labels={"occupants":"Жильцы","pets":"Питомцы","guarantee":"Гарантия","moveIn":"Въезд","termMonths":"Срок","incomeType":"Доход"}
        lines.append("Контекст: "+html.escape(" · ".join(f"{labels.get(k,k)}: {v}" for k,v in qualification.items())))
    source=item.get("sourceDisplayName") or item.get("sourceName") or item.get("sourceId") or row.inventory_source_id or row.inventory_owner_tenant or "—"
    lines.extend([f"Inventory: {html.escape(str(source))}",f"Ответственный: <b>{html.escape(str(row.assigned_actor_id or row.assigned_queue or 'central_operator'))}</b>",f"Статус: <b>{html.escape(_workflow_label(row.workflow_status))}</b>"])
    if message: lines.extend(["",html.escape(message[:1200])])
    keyboard={"inline_keyboard":[
        [{"text":"✍️ Ответить","callback_data":f"inqreply:{row.id}"},{"text":"📅 Предложить время","callback_data":f"inqtime:{row.id}"}],
        [{"text":"🚫 Недоступен","callback_data":f"inqunavail:{row.id}"}],
        [{"text":"🏠 Открыть объект","url":f"https://t.me/{settings.telegram_bot_username}?startapp=listing_{row.listing_code}"}],
    ]}
    _bot_send(settings.operator_chat_id,"\n".join(lines),keyboard,bot_token=settings.operator_bot_token or None)

def _marketplace_metric(session: Session, event_name: str, *, actor_id: Any = None, object_id: Any = None, properties: dict[str, Any] | None = None) -> None:
    safe_properties={k:v for k,v in (properties or {}).items() if k not in {"body","message","raw_text","phone","email"}}
    session.add(MarketplaceMetric(tenant=settings.growth_tenant,event_name=event_name,actor_id=str(actor_id) if actor_id is not None else None,object_id=str(object_id) if object_id is not None else None,properties_json=safe_properties))

def _parse_search_text(raw: str) -> tuple[dict[str, Any], dict[str, Any]]:
    text0 = raw.strip()
    textn = _norm(text0)
    criteria: dict[str, Any] = {}
    facts: dict[str, Any] = {}
    if re.search(r"\b(куп|покуп|compr|venta)\w*", textn): criteria["operation"] = "Venta"
    elif re.search(r"\b(аренд|снять|alquil|rent)\w*", textn): criteria["operation"] = "Alquiler"
    if re.search(r"\b(квартир|departamento|depto|apartment)\w*", textn): criteria["propertyTypes"] = ["Departamento"]
    elif re.search(r"\b(дом|casa|house)\w*", textn): criteria["propertyTypes"] = ["Casa"]
    elif re.search(r"\b(ph)\b", textn): criteria["propertyTypes"] = ["PH"]
    hoods = [h for h in _CABA_HOODS if _norm(h) in textn]
    for ascii_name,canonical in {"nunez":"Núñez","agronomia":"Agronomía","constitucion":"Constitución","san cristobal":"San Cristóbal","san nicolas":"San Nicolás","velez sarsfield":"Vélez Sarsfield","villa ortuzar":"Villa Ortúzar","villa pueyrredon":"Villa Pueyrredón"}.items():
        if ascii_name in textn and canonical not in hoods: hoods.append(canonical)
    if hoods: criteria["neighborhoods"] = hoods
    m = re.search(r"\b([1-6])\s*(?:ambientes?|амб(?:иент)?|комнат)", textn)
    if m: criteria["rooms"] = int(m.group(1))
    money = re.search(r"(?:до|max(?:imo)?|hasta)?\s*(?:usd|us\$|u\$s|доллар\w*|\$)\s*([0-9][0-9 .]{2,})", textn)
    if not money: money = re.search(r"(?:до|hasta|max(?:imo)?)\s*([0-9][0-9 .]{2,})\s*(?:usd|us\$|u\$s|доллар\w*|\$)", textn)
    if money:
        criteria["maxBudget"] = int(re.sub(r"\D", "", money.group(1)))
        criteria["budgetCurrency"] = "USD"
    ars = re.search(r"(?:до|hasta|max(?:imo)?)\s*([0-9][0-9 .]{4,})\s*(?:ars|песо|pesos?)", textn)
    if ars:
        criteria["maxBudget"] = int(re.sub(r"\D", "", ars.group(1)))
        criteria["budgetCurrency"] = "ARS"
    if re.search(r"\b(кот|кошка|собак|gato|perro|mascota)\w*", textn): facts["pets"] = True
    if re.search(r"\b(без кот|без кош|без собак|sin gato|sin perro|sin mascota)\w*", textn): facts["pets"] = False
    if re.search(r"\b(мебел|amoblad|amueblad|furnished)\w*", textn):
        criteria["features"] = sorted(set([*(criteria.get("features") or []), "amoblado"])); facts["furnished"] = True
    if re.search(r"\b(без мебел|sin amoblar|sin muebles|unfurnished)\w*", textn):
        criteria["features"] = [x for x in (criteria.get("features") or []) if x != "amoblado"]
        facts["furnished"] = False
    term = re.search(r"(?:на|por)\s*(\d{1,2})\s*(?:месяц|mes)", textn)
    if term: facts["rentalTermMonths"] = int(term.group(1))
    # Do not invent the operation. If the user did not say rent/buy, ask for it.
    return criteria, facts

def _candidate_summary(criteria: dict[str, Any], facts: dict[str, Any]) -> str:
    bits = ["покупка" if criteria.get("operation") == "Venta" else "аренда" if criteria.get("operation") == "Alquiler" else "операция не указана"]
    if criteria.get("propertyTypes"): bits.append(" / ".join(criteria["propertyTypes"]))
    if criteria.get("neighborhoods"): bits.append(" / ".join(criteria["neighborhoods"]))
    if criteria.get("rooms"): bits.append(f"{criteria['rooms']} ambientes")
    if criteria.get("maxBudget"): bits.append(f"до {criteria.get('budgetCurrency','USD')} {criteria['maxBudget']}")
    if facts.get("pets") is True: bits.append("с питомцем")
    if facts.get("pets") is False: bits.append("без питомца")
    if "amoblado" in (criteria.get("features") or []): bits.append("с мебелью")
    if facts.get("furnished") is False: bits.append("без мебели")
    if facts.get("rentalTermMonths"): bits.append(f"на {facts['rentalTermMonths']} мес.")
    return " · ".join(bits)

def _token_hash(raw: str) -> str:
    return hashlib.sha256(raw.encode()).hexdigest()

def _normalize_email(value: str) -> str:
    value=str(value or "").strip().lower()
    return value if re.fullmatch(r"[^\s@]+@[^\s@]+\.[^\s@]+",value) else ""

def _upsert_identity(session: Session, person: PersonProfile, provider: str, key: str, verified: bool = True) -> PersonIdentity:
    key=str(key or "").strip().lower() if provider=="email" else str(key or "").strip()
    now=datetime.now(UTC)
    row=session.scalar(select(PersonIdentity).where(PersonIdentity.tenant==settings.growth_tenant,PersonIdentity.provider==provider,PersonIdentity.provider_key==key))
    if row and row.person_profile_id!=person.id: raise HTTPException(status_code=409,detail="Identity conflict")
    if row is None:
        row=PersonIdentity(tenant=settings.growth_tenant,person_profile_id=person.id,provider=provider,provider_key=key,verified_at=now if verified else None,last_used_at=now); session.add(row)
    else:
        row.last_used_at=now
        if verified and row.verified_at is None: row.verified_at=now
    return row

def _new_person_session(session: Session, person: PersonProfile) -> str:
    raw=secrets.token_urlsafe(32); now=datetime.now(UTC)
    session.add(PersonSession(tenant=settings.growth_tenant,person_profile_id=person.id,token_hash=_token_hash(raw),expires_at=now+timedelta(days=90),created_at=now,last_used_at=now))
    return raw

def _person_from_session(session: Session, raw: str) -> PersonProfile | None:
    if not raw: return None
    now=datetime.now(UTC)
    row=session.scalar(select(PersonSession).where(PersonSession.tenant==settings.growth_tenant,PersonSession.token_hash==_token_hash(raw),PersonSession.revoked_at.is_(None),PersonSession.expires_at>now))
    if not row: return None
    if (now-row.last_used_at)>timedelta(minutes=15): row.last_used_at=now
    return session.get(PersonProfile,row.person_profile_id)

def _person_from_auth(session: Session, init_data: str = "", session_token: str = "", create_telegram: bool = True):
    if init_data:
        ctx=_validate_init_data(init_data); user=ctx["user"]
        person=_person_for_telegram(session,user) if create_telegram else session.scalar(select(PersonProfile).where(PersonProfile.tenant==settings.growth_tenant,PersonProfile.telegram_user_id==int(user["id"])))
        return person,user,"telegram"
    return _person_from_session(session,session_token),None,"web"

def _person_for_web_contact(session: Session, contact: dict[str,str]) -> PersonProfile:
    email=_normalize_email(contact.get("email", "")); phone=str(contact.get("phone") or "").strip()
    provider,key=("email",email) if email else ("phone",phone)
    identity=session.scalar(select(PersonIdentity).where(PersonIdentity.tenant==settings.growth_tenant,PersonIdentity.provider==provider,PersonIdentity.provider_key==key)) if key else None
    if identity: person=session.get(PersonProfile,identity.person_profile_id)
    else:
        person=PersonProfile(tenant=settings.growth_tenant,telegram_user_id=None,display_name=str(contact.get("name") or email or phone or "Пользователь")[:255],preferred_language=str(contact.get("language") or settings.public_language_default)[:8],facts_json={})
        session.add(person); session.flush(); _upsert_identity(session,person,provider,key,verified=False)
    facts=dict(person.facts_json or {})
    if email: facts["email"]=email
    if phone: facts["phone"]=phone
    if contact.get("name"): facts["name"]=str(contact["name"])[:255]; person.display_name=facts["name"]
    person.facts_json=facts; person.updated_at=datetime.now(UTC)
    return person

def _email_code_hash(challenge: str,email: str,code: str) -> str:
    secret=settings.person_auth_secret.strip() or settings.telegram_bot_token
    return hmac.new(secret.encode(),f"{challenge}:{email}:{code}".encode(),hashlib.sha256).hexdigest()

def _send_auth_email(email: str, code: str, language: str) -> None:
    if not settings.resend_api_key.strip(): raise HTTPException(status_code=503,detail="Вход по email временно недоступен")
    copy={"ru":(f"Код входа в {settings.brand_name}","Код входа","Введите его, чтобы открыть свой профиль. Код действует 10 минут."),"es":(f"Tu código para entrar a {settings.brand_name}","Tu código de acceso","Usalo para abrir tu perfil. Vence en 10 minutos."),"en":(f"Your {settings.brand_name} sign-in code","Your sign-in code","Use it to open your profile. It expires in 10 minutes.")}[language]
    subject,title,body=copy
    r=httpx.post("https://api.resend.com/emails",headers={"Authorization":f"Bearer {settings.resend_api_key}"},json={"from":settings.auth_email_from,"to":[email],"reply_to":settings.auth_email_reply_to,"subject":subject,"text":f"{title}: {code}\n\n{body}\n\n{settings.brand_name}"},timeout=10)
    if r.status_code>=300: raise HTTPException(status_code=503,detail="Не удалось отправить код")

def _person_for_telegram(session: Session, user: dict[str, Any]) -> PersonProfile:
    uid = int(user["id"])
    row = session.scalar(select(PersonProfile).where(PersonProfile.tenant == settings.growth_tenant, PersonProfile.telegram_user_id == uid))
    now = datetime.now(UTC)
    if row is None:
        row = PersonProfile(tenant=settings.growth_tenant, telegram_user_id=uid, username=user.get("username"), display_name=" ".join(x for x in [user.get("first_name"),user.get("last_name")] if x) or user.get("username"), preferred_language=str(user.get("language_code") or "ru")[:8], facts_json={})
        session.add(row); session.flush()
    else:
        row.username = user.get("username") or row.username; row.display_name=" ".join(x for x in [user.get("first_name"),user.get("last_name")] if x) or row.display_name; row.preferred_language=str(user.get("language_code") or row.preferred_language or "ru")[:8]; row.updated_at = now
    _upsert_identity(session,row,"telegram",str(uid),verified=True)
    return row

def _candidate_person_facts(session: Session, telegram_user_id: int) -> dict[str, Any]:
    row=session.scalar(select(PersonProfile).where(PersonProfile.tenant==settings.growth_tenant,PersonProfile.telegram_user_id==telegram_user_id))
    return dict(row.facts_json or {}) if row else {}

def _persist_confirmed_search(session: Session, user: dict[str, Any], candidate: SearchCandidate) -> SavedSearch:
    person = _person_for_telegram(session, user)
    facts = dict(person.facts_json or {}); facts.update(candidate.person_facts_json or {}); person.facts_json = facts; person.updated_at = datetime.now(UTC)
    criteria = dict(candidate.criteria_json or {})
    fp = _criteria_fingerprint(criteria); now = datetime.now(UTC)
    row = session.scalar(select(SavedSearch).where(SavedSearch.tenant == settings.growth_tenant, SavedSearch.telegram_user_id == int(user["id"]), SavedSearch.fingerprint == fp))
    if row is None:
        row = SavedSearch(tenant=settings.growth_tenant, telegram_user_id=int(user["id"]), person_profile_id=person.id, username=user.get("username"), display_name=person.display_name, fingerprint=fp, label=_candidate_summary(criteria,facts)[:255], criteria_json=criteria, notify=True, active=True)
        session.add(row); session.flush()
        for item in _search(criteria):
            session.add(SavedSearchMatch(search_id=row.id, listing_code=item.get("listingToken") or item.get("code") or "", source_fingerprint=item.get("sourceFingerprint") or hashlib.sha256((item.get("listingToken") or item.get("code") or "").encode()).hexdigest(), price_amount=_safe_num(item.get("priceAmount")), price_currency=item.get("priceCurrency") or None, first_seen_at=now, notified_at=now))
    else:
        row.active=True; row.notify=True; row.label=_candidate_summary(criteria,facts)[:255]; row.updated_at=now
    candidate.status="confirmed"; candidate.confirmed_at=now
    _marketplace_metric(session,"search_profile_confirmed",actor_id=user["id"],object_id=row.id,properties={"candidateId":str(candidate.id)}); session.commit(); return row

def _telegram_answer_callback(callback_id: str, text_value: str = "") -> None:
    try: httpx.post(f"https://api.telegram.org/bot{settings.telegram_bot_token}/answerCallbackQuery", json={"callback_query_id":callback_id,"text":text_value}, timeout=5)
    except Exception: pass

def _translate_marketplace(text_value: str, source: str, target: str) -> tuple[str | None,str,str | None]:
    if source == target: return text_value,"not_needed",None
    deepl_key=settings.deepl_api_key.strip()
    if deepl_key:
        try:
            host="https://api-free.deepl.com/v2/translate" if deepl_key.endswith(":fx") else "https://api.deepl.com/v2/translate"
            r=httpx.post(host,headers={"Authorization":f"DeepL-Auth-Key {deepl_key}"},data={"text":text_value,"source_lang":source.upper(),"target_lang":target.upper()},timeout=7); r.raise_for_status(); out=str((r.json().get("translations") or [{}])[0].get("text") or "").strip()
            if out: return out,"translated","deepl"
        except Exception: pass
    libre=settings.libretranslate_url.strip().rstrip("/")
    if libre:
        try:
            payload={"q":text_value,"source":source,"target":target,"format":"text"}; key=settings.libretranslate_api_key.strip()
            if key: payload["api_key"]=key
            r=httpx.post(f"{libre}/translate",json=payload,timeout=7); r.raise_for_status(); out=str(r.json().get("translatedText") or "").strip()
            if out: return out,"translated","libretranslate"
        except Exception: pass
    try:
        r=httpx.get("https://translate.googleapis.com/translate_a/single", params={"client":"gtx","sl":source,"tl":target,"dt":"t","q":text_value}, timeout=7)
        r.raise_for_status(); data=r.json(); out="".join(str(x[0]) for x in data[0] if x and x[0]).strip()
        return (out or None),("translated" if out else "failed"),("google-gtx" if out else None)
    except Exception: return None,"failed",None

@app.get("/v1/marketplace/status")
def marketplace_status(session: Session = Depends(db)):
    return {"ok":True,"enabled":settings.marketplace_enabled,"version":"20261031-first-party-agent-inbox-r8","personProfiles":session.query(PersonProfile).filter(PersonProfile.tenant==settings.growth_tenant).count(),"searchProfiles":session.query(SavedSearch).filter(SavedSearch.tenant==settings.growth_tenant,SavedSearch.active.is_(True)).count(),"partners":session.query(PartnerAgency).filter(PartnerAgency.tenant==settings.growth_tenant).count(),"conversations":session.query(MarketplaceConversation).filter(MarketplaceConversation.tenant==settings.growth_tenant).count(),"viewings":session.query(MarketplaceViewing).join(MarketplaceConversation).filter(MarketplaceConversation.tenant==settings.growth_tenant).count(),"agreements":session.query(CollaborationAgreement).filter(CollaborationAgreement.tenant==settings.growth_tenant).count(),"collaborationCases":session.query(CollaborationCase).filter(CollaborationCase.tenant==settings.growth_tenant).count(),"capabilities":["telegram-text-intake","voice-bounded-fallback","person-profile","multiple-search-profiles","saved-search-pause-resume","saved-search-dedupe","significant-price-drop-alerts","web-push-alerts","portable-web-session","bilingual-conversations","translation-provider-fallback","reply-validation","inquiry-workflow","operator-action-queue","viewing-readiness","viewing-supersede","channel-neutral-cases","partner-handoff","sla-rescue","first-party-agent-inbox","chatwoot-api-projection","listing-lifecycle-filtering","partner-registry","partner-source-linking","supported-url-import-validation","versioned-collaboration-agreements","pii-gate","sale-collaboration","partner-ops-dashboard","pilot-metrics"]}

@app.post("/v1/telegram/webhook")
def telegram_marketplace_webhook(update: dict[str, Any], x_telegram_bot_api_secret_token: str | None = Header(default=None), session: Session = Depends(db)):
    if not settings.marketplace_enabled: return {"ok":True,"disabled":True}
    expected = settings.telegram_webhook_secret
    if not expected: raise HTTPException(status_code=503,detail="Telegram webhook secret is not configured")
    if not x_telegram_bot_api_secret_token or not hmac.compare_digest(expected,x_telegram_bot_api_secret_token): raise HTTPException(status_code=401, detail="Invalid Telegram webhook secret")
    cb=update.get("callback_query") or {}
    if cb:
        data=str(cb.get("data") or ""); user=cb.get("from") or {}; cid=str(cb.get("id") or "")
        if data.startswith("search_confirm:"):
            try: candidate_id=UUID(data.split(":",1)[1])
            except Exception: return {"ok":True}
            candidate=session.scalar(select(SearchCandidate).where(SearchCandidate.id==candidate_id,SearchCandidate.tenant==settings.growth_tenant,SearchCandidate.telegram_user_id==int(user.get("id") or 0),SearchCandidate.status=="candidate"))
            if candidate:
                row=_persist_confirmed_search(session,user,candidate); url=f"{settings.miniapp_url}/?saved={row.id}"
                _bot_send(user["id"],f"Готово. Поиск сохранён: <b>{html.escape(row.label)}</b>\nУведомления о новых совпадениях включены.",reply_markup={"inline_keyboard":[[{"text":"Открыть подборку","web_app":{"url":url}}]]})
                _telegram_answer_callback(cid,"Поиск сохранён")
            return {"ok":True}
        if data.startswith("search_edit:"):
            try:
                candidate_id=UUID(data.split(":",1)[1]); candidate=session.scalar(select(SearchCandidate).where(SearchCandidate.id==candidate_id,SearchCandidate.tenant==settings.growth_tenant,SearchCandidate.telegram_user_id==int(user.get("id") or 0),SearchCandidate.status=="candidate"))
                if candidate: candidate.status="editing"; session.commit()
            except Exception: pass
            _bot_send(user["id"],"Пришлите поиск ещё раз одним сообщением с исправлениями. Я заново покажу, как его понял.")
            _telegram_answer_callback(cid,"Жду исправленный поиск"); return {"ok":True}
    msg=update.get("message") or {}; user=msg.get("from") or {}; chat=msg.get("chat") or {}
    if not user or not chat: return {"ok":True}
    if msg.get("voice"):
        _marketplace_metric(session,"voice_fallback",actor_id=user["id"]); session.commit()
        _bot_send(chat["id"],"Голосовое получил. Сейчас для голоса действует безопасный fallback: пришлите тот же запрос текстом, и я сразу соберу поиск для подтверждения.")
        return {"ok":True,"voiceFallback":True}
    raw=str(msg.get("text") or "").strip()
    if not raw: return {"ok":True}
    if raw.startswith("/start"):
        _bot_send(chat["id"],"Напишите, что вы ищете в Аргентине обычным сообщением. Например: «Ищу аренду, 2 ambientes в Palermo или Villa Crespo до 900 долларов, с котом». Я соберу поиск и попрошу подтвердить его.")
        return {"ok":True}
    if raw.startswith("/"):
        _bot_send(chat["id"],"Команду не распознал. Поиск можно написать обычным сообщением, без специальных команд.")
        return {"ok":True,"unknownCommand":True}
    criteria,facts=_parse_search_text(raw)
    known_facts=_candidate_person_facts(session,int(user["id"])); known_facts.update(facts); facts=known_facts
    meaningful=bool(criteria.get("neighborhoods") or criteria.get("rooms") or criteria.get("maxBudget") or criteria.get("operation"))
    if not meaningful or not criteria.get("operation"):
        _bot_send(chat["id"],"Я не хочу угадывать критерии. Уточните, пожалуйста: аренда или покупка. Район, ambientes и бюджет можно написать в том же сообщении свободным текстом.")
        return {"ok":True,"needsMore":True}
    candidate=SearchCandidate(tenant=settings.growth_tenant,telegram_user_id=int(user["id"]),raw_text=raw,criteria_json=criteria,person_facts_json=facts)
    session.add(candidate); session.flush(); _marketplace_metric(session,"search_candidate_created",actor_id=user["id"],object_id=candidate.id,properties={"criteriaKeys":sorted(criteria.keys())}); session.commit()
    summary=_candidate_summary(criteria,facts)
    _bot_send(chat["id"],f"Я понял так: <b>{html.escape(summary)}</b>\n\nСохранить этот поиск?",reply_markup={"inline_keyboard":[[{"text":"✅ Подтвердить","callback_data":f"search_confirm:{candidate.id}"},{"text":"✏️ Изменить","callback_data":f"search_edit:{candidate.id}"}]]})
    return {"ok":True,"candidateId":str(candidate.id)}

@app.post("/v1/partners")
def create_partner(body: PartnerIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key)
    if not body.website_url or not body.responsible_professional: raise HTTPException(status_code=422,detail="Website and responsible professional are required for partner review")
    if not (body.metadata.get("ownerTenant") or "").strip(): raise HTTPException(status_code=422,detail="metadata.ownerTenant is required for inventory attribution")
    owner_tenant=str(body.metadata.get("ownerTenant") or "").strip()
    if not SOURCE_ID_RE.fullmatch(owner_tenant) or owner_tenant==settings.growth_tenant: raise HTTPException(status_code=422,detail="Partner ownerTenant must be a valid external tenant slug")
    existing=session.scalar(select(PartnerAgency).where(PartnerAgency.tenant==settings.growth_tenant,PartnerAgency.website_url==body.website_url))
    if existing: return {"ok":True,"id":str(existing.id),"status":existing.status,"duplicate":True}
    row=PartnerAgency(tenant=settings.growth_tenant,name=body.name,website_url=body.website_url,responsible_professional=body.responsible_professional,metadata_json=body.metadata); session.add(row); session.flush(); _marketplace_metric(session,"partner_created",object_id=row.id,properties={"ownerTenant":body.metadata.get("ownerTenant")}); session.commit(); return {"ok":True,"id":str(row.id),"status":row.status,"duplicate":False}

@app.get("/v1/partners")
def list_partners(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); rows=list(session.scalars(select(PartnerAgency).where(PartnerAgency.tenant==settings.growth_tenant).order_by(PartnerAgency.created_at.desc()))); return {"items":[{"id":str(x.id),"name":x.name,"websiteUrl":x.website_url,"responsibleProfessional":x.responsible_professional,"status":x.status,"termsVersion":x.terms_version,"verified":bool((x.metadata_json or {}).get("verified")),"metadata":x.metadata_json} for x in rows]}

@app.patch("/v1/partners/{partner_id}")
def update_partner_state(partner_id: UUID, body: PartnerStateIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); row=session.get(PartnerAgency,partner_id)
    if not row or row.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    if body.verified and body.status not in {"pending","active"}: raise HTTPException(status_code=422,detail="Verification is only valid for pending or active partners")
    if body.status=="active" and not (body.verified or bool((row.metadata_json or {}).get("verified"))): raise HTTPException(status_code=422,detail="Verified partner is required before activation")
    if body.status=="active" and not row.terms_version: raise HTTPException(status_code=409,detail="Accepted partner terms are required before activation")
    if body.status=="active":
        agreement=session.scalar(select(CollaborationAgreement).where(CollaborationAgreement.tenant==settings.growth_tenant,CollaborationAgreement.partner_agency_id==row.id,CollaborationAgreement.version==row.terms_version,CollaborationAgreement.status=="accepted"))
        if not agreement: raise HTTPException(status_code=409,detail="Accepted agreement record is required before activation")
    if body.status=="active" and not ((row.metadata_json or {}).get("sourceIds") or []): raise HTTPException(status_code=409,detail="Link at least one inventory source before activation")
    if body.status=="active" and any(not (_source_registry().get(sid) or {}).get("active") for sid in ((row.metadata_json or {}).get("sourceIds") or [])): raise HTTPException(status_code=409,detail="All linked inventory sources must be active")
    if body.status=="active" and any((_source_registry().get(sid) or {}).get("adapterType")=="tokko" for sid in ((row.metadata_json or {}).get("sourceIds") or [])): raise HTTPException(status_code=409,detail="Tokko sources cannot be activated yet")
    if body.status=="active" and not row.website_url: raise HTTPException(status_code=409,detail="Partner website is required before activation")
    if body.status=="active" and not row.responsible_professional: raise HTTPException(status_code=409,detail="Responsible professional is required before activation")
    row.status=body.status; row.updated_at=datetime.now(UTC); row.metadata_json={**(row.metadata_json or {}),"verified":(bool(body.verified) or bool((row.metadata_json or {}).get("verified"))) if body.status in {"pending","active"} else False}; _marketplace_metric(session,"partner_status_changed",object_id=row.id,properties={"status":row.status}); session.commit(); return {"ok":True,"id":str(row.id),"status":row.status}

@app.get("/v1/partners/{partner_id}/dashboard")
def partner_dashboard(partner_id: UUID, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); partner=session.get(PartnerAgency,partner_id)
    if not partner or partner.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    source_ids=(partner.metadata_json or {}).get("sourceIds") or []
    conversations=list(session.scalars(select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.partner_agency_id==partner.id)))
    conversation_ids=[x.id for x in conversations]
    viewing_count=session.query(MarketplaceViewing).filter(MarketplaceViewing.conversation_id.in_(conversation_ids)).count() if conversation_ids else 0
    cases=session.query(CollaborationCase).filter(CollaborationCase.tenant==settings.growth_tenant,CollaborationCase.inventory_source_id.in_(source_ids)).count() if source_ids else 0
    listing_count=sum(1 for item in _catalog() if item.get("sourceId") in source_ids and str(item.get("status") or "active").lower() not in {"paused","unavailable","reserved","rented","sold","removed"})
    open_conversations=sum(1 for x in conversations if x.status=="open")
    source_status=[{"sourceId":sid,"active":bool((_source_registry().get(sid) or {}).get("active")),"adapterType":(_source_registry().get(sid) or {}).get("adapterType"),"importMode":(_source_registry().get(sid) or {}).get("importMode") or ""} for sid in source_ids]
    return {"partner":{"id":str(partner.id),"name":partner.name,"status":partner.status,"verified":bool((partner.metadata_json or {}).get("verified")),"termsVersion":partner.terms_version},"sources":source_status,"listingCount":listing_count,"conversations":len(conversations),"openConversations":open_conversations,"viewings":viewing_count,"collaborationCases":cases,"note":"Operational partner view only; not a CRM"}

@app.post("/v1/partners/{partner_id}/sources")
def link_partner_source(partner_id: UUID, body: PartnerSourceIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); row=session.get(PartnerAgency,partner_id)
    if not row or row.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    source=_source_registry().get(body.source_id)
    if not source or not source.get("active"): raise HTTPException(status_code=404,detail="Active inventory source not found")
    if source.get("adapterType")=="tokko": raise HTTPException(status_code=409,detail="Tokko remains disabled pending permission and security validation")
    owner=str(source.get("ownerTenant") or "")
    if owner!=str((row.metadata_json or {}).get("ownerTenant") or ""): raise HTTPException(status_code=409,detail="Source owner does not match partner ownerTenant")
    if owner==settings.growth_tenant: raise HTTPException(status_code=409,detail="Le Bleu-owned source does not require a partner link")
    source_ids=list(dict.fromkeys([*((row.metadata_json or {}).get("sourceIds") or []),body.source_id])); row.metadata_json={**(row.metadata_json or {}),"sourceIds":source_ids}; row.updated_at=datetime.now(UTC); _marketplace_metric(session,"partner_source_linked",object_id=row.id,properties={"sourceId":body.source_id}); session.commit()
    return {"ok":True,"partnerId":str(row.id),"sourceIds":source_ids}

@app.post("/v1/partners/{partner_id}/listing-imports")
def partner_listing_import(partner_id: UUID, body: PartnerListingImportIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); partner=session.get(PartnerAgency,partner_id)
    if not partner or partner.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    if partner.status!="active" or not bool((partner.metadata_json or {}).get("verified")): raise HTTPException(status_code=409,detail="Verified active partner required")
    if body.source_id not in ((partner.metadata_json or {}).get("sourceIds") or []): raise HTTPException(status_code=409,detail="Source is not linked to this partner")
    # Do not pretend a universal crawler exists. Validate only sources explicitly marked for an existing supported adapter.
    parsed=urlparse(body.url)
    if parsed.scheme not in {"http","https"} or not parsed.netloc: raise HTTPException(status_code=422,detail="Valid listing URL required")
    source=_source_registry().get(body.source_id) or {}
    if not source.get("active"): raise HTTPException(status_code=409,detail="Inventory source is inactive")
    if source.get("adapterType")=="tokko": raise HTTPException(status_code=409,detail="Tokko remains disabled pending permission and security validation")
    if source.get("importMode") not in {"website_adapter","listing_url"}: raise HTTPException(status_code=409,detail="This source has no supported URL importer")
    allowed_host=urlparse(str(source.get("websiteUrl") or source.get("baseUrl") or partner.website_url or "")).netloc.lower()
    if allowed_host and parsed.netloc.lower().removeprefix("www.")!=allowed_host.removeprefix("www."): raise HTTPException(status_code=422,detail="Listing URL host does not match the registered source")
    _marketplace_metric(session,"partner_listing_import_requested",object_id=partner.id,properties={"sourceId":body.source_id,"host":parsed.netloc.lower()}); session.commit()
    return {"ok":True,"status":"validated_for_supported_adapter","importMode":source.get("importMode"),"sourceId":body.source_id,"url":body.url}

def _webpush_send(subscription: dict[str, Any], payload: dict[str, Any]) -> bool:
    if not settings.vapid_private_key.strip(): return False
    try:
        from pywebpush import webpush
        webpush(subscription_info=subscription, data=json.dumps(payload,ensure_ascii=False), vapid_private_key=settings.vapid_private_key, vapid_claims={"sub":settings.vapid_subject}, ttl=300)
        return True
    except Exception:
        return False

@app.post("/v1/push-subscriptions")
def save_push_subscription(body: PushSubscriptionIn, session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,body.init_data,body.session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы включить уведомления")
    sub=body.subscription or {}; endpoint=str(sub.get("endpoint") or "").strip(); keys=sub.get("keys") or {}
    if not endpoint or not keys.get("p256dh") or not keys.get("auth"): raise HTTPException(status_code=422,detail="Некорректная push-подписка")
    h=hashlib.sha256(endpoint.encode()).hexdigest(); now=datetime.now(UTC)
    row=session.scalar(select(PersonPushSubscription).where(PersonPushSubscription.tenant==settings.growth_tenant,PersonPushSubscription.endpoint_hash==h))
    if row is None: row=PersonPushSubscription(tenant=settings.growth_tenant,person_profile_id=person.id,endpoint_hash=h,subscription_json=sub,active=True); session.add(row)
    else: row.person_profile_id=person.id; row.subscription_json=sub; row.active=True; row.updated_at=now
    session.commit(); return {"ok":True,"enabled":True}

@app.delete("/v1/push-subscriptions")
def delete_push_subscription(init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), endpoint: str = Query(default=""), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите")
    h=hashlib.sha256(endpoint.encode()).hexdigest() if endpoint else ""
    rows=list(session.scalars(select(PersonPushSubscription).where(PersonPushSubscription.tenant==settings.growth_tenant,PersonPushSubscription.person_profile_id==person.id)))
    for row in rows:
        if not h or row.endpoint_hash==h: row.active=False; row.updated_at=datetime.now(UTC)
    session.commit(); return {"ok":True}

@app.post("/v1/auth/device")
def device_auth(session: Session = Depends(db)):
    person=PersonProfile(tenant=settings.growth_tenant,telegram_user_id=None,display_name="Пользователь",preferred_language=settings.public_language_default,facts_json={})
    session.add(person); session.flush(); token=_new_person_session(session,person); session.commit()
    return {"ok":True,"sessionToken":token,"profile":{"id":str(person.id),"displayName":person.display_name,"preferredLanguage":person.preferred_language,"facts":{}}}

@app.post("/v1/auth/email/start")
def email_auth_start(body: EmailAuthStartIn, session: Session = Depends(db)):
    email=_normalize_email(body.email)
    if not email: raise HTTPException(status_code=400,detail="Введите корректный email")
    recent=session.query(PersonEmailChallenge).filter(PersonEmailChallenge.tenant==settings.growth_tenant,PersonEmailChallenge.email==email,PersonEmailChallenge.created_at>datetime.now(UTC)-timedelta(minutes=15)).count()
    if recent>=3: raise HTTPException(status_code=429,detail="Слишком много кодов. Попробуйте через несколько минут")
    person=None
    if body.init_data: person,_u,_m=_person_from_auth(session,body.init_data,"",True)
    if person is None:
        ident=session.scalar(select(PersonIdentity).where(PersonIdentity.tenant==settings.growth_tenant,PersonIdentity.provider=="email",PersonIdentity.provider_key==email,PersonIdentity.verified_at.is_not(None)))
        if ident: person=session.get(PersonProfile,ident.person_profile_id)
    challenge=secrets.token_urlsafe(18); code=f"{secrets.randbelow(900000)+100000:06d}"; now=datetime.now(UTC)
    row=PersonEmailChallenge(tenant=settings.growth_tenant,challenge_key=challenge,email=email,code_hash=_email_code_hash(challenge,email,code),person_profile_id=person.id if person else None,language=body.language,expires_at=now+timedelta(minutes=10),created_at=now)
    session.add(row); session.flush()
    try: _send_auth_email(email,code,body.language)
    except Exception: session.rollback(); raise
    session.commit(); return {"ok":True,"challengeId":challenge,"expiresInSeconds":600}

@app.post("/v1/auth/email/verify")
def email_auth_verify(body: EmailAuthVerifyIn, session: Session = Depends(db)):
    row=session.scalar(select(PersonEmailChallenge).where(PersonEmailChallenge.tenant==settings.growth_tenant,PersonEmailChallenge.challenge_key==body.challenge_id,PersonEmailChallenge.consumed_at.is_(None)))
    now=datetime.now(UTC)
    if not row or row.expires_at<=now: raise HTTPException(status_code=410,detail="Код устарел. Запросите новый")
    if row.attempts>=5: raise HTTPException(status_code=429,detail="Слишком много попыток")
    if not hmac.compare_digest(_email_code_hash(row.challenge_key,row.email,body.code),row.code_hash): row.attempts+=1; session.commit(); raise HTTPException(status_code=400,detail="Код не подошёл")
    existing=session.scalar(select(PersonIdentity).where(PersonIdentity.tenant==settings.growth_tenant,PersonIdentity.provider=="email",PersonIdentity.provider_key==row.email))
    person=session.get(PersonProfile,existing.person_profile_id) if existing else (session.get(PersonProfile,row.person_profile_id) if row.person_profile_id else None)
    if person is None:
        person=PersonProfile(tenant=settings.growth_tenant,telegram_user_id=None,display_name=row.email.split('@')[0],preferred_language=row.language,facts_json={"email":row.email}); session.add(person); session.flush()
    _upsert_identity(session,person,"email",row.email,verified=True); person.facts_json={**(person.facts_json or {}),"email":row.email}
    if body.init_data:
        tg=_validate_init_data(body.init_data)["user"]; tg_person=_person_for_telegram(session,tg)
        if tg_person.id!=person.id:
            # Keep Telegram profile canonical and move portable identity/facts.
            email_identity=session.scalar(select(PersonIdentity).where(PersonIdentity.person_profile_id==person.id,PersonIdentity.provider=="email"))
            if email_identity: email_identity.person_profile_id=tg_person.id
            tg_person.facts_json={**(person.facts_json or {}),**(tg_person.facts_json or {})}; person=tg_person
    row.consumed_at=now; row.person_profile_id=person.id; token=_new_person_session(session,person); session.commit()
    return {"ok":True,"sessionToken":token,"profile":{"id":str(person.id),"displayName":person.display_name,"preferredLanguage":person.preferred_language,"facts":person.facts_json or {}},"telegramLinked":person.telegram_user_id is not None}

@app.get("/v1/auth/state")
def auth_state(init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,False); session.commit()
    if not person: return {"authenticated":False,"authMode":"anonymous","telegramLinked":False}
    return {"authenticated":True,"authMode":mode,"telegramLinked":person.telegram_user_id is not None,"profileId":str(person.id)}

@app.get("/v1/profile")
def get_profile(init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы открыть профиль")
    session.commit(); return {"id":str(person.id),"displayName":person.display_name,"preferredLanguage":person.preferred_language,"facts":person.facts_json or {},"authMode":mode,"telegramLinked":person.telegram_user_id is not None}

@app.post("/v1/profile")
def save_profile(body: ProfileIn, session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,body.init_data,body.session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы сохранить профиль")
    person.preferred_language=body.preferred_language; person.facts_json={**(person.facts_json or {}),**body.facts}; person.display_name=str(body.facts.get("name") or person.display_name or "")[:255] or person.display_name; person.updated_at=datetime.now(UTC); session.commit()
    return {"id":str(person.id),"displayName":person.display_name,"preferredLanguage":person.preferred_language,"facts":person.facts_json or {},"authMode":mode,"telegramLinked":person.telegram_user_id is not None}

@app.get("/v1/readiness")
def get_readiness(listing_code: str = Query(...), search_id: UUID | None = Query(default=None), init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы запросить просмотр")
    item=_listing_by_key(listing_code)
    if not item: raise HTTPException(status_code=404,detail="Listing not found")
    search=None
    if search_id:
        search=session.get(SavedSearch,search_id)
        if not search or search.tenant!=settings.growth_tenant or search.person_profile_id!=person.id: raise HTTPException(status_code=404,detail="Search profile not found")
    result=_readiness_for(person,item,search)
    result["profileId"]=str(person.id); result["authMode"]=mode
    return result

@app.get("/v1/conversations")
def list_conversations(init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True)
    if not person: return {"items":[]}
    rows=list(session.scalars(select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.person_profile_id==person.id).order_by(MarketplaceConversation.updated_at.desc())))
    items=[]
    for row in rows:
        last=session.scalar(select(MarketplaceMessage).where(MarketplaceMessage.conversation_id==row.id).order_by(MarketplaceMessage.created_at.desc()).limit(1))
        item=_conversation_listing(row) or {}
        unread=session.query(MarketplaceMessage).filter(MarketplaceMessage.conversation_id==row.id,MarketplaceMessage.sender_role=="partner",MarketplaceMessage.created_at>(row.client_last_read_at or row.created_at)).count()
        latest_view=session.scalar(select(MarketplaceViewing).where(MarketplaceViewing.conversation_id==row.id,MarketplaceViewing.status.in_(["proposed","confirmed"])).order_by(MarketplaceViewing.created_at.desc()).limit(1))
        items.append({"id":str(row.id),"listingCode":row.listing_code,"listingAddress":item.get("address") or item.get("code") or row.listing_code,"status":row.status,"workflowStatus":row.workflow_status,"workflowLabel":_workflow_label(row.workflow_status),"primaryIntent":row.primary_intent,"nextActionType":row.next_action_type,"nextActionDueAt":row.next_action_due_at.isoformat() if row.next_action_due_at else None,"lastMessage":(last.translated_body or last.body) if last else "","updatedAt":row.updated_at.isoformat(),"unreadCount":unread,"qualificationSnapshot":row.qualification_snapshot_json or {},"viewing":({"id":str(latest_view.id),"proposedAt":latest_view.proposed_at.isoformat(),"status":latest_view.status} if latest_view else None)})
    return {"items":items}

@app.post("/v1/conversations")
def create_conversation(body: ConversationIn, session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    if not settings.marketplace_enabled: raise HTTPException(status_code=503,detail="Marketplace is not enabled")
    person,user,mode=_person_from_auth(session,body.init_data,session_token,True); item=_listing_by_key(body.listing_code)
    if not person: raise HTTPException(status_code=401,detail="Войдите, чтобы отправить запрос")
    actor_id=int(user["id"]) if user else None
    if body.intent=="question" and not body.message.strip(): raise HTTPException(status_code=422,detail="Напишите вопрос")
    search=None
    if body.search_id:
        search=session.get(SavedSearch,body.search_id)
        if not search or search.tenant!=settings.growth_tenant or search.person_profile_id!=person.id: raise HTTPException(status_code=404,detail="Search profile not found")
    if not item: raise HTTPException(status_code=404,detail="Listing not found")
    if str(item.get("status") or "active").lower() in {"paused","unavailable","reserved","rented","sold","removed"}: raise HTTPException(status_code=409,detail="Объект больше недоступен")
    readiness=_readiness_for(person,item,search)
    if body.intent=="viewing" and not readiness["ready"]:
        raise HTTPException(status_code=422,detail={"code":"PROFILE_INCOMPLETE","message":"Заполните недостающие данные профиля","missing":readiness["missing"]})
    prov=_routing_context(item); operation=str(item.get("operation") or ""); partner=None
    # Rental can route to a verified inventory partner. A platform-origin buyer stays buyer-side first.
    if operation!="Venta" and prov.get("routingMode")=="collaboration_required":
        partner=next((p for p in session.scalars(select(PartnerAgency).where(PartnerAgency.tenant==settings.growth_tenant,PartnerAgency.status=="active")) if bool((p.metadata_json or {}).get("verified")) and prov.get("inventorySourceId") in ((p.metadata_json or {}).get("sourceIds") or []) and str((p.metadata_json or {}).get("ownerTenant") or "")==prov.get("inventoryOwnerTenant")),None)
    assignment=_resolve_case_assignment(session,item,partner)
    source_channel=_effective_channel(mode,body.source_channel); listing_key=item.get("listingToken") or item.get("code") or body.listing_code; now=datetime.now(UTC)
    row=session.scalar(select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.person_profile_id==person.id,MarketplaceConversation.listing_code==listing_key,MarketplaceConversation.status=="open").order_by(MarketplaceConversation.created_at.desc()).limit(1))
    created=row is None
    if row is None:
        row=MarketplaceConversation(tenant=settings.growth_tenant,person_profile_id=person.id,search_id=body.search_id,listing_code=listing_key,inventory_source_id=prov.get("inventorySourceId"),inventory_owner_tenant=prov.get("inventoryOwnerTenant"),partner_agency_id=partner.id if partner else None,qualification_snapshot_json=readiness["snapshot"] if body.intent=="viewing" else {},primary_intent=body.intent,workflow_status="new",source_channel=source_channel,preferred_outbound_channel=_preferred_channel(person,source_channel)); session.add(row); session.flush()
    elif body.intent=="viewing":
        row.primary_intent="viewing"; row.qualification_snapshot_json=readiness["snapshot"]
    row.assigned_actor_type=assignment["actorType"]; row.assigned_actor_id=assignment["actorId"]; row.assigned_queue=assignment.get("queue"); row.routing_decision_json={**assignment,"inventoryOwner":prov.get("inventoryOwnerTenant"),"inventorySourceId":prov.get("inventorySourceId"),"operation":operation}; row.source_channel=row.source_channel or source_channel; row.preferred_outbound_channel=row.preferred_outbound_channel or _preferred_channel(person,source_channel)
    row.workflow_status="waiting_partner" if partner else "new"; row.next_action_type="contact_partner" if partner else ("check_availability" if body.intent=="viewing" else "reply_client"); row.next_action_due_at=now+timedelta(minutes=max(5,settings.operator_sla_minutes)); row.last_client_activity_at=now; row.updated_at=now
    person.preferred_language=body.source_language; person.updated_at=now
    translation_status="not_needed"
    if body.intent=="question":
        client_text=body.message.strip(); translated,translation_status,provider=_translate_marketplace(client_text,body.source_language,"es"); msg=MarketplaceMessage(conversation_id=row.id,sender_role="client",source_language=body.source_language,body=client_text,translated_body=translated,translation_status=translation_status,translation_provider=provider,delivery_status="partner_routed" if partner else "operator_queue",source_channel=source_channel); session.add(msg); session.flush(); _queue_communication_projection(session,row.id,"message_created",message_id=msg.id)
    else:
        windows=[str(x).strip()[:120] for x in body.viewing_windows if str(x).strip()]
        session.add(MarketplaceViewingRequest(conversation_id=row.id,preferred_windows_json=windows,note=body.message.strip() or None,status="pending"))
    _queue_communication_projection(session,row.id,"case_created" if created else "case_updated")
    _marketplace_metric(session,"viewing_requested" if body.intent=="viewing" else "conversation_message",actor_id=actor_id,object_id=row.id,properties={"routingMode":prov.get("routingMode"),"inventoryOwner":prov.get("inventoryOwnerTenant"),"authMode":mode,"sourceChannel":source_channel,"assignmentReason":assignment["reason"]}); session.commit()
    if operation!="Venta" and prov.get("routingMode")=="collaboration_required" and not partner: _marketplace_metric(session,"partner_route_missing",object_id=row.id,properties={"inventoryOwner":prov.get("inventoryOwnerTenant"),"sourceId":prov.get("inventorySourceId")}); session.commit()
    _operator_inquiry_notification(session,row)
    if person.telegram_user_id and person.telegram_user_id>0 and row.preferred_outbound_channel=="telegram":
        if body.source_language=="es":
            ack=("✅ <b>Solicitud de visita enviada</b>\n\nEl agente verificará la propiedad y propondrá un horario concreto. La respuesta quedará en «Mis consultas»." if body.intent=="viewing" else "✅ <b>Consulta enviada</b>\nLa respuesta quedará en «Mis consultas».")
        elif body.source_language=="en":
            ack=("✅ <b>Viewing request sent</b>\n\nThe agent will verify the property and propose a specific time. The reply will be saved in “My inquiries”." if body.intent=="viewing" else "✅ <b>Question sent</b>\nThe reply will be saved in “My inquiries”.")
        else:
            ack=("✅ <b>Запрос на просмотр отправлен</b>\n\nАгент проверит объект и предложит конкретное время. Ответ сохранится в «Моих обращениях»." if body.intent=="viewing" else "✅ <b>Вопрос отправлен</b>\nОтвет сохранится в «Моих обращениях».")
        _bot_send(person.telegram_user_id,ack)
    return {"ok":True,"id":str(row.id),"translationStatus":translation_status,"routingMode":prov.get("routingMode"),"inventoryOwner":prov.get("inventoryOwnerTenant"),"partnerLinked":partner is not None,"deliveryState":"partner_routed" if partner else "operator_queue","workflowStatus":row.workflow_status,"assignment":assignment}

@app.get("/v1/conversations/{conversation_id}")
def get_conversation(conversation_id: UUID, init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,init_data,session_token,True); row=session.get(MarketplaceConversation,conversation_id)
    if not person or not row or row.tenant!=settings.growth_tenant or row.person_profile_id!=person.id: raise HTTPException(status_code=404,detail="Conversation not found")
    item=_conversation_listing(row) or {}; msgs=list(session.scalars(select(MarketplaceMessage).where(MarketplaceMessage.conversation_id==row.id).order_by(MarketplaceMessage.created_at.asc()))); views=list(session.scalars(select(MarketplaceViewing).where(MarketplaceViewing.conversation_id==row.id).order_by(MarketplaceViewing.created_at.asc()))); requests=list(session.scalars(select(MarketplaceViewingRequest).where(MarketplaceViewingRequest.conversation_id==row.id).order_by(MarketplaceViewingRequest.created_at.asc()))); row.client_last_read_at=datetime.now(UTC); session.commit()
    return {"id":str(row.id),"status":row.status,"workflowStatus":row.workflow_status,"workflowLabel":_workflow_label(row.workflow_status),"primaryIntent":row.primary_intent,"nextActionType":row.next_action_type,"nextActionDueAt":row.next_action_due_at.isoformat() if row.next_action_due_at else None,"listingCode":row.listing_code,"listingAddress":item.get("address") or item.get("code") or row.listing_code,"qualificationSnapshot":row.qualification_snapshot_json or {},"messages":[{"id":str(m.id),"senderRole":m.sender_role,"body":m.body,"translatedBody":m.translated_body,"translationStatus":m.translation_status,"deliveryStatus":m.delivery_status,"sourceChannel":m.source_channel,"replyToMessageId":str(m.reply_to_message_id) if m.reply_to_message_id else None,"createdAt":m.created_at.isoformat()} for m in msgs],"viewingRequests":[{"id":str(v.id),"preferredWindows":v.preferred_windows_json or [],"note":v.note,"status":v.status,"createdAt":v.created_at.isoformat()} for v in requests],"viewings":[{"id":str(v.id),"proposedAt":v.proposed_at.isoformat(),"status":v.status} for v in views]}

@app.post("/v1/conversations/{conversation_id}/messages")
def client_message(conversation_id: UUID, body: ClientMessageIn, session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    person,user,mode=_person_from_auth(session,body.init_data,session_token,True); conv=session.get(MarketplaceConversation,conversation_id)
    if not person or not conv or conv.tenant!=settings.growth_tenant or conv.person_profile_id!=person.id: raise HTTPException(status_code=404,detail="Conversation not found")
    if body.reply_to_message_id:
        parent=session.get(MarketplaceMessage,body.reply_to_message_id)
        if not parent or parent.conversation_id!=conv.id: raise HTTPException(status_code=422,detail="Reply target is not in this conversation")
    now=datetime.now(UTC); source_channel=_effective_channel(mode,body.source_channel); translated,status,provider=_translate_marketplace(body.body,body.source_language,"es"); msg=MarketplaceMessage(conversation_id=conv.id,sender_role="client",source_language=body.source_language,body=body.body,translated_body=translated,translation_status=status,translation_provider=provider,reply_to_message_id=body.reply_to_message_id,delivery_status="partner_routed" if conv.partner_agency_id else "operator_queue",source_channel=source_channel); session.add(msg); session.flush(); conv.updated_at=now; conv.last_client_activity_at=now; conv.workflow_status="waiting_partner" if conv.partner_agency_id else "new"; conv.next_action_type="contact_partner" if conv.partner_agency_id else "reply_client"; conv.next_action_due_at=now+timedelta(minutes=max(5,settings.operator_sla_minutes)); _queue_communication_projection(session,conv.id,"message_created",message_id=msg.id); _marketplace_metric(session,"conversation_message",actor_id=int(user["id"]) if user else None,object_id=conv.id,properties={"direction":"client_to_partner","translationStatus":status,"authMode":mode,"sourceChannel":source_channel}); session.commit()
    if not conv.partner_agency_id: _operator_inquiry_notification(session,conv,message=translated or body.body)
    return {"ok":True,"id":str(msg.id),"translationStatus":status,"deliveryStatus":msg.delivery_status}

@app.post("/v1/internal/conversations/{conversation_id}/messages")
def partner_message(conversation_id: UUID, body: MessageIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); conv=session.get(MarketplaceConversation,conversation_id)
    if not conv or conv.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Conversation not found")
    if conv.inventory_owner_tenant!=settings.growth_tenant and not conv.partner_agency_id: raise HTTPException(status_code=409,detail="Conversation has no verified partner route")
    if conv.partner_agency_id:
        partner=session.get(PartnerAgency,conv.partner_agency_id)
        if not partner or partner.status!="active" or not bool((partner.metadata_json or {}).get("verified")): raise HTTPException(status_code=409,detail="Partner route is no longer active")
    if body.reply_to_message_id:
        parent=session.get(MarketplaceMessage,body.reply_to_message_id)
        if not parent or parent.conversation_id!=conv.id: raise HTTPException(status_code=422,detail="Reply target is not in this conversation")
    now=datetime.now(UTC); person=session.get(PersonProfile,conv.person_profile_id); target_language=(person.preferred_language if person and person.preferred_language in {"ru","es","en"} else "ru"); translated,status,provider=_translate_marketplace(body.body,body.source_language,target_language); msg=MarketplaceMessage(conversation_id=conv.id,sender_role="partner",source_language=body.source_language,body=body.body,translated_body=translated,translation_status=status,translation_provider=provider,reply_to_message_id=body.reply_to_message_id,source_channel="internal"); session.add(msg); session.flush(); _queue_communication_projection(session,conv.id,"message_created",message_id=msg.id); conv.updated_at=now; conv.last_operator_activity_at=now; conv.first_response_at=conv.first_response_at or now; conv.workflow_status="waiting_client"; conv.next_action_type="wait_client"; conv.next_action_due_at=None; session.flush(); _marketplace_metric(session,"partner_message",object_id=msg.id,properties={"conversationId":str(conv.id),"translationStatus":status}); session.commit()
    delivered=bool(person and person.telegram_user_id and person.telegram_user_id>0 and _bot_send(person.telegram_user_id,f"💬 <b>Новый ответ по объекту</b>\n\n{html.escape(translated or body.body)}",reply_markup={"inline_keyboard":[[{"text":"Открыть объект","web_app":{"url":f'{settings.miniapp_url}/?listing={conv.listing_code}'}}]]}))
    msg.delivery_status="delivered" if delivered else "stored"; session.commit(); return {"ok":True,"id":str(msg.id),"translationStatus":status,"deliveryStatus":msg.delivery_status}

@app.post("/v1/internal/conversations/{conversation_id}/viewings")
def propose_viewing(conversation_id: UUID, body: ViewingIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); conv=session.get(MarketplaceConversation,conversation_id)
    if not conv or conv.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Conversation not found")
    if conv.inventory_owner_tenant!=settings.growth_tenant and not conv.partner_agency_id: raise HTTPException(status_code=409,detail="Conversation has no verified partner route")
    if conv.partner_agency_id:
        partner=session.get(PartnerAgency,conv.partner_agency_id)
        if not partner or partner.status!="active" or not bool((partner.metadata_json or {}).get("verified")): raise HTTPException(status_code=409,detail="Partner route is no longer active")
    proposed_at=body.proposed_at if body.proposed_at.tzinfo else body.proposed_at.replace(tzinfo=UTC)
    if proposed_at <= datetime.now(UTC): raise HTTPException(status_code=422,detail="Viewing time must be in the future")
    now=datetime.now(UTC)
    for previous in session.scalars(select(MarketplaceViewing).where(MarketplaceViewing.conversation_id==conv.id,MarketplaceViewing.status=="proposed")): previous.status="superseded"; previous.updated_at=now
    for request in session.scalars(select(MarketplaceViewingRequest).where(MarketplaceViewingRequest.conversation_id==conv.id,MarketplaceViewingRequest.status=="pending")): request.status="fulfilled"; request.updated_at=now
    row=MarketplaceViewing(conversation_id=conv.id,proposed_at=proposed_at); session.add(row); conv.workflow_status="waiting_client"; conv.next_action_type="wait_client_confirmation"; conv.next_action_due_at=None; conv.last_operator_activity_at=now; conv.first_response_at=conv.first_response_at or now; session.flush(); _marketplace_metric(session,"viewing_proposed",object_id=row.id,properties={"conversationId":str(conv.id)}); session.commit(); person=session.get(PersonProfile,conv.person_profile_id)
    if person and person.telegram_user_id and person.telegram_user_id>0:
        confirm_url=f"{settings.miniapp_url}/?listing={conv.listing_code}&viewing={row.id}"
        _bot_send(person.telegram_user_id,f"📅 <b>Предложено время просмотра</b>\n{html.escape(proposed_at.isoformat())}\n\nПодтвердите, подходит ли это время.",reply_markup={"inline_keyboard":[[{"text":"Подтвердить время","web_app":{"url":confirm_url}}]]})
    return {"ok":True,"id":str(row.id),"status":row.status}

@app.post("/v1/viewings/{viewing_id}/{action}")
def client_viewing_action(viewing_id: UUID, action: str, init_data: str = Query(default=""), session_token: str = Header(default="",alias="X-Session-Token"), session: Session = Depends(db)):
    if not settings.marketplace_enabled: raise HTTPException(status_code=503,detail="Marketplace is not enabled")
    person,user,mode=_person_from_auth(session,init_data,session_token,True); row=session.get(MarketplaceViewing,viewing_id); conv=session.get(MarketplaceConversation,row.conversation_id) if row else None
    if not row or not conv or conv.tenant!=settings.growth_tenant or not person or conv.person_profile_id!=person.id: raise HTTPException(status_code=404,detail="Viewing not found")
    if action not in {"confirm","cancel"}: raise HTTPException(status_code=422,detail="Unsupported viewing action")
    desired="confirmed" if action=="confirm" else "cancelled"
    if row.status==desired: return {"ok":True,"status":row.status,"duplicate":True}
    if action=="confirm" and row.proposed_at <= datetime.now(UTC): raise HTTPException(status_code=409,detail="Viewing proposal has expired")
    if row.status=="confirmed" and action=="cancel": pass
    elif row.status!="proposed": raise HTTPException(status_code=409,detail=f"Viewing is already {row.status}")
    now=datetime.now(UTC); row.status=desired; row.updated_at=now
    if action=="confirm": conv.workflow_status="scheduled"; conv.next_action_type="viewing"; conv.next_action_due_at=row.proposed_at
    else: conv.workflow_status="new"; conv.next_action_type="reschedule_viewing"; conv.next_action_due_at=now+timedelta(minutes=max(5,settings.operator_sla_minutes)); _operator_inquiry_notification(session,conv,message="Клиент отклонил предложенное время. Нужно согласовать другое.")
    conv.updated_at=now; conv.last_client_activity_at=now; _marketplace_metric(session,f"viewing_{desired}",actor_id=person.telegram_user_id,object_id=row.id); session.commit(); return {"ok":True,"status":row.status,"duplicate":False,"workflowStatus":conv.workflow_status}

_AGENT_SESSION_COOKIE = "pn_agent_session"
_agent_login_attempts: dict[str, list[datetime]] = {}

def _agent_inbox_enabled() -> bool:
    return bool(settings.agent_inbox_password.strip())

def _agent_session_secret() -> bytes:
    material=f"{settings.service_key}:{settings.agent_inbox_password}".encode()
    return hashlib.sha256(material).digest()

def _issue_agent_session() -> str:
    expires=int((datetime.now(UTC)+timedelta(hours=max(1,settings.agent_session_hours))).timestamp())
    payload=str(expires)
    sig=hmac.new(_agent_session_secret(),payload.encode(),hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"

def _agent_session_valid(raw: str) -> bool:
    if not raw or not _agent_inbox_enabled(): return False
    try:
        expiry_s,sig=raw.split(".",1); expiry=int(expiry_s)
    except Exception: return False
    if expiry<=int(datetime.now(UTC).timestamp()): return False
    expected=hmac.new(_agent_session_secret(),expiry_s.encode(),hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,sig)

def _require_agent(request: Request) -> None:
    if not _agent_session_valid(request.cookies.get(_AGENT_SESSION_COOKIE,"")):
        raise HTTPException(status_code=401,detail="Agent session required")

def _agent_rate_key(request: Request) -> str:
    return request.client.host if request.client else "unknown"

@app.get("/v1/agent/session")
def agent_session_state(request: Request):
    return {"enabled":_agent_inbox_enabled(),"authenticated":_agent_session_valid(request.cookies.get(_AGENT_SESSION_COOKIE,""))}

@app.post("/v1/agent/session")
def agent_session_login(body: AgentLoginIn, request: Request, response: Response):
    if not _agent_inbox_enabled(): raise HTTPException(status_code=503,detail="Agent inbox is not configured")
    now=datetime.now(UTC); key=_agent_rate_key(request); cutoff=now-timedelta(minutes=15)
    recent=[x for x in _agent_login_attempts.get(key,[]) if x>cutoff]; _agent_login_attempts[key]=recent
    if len(recent)>=8: raise HTTPException(status_code=429,detail="Too many login attempts")
    if not hmac.compare_digest(body.password,settings.agent_inbox_password):
        recent.append(now); _agent_login_attempts[key]=recent; raise HTTPException(status_code=401,detail="Неверный код доступа")
    _agent_login_attempts.pop(key,None); token=_issue_agent_session(); max_age=max(3600,settings.agent_session_hours*3600)
    response.set_cookie(_AGENT_SESSION_COOKIE,token,max_age=max_age,httponly=True,secure=True,samesite="strict",path="/")
    return {"ok":True,"authenticated":True}

@app.delete("/v1/agent/session")
def agent_session_logout(response: Response):
    response.delete_cookie(_AGENT_SESSION_COOKIE,path="/")
    return {"ok":True}

@app.get("/v1/internal/conversations")
def internal_conversations(queue: str = Query(default="needs_action"), x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); now=datetime.now(UTC); query=select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.status=="open")
    if queue=="overdue": query=query.where(MarketplaceConversation.next_action_due_at.is_not(None),MarketplaceConversation.next_action_due_at<now)
    elif queue=="rescue": query=query.where(MarketplaceConversation.escalation_level>=2)
    elif queue=="waiting_partner": query=query.where(MarketplaceConversation.workflow_status=="waiting_partner")
    elif queue=="waiting_client": query=query.where(MarketplaceConversation.workflow_status=="waiting_client")
    elif queue=="scheduled": query=query.where(MarketplaceConversation.workflow_status=="scheduled")
    elif queue=="new": query=query.where(MarketplaceConversation.workflow_status=="new")
    else: query=query.where(MarketplaceConversation.next_action_type.is_not(None),MarketplaceConversation.workflow_status.not_in(["waiting_client","scheduled"]))
    rows=list(session.scalars(query.order_by(MarketplaceConversation.next_action_due_at.asc().nullslast(),MarketplaceConversation.updated_at.desc()).limit(100)))
    return {"items":[{"id":str(x.id),"listingCode":x.listing_code,"workflowStatus":x.workflow_status,"primaryIntent":x.primary_intent,"nextActionType":x.next_action_type,"nextActionDueAt":x.next_action_due_at.isoformat() if x.next_action_due_at else None,"overdue":bool(x.next_action_due_at and x.next_action_due_at<now),"assignedActorType":x.assigned_actor_type,"assignedActorId":x.assigned_actor_id,"assignedQueue":x.assigned_queue,"sourceChannel":x.source_channel,"escalationLevel":x.escalation_level,"rescueReason":x.rescue_reason,"updatedAt":x.updated_at.isoformat()} for x in rows]}

@app.get("/v1/internal/conversations/{conversation_id}")
def internal_conversation(conversation_id: UUID, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); row=session.get(MarketplaceConversation,conversation_id)
    if not row or row.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Conversation not found")
    item=_conversation_listing(row) or {}; person=session.get(PersonProfile,row.person_profile_id); latest=session.scalar(select(MarketplaceMessage).where(MarketplaceMessage.conversation_id==row.id).order_by(MarketplaceMessage.created_at.desc()).limit(1)); req=session.scalar(select(MarketplaceViewingRequest).where(MarketplaceViewingRequest.conversation_id==row.id,MarketplaceViewingRequest.status=="pending").order_by(MarketplaceViewingRequest.created_at.desc()).limit(1))
    facts=(person.facts_json or {}) if person else {}
    return {"id":str(row.id),"listingCode":row.listing_code,"listingAddress":item.get("address") or item.get("code") or row.listing_code,"workflowStatus":row.workflow_status,"primaryIntent":row.primary_intent,"nextActionType":row.next_action_type,"nextActionDueAt":row.next_action_due_at.isoformat() if row.next_action_due_at else None,"client":{"name":person.display_name if person else None,"username":person.username if person else None,"telegramUserId":person.telegram_user_id if person else None,"phone":facts.get("phone"),"email":facts.get("email")},"qualificationSnapshot":row.qualification_snapshot_json or {},"preferredWindows":req.preferred_windows_json if req else [],"assignedActorType":row.assigned_actor_type,"assignedActorId":row.assigned_actor_id,"assignedQueue":row.assigned_queue,"routingDecision":row.routing_decision_json or {},"sourceChannel":row.source_channel,"preferredOutboundChannel":row.preferred_outbound_channel,"escalationLevel":row.escalation_level,"rescueReason":row.rescue_reason,"lastMessage":(latest.translated_body or latest.body) if latest else ""}

@app.post("/v1/internal/conversations/{conversation_id}/unavailable")
def mark_conversation_unavailable(conversation_id: UUID, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); conv=session.get(MarketplaceConversation,conversation_id)
    if not conv or conv.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Conversation not found")
    if conv.workflow_status=="unavailable": return {"ok":True,"status":"unavailable","duplicate":True}
    now=datetime.now(UTC); conv.workflow_status="unavailable"; conv.status="closed"; conv.next_action_type=None; conv.next_action_due_at=None; conv.close_reason="listing_unavailable"; conv.closed_at=now; conv.updated_at=now; conv.last_operator_activity_at=now
    for request in session.scalars(select(MarketplaceViewingRequest).where(MarketplaceViewingRequest.conversation_id==conv.id,MarketplaceViewingRequest.status=="pending")): request.status="cancelled"; request.updated_at=now
    _marketplace_metric(session,"listing_unavailable_after_inquiry",object_id=conv.id); session.commit(); person=session.get(PersonProfile,conv.person_profile_id)
    if person and person.telegram_user_id and person.telegram_user_id>0: _bot_send(person.telegram_user_id,"Этот объект больше недоступен. Откройте каталог — подберём похожие варианты.",reply_markup={"inline_keyboard":[[{"text":"Показать другие варианты","web_app":{"url":settings.miniapp_url}}]]})
    return {"ok":True,"status":"unavailable","duplicate":False}

@app.get("/v1/agent/cases")
def agent_cases(request: Request, queue: str = Query(default="needs_action"), session: Session = Depends(db)):
    _require_agent(request); now=datetime.now(UTC)
    query=select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.status=="open")
    if queue=="overdue": query=query.where(MarketplaceConversation.next_action_due_at.is_not(None),MarketplaceConversation.next_action_due_at<now)
    elif queue=="rescue": query=query.where(MarketplaceConversation.escalation_level>=2)
    elif queue=="waiting_partner": query=query.where(MarketplaceConversation.workflow_status=="waiting_partner")
    elif queue=="waiting_client": query=query.where(MarketplaceConversation.workflow_status=="waiting_client")
    elif queue=="scheduled": query=query.where(MarketplaceConversation.workflow_status=="scheduled")
    elif queue=="new": query=query.where(MarketplaceConversation.workflow_status=="new")
    else: query=query.where(MarketplaceConversation.next_action_type.is_not(None),MarketplaceConversation.workflow_status.not_in(["waiting_client","scheduled"]))
    rows=list(session.scalars(query.order_by(MarketplaceConversation.next_action_due_at.asc().nullslast(),MarketplaceConversation.updated_at.desc()).limit(80)))
    items=[]
    for row in rows:
        listing=_conversation_listing(row) or {}; person=session.get(PersonProfile,row.person_profile_id)
        latest=session.scalar(select(MarketplaceMessage).where(MarketplaceMessage.conversation_id==row.id).order_by(MarketplaceMessage.created_at.desc()).limit(1))
        items.append({"id":str(row.id),"listingCode":row.listing_code,"listingAddress":listing.get("address") or listing.get("code") or row.listing_code,"workflowStatus":row.workflow_status,"primaryIntent":row.primary_intent,"nextActionType":row.next_action_type,"nextActionDueAt":row.next_action_due_at.isoformat() if row.next_action_due_at else None,"overdue":bool(row.next_action_due_at and row.next_action_due_at<now),"assignedActorType":row.assigned_actor_type,"assignedActorId":row.assigned_actor_id,"assignedQueue":row.assigned_queue,"sourceChannel":row.source_channel,"escalationLevel":row.escalation_level,"rescueReason":row.rescue_reason,"updatedAt":row.updated_at.isoformat(),"client":{"name":person.display_name if person else None,"username":person.username if person else None},"lastMessage":(latest.translated_body or latest.body) if latest else "","qualificationSnapshot":row.qualification_snapshot_json or {}})
    return {"items":items,"queue":queue,"count":len(items)}

@app.get("/v1/agent/cases/{conversation_id}")
def agent_case(conversation_id: UUID, request: Request, session: Session = Depends(db)):
    _require_agent(request)
    detail=internal_conversation(conversation_id,settings.service_key,session)
    messages=list(session.scalars(select(MarketplaceMessage).where(MarketplaceMessage.conversation_id==conversation_id).order_by(MarketplaceMessage.created_at.asc())))
    requests=list(session.scalars(select(MarketplaceViewingRequest).where(MarketplaceViewingRequest.conversation_id==conversation_id).order_by(MarketplaceViewingRequest.created_at.asc())))
    viewings=list(session.scalars(select(MarketplaceViewing).where(MarketplaceViewing.conversation_id==conversation_id).order_by(MarketplaceViewing.created_at.asc())))
    detail["messages"]=[{"id":str(m.id),"senderRole":m.sender_role,"sourceLanguage":m.source_language,"body":m.body,"translatedBody":m.translated_body,"translationStatus":m.translation_status,"deliveryStatus":m.delivery_status,"sourceChannel":m.source_channel,"createdAt":m.created_at.isoformat()} for m in messages]
    detail["viewingRequests"]=[{"id":str(v.id),"preferredWindows":v.preferred_windows_json or [],"note":v.note,"status":v.status,"createdAt":v.created_at.isoformat()} for v in requests]
    detail["viewings"]=[{"id":str(v.id),"proposedAt":v.proposed_at.isoformat(),"status":v.status,"createdAt":v.created_at.isoformat()} for v in viewings]
    detail["listingUrl"]=f"{settings.miniapp_url}/?listing={detail['listingCode']}"
    return detail

@app.post("/v1/agent/cases/{conversation_id}/messages")
def agent_case_message(conversation_id: UUID, body: MessageIn, request: Request, session: Session = Depends(db)):
    _require_agent(request)
    return partner_message(conversation_id,body,settings.service_key,session)

@app.post("/v1/agent/cases/{conversation_id}/viewings")
def agent_case_viewing(conversation_id: UUID, body: ViewingIn, request: Request, session: Session = Depends(db)):
    _require_agent(request)
    return propose_viewing(conversation_id,body,settings.service_key,session)

@app.post("/v1/agent/cases/{conversation_id}/unavailable")
def agent_case_unavailable(conversation_id: UUID, request: Request, session: Session = Depends(db)):
    _require_agent(request)
    return mark_conversation_unavailable(conversation_id,settings.service_key,session)

@app.post("/v1/internal/conversations/rescue-sweep")
def rescue_sweep(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); now=datetime.now(UTC); changed=[]
    rows=list(session.scalars(select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.status=="open",MarketplaceConversation.next_action_due_at.is_not(None),MarketplaceConversation.next_action_due_at<now)))
    for row in rows:
        overdue=max(0,(now-row.next_action_due_at).total_seconds()/60)
        level=3 if overdue>=settings.rescue_required_minutes else 2 if overdue>=settings.rescue_escalation_minutes else 1
        if level>row.escalation_level:
            row.escalation_level=level; row.rescue_reason="partner_non_response" if row.workflow_status=="waiting_partner" else "next_action_overdue"; row.updated_at=now
            if level>=2 and row.assigned_queue!="central_rescue":
                row.assigned_queue="central_rescue"
            _marketplace_metric(session,"case_escalated",object_id=row.id,properties={"level":level,"reason":row.rescue_reason,"workflowStatus":row.workflow_status})
            changed.append({"id":str(row.id),"level":level,"reason":row.rescue_reason})
    session.commit(); return {"ok":True,"changed":changed,"count":len(changed)}

@app.post("/v1/internal/listing-responsibilities")
def upsert_listing_responsibility(body: ListingResponsibilityIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key)
    row=session.scalar(select(ListingResponsibility).where(ListingResponsibility.tenant==settings.growth_tenant,ListingResponsibility.inventory_source_id==body.inventory_source_id,ListingResponsibility.listing_key==body.listing_key))
    if row is None:
        row=ListingResponsibility(tenant=settings.growth_tenant,inventory_source_id=body.inventory_source_id,listing_key=body.listing_key,actor_type=body.actor_type,actor_id=body.actor_id); session.add(row)
    row.operation=body.operation; row.actor_type=body.actor_type; row.actor_id=body.actor_id; row.fallback_actor_type=body.fallback_actor_type; row.fallback_actor_id=body.fallback_actor_id; row.metadata_json=body.metadata; row.active=True; row.updated_at=datetime.now(UTC); session.commit()
    return {"ok":True,"id":str(row.id),"listingKey":row.listing_key,"actorType":row.actor_type,"actorId":row.actor_id}

@app.get("/v1/internal/listing-responsibilities")
def list_listing_responsibilities(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); rows=list(session.scalars(select(ListingResponsibility).where(ListingResponsibility.tenant==settings.growth_tenant,ListingResponsibility.active.is_(True)).order_by(ListingResponsibility.updated_at.desc())))
    return {"items":[{"id":str(x.id),"inventorySourceId":x.inventory_source_id,"listingKey":x.listing_key,"operation":x.operation,"actorType":x.actor_type,"actorId":x.actor_id,"fallbackActorType":x.fallback_actor_type,"fallbackActorId":x.fallback_actor_id} for x in rows]}

def _handoff_snapshot(session: Session, conv: MarketplaceConversation) -> dict[str, Any]:
    item=_conversation_listing(conv) or {}; person=session.get(PersonProfile,conv.person_profile_id); q=conv.qualification_snapshot_json or {}
    return {"listingCode":conv.listing_code,"address":item.get("address") or item.get("code") or conv.listing_code,"operation":item.get("operation"),"language":person.preferred_language if person else None,"requestedOutcome":conv.primary_intent,"qualification":q,"demandOrigin":settings.brand_name,"inventorySource":item.get("sourceDisplayName") or item.get("sourceId") or conv.inventory_source_id}

@app.post("/v1/internal/partner-handoffs")
def create_partner_handoff(body: PartnerHandoffIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); conv=session.get(MarketplaceConversation,body.conversation_id)
    if not conv or conv.tenant!=settings.growth_tenant or conv.status!="open": raise HTTPException(status_code=404,detail="Open case not found")
    if body.partner_agency_id:
        partner=session.get(PartnerAgency,body.partner_agency_id)
        if not partner or partner.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    existing=session.scalar(select(PartnerHandoff).where(PartnerHandoff.conversation_id==conv.id,PartnerHandoff.status=="pending").order_by(PartnerHandoff.created_at.desc()).limit(1))
    if existing: return {"ok":True,"id":str(existing.id),"status":existing.status,"duplicate":True,"expiresAt":existing.expires_at.isoformat()}
    raw=secrets.token_urlsafe(32); now=datetime.now(UTC); row=PartnerHandoff(tenant=settings.growth_tenant,conversation_id=conv.id,partner_agency_id=body.partner_agency_id,transport=body.transport,recipient_ref=body.recipient_ref,sanitized_snapshot_json=_handoff_snapshot(session,conv),claim_token_hash=_token_hash(raw),status="pending",expires_at=now+timedelta(minutes=max(15,settings.partner_handoff_ttl_minutes)),created_at=now,updated_at=now); session.add(row); conv.workflow_status="waiting_partner"; conv.next_action_type="partner_claim"; conv.next_action_due_at=now+timedelta(minutes=max(5,settings.operator_sla_minutes)); conv.rescue_reason=None; session.flush(); _marketplace_metric(session,"partner_handoff_created",object_id=row.id,properties={"conversationId":str(conv.id),"transport":body.transport}); session.commit()
    return {"ok":True,"id":str(row.id),"status":row.status,"duplicate":False,"claimToken":raw,"expiresAt":row.expires_at.isoformat(),"snapshot":row.sanitized_snapshot_json}

@app.post("/v1/partner-handoffs/claim")
def claim_partner_handoff(body: PartnerHandoffClaimIn, session: Session = Depends(db)):
    now=datetime.now(UTC); row=session.scalar(select(PartnerHandoff).where(PartnerHandoff.claim_token_hash==_token_hash(body.token))); conv=session.get(MarketplaceConversation,row.conversation_id) if row else None
    if not row or not conv or row.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Handoff not found")
    if row.status in {"claimed","declined"}: return {"ok":True,"status":row.status,"duplicate":True}
    if row.status!="pending" or row.expires_at<=now:
        if row.status=="pending": row.status="expired"; row.updated_at=now; conv.escalation_level=max(conv.escalation_level,2); conv.assigned_queue="central_rescue"; conv.rescue_reason="partner_handoff_expired"; session.commit()
        raise HTTPException(status_code=409,detail="Handoff expired")
    row.status="claimed" if body.accept else "declined"; row.claimed_by=body.claimant; row.claimed_at=now; row.updated_at=now
    if body.accept:
        conv.assigned_actor_type="partner_agent"; conv.assigned_actor_id=body.claimant; conv.assigned_queue=f"partner:{row.partner_agency_id}" if row.partner_agency_id else "external_partner"; conv.workflow_status="in_progress"; conv.next_action_type="reply_client"; conv.next_action_due_at=now+timedelta(minutes=max(5,settings.operator_sla_minutes)); conv.rescue_reason=None
    else:
        conv.assigned_actor_type="queue"; conv.assigned_actor_id="central_rescue"; conv.assigned_queue="central_rescue"; conv.workflow_status="new"; conv.next_action_type="reroute_partner"; conv.next_action_due_at=now; conv.escalation_level=max(conv.escalation_level,2); conv.rescue_reason="partner_declined"
    _marketplace_metric(session,"partner_handoff_claimed" if body.accept else "partner_handoff_declined",object_id=row.id,properties={"conversationId":str(conv.id)}); session.commit(); return {"ok":True,"status":row.status,"duplicate":False}

@app.get("/v1/internal/partner-handoffs")
def list_partner_handoffs(status: str = Query(default="pending"), x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); rows=list(session.scalars(select(PartnerHandoff).where(PartnerHandoff.tenant==settings.growth_tenant,PartnerHandoff.status==status).order_by(PartnerHandoff.created_at.desc()).limit(100)))
    return {"items":[{"id":str(x.id),"conversationId":str(x.conversation_id),"partnerAgencyId":str(x.partner_agency_id) if x.partner_agency_id else None,"transport":x.transport,"status":x.status,"snapshot":x.sanitized_snapshot_json,"sentAt":x.sent_at.isoformat() if x.sent_at else None,"expiresAt":x.expires_at.isoformat(),"claimedAt":x.claimed_at.isoformat() if x.claimed_at else None,"claimedBy":x.claimed_by,"attempts":x.attempts,"lastError":x.last_error} for x in rows]}

def _chatwoot_configured() -> bool:
    return bool(settings.chatwoot_enabled and settings.chatwoot_base_url.strip() and settings.chatwoot_account_id and settings.chatwoot_api_inbox_id and settings.chatwoot_api_token.strip())

def _chatwoot_api(method: str, path: str, payload: dict[str, Any] | None = None) -> dict[str, Any]:
    if not _chatwoot_configured(): raise RuntimeError("Chatwoot integration is not configured")
    url=settings.chatwoot_base_url.rstrip("/")+path
    headers={"Authorization":f"Bearer {settings.chatwoot_api_token.strip()}","Content-Type":"application/json"}
    with httpx.Client(timeout=10.0) as client:
        response=client.request(method,url,headers=headers,json=payload)
    if response.status_code>=400: raise RuntimeError(f"Chatwoot HTTP {response.status_code}: {response.text[:500]}")
    try: return response.json()
    except Exception: return {}

def _chatwoot_contact_parts(data: dict[str, Any]) -> tuple[str | None,str | None]:
    candidates=[]
    if isinstance(data,dict):
        candidates.append(data)
        payload=data.get("payload")
        if isinstance(payload,dict):
            candidates.append(payload.get("contact") if isinstance(payload.get("contact"),dict) else payload)
        elif isinstance(payload,list) and payload and isinstance(payload[0],dict):
            candidates.append(payload[0])
    contact_id=None; source_id=None
    for candidate in candidates:
        if not isinstance(candidate,dict): continue
        contact_id=contact_id or candidate.get("id")
        inboxes=candidate.get("contact_inboxes") or []
        if isinstance(inboxes,dict): inboxes=[inboxes]
        for inbox in inboxes:
            if isinstance(inbox,dict) and inbox.get("source_id"):
                source_id=inbox.get("source_id"); break
        if contact_id and source_id: break
    return str(contact_id) if contact_id is not None else None,str(source_id) if source_id else None

def _ensure_chatwoot_projection(session: Session, conv: MarketplaceConversation) -> CommunicationProjection:
    projection=session.scalar(select(CommunicationProjection).where(CommunicationProjection.provider=="chatwoot",CommunicationProjection.conversation_id==conv.id))
    if projection is None:
        projection=CommunicationProjection(provider="chatwoot",conversation_id=conv.id,sync_status="pending"); session.add(projection); session.flush()
    if projection.external_conversation_id and projection.external_contact_id: return projection
    person=session.get(PersonProfile,conv.person_profile_id)
    if not person: raise RuntimeError("Person profile missing")
    facts=person.facts_json or {}; identifier=f"pn-person-{person.id}"
    contact_payload={"inbox_id":settings.chatwoot_api_inbox_id,"name":person.display_name or person.username or "Клиент","identifier":identifier,"additional_attributes":{"property_network_person_id":str(person.id),"preferred_language":person.preferred_language}}
    if facts.get("email"): contact_payload["email"]=str(facts.get("email"))
    if facts.get("phone"): contact_payload["phone_number"]=str(facts.get("phone"))
    created=_chatwoot_api("POST",f"/api/v1/accounts/{settings.chatwoot_account_id}/contacts",contact_payload)
    contact_id,source_id=_chatwoot_contact_parts(created)
    if not contact_id: raise RuntimeError("Chatwoot contact response missing id")
    if not source_id:
        source_id=f"pn-{person.id}"
        linked=_chatwoot_api("POST",f"/api/v1/accounts/{settings.chatwoot_account_id}/contacts/{contact_id}/contact_inboxes",{"inbox_id":settings.chatwoot_api_inbox_id,"source_id":source_id})
        if isinstance(linked,dict) and linked.get("source_id"): source_id=str(linked.get("source_id"))
    item=_conversation_listing(conv) or {}
    conversation_payload={"source_id":source_id,"inbox_id":settings.chatwoot_api_inbox_id,"contact_id":int(contact_id),"status":"open","additional_attributes":{"property_network_case_id":str(conv.id),"listing_code":conv.listing_code,"listing_address":item.get("address") or item.get("code") or conv.listing_code,"source_channel":conv.source_channel,"assigned_queue":conv.assigned_queue,"product":settings.brand_name}}
    cw_conv=_chatwoot_api("POST",f"/api/v1/accounts/{settings.chatwoot_account_id}/conversations",conversation_payload)
    conversation_id=cw_conv.get("id") if isinstance(cw_conv,dict) else None
    if conversation_id is None: raise RuntimeError("Chatwoot conversation response missing id")
    projection.external_contact_id=str(contact_id); projection.external_conversation_id=str(conversation_id); projection.external_inbox_id=str(settings.chatwoot_api_inbox_id); projection.sync_status="synced"; projection.last_error=None; projection.updated_at=datetime.now(UTC); session.flush(); return projection

def _drain_chatwoot_outbox(session: Session, limit: int = 20) -> dict[str, Any]:
    if not _chatwoot_configured(): return {"enabled":settings.chatwoot_enabled,"configured":False,"processed":0,"sent":0,"failed":0}
    now=datetime.now(UTC); rows=list(session.scalars(select(CommunicationOutbox).where(CommunicationOutbox.provider=="chatwoot",CommunicationOutbox.status.in_(["pending","failed"]),((CommunicationOutbox.next_attempt_at.is_(None))|(CommunicationOutbox.next_attempt_at<=now))).order_by(CommunicationOutbox.created_at.asc()).limit(max(1,min(100,limit)))))
    sent=0; failed=0
    for row in rows:
        try:
            if not row.conversation_id: raise RuntimeError("Outbox row has no conversation")
            conv=session.get(MarketplaceConversation,row.conversation_id)
            if not conv: raise RuntimeError("Canonical conversation missing")
            projection=_ensure_chatwoot_projection(session,conv)
            if row.kind=="message_created" and row.message_id:
                msg=session.get(MarketplaceMessage,row.message_id)
                if not msg: raise RuntimeError("Canonical message missing")
                content=(msg.translated_body if msg.sender_role=="client" and msg.translation_status in {"translated","not_needed"} and msg.translated_body else msg.body)
                result=_chatwoot_api("POST",f"/api/v1/accounts/{settings.chatwoot_account_id}/conversations/{projection.external_conversation_id}/messages",{"content":content,"message_type":"incoming","private":False,"content_type":"text","content_attributes":{"property_network_message_id":str(msg.id),"source_channel":msg.source_channel}})
                if isinstance(result,dict) and result.get("id") is not None: row.external_delivery_id=str(result.get("id"))
            row.status="sent"; row.attempts+=1; row.last_error=None; row.next_attempt_at=None; row.updated_at=now; sent+=1
        except Exception as exc:
            row.status="failed"; row.attempts+=1; row.last_error=str(exc)[:500]; row.next_attempt_at=now+timedelta(minutes=min(60,2**min(row.attempts,5))); row.updated_at=now; failed+=1
        session.commit()
    return {"enabled":True,"configured":True,"processed":len(rows),"sent":sent,"failed":failed}

def _verify_chatwoot_webhook(raw: bytes, timestamp: str, signature: str) -> bool:
    if not settings.chatwoot_webhook_secret or not timestamp or not signature: return False
    try: ts=int(timestamp)
    except ValueError: return False
    if abs(int(datetime.now(UTC).timestamp())-ts)>max(60,settings.chatwoot_webhook_max_age_seconds): return False
    expected="sha256="+hmac.new(settings.chatwoot_webhook_secret.encode(),timestamp.encode()+b"."+raw,hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected,signature)

@app.post("/v1/integrations/chatwoot/webhook")
async def chatwoot_webhook(request: Request, session: Session = Depends(db)):
    raw=await request.body(); signature=request.headers.get("X-Chatwoot-Signature",""); timestamp=request.headers.get("X-Chatwoot-Timestamp",""); delivery=request.headers.get("X-Chatwoot-Delivery","")
    if not _verify_chatwoot_webhook(raw,timestamp,signature): raise HTTPException(status_code=401,detail="Invalid Chatwoot signature")
    if delivery and session.scalar(select(IntegrationDelivery).where(IntegrationDelivery.provider=="chatwoot",IntegrationDelivery.delivery_id==delivery)): return {"ok":True,"duplicate":True}
    try: payload=json.loads(raw)
    except Exception: raise HTTPException(status_code=400,detail="Invalid JSON")
    event_name=str(payload.get("event") or "")
    if delivery: session.add(IntegrationDelivery(provider="chatwoot",delivery_id=delivery,event_name=event_name))
    if event_name!="message_created": session.commit(); return {"ok":True,"ignored":True}
    if bool(payload.get("private")): session.commit(); return {"ok":True,"ignored":True}
    sender=payload.get("sender") or {}; sender_type=str(sender.get("type") or "").lower()
    if sender_type in {"contact"}: session.commit(); return {"ok":True,"ignored":True}
    cw_conv=payload.get("conversation") or {}; external_id=str(cw_conv.get("id") or "")
    projection=session.scalar(select(CommunicationProjection).where(CommunicationProjection.provider=="chatwoot",CommunicationProjection.external_conversation_id==external_id))
    if not projection: session.commit(); return {"ok":True,"ignored":True,"reason":"projection_missing"}
    conv=session.get(MarketplaceConversation,projection.conversation_id); content=str(payload.get("content") or "").strip()
    if not conv or not content: session.commit(); return {"ok":True,"ignored":True}
    ext_msg=str(payload.get("id") or "")
    if ext_msg and session.scalar(select(MarketplaceMessage).where(MarketplaceMessage.external_provider=="chatwoot",MarketplaceMessage.external_message_id==ext_msg)): session.commit(); return {"ok":True,"duplicate":True}
    person=session.get(PersonProfile,conv.person_profile_id); target_language=person.preferred_language if person and person.preferred_language in {"ru","es","en"} else "ru"; translated,status,provider=_translate_marketplace(content,"es",target_language); now=datetime.now(UTC); msg=MarketplaceMessage(conversation_id=conv.id,sender_role="partner",source_language="es",body=content,translated_body=translated,translation_status=status,translation_provider=provider,delivery_status="stored",source_channel="chatwoot",external_provider="chatwoot",external_message_id=ext_msg or None); session.add(msg); conv.updated_at=now; conv.last_operator_activity_at=now; conv.first_response_at=conv.first_response_at or now; conv.workflow_status="waiting_client"; conv.next_action_type="wait_client"; conv.next_action_due_at=None
    delivered=False
    if person and person.telegram_user_id and person.telegram_user_id>0 and conv.preferred_outbound_channel=="telegram": delivered=bool(_bot_send(person.telegram_user_id,f"💬 <b>Новый ответ по объекту</b>\n\n{html.escape(translated or content)}"))
    msg.delivery_status="delivered" if delivered else "stored"; _marketplace_metric(session,"chatwoot_agent_message",object_id=msg.id,properties={"conversationId":str(conv.id),"deliveryStatus":msg.delivery_status}); session.commit(); return {"ok":True,"messageId":str(msg.id),"deliveryStatus":msg.delivery_status}

@app.get("/v1/internal/integrations/chatwoot/status")
def chatwoot_status(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); pending=session.query(CommunicationOutbox).filter(CommunicationOutbox.provider=="chatwoot",CommunicationOutbox.status.in_(["pending","failed"])).count(); projected=session.query(CommunicationProjection).filter(CommunicationProjection.provider=="chatwoot").count()
    return {"enabled":settings.chatwoot_enabled,"configured":_chatwoot_configured(),"pendingOutbox":pending,"projections":projected}

@app.post("/v1/internal/integrations/chatwoot/drain")
def chatwoot_drain(limit: int = Query(default=20,ge=1,le=100), x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); return _drain_chatwoot_outbox(session,limit)

@app.post("/v1/collaboration-cases")
def create_collaboration_case(body: CollaborationIn, session: Session = Depends(db)):
    if not settings.marketplace_enabled: raise HTTPException(status_code=503,detail="Marketplace is not enabled")
    ctx=_validate_init_data(body.init_data); user=ctx["user"]; person=_person_for_telegram(session,user); item=_listing_by_key(body.listing_code)
    if body.search_id:
        search=session.get(SavedSearch,body.search_id)
        if not search or search.tenant!=settings.growth_tenant or search.telegram_user_id!=int(user["id"]): raise HTTPException(status_code=404,detail="Search profile not found")
    if not item: raise HTTPException(status_code=404,detail="Listing not found")
    if str(item.get("status") or "active").lower() in {"paused","unavailable","reserved","rented","sold","removed"}: raise HTTPException(status_code=409,detail="Listing is not currently available")
    prov=_routing_context(item); owner=str(prov.get("inventoryOwnerTenant") or settings.growth_tenant)
    if owner==settings.growth_tenant: raise HTTPException(status_code=409,detail="Listing is owned by the buyer-origin tenant; collaboration is not required")
    existing=session.scalar(select(CollaborationCase).where(CollaborationCase.tenant==settings.growth_tenant,CollaborationCase.person_profile_id==person.id,CollaborationCase.listing_code==(item.get("listingToken") or item.get("code") or body.listing_code),CollaborationCase.status.in_(["requested","accepted"])).order_by(CollaborationCase.created_at.desc()).limit(1))
    if existing: return {"ok":True,"id":str(existing.id),"status":existing.status,"piiReleased":existing.pii_released_at is not None,"buyerOrigin":existing.buyer_origin_tenant,"inventoryOwner":existing.inventory_owner_tenant,"duplicate":True}
    conversation=session.scalar(select(MarketplaceConversation).where(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceConversation.person_profile_id==person.id,MarketplaceConversation.listing_code==(item.get("listingToken") or item.get("code") or body.listing_code)).order_by(MarketplaceConversation.created_at.desc()).limit(1))
    row=CollaborationCase(tenant=settings.growth_tenant,person_profile_id=person.id,search_id=body.search_id,listing_code=item.get("listingToken") or item.get("code") or body.listing_code,buyer_origin_tenant=settings.growth_tenant,inventory_source_id=prov.get("inventorySourceId"),inventory_owner_tenant=owner,introduction_evidence_json={"telegram_user_id":int(user["id"]),"created_at":datetime.now(UTC).isoformat(),"conversation_id":str(conversation.id) if conversation else None}); session.add(row); session.flush(); _marketplace_metric(session,"collaboration_requested",actor_id=user["id"],object_id=row.id,properties={"buyerOrigin":row.buyer_origin_tenant,"inventoryOwner":row.inventory_owner_tenant}); session.commit(); return {"ok":True,"id":str(row.id),"status":row.status,"piiReleased":False,"buyerOrigin":row.buyer_origin_tenant,"inventoryOwner":row.inventory_owner_tenant,"duplicate":False}

@app.post("/v1/internal/collaboration-agreements")
def create_collaboration_agreement(body: AgreementIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key)
    partner=session.get(PartnerAgency,body.partner_agency_id)
    if not partner or partner.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Partner not found")
    if partner.status=="rejected": raise HTTPException(status_code=409,detail="Rejected partner cannot receive an agreement")
    if not body.terms: raise HTTPException(status_code=422,detail="Agreement terms cannot be empty")
    existing=session.scalar(select(CollaborationAgreement).where(CollaborationAgreement.tenant==settings.growth_tenant,CollaborationAgreement.partner_agency_id==partner.id,CollaborationAgreement.version==body.version))
    if existing: return {"ok":True,"id":str(existing.id),"status":existing.status,"version":existing.version}
    row=CollaborationAgreement(tenant=settings.growth_tenant,partner_agency_id=partner.id,version=body.version,terms_json=body.terms,status="draft"); session.add(row); session.flush(); _marketplace_metric(session,"agreement_created",object_id=row.id,properties={"partnerId":str(partner.id),"version":row.version}); session.commit()
    return {"ok":True,"id":str(row.id),"status":row.status,"version":row.version}

@app.post("/v1/internal/collaboration-agreements/{agreement_id}/accept")
def accept_collaboration_agreement(agreement_id: UUID, body: AgreementAcceptIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); row=session.get(CollaborationAgreement,agreement_id)
    if not row or row.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Agreement not found")
    if row.status=="revoked" and body.accepted: raise HTTPException(status_code=409,detail="Revoked agreement version cannot be reactivated")
    if row.status=="accepted" and body.accepted: return {"ok":True,"id":str(row.id),"status":row.status,"version":row.version,"acceptedAt":row.accepted_at.isoformat() if row.accepted_at else None,"duplicate":True}
    if body.accepted and not body.partner_confirmed: raise HTTPException(status_code=422,detail="Explicit partner confirmation is required")
    if body.accepted and not row.terms_json: raise HTTPException(status_code=422,detail="Agreement terms cannot be empty")
    partner=session.get(PartnerAgency,row.partner_agency_id)
    if body.accepted and (not partner or not ((partner.metadata_json or {}).get("sourceIds") or [])): raise HTTPException(status_code=409,detail="Link partner inventory source before accepting terms")
    if body.accepted and not bool((partner.metadata_json or {}).get("verified")): raise HTTPException(status_code=409,detail="Verify partner before accepting terms")
    if body.accepted and partner.status not in {"pending","active"}: raise HTTPException(status_code=409,detail="Partner status does not allow agreement acceptance")
    if body.accepted and any(k in row.terms_json for k in {"sellerSideSplit","buyerSideCommission"}) and not bool(row.terms_json.get("commercialApproved")): raise HTTPException(status_code=409,detail="Commercial commission terms require explicit approval")
    row.status="accepted" if body.accepted else "revoked"; row.accepted_at=datetime.now(UTC) if body.accepted else None
    if partner:
        partner.terms_version=row.version if body.accepted else (None if partner.terms_version==row.version else partner.terms_version); partner.updated_at=datetime.now(UTC)
    _marketplace_metric(session,"agreement_accepted" if body.accepted else "agreement_revoked",object_id=row.id,properties={"version":row.version,"partnerId":str(row.partner_agency_id)})
    session.commit(); return {"ok":True,"id":str(row.id),"status":row.status,"version":row.version,"acceptedAt":row.accepted_at.isoformat() if row.accepted_at else None}

@app.post("/v1/internal/collaboration-cases/{case_id}/decision")
def decide_collaboration_case(case_id: UUID, body: CollaborationDecisionIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); case=session.get(CollaborationCase,case_id); agreement=session.get(CollaborationAgreement,body.agreement_id)
    if not case or case.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Collaboration case not found")
    desired="accepted" if body.accept else "declined"
    if case.status==desired: return {"ok":True,"id":str(case.id),"status":case.status,"piiReleased":case.pii_released_at is not None,"duplicate":True}
    if case.status!="requested": raise HTTPException(status_code=409,detail=f"Collaboration case is already {case.status}")
    if not agreement or agreement.tenant!=settings.growth_tenant or agreement.status!="accepted": raise HTTPException(status_code=409,detail="Accepted collaboration agreement required")
    if agreement.accepted_at is None: raise HTTPException(status_code=409,detail="Agreement acceptance timestamp is missing")
    partner=session.get(PartnerAgency,agreement.partner_agency_id)
    if case.inventory_owner_tenant!=settings.growth_tenant:
        if not partner or str((partner.metadata_json or {}).get("ownerTenant") or "")!=case.inventory_owner_tenant: raise HTTPException(status_code=409,detail="Agreement partner does not own this inventory side")
    if not partner or partner.status!="active" or not bool((partner.metadata_json or {}).get("verified")): raise HTTPException(status_code=409,detail="Verified active partner required")
    if case.inventory_source_id not in ((partner.metadata_json or {}).get("sourceIds") or []): raise HTTPException(status_code=409,detail="Agreement partner is not linked to this inventory source")
    if partner.terms_version!=agreement.version: raise HTTPException(status_code=409,detail="Partner has not activated this agreement version")
    case.agreement_id=agreement.id; case.status="accepted" if body.accept else "declined"; case.updated_at=datetime.now(UTC)
    # PII is released only after an explicit case acceptance under an accepted, versioned agreement.
    if body.accept: case.pii_released_at=datetime.now(UTC)
    _marketplace_metric(session,"collaboration_accepted" if body.accept else "collaboration_declined",object_id=case.id,properties={"agreementVersion":agreement.version,"piiReleased":case.pii_released_at is not None})
    session.commit(); return {"ok":True,"id":str(case.id),"status":case.status,"agreementVersion":agreement.version,"piiReleased":case.pii_released_at is not None}

@app.post("/v1/internal/collaboration-cases/{case_id}/outcome")
def collaboration_outcome(case_id: UUID, body: CollaborationOutcomeIn, x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); case=session.get(CollaborationCase,case_id)
    if not case or case.tenant!=settings.growth_tenant: raise HTTPException(status_code=404,detail="Collaboration case not found")
    if case.status!="accepted": raise HTTPException(status_code=409,detail="Collaboration case must be accepted first")
    if body.outcome in {"closed_won","closed_lost"}: case.status=body.outcome
    case.updated_at=datetime.now(UTC); _marketplace_metric(session,f"collaboration_{body.outcome}",object_id=case.id,properties={"hasNote":bool(body.note)}); session.commit()
    return {"ok":True,"id":str(case.id),"status":case.status,"outcome":body.outcome}

@app.get("/v1/internal/marketplace-metrics")
def marketplace_metrics(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key)
    rows=session.execute(select(MarketplaceMetric.event_name,func.count(MarketplaceMetric.id)).where(MarketplaceMetric.tenant==settings.growth_tenant).group_by(MarketplaceMetric.event_name)).all()
    return {"events":{name:int(count) for name,count in rows},"partners":session.query(PartnerAgency).filter(PartnerAgency.tenant==settings.growth_tenant).count(),"activePartners":session.query(PartnerAgency).filter(PartnerAgency.tenant==settings.growth_tenant,PartnerAgency.status=="active").count(),"conversations":session.query(MarketplaceConversation).filter(MarketplaceConversation.tenant==settings.growth_tenant).count(),"viewingsConfirmed":session.query(MarketplaceViewing).join(MarketplaceConversation).filter(MarketplaceConversation.tenant==settings.growth_tenant,MarketplaceViewing.status=="confirmed").count(),"collaborationAccepted":session.query(CollaborationCase).filter(CollaborationCase.tenant==settings.growth_tenant,CollaborationCase.status=="accepted").count()}

@app.get("/v1/internal/collaboration-cases")
def list_collaboration_cases(x_intent_key: str | None = Header(default=None), session: Session = Depends(db)):
    _marketplace_service_auth(x_intent_key); rows=list(session.scalars(select(CollaborationCase).where(CollaborationCase.tenant==settings.growth_tenant).order_by(CollaborationCase.created_at.desc()))); return {"items":[{"id":str(x.id),"listingCode":x.listing_code,"status":x.status,"buyerOrigin":x.buyer_origin_tenant,"inventoryOwner":x.inventory_owner_tenant,"inventorySourceId":x.inventory_source_id,"agreementId":str(x.agreement_id) if x.agreement_id else None,"piiReleasedAt":x.pii_released_at.isoformat() if x.pii_released_at else None,"createdAt":x.created_at.isoformat()} for x in rows]}
