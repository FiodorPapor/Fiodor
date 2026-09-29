from __future__ import annotations

import base64
import hashlib
import hmac
import html
import re
from datetime import UTC, datetime, timedelta
from decimal import Decimal
from typing import Any
from uuid import UUID, uuid4

from fastapi import Depends, FastAPI, Header, HTTPException, Query
from fastapi.responses import HTMLResponse
from pydantic import BaseModel, Field
from pydantic_settings import BaseSettings, SettingsConfigDict
from sqlalchemy import (
    JSON,
    BigInteger,
    Boolean,
    DateTime,
    ForeignKey,
    Index,
    Numeric,
    String,
    UniqueConstraint,
    create_engine,
    func,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, relationship, sessionmaker


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_file=".env", extra="ignore")
    database_url: str
    service_key: str
    identity_salt: str
    token_secret: str
    default_tenant: str = "lebleu"
    default_tenant_name: str = "Le Bleu"
    default_timezone: str = "America/Argentina/Buenos_Aires"
    default_bot_username: str = "LeBleuArgentinaBot"


settings = Settings()
engine = create_engine(settings.database_url, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)


class Base(DeclarativeBase):
    pass


class Tenant(Base):
    __tablename__ = "tenants"
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    slug: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    name: Mapped[str] = mapped_column(String(160))
    timezone: Mapped[str] = mapped_column(String(64), default="UTC")
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


class TrackingLink(Base):
    __tablename__ = "tracking_links"
    __table_args__ = (
        UniqueConstraint("tenant_id", "canonical_key", name="uq_tracking_links_tenant_key"),
        Index("ix_tracking_links_tenant_source_campaign", "tenant_id", "source", "campaign"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    token: Mapped[str] = mapped_column(String(24), unique=True, index=True)
    canonical_key: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(80))
    medium: Mapped[str] = mapped_column(String(80))
    campaign: Mapped[str] = mapped_column(String(120))
    content: Mapped[str | None] = mapped_column(String(160), nullable=True)
    placement: Mapped[str | None] = mapped_column(String(200), nullable=True)
    listing_code: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    intent: Mapped[str | None] = mapped_column(String(80), nullable=True)
    bot_username: Mapped[str] = mapped_column(String(80))
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    active: Mapped[bool] = mapped_column(Boolean, default=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    tenant: Mapped[Tenant] = relationship()


class Event(Base):
    __tablename__ = "events"
    __table_args__ = (
        Index("ix_events_tenant_time", "tenant_id", "occurred_at"),
        Index("ix_events_tenant_event_time", "tenant_id", "event_name", "occurred_at"),
        Index("ix_events_tenant_source_campaign", "tenant_id", "source", "campaign"),
        Index("ix_events_actor", "tenant_id", "actor_key", "occurred_at"),
    )
    id: Mapped[int] = mapped_column(BigInteger, primary_key=True, autoincrement=True)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    occurred_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))
    event_name: Mapped[str] = mapped_column(String(80), index=True)
    actor_key: Mapped[str | None] = mapped_column(String(64), nullable=True)
    anonymous_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    session_id: Mapped[str | None] = mapped_column(String(120), nullable=True)
    link_token: Mapped[str | None] = mapped_column(String(24), nullable=True, index=True)
    listing_code: Mapped[str | None] = mapped_column(String(120), nullable=True, index=True)
    source: Mapped[str | None] = mapped_column(String(80), nullable=True)
    medium: Mapped[str | None] = mapped_column(String(80), nullable=True)
    campaign: Mapped[str | None] = mapped_column(String(120), nullable=True)
    content: Mapped[str | None] = mapped_column(String(160), nullable=True)
    placement: Mapped[str | None] = mapped_column(String(200), nullable=True)
    properties_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    is_test: Mapped[bool] = mapped_column(Boolean, default=False)


class Spend(Base):
    __tablename__ = "spend"
    __table_args__ = (
        Index("ix_spend_tenant_period", "tenant_id", "period_start"),
        Index("ix_spend_tenant_source_campaign", "tenant_id", "source", "campaign"),
    )
    id: Mapped[UUID] = mapped_column(primary_key=True, default=uuid4)
    tenant_id: Mapped[UUID] = mapped_column(ForeignKey("tenants.id"), index=True)
    source: Mapped[str] = mapped_column(String(80))
    medium: Mapped[str] = mapped_column(String(80))
    campaign: Mapped[str] = mapped_column(String(120))
    placement: Mapped[str | None] = mapped_column(String(200), nullable=True)
    period_start: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    period_end: Mapped[datetime] = mapped_column(DateTime(timezone=True))
    amount: Mapped[Decimal] = mapped_column(Numeric(14, 2))
    currency: Mapped[str] = mapped_column(String(12))
    impressions: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    clicks: Mapped[int | None] = mapped_column(BigInteger, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(UTC))


EVENT_NAMES = {
    "bot_started",
    "catalog_opened",
    "listing_opened",
    "gallery_opened",
    "share_clicked",
    "search_started",
    "search_submitted",
    "notification_opt_in",
    "notification_sent",
    "notification_clicked",
    "availability_requested",
    "question_submitted",
    "viewing_requested",
    "lead_qualified",
    "viewing_scheduled",
    "reservation_started",
    "deal_won",
    "deal_lost",
}

# CRM-neutral commercial funnel. Product actions such as listing_opened,
# search_submitted and availability_requested are measured separately because they
# are parallel intent paths rather than mandatory sequential steps.
FUNNEL = [
    "bot_started",
    "lead_qualified",
    "viewing_scheduled",
    "reservation_started",
    "deal_won",
]


class EnsureLinkIn(BaseModel):
    tenant: str = "lebleu"
    source: str = Field(min_length=1, max_length=80)
    medium: str = Field(min_length=1, max_length=80)
    campaign: str = Field(min_length=1, max_length=120)
    content: str | None = Field(default=None, max_length=160)
    placement: str | None = Field(default=None, max_length=200)
    listing_code: str | None = Field(default=None, max_length=120)
    intent: str | None = Field(default=None, max_length=80)
    bot_username: str | None = Field(default=None, max_length=80)
    metadata: dict[str, Any] = Field(default_factory=dict)


class EventIn(BaseModel):
    tenant: str = "lebleu"
    event_name: str
    actor_external_id: str | int | None = None
    anonymous_id: str | None = Field(default=None, max_length=120)
    session_id: str | None = Field(default=None, max_length=120)
    link_token: str | None = Field(default=None, max_length=24)
    listing_code: str | None = Field(default=None, max_length=120)
    source: str | None = Field(default=None, max_length=80)
    medium: str | None = Field(default=None, max_length=80)
    campaign: str | None = Field(default=None, max_length=120)
    content: str | None = Field(default=None, max_length=160)
    placement: str | None = Field(default=None, max_length=200)
    properties: dict[str, Any] = Field(default_factory=dict)
    occurred_at: datetime | None = None
    is_test: bool = False


class SpendIn(BaseModel):
    tenant: str = "lebleu"
    source: str
    medium: str
    campaign: str
    placement: str | None = None
    period_start: datetime
    period_end: datetime
    amount: Decimal
    currency: str
    impressions: int | None = None
    clicks: int | None = None
    metadata: dict[str, Any] = Field(default_factory=dict)


def db():
    with SessionLocal() as session:
        yield session


def require_key(x_growth_key: str | None = Header(default=None)):
    if not x_growth_key or not hmac.compare_digest(x_growth_key, settings.service_key):
        raise HTTPException(status_code=401, detail="invalid growth key")


def _tenant(session: Session, slug: str) -> Tenant:
    row = session.scalar(select(Tenant).where(Tenant.slug == slug))
    if row:
        return row
    row = Tenant(
        slug=slug,
        name=settings.default_tenant_name if slug == settings.default_tenant else slug,
        timezone=settings.default_timezone if slug == settings.default_tenant else "UTC",
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return row


def _token(tenant: str, canonical_key: str) -> str:
    raw = hmac.new(settings.token_secret.encode(), f"{tenant}|{canonical_key}".encode(), hashlib.sha256).digest()
    return base64.urlsafe_b64encode(raw).decode().rstrip("=")[:12]


def _actor_key(value: str | int | None) -> str | None:
    if value is None:
        return None
    return hmac.new(settings.identity_salt.encode(), str(value).encode(), hashlib.sha256).hexdigest()[:32]


def _clean(value: str | None) -> str | None:
    if value is None:
        return None
    v = re.sub(r"\s+", " ", value.strip())
    return v or None


app = FastAPI(title="Growth Core", version="0.1.0")


@app.on_event("startup")
def startup():
    Base.metadata.create_all(engine)
    with SessionLocal() as session:
        _tenant(session, settings.default_tenant)


@app.get("/health")
def health():
    return {"status": "ok", "service": "growth-core", "version": "0.1.0"}


@app.post("/v1/links/ensure", dependencies=[Depends(require_key)])
def ensure_link(body: EnsureLinkIn, session: Session = Depends(db)):
    tenant = _tenant(session, body.tenant)
    source, medium, campaign = _clean(body.source), _clean(body.medium), _clean(body.campaign)
    content, placement = _clean(body.content), _clean(body.placement)
    listing_code, intent = _clean(body.listing_code), _clean(body.intent)
    canonical_key = "|".join(
        [
            source or "",
            medium or "",
            campaign or "",
            content or "",
            placement or "",
            listing_code or "",
            intent or "",
        ]
    )
    row = session.scalar(
        select(TrackingLink).where(
            TrackingLink.tenant_id == tenant.id,
            TrackingLink.canonical_key == canonical_key,
        )
    )
    bot = (body.bot_username or settings.default_bot_username).lstrip("@")
    if row is None:
        row = TrackingLink(
            tenant_id=tenant.id,
            token=_token(body.tenant, canonical_key),
            canonical_key=canonical_key,
            source=source or "unknown",
            medium=medium or "unknown",
            campaign=campaign or "unknown",
            content=content,
            placement=placement,
            listing_code=listing_code,
            intent=intent,
            bot_username=bot,
            metadata_json=body.metadata,
        )
        session.add(row)
    else:
        row.bot_username = bot
        row.metadata_json = body.metadata
        row.active = True
    session.commit()
    return {
        "token": row.token,
        "start_parameter": f"trk_{row.token}",
        "telegram_url": f"https://t.me/{row.bot_username}?start=trk_{row.token}",
        "source": row.source,
        "medium": row.medium,
        "campaign": row.campaign,
        "listing_code": row.listing_code,
        "intent": row.intent,
    }


@app.get("/v1/links/{token}", dependencies=[Depends(require_key)])
def get_link(token: str, tenant: str = Query("lebleu"), session: Session = Depends(db)):
    t = _tenant(session, tenant)
    row = session.scalar(
        select(TrackingLink).where(TrackingLink.tenant_id == t.id, TrackingLink.token == token)
    )
    if not row:
        raise HTTPException(status_code=404, detail="tracking link not found")
    return {
        "token": row.token,
        "source": row.source,
        "medium": row.medium,
        "campaign": row.campaign,
        "content": row.content,
        "placement": row.placement,
        "listing_code": row.listing_code,
        "intent": row.intent,
        "metadata": row.metadata_json,
    }


@app.post("/v1/events", dependencies=[Depends(require_key)])
def capture_event(body: EventIn, session: Session = Depends(db)):
    if body.event_name not in EVENT_NAMES:
        raise HTTPException(status_code=422, detail=f"unknown event_name: {body.event_name}")
    tenant = _tenant(session, body.tenant)
    link = None
    if body.link_token:
        link = session.scalar(
            select(TrackingLink).where(
                TrackingLink.tenant_id == tenant.id,
                TrackingLink.token == body.link_token,
            )
        )
    row = Event(
        tenant_id=tenant.id,
        occurred_at=body.occurred_at or datetime.now(UTC),
        event_name=body.event_name,
        actor_key=_actor_key(body.actor_external_id),
        anonymous_id=body.anonymous_id,
        session_id=body.session_id,
        link_token=body.link_token,
        listing_code=body.listing_code or (link.listing_code if link else None),
        source=body.source or (link.source if link else None),
        medium=body.medium or (link.medium if link else None),
        campaign=body.campaign or (link.campaign if link else None),
        content=body.content or (link.content if link else None),
        placement=body.placement or (link.placement if link else None),
        properties_json=body.properties,
        is_test=body.is_test,
    )
    session.add(row)
    session.commit()
    session.refresh(row)
    return {"ok": True, "event_id": row.id, "actor_key": row.actor_key}


@app.post("/v1/spend", dependencies=[Depends(require_key)])
def capture_spend(body: SpendIn, session: Session = Depends(db)):
    tenant = _tenant(session, body.tenant)
    row = Spend(
        tenant_id=tenant.id,
        source=body.source,
        medium=body.medium,
        campaign=body.campaign,
        placement=body.placement,
        period_start=body.period_start,
        period_end=body.period_end,
        amount=body.amount,
        currency=body.currency.upper(),
        impressions=body.impressions,
        clicks=body.clicks,
        metadata_json=body.metadata,
    )
    session.add(row)
    session.commit()
    return {"ok": True, "id": str(row.id)}


def _window(days: int):
    return datetime.now(UTC) - timedelta(days=days)


@app.get("/v1/metrics/funnel", dependencies=[Depends(require_key)])
def funnel_metrics(
    tenant: str = Query("lebleu"),
    days: int = Query(30, ge=1, le=3650),
    source: str | None = None,
    campaign: str | None = None,
    include_test: bool = False,
    session: Session = Depends(db),
):
    t = _tenant(session, tenant)
    conditions = [Event.tenant_id == t.id, Event.occurred_at >= _window(days)]
    if not include_test:
        conditions.append(Event.is_test.is_(False))
    if source:
        conditions.append(Event.source == source)
    if campaign:
        conditions.append(Event.campaign == campaign)
    rows = session.execute(
        select(Event.event_name, func.count(Event.id), func.count(func.distinct(Event.actor_key)))
        .where(*conditions)
        .group_by(Event.event_name)
    ).all()
    by_event = {name: {"events": int(count), "people": int(people)} for name, count, people in rows}
    steps = []
    first_people = by_event.get(FUNNEL[0], {}).get("people", 0)
    prev_people = None
    for name in FUNNEL:
        people = by_event.get(name, {}).get("people", 0)
        steps.append(
            {
                "event": name,
                "people": people,
                "from_start_pct": round((people / first_people * 100), 1) if first_people else None,
                "from_previous_pct": round((people / prev_people * 100), 1) if prev_people else None,
            }
        )
        prev_people = people
    return {"tenant": tenant, "days": days, "steps": steps, "events": by_event}


@app.get("/v1/metrics/acquisition", dependencies=[Depends(require_key)])
def acquisition_metrics(
    tenant: str = Query("lebleu"),
    days: int = Query(30, ge=1, le=3650),
    include_test: bool = False,
    session: Session = Depends(db),
):
    t = _tenant(session, tenant)
    since = _window(days)
    conditions = [Event.tenant_id == t.id, Event.occurred_at >= since]
    if not include_test:
        conditions.append(Event.is_test.is_(False))
    rows = session.execute(
        select(
            func.coalesce(Event.source, "unknown"),
            func.coalesce(Event.medium, "unknown"),
            func.coalesce(Event.campaign, "unknown"),
            func.count(func.distinct(Event.actor_key)),
            func.count(Event.id).filter(Event.event_name == "bot_started"),
            func.count(Event.id).filter(Event.event_name == "listing_opened"),
            func.count(Event.id).filter(Event.event_name == "search_submitted"),
            func.count(Event.id).filter(Event.event_name == "availability_requested"),
            func.count(Event.id).filter(Event.event_name == "viewing_requested"),
            func.count(Event.id).filter(Event.event_name == "lead_qualified"),
            func.count(Event.id).filter(Event.event_name == "deal_won"),
        )
        .where(*conditions)
        .group_by(Event.source, Event.medium, Event.campaign)
    ).all()

    spend_rows = session.execute(
        select(
            Spend.source,
            Spend.medium,
            Spend.campaign,
            Spend.currency,
            func.sum(Spend.amount),
            func.sum(Spend.impressions),
            func.sum(Spend.clicks),
        )
        .where(
            Spend.tenant_id == t.id,
            Spend.period_end >= since,
            Spend.period_start <= datetime.now(UTC),
        )
        .group_by(Spend.source, Spend.medium, Spend.campaign, Spend.currency)
    ).all()
    spend_map: dict[tuple[str, str, str], dict[str, Any]] = {}
    for source, medium, campaign, currency, amount, impressions, clicks in spend_rows:
        bucket = spend_map.setdefault(
            (source, medium, campaign),
            {"by_currency": {}, "impressions": 0, "clicks": 0},
        )
        bucket["by_currency"][currency] = float(amount or 0)
        bucket["impressions"] += int(impressions or 0)
        bucket["clicks"] += int(clicks or 0)

    event_map: dict[tuple[str, str, str], dict[str, int]] = {}
    for source, medium, campaign, people, starts, listings, searches, availability, viewings, leads, wins in rows:
        event_map[(source, medium, campaign)] = {
            "people": int(people),
            "bot_starts": int(starts),
            "listing_opened": int(listings),
            "search_submitted": int(searches),
            "availability_requested": int(availability),
            "viewing_requested": int(viewings),
            "lead_qualified": int(leads),
            "deal_won": int(wins),
        }

    # Include spend-only campaigns too. A campaign that spent money and produced zero
    # events is commercially important and must never disappear from reporting.
    out = []
    for source, medium, campaign in sorted(set(event_map) | set(spend_map)):
        metrics = event_map.get(
            (source, medium, campaign),
            {
                "people": 0,
                "bot_starts": 0,
                "listing_opened": 0,
                "search_submitted": 0,
                "availability_requested": 0,
                "viewing_requested": 0,
                "lead_qualified": 0,
                "deal_won": 0,
            },
        )
        spend = spend_map.get((source, medium, campaign), {"by_currency": {}, "impressions": 0, "clicks": 0})
        currencies = spend["by_currency"]
        unit_currency = next(iter(currencies)) if len(currencies) == 1 else None
        amount = currencies.get(unit_currency, 0.0) if unit_currency else None
        people = metrics["people"]
        leads = metrics["lead_qualified"]
        viewings = metrics["viewing_requested"]
        wins = metrics["deal_won"]
        clicks = int(spend["clicks"])
        out.append(
            {
                "source": source,
                "medium": medium,
                "campaign": campaign,
                **metrics,
                "spend": currencies,
                "impressions": int(spend["impressions"]),
                "clicks": clicks,
                "visitor_to_lead_pct": round(leads / people * 100, 1) if people else None,
                "lead_to_viewing_request_pct": round(viewings / leads * 100, 1) if leads else None,
                "lead_to_win_pct": round(wins / leads * 100, 1) if leads else None,
                "visitor_to_win_pct": round(wins / people * 100, 1) if people else None,
                "click_to_lead_pct": round(leads / clicks * 100, 1) if clicks else None,
                "cost_per_person": round(amount / people, 2) if amount is not None and people else None,
                "cost_per_lead": round(amount / leads, 2) if amount is not None and leads else None,
                "cost_per_viewing_request": round(amount / viewings, 2) if amount is not None and viewings else None,
                "cost_per_win": round(amount / wins, 2) if amount is not None and wins else None,
                "cost_currency": unit_currency,
            }
        )
    return {"tenant": tenant, "days": days, "channels": out}


@app.get("/dashboard", response_class=HTMLResponse, dependencies=[Depends(require_key)])
def dashboard(
    tenant: str = Query("lebleu"),
    days: int = Query(30, ge=1, le=3650),
    session: Session = Depends(db),
):
    data = acquisition_metrics(tenant=tenant, days=days, include_test=False, session=session)
    funnel = funnel_metrics(tenant=tenant, days=days, include_test=False, session=session)
    rows = "".join(
        "<tr>"
        + "".join(
            f"<td>{html.escape(str(x))}</td>"
            for x in [
                r["source"],
                r["medium"],
                r["campaign"],
                r["people"],
                r["bot_starts"],
                r["listing_opened"],
                r["search_submitted"],
                r["lead_qualified"],
                f'{r["visitor_to_lead_pct"]}%' if r["visitor_to_lead_pct"] is not None else "—",
                r["viewing_requested"],
                r["deal_won"],
                " · ".join(f"{currency} {amount:,.2f}" for currency, amount in r["spend"].items()) or "—",
                (
                    f"{r['cost_currency']} {r['cost_per_lead']:,.2f}"
                    if r["cost_currency"] and r["cost_per_lead"] is not None
                    else "—"
                ),
            ]
        )
        + "</tr>"
        for r in data["channels"]
    ) or '<tr><td colspan="13" class="empty">Пока нет production-событий. Это честный ноль, а не нарисованная аналитика.</td></tr>'
    steps = "".join(
        f'<div class="step"><b>{html.escape(s["event"])}</b><span>{s["people"]} чел.</span><small>{s["from_start_pct"] if s["from_start_pct"] is not None else "—"}% от старта</small></div>'
        for s in funnel["steps"]
    )
    return f"""<!doctype html>
<html>
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Growth Core · {html.escape(tenant)}</title>
<style>
body{{font-family:Inter,system-ui,sans-serif;background:#f4f5f7;color:#18191b;margin:0;padding:24px}}
main{{max-width:1120px;margin:auto}}
h1{{font-size:28px;margin:0 0 6px}}
.muted{{color:#6c727f;margin-bottom:24px}}
.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(140px,1fr));gap:10px;margin:18px 0}}
.step{{background:#fff;border:1px solid #e5e7eb;border-radius:14px;padding:14px;display:flex;flex-direction:column;gap:5px}}
.step span{{font-size:24px}}
.step small{{color:#6c727f}}
.card{{background:#fff;border:1px solid #e5e7eb;border-radius:16px;padding:16px;overflow:auto}}
table{{border-collapse:collapse;width:100%;font-size:14px}}
th,td{{padding:10px;border-bottom:1px solid #eee;text-align:left;white-space:nowrap}}
th{{color:#6c727f;font-weight:600}}
.empty{{text-align:center;color:#6c727f;padding:28px}}
</style>
</head>
<body>
<main>
<h1>Growth Core</h1>
<div class="muted">{html.escape(tenant)} · последние {days} дней · тестовые события исключены</div>
<div class="grid">{steps}</div>
<div class="card">
<table>
<thead><tr><th>Источник</th><th>Тип</th><th>Кампания</th><th>Люди</th><th>Bot start</th><th>Объекты</th><th>Поиск</th><th>Лиды</th><th>Lead %</th><th>Запросы просмотра</th><th>Сделки</th><th>Расход</th><th>CPL</th></tr></thead>
<tbody>{rows}</tbody>
</table>
</div>
</main>
</body>
</html>"""
