"""Telegram inbound: CRM capture plus admin-only controls and approval callbacks."""

from __future__ import annotations

import uuid
import time
import hashlib
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any
from urllib.parse import quote

import httpx
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.errors import StateTransitionError
from app.core.logging import get_logger
from app.models.comms import Conversation
from app.models.crm import Opportunity
from app.models.enums import Direction, MessageType
from app.models.outbound import Approval, Draft
from app.services import capture as capture_service
from app.services import contacts as contacts_service
from app.services import drafts as drafts_service
from app.services import jobs as jobs_service
from app.services import growth as growth_service
from app.services import workspaces as workspaces_service

logger = get_logger("channels.telegram")


@dataclass(slots=True)
class TelegramUpdate:
    kind: str
    update_id: int | None
    user_id: int | None
    chat_id: str | None
    chat_type: str | None
    message_id: str | None
    text: str | None = None
    voice_file_id: str | None = None
    voice_mime_type: str | None = None
    voice_duration: int | None = None
    document_file_id: str | None = None
    document_mime_type: str | None = None
    document_filename: str | None = None
    callback_data: str | None = None
    callback_id: str | None = None
    callback_message_id: str | None = None
    reply_to_message_id: str | None = None
    reply_to_text: str | None = None
    username: str | None = None
    display_name: str | None = None
    chat_display_name: str | None = None
    contact_phone: str | None = None
    business_connection_id: str | None = None
    timestamp: datetime | None = None
    raw: dict[str, Any] = field(default_factory=dict)

    @property
    def is_callback(self) -> bool:
        return self.kind == "callback_query"

    @property
    def is_private_chat(self) -> bool:
        return self.chat_type == "private"

    @property
    def is_business_message(self) -> bool:
        return self.kind in {"business_message", "edited_business_message"}


def parse_update(payload: dict[str, Any]) -> TelegramUpdate:
    """Flatten a Telegram Update into the handful of fields we care about."""
    if not isinstance(payload, dict):
        return TelegramUpdate(
            kind="unknown",
            update_id=None,
            user_id=None,
            chat_id=None,
            chat_type=None,
            message_id=None,
        )

    callback = payload.get("callback_query")
    if isinstance(callback, dict):
        sender = callback.get("from") or {}
        source_message = callback.get("message") or {}
        chat = source_message.get("chat") or {} if isinstance(source_message, dict) else {}
        return TelegramUpdate(
            kind="callback_query",
            update_id=payload.get("update_id"),
            user_id=sender.get("id") if isinstance(sender, dict) else None,
            chat_id=str(chat.get("id")) if chat.get("id") is not None else None,
            chat_type=chat.get("type") if isinstance(chat, dict) else None,
            message_id=None,
            callback_data=str(callback.get("data") or ""),
            callback_id=str(callback.get("id") or ""),
            callback_message_id=(
                str(source_message.get("message_id"))
                if isinstance(source_message, dict) and source_message.get("message_id")
                else None
            ),
            username=sender.get("username") if isinstance(sender, dict) else None,
            raw=payload,
        )

    kind = next(
        (
            candidate
            for candidate in (
                "message",
                "edited_message",
                "business_connection",
                "business_message",
                "edited_business_message",
                "deleted_business_messages",
            )
            if isinstance(payload.get(candidate), dict)
        ),
        "unknown",
    )
    if kind in {"business_connection", "deleted_business_messages"}:
        business = payload.get(kind) or {}
        return TelegramUpdate(
            kind=kind,
            update_id=payload.get("update_id"),
            user_id=None,
            chat_id=None,
            chat_type=None,
            message_id=None,
            business_connection_id=(
                str(business.get("id") or business.get("business_connection_id"))
                if business.get("id") or business.get("business_connection_id")
                else None
            ),
            raw=payload,
        )

    message = payload.get(kind) or {}
    if not isinstance(message, dict):
        return TelegramUpdate(
            kind="unknown",
            update_id=None,
            user_id=None,
            chat_id=None,
            chat_type=None,
            message_id=None,
        )

    sender = message.get("from") or {}
    chat = message.get("chat") or {}
    voice = message.get("voice") or message.get("audio") or {}
    document = message.get("document") or {}
    contact = message.get("contact") or {}
    reply_to = message.get("reply_to_message") or {}

    display_name = None
    if isinstance(sender, dict):
        display_name = " ".join(
            part for part in (sender.get("first_name"), sender.get("last_name")) if part
        ).strip() or sender.get("username")
    chat_display_name = " ".join(
        part for part in (chat.get("first_name"), chat.get("last_name")) if part
    ).strip() or chat.get("username")

    timestamp = None
    if message.get("date"):
        try:
            timestamp = datetime.fromtimestamp(int(message["date"]), tz=UTC)
        except (TypeError, ValueError):
            timestamp = None

    return TelegramUpdate(
        kind=kind,
        update_id=payload.get("update_id"),
        user_id=sender.get("id") if isinstance(sender, dict) else None,
        chat_id=str(chat.get("id")) if chat.get("id") is not None else None,
        chat_type=chat.get("type") if isinstance(chat, dict) else None,
        message_id=str(message.get("message_id")) if message.get("message_id") else None,
        text=message.get("text") or message.get("caption"),
        voice_file_id=voice.get("file_id") if isinstance(voice, dict) else None,
        voice_mime_type=(voice.get("mime_type") or "audio/ogg")
        if isinstance(voice, dict) and voice.get("file_id")
        else None,
        voice_duration=voice.get("duration") if isinstance(voice, dict) else None,
        document_file_id=document.get("file_id") if isinstance(document, dict) else None,
        document_mime_type=document.get("mime_type") if isinstance(document, dict) else None,
        document_filename=document.get("file_name") if isinstance(document, dict) else None,
        reply_to_text=reply_to.get("text") if isinstance(reply_to, dict) else None,
        reply_to_message_id=(
            str(reply_to.get("message_id"))
            if isinstance(reply_to, dict) and reply_to.get("message_id") is not None
            else None
        ),
        username=sender.get("username") if isinstance(sender, dict) else None,
        display_name=display_name,
        chat_display_name=chat_display_name,
        contact_phone=(contact.get("phone_number") if isinstance(contact, dict) else None),
        business_connection_id=(
            str(message.get("business_connection_id"))
            if message.get("business_connection_id") is not None
            else None
        ),
        timestamp=timestamp,
        raw=payload,
    )


def is_authorised(update: TelegramUpdate, allowed_ids: set[int]) -> bool:
    """An empty allow-list denies everyone.

    Failing closed matters: an unset `TELEGRAM_ALLOWED_USER_IDS` in production would
    otherwise turn the bot into an open write endpoint for anyone who finds it.
    """
    if not allowed_ids:
        return False
    return update.user_id is not None and update.user_id in allowed_ids


# --------------------------------------------------------------------- capture


def _lebleu_start_payload(text: str | None) -> str | None:
    if not text:
        return None
    parts = text.strip().split(maxsplit=1)
    if len(parts) != 2 or not parts[0].startswith("/start"):
        return None
    return parts[1].strip()[:80] or None


def _lebleu_start_code(text: str | None) -> str | None:
    payload = _lebleu_start_payload(text)
    if not payload or not payload.startswith("lb_"):
        return None
    return payload[3:] or None


def _growth_resolve_tracking(payload: str | None, settings: Any) -> dict[str, Any] | None:
    if not payload or not payload.startswith("trk_"):
        return None
    base = str(getattr(settings, "growth_core_url", "") or "").rstrip("/")
    key = str(getattr(settings, "growth_core_key", "") or "")
    if not base or not key:
        return None
    token = payload[4:]
    if not token:
        return None
    try:
        response = httpx.get(
            f"{base}/v1/links/{token}",
            params={"tenant": getattr(settings, "growth_core_tenant", "lebleu")},
            headers={"X-Growth-Key": key},
            timeout=3.0,
        )
        response.raise_for_status()
        data = response.json()
        if isinstance(data, dict):
            data["token"] = token
            return data
    except Exception as exc:
        logger.warning("growth_tracking_resolve_failed", error=str(exc)[:160])
    return None


def _growth_capture(
    settings: Any,
    update: TelegramUpdate,
    event_name: str,
    *,
    link_token: str | None = None,
    listing_code: str | None = None,
    properties: dict[str, Any] | None = None,
) -> None:
    growth_service.capture_event(
        settings,
        event_name=event_name,
        actor_external_id=update.user_id,
        link_token=link_token,
        listing_code=listing_code,
        properties=properties,
        occurred_at=update.timestamp,
        is_test=bool(update.user_id is not None and update.user_id in settings.allowed_telegram_ids),
    )


_LEBLEU_CATALOG_URL = "https://lebleu-preview.srv1636153.hstgr.cloud/data/full/catalog.json"
_lebleu_catalog_cache: dict[str, Any] = {"loaded_at": 0.0, "items": {}}


def _lebleu_listing(code: str) -> dict[str, Any]:
    # Keep the requested key immutable. A previous implementation reused the
    # function argument while indexing the fetched catalog, so a cold-cache lookup
    # could accidentally return the last listing in the catalog.
    lookup_key = str(code or "")
    now = time.monotonic()
    items = _lebleu_catalog_cache.get("items") or {}
    if not items or now - float(_lebleu_catalog_cache.get("loaded_at") or 0) > 300:
        try:
            response = httpx.get(_LEBLEU_CATALOG_URL, timeout=12.0)
            response.raise_for_status()
            data = response.json()
            items = {}
            for x in data:
                if not isinstance(x, dict):
                    continue
                item_code = str(x.get("code") or x.get("slug") or "")
                source_url = str(x.get("sourceUrl") or "")
                if item_code:
                    items[item_code] = x  # backwards compatibility for already-published links
                    if source_url:
                        token = f"{item_code}_{hashlib.sha256(source_url.encode()).hexdigest()[:8]}"
                        items[token] = x
            _lebleu_catalog_cache.update({"loaded_at": now, "items": items})
        except Exception as exc:
            logger.warning("lebleu_catalog_lookup_failed", error=str(exc)[:180])
    found = dict((items or {}).get(lookup_key) or {})
    if found:
        return found
    # A catalog-quality pass can suppress a stale duplicate URL while old tracked
    # links may still exist in shares/history. Property Intent Core owns the alias
    # map and resolves those legacy source-bound tokens to the canonical listing.
    try:
        response = httpx.get(
            f"http://property-intent-api:8080/v1/catalog/{quote(lookup_key, safe='')}",
            timeout=5.0,
        )
        if response.status_code == 200:
            data = response.json()
            if isinstance(data, dict):
                return data
    except Exception:
        pass
    return {}


def _lebleu_effective_type(item: dict[str, Any]) -> str:
    raw = str(item.get("propertyType") or item.get("property_type") or "").strip()
    if raw:
        return raw
    hay = " ".join(str(item.get(k) or "") for k in ("slug", "description", "sourceUrl", "source_url")).lower()
    if "finca" in hay:
        return "Finca"
    if "edificio en block" in hay or "edificio comercial" in hay:
        return "Edificio Comercial"
    if "galpón" in hay or "galpon" in hay:
        return "Galpón"
    if "campo" in hay:
        return "Campo"
    return ""


def _lebleu_price(item: dict[str, Any]) -> str:
    amount = item.get("priceAmount") if item.get("priceAmount") is not None else item.get("price_amount")
    currency_raw = item.get("priceCurrency") if item.get("priceCurrency") is not None else item.get("price_currency")
    operation = str(item.get("operation") or "")
    typ = _lebleu_effective_type(item)
    if not amount:
        return "цена по запросу"
    try:
        number = float(amount)
        if operation == "Venta" and str(currency_raw) == "USD" and 0 < number < 5000 and typ != "Cochera":
            return "цена требует уточнения"
        value = f"{number:,.0f}".replace(",", " ")
    except (TypeError, ValueError):
        value = str(amount)
    currency = "USD" if currency_raw == "USD" else str(currency_raw or "")
    return f"{currency} {value}".strip()


def _lebleu_listing_title(item: dict[str, Any], code: str) -> str:
    code_value = str(item.get("code") or "")
    op = {"Venta": "Продажа", "Alquiler": "Аренда", "Alquiler temporario": "Временная аренда"}.get(
        str(item.get("operation") or ""), "Объект"
    )
    if code_value == "LAP9861952" and str(item.get("operation") or "") == "Alquiler":
        op = "Аренда / временная аренда"
    raw_type = _lebleu_effective_type(item)
    typ = {
        "Departamento": "квартира", "Casa": "дом", "PH": "PH", "Terreno": "участок",
        "Terreno o Lote": "участок", "Local Comercial": "коммерческое помещение",
        "Edificio Comercial": "коммерческое здание", "Oficina": "офис", "Cochera": "парковка",
        "Finca": "финка / загородное владение", "Campo": "земельный участок / поле",
        "Galpón": "склад / производственное помещение",
    }.get(raw_type, (raw_type or "объект").lower())
    address = str(item.get("address") or "").strip()
    return f"{op} · {typ}" + (f"\n📍 {address}" if address else "") + f"\n💵 {_lebleu_price(item)}"


def _lebleu_conversation(
    session: Session, workspace_id: uuid.UUID, chat_id: str | None
) -> Conversation | None:
    if not chat_id:
        return None
    return session.scalar(
        select(Conversation).where(
            Conversation.workspace_id == workspace_id,
            Conversation.channel == "telegram",
            Conversation.external_thread_id == chat_id,
        )
    )


def _lebleu_active_opportunity(session: Session, workspace_id: uuid.UUID, chat_id: str | None) -> Opportunity | None:
    conversation = _lebleu_conversation(session, workspace_id, chat_id)
    if conversation is None or conversation.opportunity_id is None:
        return None
    opportunity = session.get(Opportunity, conversation.opportunity_id)
    if opportunity is None or opportunity.source != "lebleu_telegram":
        return None
    return opportunity


def _lebleu_create_listing_opportunity(
    session: Session,
    *,
    workspace_id: uuid.UUID,
    conversation: Conversation | None,
    contact_id: uuid.UUID | None,
    update: TelegramUpdate,
    code: str,
    item: dict[str, Any],
    tracking: dict[str, Any] | None = None,
    entry_action: str | None = None,
) -> Opportunity:
    extra = {
        "listing_code": str(item.get("code") or code),
        "listing_token": code,
        "listing": {
            "operation": item.get("operation"), "property_type": _lebleu_effective_type(item),
            "address": item.get("address"), "price_amount": item.get("priceAmount"),
            "price_currency": item.get("priceCurrency"), "source_url": item.get("sourceUrl"),
        },
        "qualification_status": "active",
        "qualification_step": "intent",
        "answers": {},
        "telegram_username": update.username,
        "telegram_user_id": update.user_id,
        "tracking_token": (tracking or {}).get("token"),
        "tracking_source": (tracking or {}).get("source"),
        "tracking_medium": (tracking or {}).get("medium"),
        "tracking_campaign": (tracking or {}).get("campaign"),
        "tracking_content": (tracking or {}).get("content"),
        "tracking_placement": (tracking or {}).get("placement"),
        "entry_action": entry_action,
    }
    opportunity = Opportunity(
        workspace_id=workspace_id,
        name=f"Le Bleu · {item.get('address') or code}",
        type="real_estate_lead",
        stage="qualifying",
        contact_id=contact_id,
        source="lebleu_telegram",
        summary_current=f"Лид из Telegram по объекту {item.get('address') or code}",
        next_action="Квалифицировать запрос",
        extra_json=extra,
    )
    session.add(opportunity)
    session.flush()
    if conversation is not None:
        conversation.opportunity_id = opportunity.id
    return opportunity


def _lebleu_new_opportunity(
    session: Session,
    *,
    workspace_id: uuid.UUID,
    result: Any,
    update: TelegramUpdate,
    code: str,
    item: dict[str, Any],
    tracking: dict[str, Any] | None = None,
) -> Opportunity:
    conversation = session.get(Conversation, result.conversation_id)
    return _lebleu_create_listing_opportunity(
        session,
        workspace_id=workspace_id,
        conversation=conversation,
        contact_id=result.contact_id,
        update=update,
        code=code,
        item=item,
        tracking=tracking,
    )


def _lebleu_new_catalog_search_opportunity(
    session: Session,
    *,
    workspace_id: uuid.UUID,
    result: Any,
    update: TelegramUpdate,
    tracking: dict[str, Any] | None = None,
) -> Opportunity:
    conversation = session.get(Conversation, result.conversation_id)
    extra = {
        "request_kind": "catalog_no_match",
        "qualification_status": "active",
        "qualification_step": "notes",
        "answers": {},
        "telegram_username": update.username,
        "telegram_user_id": update.user_id,
        "tracking_token": (tracking or {}).get("token"),
        "tracking_source": (tracking or {}).get("source"),
        "tracking_medium": (tracking or {}).get("medium"),
        "tracking_campaign": (tracking or {}).get("campaign"),
        "tracking_content": (tracking or {}).get("content"),
        "tracking_placement": (tracking or {}).get("placement"),
    }
    opportunity = Opportunity(
        workspace_id=workspace_id,
        name="Le Bleu · подбор вне каталога",
        type="real_estate_lead",
        stage="qualifying",
        contact_id=result.contact_id,
        source="lebleu_telegram",
        summary_current="Клиент не нашёл подходящий объект в каталоге Le Bleu",
        next_action="Получить критерии поиска клиента",
        extra_json=extra,
    )
    session.add(opportunity)
    session.flush()
    if conversation is not None:
        conversation.opportunity_id = opportunity.id
    return opportunity


_LEBLEU_ENTRY_ACTIONS = {
    "a": "availability",
    "v": "view",
    "q": "question",
    "g": "gallery",
    "s": "similar",
}


def _lebleu_entry_callback(action: str, listing_token: str, tracking_token: str | None = None) -> str:
    reverse = {value: key for key, value in _LEBLEU_ENTRY_ACTIONS.items()}
    short = reverse[action]
    payload = f"lbi:{short}:{listing_token}"
    if tracking_token:
        payload += f":{tracking_token}"
    # Telegram callback_data is capped at 64 bytes. Our listing/tracking tokens are
    # intentionally compact, but fail closed rather than emitting an unusable button.
    if len(payload.encode("utf-8")) > 64:
        raise ValueError("Le Bleu callback payload exceeds Telegram 64-byte limit")
    return payload


def _lebleu_parse_entry_callback(data: str) -> tuple[str, str, str | None] | None:
    if not data.startswith("lbi:"):
        return None
    parts = data.split(":", 3)
    if len(parts) < 3:
        return None
    action = _LEBLEU_ENTRY_ACTIONS.get(parts[1])
    listing_token = parts[2].strip()
    tracking_token = parts[3].strip() if len(parts) == 4 and parts[3].strip() else None
    if not action or not listing_token:
        return None
    return action, listing_token, tracking_token


def _lebleu_send(providers: Any, chat_id: str, text: str, rows: list[list[tuple[str, str]]] | None = None) -> None:
    markup = None
    if rows:
        markup = {"inline_keyboard": [[{"text": text_, "callback_data": data} for text_, data in row] for row in rows]}
    providers.telegram.send_text(chat_id, text, reply_markup=markup)


def _lebleu_notify_operator(providers: Any, settings: Any, update: TelegramUpdate, text: str, item: dict[str, Any] | None = None) -> bool:
    approval_chat = str(getattr(settings, "telegram_approval_chat_id", "") or "").strip()
    if not approval_chat or approval_chat == str(update.chat_id or ""):
        return False
    buttons: list[list[dict[str, str]]] = []
    user_url = f"https://t.me/{update.username}" if update.username else (f"tg://user?id={update.user_id}" if update.user_id else "")
    if user_url:
        buttons.append([{"text": "✉️ Открыть клиента", "url": user_url}])
    source_url = str((item or {}).get("source_url") or (item or {}).get("sourceUrl") or "").strip()
    if source_url:
        buttons.append([{"text": "🏠 Открыть объект Le Bleu", "url": source_url}])
    markup = {"inline_keyboard": buttons} if buttons else None
    try:
        internal_text = "🔒 ВНУТРЕННЕЕ · видно только вам\n\n" + text
        internal_sender = providers.telegram
        # Dedicated Le Bleu bot is client-facing only. Operator/CRM alerts stay in the
        # CRM control bot so roles never bleed back together.
        if (
            getattr(settings, "lebleu_telegram_bot_token", "")
            and getattr(providers.telegram, "bot_token", None) == getattr(settings, "lebleu_telegram_bot_token", "")
            and getattr(settings, "telegram_bot_token", "")
        ):
            from app.providers.messaging import TelegramBotSender
            internal_sender = TelegramBotSender(bot_token=settings.telegram_bot_token)
        internal_sender.send_text(approval_chat, internal_text, reply_markup=markup)
        return True
    except Exception as exc:
        logger.warning("lebleu_telegram_router_failed", error=str(exc)[:180])
        return False


def _lebleu_update_answer(opportunity: Opportunity, key: str, value: str, step: str) -> None:
    extra = dict(opportunity.extra_json or {})
    answers = dict(extra.get("answers") or {})
    answers[key] = value
    extra["answers"] = answers
    extra["qualification_step"] = step
    opportunity.extra_json = extra


def _growth_capture_opportunity(
    settings: Any,
    update: TelegramUpdate,
    opportunity: Opportunity,
    event_name: str,
    *,
    properties: dict[str, Any] | None = None,
) -> None:
    extra = dict(opportunity.extra_json or {})
    _growth_capture(
        settings,
        update,
        event_name,
        link_token=str(extra.get("tracking_token") or "") or None,
        listing_code=str(extra.get("listing_token") or extra.get("listing_code") or "") or None,
        properties=properties,
    )


def _lebleu_human(value: str) -> str:
    return {
        "view": "хочет посмотреть объект", "availability": "проверить актуальность",
        "question": "задал вопрос по объекту", "similar": "подобрать похожие",
        "terms": "уточнить условия",
        "week": "в течение недели", "month": "в течение месяца", "later": "пока изучает",
        "fit": "бюджет подходит", "lower": "нужен дешевле", "higher": "может рассмотреть выше",
        "short": "до 3 месяцев", "mid": "3–12 месяцев", "long": "12+ месяцев",
    }.get(value, value)


def _lebleu_finalize_catalog_search(
    session: Session,
    opportunity: Opportunity,
    update: TelegramUpdate,
    providers: Any,
    settings: Any,
) -> None:
    extra = dict(opportunity.extra_json or {})
    if extra.get("qualification_status") == "completed":
        return
    answers = dict(extra.get("answers") or {})
    note = str(answers.get("note") or "").strip()
    extra.update({
        "qualification_status": "completed",
        "qualification_step": "done",
        "lead_score": 60,
        "temperature": "WARM",
        "qualified_at": datetime.now(UTC).isoformat(),
        "router": "telegram_operator",
    })
    opportunity.extra_json = extra
    opportunity.stage = "qualifying"
    opportunity.probability = 60
    opportunity.next_action = "Подобрать варианты по запросу клиента и ответить в Telegram"
    who = f"@{update.username}" if update.username else (update.display_name or str(update.user_id or ""))
    summary = "\n".join([
        "🏠 LEAD LE BLEU · НЕ НАШЁЛ ПОДХОДЯЩЕЕ В КАТАЛОГЕ",
        f"Клиент: {who}",
        f"Запрос: {note or 'не указан'}",
        f"CRM opportunity: {opportunity.id}",
        "",
        "Следующий шаг: подобрать релевантные варианты и ответить клиенту в Telegram.",
    ])
    opportunity.summary_current = summary
    session.flush()
    if update.chat_id:
        providers.telegram.send_text(
            update.chat_id,
            "Спасибо, запрос получили. Подберём подходящие варианты и вернёмся с ответом здесь.",
        )
    telegram_routed = _lebleu_notify_operator(providers, settings, update, summary)
    extra = dict(opportunity.extra_json or {})
    extra["routed_internal"] = telegram_routed
    extra["routed_telegram"] = telegram_routed
    opportunity.extra_json = extra
    _growth_capture_opportunity(
        settings,
        update,
        opportunity,
        "lead_qualified",
        properties={"lead_kind": "catalog_search", "temperature": "WARM"},
    )


def _lebleu_finalize(session: Session, opportunity: Opportunity, update: TelegramUpdate, providers: Any, settings: Any) -> None:
    extra = dict(opportunity.extra_json or {})
    if extra.get("qualification_status") == "completed":
        return
    answers = dict(extra.get("answers") or {})
    intent, timing = answers.get("intent", ""), answers.get("timing", "")

    score = 20
    score += {"view": 60, "availability": 45, "question": 35, "similar": 25, "terms": 30}.get(intent, 0)
    score += {"week": 15, "month": 10, "later": 3}.get(timing, 0)
    if answers.get("note"):
        score += 5
    if answers.get("contact_method") == "whatsapp" and answers.get("phone"):
        score += 5
    score = min(score, 100)
    temperature = "HOT" if score >= 75 else "WARM" if score >= 50 else "EARLY"

    extra.update({
        "qualification_status": "completed",
        "qualification_step": "done",
        "lead_score": score,
        "temperature": temperature,
        "qualified_at": datetime.now(UTC).isoformat(),
        "router": "fiodor_whatsapp",
    })
    opportunity.extra_json = extra
    opportunity.stage = "qualifying"
    opportunity.probability = score
    opportunity.next_action = "Проверить актуальность объекта и передать ответственному агенту Le Bleu"
    item = extra.get("listing") or {}

    who = f"@{update.username}" if update.username else (update.display_name or str(update.user_id or ""))
    contact_method = "WhatsApp" if answers.get("contact_method") == "whatsapp" else "Telegram"
    internal_lines = [
        f"🏠 LEAD LE BLEU · {temperature} · score {score}",
        f"Объект: {item.get('address') or 'без адреса'}",
        f"Тип: {item.get('operation') or ''} · {item.get('property_type') or ''}",
        f"Цена: {_lebleu_price({'priceAmount': item.get('price_amount'), 'priceCurrency': item.get('price_currency')})}",
        f"Запрос: {_lebleu_human(str(answers.get('intent') or ''))}",
        f"Срок: {_lebleu_human(str(answers.get('timing') or ''))}",
    ]
    if answers.get("budget"):
        internal_lines.append(f"Бюджет: {_lebleu_human(str(answers['budget']))}")
    if answers.get("stay"):
        internal_lines.append(f"Срок аренды: {_lebleu_human(str(answers['stay']))}")
    internal_lines.append(f"Связь: {contact_method}")
    if answers.get("phone"):
        internal_lines.append(f"Телефон клиента: {answers['phone']}")
    internal_lines.append(f"Telegram клиента: {who}")
    if answers.get("note"):
        internal_lines.append(f"Комментарий: {answers['note']}")
    internal_lines.extend([
        f"Ref. внутренняя: {extra.get('listing_code')}",
        f"CRM opportunity: {opportunity.id}",
        "",
        "Следующий шаг: проверить актуальность объекта и определить ответственного агента.",
    ])
    summary = "\n".join(internal_lines)
    opportunity.summary_current = summary

    # Validate/persist CRM state before any external notification. This prevents
    # Telegram retries from duplicating client confirmations if the DB rejects a write.
    session.flush()

    if update.chat_id:
        if contact_method == "WhatsApp" and answers.get("phone"):
            confirmation = "Спасибо! Запрос у нас. Сейчас проверим актуальность и детали объекта и напишем вам в WhatsApp по указанному номеру. Если хотите что-то добавить, можете написать и сюда."
        else:
            confirmation = "Спасибо! Запрос у нас. Сейчас проверим актуальность и детали объекта и вернёмся с ответом прямо в этот чат. Если хотите что-то добавить, просто напишите сюда."
        providers.telegram.send_text(update.chat_id, confirmation, reply_markup={"remove_keyboard": True})

    # Primary internal router: Fiodor's configured WhatsApp test-recipient.
    routed = False
    router = str(getattr(settings, "whatsapp_test_recipient", "") or "").strip()
    if router:
        intent_es = {
            "view": "quiere visitar", "availability": "quiere confirmar disponibilidad",
            "question": "tiene una consulta sobre la propiedad", "terms": "quiere consultar condiciones",
            "similar": "quiere opciones similares",
        }.get(intent, intent)
        timing_es = {"week": "esta semana", "month": "este mes", "later": "está explorando"}.get(timing, timing)
        agent_forward = [
            f"Hola, tengo un lead interesado en {item.get('address') or 'este inmueble'}.",
            f"Interés: {intent_es}. Plazo: {timing_es}.",
        ]
        if answers.get("budget"):
            agent_forward.append(f"Presupuesto: {_lebleu_human(str(answers['budget']))}.")
        if answers.get("phone"):
            agent_forward.append(f"Contacto cliente: {answers['phone']}.")
        elif update.username:
            agent_forward.append(f"Telegram cliente: @{update.username}.")
        agent_forward.append("¿Te corresponde esta propiedad? Si sí, te paso el contexto completo y coordinamos el seguimiento.")
        forward = summary + "\n\nPARA REENVIAR AL AGENTE:\n" + " ".join(agent_forward)
        try:
            providers.whatsapp.send_text(router, forward)
            routed = True
        except Exception as exc:
            logger.warning("lebleu_whatsapp_router_failed", error=str(exc)[:180])

    # Telegram operator alert is always sent. WhatsApp is an additional route, not a substitute.
    telegram_routed = _lebleu_notify_operator(providers, settings, update, summary, item)
    routed = routed or telegram_routed
    extra = dict(opportunity.extra_json or {})
    extra["routed_internal"] = routed
    extra["routed_telegram"] = telegram_routed
    opportunity.extra_json = extra
    _growth_capture_opportunity(
        settings,
        update,
        opportunity,
        "lead_qualified",
        properties={"intent": intent, "temperature": temperature, "score": score},
    )


def _lebleu_callback_expected(field: str) -> set[str]:
    return {
        "intent": {"intent"},
        "timing": {"timing"},
        "budget": {"budget_or_stay"},
        "stay": {"budget_or_stay"},
        "contact": {"contact"},
        "finish": {"notes"},
    }.get(field, set())


def handle_lebleu_callback(
    session: Session,
    update: TelegramUpdate,
    *,
    workspace_id: uuid.UUID,
    providers: Any,
    settings: Any,
) -> dict[str, Any]:
    data = update.callback_data or ""
    entry = _lebleu_parse_entry_callback(data)
    opportunity: Opportunity | None = None

    if entry is not None:
        entry_action, listing_token, tracking_token = entry
        item = _lebleu_listing(listing_token)

        if entry_action == "gallery":
            _growth_capture(
                settings,
                update,
                "gallery_opened",
                link_token=tracking_token,
                listing_code=listing_token,
            )
            try:
                providers.telegram.answer_callback(update.callback_id or "", "Отправляю фотографии")
            except Exception:
                pass
            photos = [str(x) for x in (item.get("imageUrls") or []) if x]
            if not photos:
                if update.chat_id:
                    providers.telegram.send_text(update.chat_id, "Для этого объекта фотографии сейчас недоступны.")
                return {"handled": True, "action": "gallery_empty"}
            if update.chat_id:
                providers.telegram.send_text(update.chat_id, f"Фото объекта · {len(photos)} шт.")
                for start in range(0, len(photos), 10):
                    providers.telegram.send_media_group(update.chat_id, photos[start:start + 10])
                    time.sleep(0.35)
            return {"handled": True, "action": "gallery"}

        conversation = _lebleu_conversation(session, workspace_id, update.chat_id)
        if conversation is None:
            providers.telegram.answer_callback(update.callback_id or "", "Запрос устарел. Откройте объект заново.")
            return {"handled": False, "reason": "no_conversation"}

        existing = _lebleu_active_opportunity(session, workspace_id, update.chat_id)
        if existing is not None:
            existing_extra = dict(existing.extra_json or {})
            same_listing = str(existing_extra.get("listing_token") or "") == listing_token
            if same_listing and existing_extra.get("qualification_status") == "completed":
                providers.telegram.answer_callback(update.callback_id or "", "Заявка уже принята")
                return {"handled": True, "action": "already_completed", "opportunity_id": str(existing.id)}
            existing_intent = str((existing_extra.get("answers") or {}).get("intent") or "")
            if same_listing and existing_intent == entry_action:
                providers.telegram.answer_callback(update.callback_id or "", "Уже принято")
                return {"handled": True, "action": "already_started", "opportunity_id": str(existing.id)}

        tracking = _growth_resolve_tracking(f"trk_{tracking_token}", settings) if tracking_token else None
        opportunity = _lebleu_create_listing_opportunity(
            session,
            workspace_id=workspace_id,
            conversation=conversation,
            contact_id=conversation.contact_id,
            update=update,
            code=listing_token,
            item=item,
            tracking=tracking,
            entry_action=entry_action,
        )
        data = f"lbq:intent:{entry_action}"
    elif data.startswith("lbq:"):
        opportunity = _lebleu_active_opportunity(session, workspace_id, update.chat_id)
        if opportunity is None:
            providers.telegram.answer_callback(update.callback_id or "", "Запрос устарел. Откройте объект заново.")
            return {"handled": False, "reason": "no_active_opportunity"}
    else:
        return {"handled": False, "reason": "not_lebleu"}

    _, field, value = (data.split(":", 2) + ["", ""])[:3]
    extra = dict(opportunity.extra_json or {})
    step = str(extra.get("qualification_step") or "")

    if field == "gallery":
        _growth_capture_opportunity(settings, update, opportunity, "gallery_opened")
        try:
            providers.telegram.answer_callback(update.callback_id or "", "Отправляю фотографии")
        except Exception:
            pass
        token = str(extra.get("listing_token") or extra.get("listing_code") or "")
        item = _lebleu_listing(token)
        photos = [str(x) for x in (item.get("imageUrls") or []) if x]
        if not photos:
            if update.chat_id:
                providers.telegram.send_text(update.chat_id, "Для этого объекта фотографии сейчас недоступны.")
            return {"handled": True, "action": "gallery_empty", "opportunity_id": str(opportunity.id)}
        if update.chat_id:
            providers.telegram.send_text(update.chat_id, f"Фото объекта · {len(photos)} шт.")
            for start in range(0, len(photos), 10):
                providers.telegram.send_media_group(update.chat_id, photos[start:start + 10])
                time.sleep(0.35)
        return {"handled": True, "action": "gallery", "opportunity_id": str(opportunity.id)}

    if extra.get("qualification_status") == "completed":
        providers.telegram.answer_callback(update.callback_id or "", "Заявка уже принята")
        return {"handled": True, "action": "already_completed", "opportunity_id": str(opportunity.id)}
    expected = _lebleu_callback_expected(field)
    if expected and step not in expected:
        providers.telegram.answer_callback(update.callback_id or "", "Этот шаг уже заполнен")
        return {"handled": True, "action": "stale_callback", "opportunity_id": str(opportunity.id)}

    try:
        providers.telegram.answer_callback(update.callback_id or "", "Принято")
        if update.callback_message_id and update.chat_id:
            providers.telegram.clear_inline_keyboard(update.chat_id, update.callback_message_id)
    except Exception as exc:
        logger.warning("lebleu_clear_keyboard_failed", error=str(exc)[:120])

    chat_id = update.chat_id or ""
    if field == "intent":
        if value == "view":
            _growth_capture_opportunity(settings, update, opportunity, "viewing_requested")
            _lebleu_update_answer(opportunity, "intent", value, "timing")
            _lebleu_send(providers, chat_id, "Когда вам удобнее организовать просмотр?", [[("Сегодня / завтра", "lbq:timing:week"), ("В течение недели", "lbq:timing:month")], [("Позже", "lbq:timing:later")]])
        elif value == "availability":
            _growth_capture_opportunity(settings, update, opportunity, "availability_requested")
            _lebleu_update_answer(opportunity, "intent", value, "done")
            _lebleu_update_answer(opportunity, "contact_method", "telegram", "done")
            _lebleu_finalize(session, opportunity, update, providers, settings)
        elif value in {"question", "similar"}:
            if value == "similar":
                _growth_capture_opportunity(settings, update, opportunity, "search_started")
            _lebleu_update_answer(opportunity, "intent", value, "notes")
            prompt = "Напишите ваш вопрос по объекту одним сообщением." if value == "question" else "Напишите одним сообщением, что важно в похожем варианте: район, бюджет и ключевые требования."
            providers.telegram.send_text(chat_id, prompt)
        else:
            return {"handled": False, "reason": "unknown_lebleu_intent"}
    elif field == "timing":
        _lebleu_update_answer(opportunity, "timing", value, "done")
        _lebleu_update_answer(opportunity, "contact_method", "telegram", "done")
        _lebleu_finalize(session, opportunity, update, providers, settings)
    elif field in {"budget", "stay"}:
        # Backward compatibility for old conversations created before the simplified funnel.
        _lebleu_update_answer(opportunity, field, value, "contact")
        _lebleu_send(providers, chat_id, "Где вам удобнее получить ответ?", [[("Telegram", "lbq:contact:telegram"), ("WhatsApp", "lbq:contact:whatsapp")]])
    elif field == "contact":
        _lebleu_update_answer(opportunity, "contact_method", value, "phone" if value == "whatsapp" else "done")
        if value == "whatsapp":
            providers.telegram.send_text(
                chat_id,
                "Отправьте номер одной кнопкой. Он будет использован только для ответа по вашему запросу.",
                reply_markup={
                    "keyboard": [[{"text": "Поделиться номером", "request_contact": True}], [{"text": "Остаться в Telegram"}]],
                    "resize_keyboard": True, "one_time_keyboard": True,
                },
            )
        else:
            _lebleu_finalize(session, opportunity, update, providers, settings)
    elif field == "finish":
        _lebleu_finalize(session, opportunity, update, providers, settings)
    else:
        return {"handled": False, "reason": "unknown_lebleu_action"}
    session.flush()
    return {"handled": True, "action": field, "opportunity_id": str(opportunity.id)}

def handle_message(
    session: Session,
    update: TelegramUpdate,
    *,
    workspace_id: uuid.UUID,
    settings: Any,
    providers: Any,
    is_client: bool = False,
) -> dict[str, Any]:
    """Store a Telegram text or voice message from Fiodor."""
    media = None
    message_type = MessageType.text

    file_id = update.voice_file_id or update.document_file_id
    if file_id:
        mime = (
            update.voice_mime_type
            if update.voice_file_id
            else (update.document_mime_type or "application/octet-stream")
        )
        message_type = MessageType.voice if update.voice_file_id else MessageType.document
        try:
            data = providers.telegram.get_file_bytes(file_id)
            media = capture_service.MediaInput(
                data=data,
                mime_type=mime,
                filename=update.document_filename or f"{file_id}.ogg",
            )
        except Exception as exc:
            logger.warning("telegram_file_download_failed", error=str(exc)[:200])
            media = None

    if not update.text and media is None and not update.contact_phone:
        return {"ignored": True, "reason": "no text or media"}

    stored_text = update.text or (f"[shared contact] {update.contact_phone}" if update.contact_phone else None)
    lebleu_payload = _lebleu_start_payload(update.text)
    tracking = _growth_resolve_tracking(lebleu_payload, settings)
    lebleu_code = (
        str(tracking.get("listing_code") or "").strip()
        if tracking
        else (_lebleu_start_code(update.text) or "")
    ) or None
    catalog_help = bool(
        (tracking and tracking.get("intent") == "catalog_help")
        or (not tracking and lebleu_payload == "catalog_help")
    )
    fiodor_meta: dict[str, Any] = {"telegram_client": is_client}
    if tracking:
        fiodor_meta["growth_tracking"] = {
            k: tracking.get(k)
            for k in ("token", "source", "medium", "campaign", "content", "placement", "intent")
            if tracking.get(k) is not None
        }
    if lebleu_code:
        fiodor_meta.update({"source": "lebleu_telegram", "listing_code": lebleu_code})
    elif catalog_help:
        fiodor_meta.update({"source": "lebleu_telegram", "request_kind": "catalog_no_match"})
    raw_payload = {**update.raw, "_fiodor": fiodor_meta}
    result = capture_service.capture_message(
        session,
        workspace_id=workspace_id,
        channel="telegram",
        external_thread_id=update.chat_id or str(update.user_id),
        sender_identity=str(update.user_id),
        sender_display_name=update.display_name or update.username,
        message_type=message_type,
        external_message_id=(
            f"telegram:{update.chat_id}:{update.message_id}"
            if update.chat_id and update.message_id
            else update.message_id
        ),
        content_text=stored_text,
        raw_payload=raw_payload,
        sent_at=update.timestamp,
        media=media,
        settings=settings,
        storage=providers.storage,
        actor="telegram_webhook",
    )

    dedicated_lebleu_sender = bool(
        getattr(settings, "lebleu_telegram_bot_token", "")
        and getattr(providers.telegram, "bot_token", None) == getattr(settings, "lebleu_telegram_bot_token", "")
    )
    if result.created and result.transcript is None and update.text:
        jobs_service.enqueue(
            session,
            workspace_id=workspace_id,
            job_type="process_message",
            # Le Bleu has its own qualification funnel and operator cards. Do not turn
            # every public-funnel message into a personal CRM reply draft.
            payload={"message_id": str(result.message.id), "auto_draft": is_client and not dedicated_lebleu_sender},
            dedupe_key=f"process_message:{result.message.id}",
        )

    if result.created and tracking:
        tracking_token = str(tracking.get("token") or "") or None
        _growth_capture(
            settings,
            update,
            "bot_started",
            link_token=tracking_token,
            listing_code=lebleu_code,
            properties={"intent": tracking.get("intent")},
        )
        if tracking.get("source") == "saved_search" or tracking.get("campaign") == "reactivation":
            _growth_capture(
                settings,
                update,
                "notification_clicked",
                link_token=tracking_token,
                listing_code=lebleu_code,
            )
        if lebleu_code:
            _growth_capture(
                settings,
                update,
                "listing_opened",
                link_token=tracking_token,
                listing_code=lebleu_code,
            )
        elif catalog_help:
            _growth_capture(
                settings,
                update,
                "search_started",
                link_token=tracking_token,
            )

    if result.created and catalog_help and update.chat_id:
        try:
            opportunity = _lebleu_new_catalog_search_opportunity(
                session, workspace_id=workspace_id, result=result, update=update, tracking=tracking
            )
            providers.telegram.send_text(
                update.chat_id,
                "Не нашли подходящий объект? Напишите одним сообщением, что ищете: "
                "покупка или аренда, район, тип/количество комнат, бюджет и что для вас важно.",
            )
            _lebleu_notify_operator(
                providers,
                settings,
                update,
                "\n".join([
                    "🆕 LEAD LE BLEU · не нашёл подходящее в каталоге",
                    f"Клиент: @{update.username}" if update.username else f"Клиент: {update.display_name or update.user_id}",
                    f"CRM opportunity: {opportunity.id}",
                    "Статус: ждём критерии поиска одним сообщением.",
                ]),
            )
        except Exception as exc:
            logger.warning("telegram_lebleu_catalog_help_failed", error=str(exc)[:200])
    elif result.created and lebleu_code and update.chat_id:
        try:
            item = _lebleu_listing(lebleu_code)
            tracking_token = str((tracking or {}).get("token") or "") or None
            raw_code = str(item.get("code") or lebleu_code.split("_", 1)[0])
            miniapp_url = f"https://lebleu-app.srv1636153.hstgr.cloud/?v=20261001c&listing={quote(raw_code)}"
            if tracking_token:
                miniapp_url += f"&trk={quote(tracking_token)}"
            providers.telegram.send_text(
                update.chat_id,
                "Здравствуйте! Вы выбрали объект Le Bleu:\n\n"
                + _lebleu_listing_title(item, lebleu_code)
                + "\n\nЧто хотите сделать?",
                reply_markup={"inline_keyboard": [
                    [{"text": "Открыть карточку и все фото", "web_app": {"url": miniapp_url}}],
                    [
                        {"text": "✅ Актуальность", "callback_data": _lebleu_entry_callback("availability", lebleu_code, tracking_token)},
                        {"text": "📅 Просмотр", "callback_data": _lebleu_entry_callback("view", lebleu_code, tracking_token)},
                    ],
                    [
                        {"text": "❓ Вопрос", "callback_data": _lebleu_entry_callback("question", lebleu_code, tracking_token)},
                        {"text": f"📷 {len(item.get('imageUrls') or [])} фото", "callback_data": _lebleu_entry_callback("gallery", lebleu_code, tracking_token)},
                    ],
                    [{"text": "🔎 Похожие", "callback_data": _lebleu_entry_callback("similar", lebleu_code, tracking_token)}],
                ]},
            )
            # Deliberately no CRM Opportunity or operator alert here. Opening a card is
            # engagement. A sales Opportunity is created only after an explicit action.
        except Exception as exc:
            logger.warning("telegram_lebleu_welcome_failed", error=str(exc)[:200])
    elif result.created and update.text and update.text.strip().startswith("/start") and update.chat_id:
        try:
            miniapp_url = "https://lebleu-app.srv1636153.hstgr.cloud/?v=20261001c"
            if tracking and tracking.get("token"):
                miniapp_url += f"&trk={tracking['token']}"
            acquisition_entry = bool(tracking and tracking.get("intent") == "miniapp")
            welcome_text = (
                "Le Bleu · недвижимость в Буэнос-Айресе на русском.\n\n"
                "Ищите по району, бюджету и комнатам, смотрите фотографии объектов. "
                "Если подходящего варианта сейчас нет, сохраните поиск и при желании включите уведомления."
                if acquisition_entry
                else
                "Здравствуйте! Это бот Le Bleu.\n\n"
                "Можно открыть поиск по актуальным объектам, настроить фильтры и сохранить критерии. "
                "Если подходящий вариант появится позже, уведомления включаются отдельно по вашему желанию."
            )
            welcome_buttons = (
                [[{"text": "Открыть каталог", "web_app": {"url": miniapp_url}}]]
                if acquisition_entry
                else [
                    [{"text": "Найти объект", "web_app": {"url": miniapp_url}}],
                    [
                        {"text": "Каталог в Telegram", "url": "https://t.me/lebleu_argentina_ru"},
                        {"text": "Сайт Le Bleu", "url": "https://www.lebleu.com.ar/"},
                    ],
                ]
            )
            providers.telegram.send_text(
                update.chat_id,
                welcome_text,
                reply_markup={"inline_keyboard": welcome_buttons},
            )
        except Exception as exc:
            logger.warning("telegram_start_welcome_failed", error=str(exc)[:200])
    elif result.created and update.chat_id:
        opportunity = _lebleu_active_opportunity(session, workspace_id, update.chat_id)
        if opportunity is not None:
            step = (opportunity.extra_json or {}).get("qualification_step")
            if step == "phone":
                if update.contact_phone:
                    _lebleu_update_answer(opportunity, "phone", update.contact_phone, "done")
                    _lebleu_finalize(session, opportunity, update, providers, settings)
                elif update.text and update.text.strip().lower() == "остаться в telegram":
                    _lebleu_update_answer(opportunity, "contact_method", "telegram", "done")
                    _lebleu_finalize(session, opportunity, update, providers, settings)
                elif update.text:
                    digits = "".join(ch for ch in update.text if ch.isdigit())
                    if len(digits) >= 8:
                        _lebleu_update_answer(opportunity, "phone", update.text.strip()[:80], "done")
                        _lebleu_finalize(session, opportunity, update, providers, settings)
                    else:
                        providers.telegram.send_text(update.chat_id, "Нажмите «Поделиться номером WhatsApp» или выберите «Остаться в Telegram».")
            elif step == "notes" and update.text and not update.text.startswith("/"):
                _lebleu_update_answer(opportunity, "note", update.text.strip()[:800], "done")
                current_extra = dict(opportunity.extra_json or {})
                if current_extra.get("request_kind") == "catalog_no_match":
                    _growth_capture_opportunity(settings, update, opportunity, "search_submitted")
                    _lebleu_finalize_catalog_search(session, opportunity, update, providers, settings)
                else:
                    intent = str((current_extra.get("answers") or {}).get("intent") or "")
                    if intent == "similar":
                        _growth_capture_opportunity(settings, update, opportunity, "search_submitted")
                    elif intent == "question":
                        _growth_capture_opportunity(settings, update, opportunity, "question_submitted")
                    _lebleu_finalize(session, opportunity, update, providers, settings)

    return {
        "message_id": str(result.message.id),
        "conversation_id": str(result.conversation_id),
        "transcript_id": str(result.transcript.id) if result.transcript else None,
        "duplicate": result.duplicate,
        "ignored": False,
    }


def handle_business_message(
    session: Session,
    update: TelegramUpdate,
    *,
    workspace_id: uuid.UUID,
    settings: Any,
    providers: Any,
) -> dict[str, Any]:
    """Capture one verified Telegram Chat Automation personal-chat event.

    Connection state is fetched from Bot API for every event.  The inbound JSON carries
    a connection id, but is never by itself authority to read or reply to a chat.
    """
    if not update.business_connection_id or not update.chat_id or not update.message_id:
        return {"ignored": True, "reason": "business_message_incomplete"}
    try:
        connection = providers.telegram.get_business_connection(update.business_connection_id)
    except Exception:
        logger.warning("telegram_business_connection_unavailable")
        return {"ignored": True, "reason": "business_connection_unavailable"}

    owner = connection.get("user") if isinstance(connection, dict) else None
    owner_id = owner.get("id") if isinstance(owner, dict) else None
    if not isinstance(connection, dict) or not connection.get("is_enabled"):
        logger.info("telegram_business_connection_ignored", result_category="disabled")
        return {"ignored": True, "reason": "business_connection_disabled"}
    if not isinstance(owner_id, int) or owner_id not in settings.allowed_telegram_ids:
        logger.info("telegram_business_connection_ignored", result_category="owner_not_admin")
        return {"ignored": True, "reason": "business_connection_owner_not_admin"}

    is_owner_message = update.user_id == owner_id
    counterparty_id = update.chat_id if is_owner_message else str(update.user_id or "")
    if not counterparty_id:
        return {"ignored": True, "reason": "business_counterparty_missing"}

    workspace = workspaces_service.get(session, workspace_id)
    ignored_ids = {str(x) for x in (workspace.settings_json.get("telegram_crm_ignore_ids") or [])}
    if str(counterparty_id) in ignored_ids:
        logger.info("telegram_business_contact_ignored", counterparty_id=str(counterparty_id))
        return {"ignored": True, "reason": "contact_excluded_from_crm"}

    counterparty_name = update.chat_display_name if is_owner_message else update.display_name
    contact, _ = contacts_service.resolve_or_create(
        session,
        workspace_id=workspace_id,
        channel="telegram",
        value=counterparty_id,
        display_name=counterparty_name or counterparty_id,
    )
    # Keep the stable numeric Telegram id as the primary identity, but also retain the
    # username when Telegram gives it to us so CRM UI can open the human chat directly.
    counterparty_username = update.username if not is_owner_message else None
    if counterparty_username:
        try:
            contacts_service.add_identity(
                session,
                workspace_id=workspace_id,
                contact_id=contact.id,
                channel="telegram",
                value="@" + counterparty_username.lstrip("@"),
                external_id=counterparty_id,
                verified=True,
                actor="telegram_business_webhook",
            )
        except Exception as exc:
            logger.info("telegram_username_identity_skipped", error=type(exc).__name__)

    media = None
    message_type = MessageType.text
    file_id = update.voice_file_id or update.document_file_id
    if file_id:
        mime = (
            update.voice_mime_type
            if update.voice_file_id
            else (update.document_mime_type or "application/octet-stream")
        )
        message_type = MessageType.voice if update.voice_file_id else MessageType.document
        try:
            media = capture_service.MediaInput(
                data=providers.telegram.get_file_bytes(file_id),
                mime_type=mime,
                filename=update.document_filename or f"{file_id}.ogg",
            )
        except Exception:
            logger.warning("telegram_business_file_download_failed")

    if not update.text and media is None:
        return {"ignored": True, "reason": "no_text_or_media"}

    raw_payload = {
        **update.raw,
        "_fiodor": {
            "telegram_business": True,
            "telegram_client": not is_owner_message,
            "business_connection_id": update.business_connection_id,
            "business_connection_owner_user_id": owner_id,
            "business_chat_id": update.chat_id,
            "business_message_id": update.message_id,
        },
    }
    result = capture_service.capture_message(
        session,
        workspace_id=workspace_id,
        channel="telegram",
        external_thread_id=f"business:{update.business_connection_id}:{update.chat_id}",
        sender_identity=str(update.user_id or owner_id),
        sender_display_name=update.display_name or update.chat_display_name,
        direction=Direction.outbound if is_owner_message else Direction.inbound,
        message_type=message_type,
        external_message_id=(
            f"telegram-business:{update.business_connection_id}:{update.chat_id}:{update.message_id}"
        ),
        content_text=update.text,
        raw_payload=raw_payload,
        sent_at=update.timestamp,
        media=media,
        contact_id=contact.id,
        settings=settings,
        storage=providers.storage,
        actor="telegram_business_webhook",
    )
    if result.created and is_owner_message:
        # A native reply in the user's normal Telegram chat is the preferred fast path.
        # Close any pending CRM reply for this conversation so the inbox reflects the
        # human action immediately and old approval prompts cannot be sent later.
        pending = list(session.scalars(
            select(Draft).where(
                Draft.workspace_id == workspace_id,
                Draft.conversation_id == result.conversation_id,
                Draft.channel == "telegram",
                Draft.status == "pending_approval",
            )
        ))
        for draft in pending:
            approval = session.scalar(
                select(Approval)
                .where(
                    Approval.workspace_id == workspace_id,
                    Approval.entity_type == "draft",
                    Approval.entity_id == draft.id,
                    Approval.status == "pending",
                )
                .order_by(Approval.created_at.desc())
            )
            external_ref = approval.external_ref if approval else None
            drafts_service.reject(
                session,
                workspace_id=workspace_id,
                draft_id=draft.id,
                actor=f"telegram:{owner_id}",
                reason="answered_in_native_telegram",
            )
            if external_ref and settings.telegram_approval_chat_id:
                try:
                    providers.telegram.edit_message(
                        settings.telegram_approval_chat_id,
                        external_ref,
                        "✅ Ответ уже отправлен в обычном Telegram. CRM отметила диалог как обработанный.",
                    )
                except Exception:
                    logger.info("telegram_native_reply_notice_update_skipped")

    if result.created and result.transcript is None and update.text:
        jobs_service.enqueue(
            session,
            workspace_id=workspace_id,
            job_type="process_message",
            payload={"message_id": str(result.message.id), "auto_draft": not is_owner_message},
            dedupe_key=f"process_message:{result.message.id}",
        )
    return {
        "message_id": str(result.message.id),
        "conversation_id": str(result.conversation_id),
        "transcript_id": str(result.transcript.id) if result.transcript else None,
        "duplicate": result.duplicate,
        "ignored": False,
    }


# ------------------------------------------------------------------- callbacks


def handle_callback(
    session: Session,
    update: TelegramUpdate,
    *,
    workspace_id: uuid.UUID,
    providers: Any,
) -> dict[str, Any]:
    """Process an approve / reject / edit button press.

    Approving here sends immediately, because the button press *is* the approval — but
    it still goes through `drafts.send`, which re-checks the status. Double-tapping the
    button is safe: the second call finds the draft already sent and returns the same
    message.
    """
    data = update.callback_data or ""
    action, _, raw_id = data.partition(":")
    answer = providers.telegram.answer_callback

    if action not in ("approve", "reject", "edit") or not raw_id:
        answer(update.callback_id or "", "Unrecognised action")
        return {"handled": False, "reason": "unknown action"}

    try:
        draft_id = uuid.UUID(raw_id)
    except ValueError:
        answer(update.callback_id or "", "Bad draft id")
        return {"handled": False, "reason": "bad draft id"}

    actor = f"telegram:{update.user_id}"

    if action == "edit":
        answer(
            update.callback_id or "",
            "Reply to this message with the corrected text.",
        )
        return {"handled": True, "action": "edit", "draft_id": str(draft_id)}

    if action == "reject":
        try:
            drafts_service.reject(
                session,
                workspace_id=workspace_id,
                draft_id=draft_id,
                actor=actor,
                reason="rejected from Telegram",
            )
        except StateTransitionError as exc:
            answer(update.callback_id or "", str(exc)[:180])
            return {"handled": False, "reason": str(exc)}
        session.commit()
        answer(update.callback_id or "", "Rejected. Nothing was sent.")
        return {"handled": True, "action": "reject", "draft_id": str(draft_id)}

    # approve
    try:
        draft = drafts_service.approve(
            session, workspace_id=workspace_id, draft_id=draft_id, actor=actor
        )
    except StateTransitionError as exc:
        answer(update.callback_id or "", str(exc)[:180])
        return {"handled": False, "reason": str(exc)}

    sender = providers.whatsapp if draft.channel == "whatsapp" else providers.telegram
    try:
        message = drafts_service.send(
            session,
            workspace_id=workspace_id,
            draft_id=draft_id,
            sender=sender,
            actor=actor,
        )
    except Exception as exc:
        session.commit()  # keep the approval; the draft is marked failed
        answer(update.callback_id or "", f"Approved but send failed: {type(exc).__name__}")
        return {"handled": True, "action": "approve", "sent": False, "error": str(exc)[:200]}

    session.commit()
    answer(update.callback_id or "", "Sent ✅")
    return {
        "handled": True,
        "action": "approve",
        "sent": True,
        "draft_id": str(draft_id),
        "message_id": str(message.id),
    }


def handle_edit_reply(
    session: Session,
    update: TelegramUpdate,
    *,
    workspace_id: uuid.UUID,
    draft_id: uuid.UUID,
    providers: Any,
) -> dict[str, Any]:
    """Approve a draft with edited text supplied as a Telegram reply."""
    if not update.text:
        return {"handled": False, "reason": "empty edit"}

    actor = f"telegram:{update.user_id}"
    draft = drafts_service.approve(
        session,
        workspace_id=workspace_id,
        draft_id=draft_id,
        actor=actor,
        edited_text=update.text,
    )
    sender = providers.whatsapp if draft.channel == "whatsapp" else providers.telegram
    message = drafts_service.send(
        session, workspace_id=workspace_id, draft_id=draft.id, sender=sender, actor=actor
    )
    session.commit()
    return {
        "handled": True,
        "action": "approve_edited",
        "draft_id": str(draft.id),
        "message_id": str(message.id),
    }
