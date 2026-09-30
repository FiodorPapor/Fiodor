"""Channel webhooks: signature verification, allow-lists, media failure, retry safety."""

from __future__ import annotations

import json

import pytest
from sqlalchemy import func, select

from app.channels.whatsapp import parser as whatsapp_parser
from app.core.security import verify_meta_signature
from app.models.comms import Message
from app.models.crm import Contact
from app.models.enums import Direction, MessageStatus, MessageType
from app.models.outbound import Approval, Draft
from tests.conftest import ALLOWED_TELEGRAM_ID, sign_whatsapp

AUDIO = b"OggS\x00fake opus voice note"


def whatsapp_text_payload(
    *, message_id="wamid.TEXT1", from_number="5491112345678", text="Hola, ¿cómo va?"
):
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "BUSINESS_ID",
                "changes": [
                    {
                        "field": "messages",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "5491100000000",
                                "phone_number_id": "PHONE_ID",
                            },
                            "contacts": [
                                {"profile": {"name": "María González"}, "wa_id": from_number}
                            ],
                            "messages": [
                                {
                                    "from": from_number,
                                    "id": message_id,
                                    "timestamp": "1785000000",
                                    "type": "text",
                                    "text": {"body": text},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }


def whatsapp_voice_payload(
    *, message_id="wamid.VOICE1", from_number="5491112345678", media_id="MEDIA_1"
):
    payload = whatsapp_text_payload(message_id=message_id, from_number=from_number)
    payload["entry"][0]["changes"][0]["value"]["messages"] = [
        {
            "from": from_number,
            "id": message_id,
            "timestamp": "1785000000",
            "type": "audio",
            "audio": {"id": media_id, "mime_type": "audio/ogg; codecs=opus", "voice": True},
        }
    ]
    return payload


def whatsapp_echo_payload(
    *, message_id="wamid.ECHO1", to_number="5491112345678", text="Respuesta desde el teléfono"
):
    return {
        "object": "whatsapp_business_account",
        "entry": [
            {
                "id": "BUSINESS_ID",
                "changes": [
                    {
                        "field": "smb_message_echoes",
                        "value": {
                            "messaging_product": "whatsapp",
                            "metadata": {
                                "display_phone_number": "5491100000000",
                                "phone_number_id": "PHONE_ID",
                            },
                            "message_echoes": [
                                {
                                    "from": "5491100000000",
                                    "to": to_number,
                                    "id": message_id,
                                    "timestamp": "1785000200",
                                    "type": "text",
                                    "text": {"body": text},
                                }
                            ],
                        },
                    }
                ],
            }
        ],
    }


def post_whatsapp(client, payload, *, sign=True):
    body = json.dumps(payload).encode()
    headers = {"Content-Type": "application/json"}
    if sign:
        headers["X-Hub-Signature-256"] = sign_whatsapp(body)
    return client.post("/webhooks/whatsapp", content=body, headers=headers)


class TestSignatureVerification:
    def test_valid_signature_accepted(self):
        body = b'{"test": true}'
        signature = sign_whatsapp(body, "secret")
        assert verify_meta_signature("secret", body, signature) is True

    def test_wrong_secret_rejected(self):
        body = b'{"test": true}'
        assert verify_meta_signature("wrong", body, sign_whatsapp(body, "secret")) is False

    def test_tampered_body_rejected(self):
        signature = sign_whatsapp(b'{"amount": 1}', "secret")
        assert verify_meta_signature("secret", b'{"amount": 9999}', signature) is False

    def test_missing_signature_rejected(self):
        assert verify_meta_signature("secret", b"{}", None) is False

    def test_malformed_signature_rejected(self):
        assert verify_meta_signature("secret", b"{}", "deadbeef") is False

    def test_empty_app_secret_rejects_everything(self):
        """An unconfigured secret must fail closed, not accept all traffic."""
        body = b"{}"
        assert verify_meta_signature("", body, sign_whatsapp(body, "")) is False


class TestWhatsAppVerifyHandshake:
    def test_correct_token_echoes_challenge(self, anon_client):
        response = anon_client.get(
            "/webhooks/whatsapp",
            params={
                "hub.mode": "subscribe",
                "hub.verify_token": "test_verify_token",
                "hub.challenge": "challenge-12345",
            },
        )
        assert response.status_code == 200
        assert response.text == "challenge-12345"

    def test_wrong_token_forbidden(self, anon_client):
        response = anon_client.get(
            "/webhooks/whatsapp",
            params={
                "hub.mode": "subscribe",
                "hub.verify_token": "wrong",
                "hub.challenge": "challenge-12345",
            },
        )
        assert response.status_code == 403

    def test_missing_params_forbidden(self, anon_client):
        assert anon_client.get("/webhooks/whatsapp").status_code == 403


class TestWhatsAppParser:
    def test_parses_text(self):
        parsed = whatsapp_parser.parse_webhook(whatsapp_text_payload())
        assert parsed.webhook_object == "whatsapp_business_account"
        assert parsed.waba_entry_id == "BUSINESS_ID"
        assert parsed.change_field == "messages"
        assert parsed.phone_number_id == "PHONE_ID"
        assert len(parsed.messages) == 1
        message = parsed.messages[0]
        assert message.text == "Hola, ¿cómo va?"
        assert message.from_number == "5491112345678"
        assert message.sender_name == "María González"
        assert message.message_type == MessageType.text

    def test_parses_voice_with_media_id(self):
        parsed = whatsapp_parser.parse_webhook(whatsapp_voice_payload())
        message = parsed.messages[0]
        assert message.message_type == MessageType.voice
        assert message.media_id == "MEDIA_1"
        assert message.media_mime_type == "audio/ogg"

    def test_parses_status_updates(self):
        payload = {
            "entry": [
                {
                    "changes": [
                        {
                            "value": {
                                "statuses": [
                                    {
                                        "id": "wamid.OUT1",
                                        "status": "delivered",
                                        "recipient_id": "5491112345678",
                                        "timestamp": "1785000100",
                                    }
                                ]
                            }
                        }
                    ]
                }
            ]
        }
        parsed = whatsapp_parser.parse_webhook(payload)
        assert len(parsed.statuses) == 1
        assert parsed.statuses[0].status == "delivered"

    def test_parses_coexistence_message_echo(self):
        parsed = whatsapp_parser.parse_webhook(whatsapp_echo_payload())
        assert parsed.change_field == "smb_message_echoes"
        assert len(parsed.echoes) == 1
        echo = parsed.echoes[0]
        assert echo.external_message_id == "wamid.ECHO1"
        assert echo.from_number == "5491100000000"
        assert echo.to_number == "5491112345678"
        assert echo.message_type == MessageType.text
        assert echo.text == "Respuesta desde el teléfono"

    @pytest.mark.parametrize(
        "payload",
        [
            {},
            {"entry": []},
            {"entry": [{}]},
            {"entry": [{"changes": [{}]}]},
            {"entry": "not a list"},
            None,
        ],
    )
    def test_malformed_payloads_do_not_raise(self, payload):
        """Meta adds fields over time; a parser crash means an infinite retry loop."""
        parsed = whatsapp_parser.parse_webhook(payload)
        assert parsed.is_empty

    def test_message_without_id_is_skipped(self):
        payload = whatsapp_text_payload()
        del payload["entry"][0]["changes"][0]["value"]["messages"][0]["id"]
        assert whatsapp_parser.parse_webhook(payload).is_empty


class TestWhatsAppInbound:
    def test_unsigned_request_is_rejected_and_stores_nothing(
        self, anon_client, session, workspace_id
    ):
        response = post_whatsapp(anon_client, whatsapp_text_payload(), sign=False)
        assert response.status_code == 403
        count = session.scalar(
            select(func.count()).select_from(Message).where(Message.workspace_id == workspace_id)
        )
        assert count == 0

    def test_signed_text_is_stored(self, anon_client, session, workspace_id):
        response = post_whatsapp(anon_client, whatsapp_text_payload())
        assert response.status_code == 200
        assert response.json()["processed"] == 1

        message = session.scalar(
            select(Message).where(Message.external_message_id == "wamid.TEXT1")
        )
        assert message is not None
        assert message.content_text == "Hola, ¿cómo va?"

    def test_coexistence_echo_is_stored_as_outbound(self, anon_client, session, workspace_id):
        response = post_whatsapp(anon_client, whatsapp_echo_payload())
        assert response.status_code == 200
        assert response.json()["processed"] == 1

        message = session.scalar(
            select(Message).where(Message.external_message_id == "wamid.ECHO1")
        )
        assert message is not None
        assert message.workspace_id == workspace_id
        assert message.direction == Direction.outbound
        assert message.content_text == "Respuesta desde el teléfono"
        assert message.status == MessageStatus.sent

    @pytest.mark.parametrize("field", ["history", "smb_app_state_sync"])
    def test_coexistence_sync_fields_are_acknowledged_without_side_effects(
        self, field, anon_client, session
    ):
        payload = whatsapp_echo_payload()
        change = payload["entry"][0]["changes"][0]
        change["field"] = field
        change["value"].pop("message_echoes")
        change["value"][field if field == "history" else "state_sync"] = []

        response = post_whatsapp(anon_client, payload)
        assert response.status_code == 200
        assert response.json() == {
            "status": "ignored",
            "reason": "coexistence sync acknowledged",
        }
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_wrong_waba_is_ignored_without_side_effects(self, anon_client, session):
        payload = whatsapp_text_payload()
        payload["entry"][0]["id"] = "WRONG"
        response = post_whatsapp(anon_client, payload)
        assert response.json() == {"status": "ignored", "reason": "wrong_waba"}
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_wrong_phone_number_is_ignored_without_side_effects(self, anon_client, session):
        payload = whatsapp_text_payload()
        payload["entry"][0]["changes"][0]["value"]["metadata"]["phone_number_id"] = "WRONG"
        response = post_whatsapp(anon_client, payload)
        assert response.json() == {"status": "ignored", "reason": "wrong_phone_number"}
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_contact_is_resolved_from_the_phone_number(
        self, anon_client, session, workspace_id, contact
    ):
        post_whatsapp(anon_client, whatsapp_text_payload())
        message = session.scalar(
            select(Message).where(Message.external_message_id == "wamid.TEXT1")
        )
        assert message.contact_id == contact.id

    def test_retry_of_the_same_delivery_is_safe(self, anon_client, session, workspace_id):
        """Meta retries anything that does not return 200; a retry must not duplicate."""
        payload = whatsapp_text_payload()
        first = post_whatsapp(anon_client, payload)
        second = post_whatsapp(anon_client, payload)

        assert first.json()["processed"] == 1
        assert second.json()["duplicates"] == 1

        count = session.scalar(
            select(func.count()).select_from(Message).where(Message.workspace_id == workspace_id)
        )
        assert count == 1

    def test_voice_message_downloads_and_stores_media(
        self, anon_client, session, workspace_id, providers
    ):
        providers.media.register("MEDIA_1", AUDIO, mime_type="audio/ogg")
        response = post_whatsapp(anon_client, whatsapp_voice_payload())
        assert response.status_code == 200

        message = session.scalar(
            select(Message).where(Message.external_message_id == "wamid.VOICE1")
        )
        assert message.message_type == MessageType.voice

        from app.models.comms import Attachment, Transcript

        attachment = session.scalar(select(Attachment).where(Attachment.message_id == message.id))
        assert attachment is not None
        assert providers.storage.get(attachment.storage_key) == AUDIO
        transcript = session.scalar(select(Transcript).where(Transcript.message_id == message.id))
        assert transcript is not None
        assert transcript.status == "pending"

    def test_media_download_failure_still_keeps_the_message(
        self, anon_client, session, workspace_id, providers
    ):
        """Losing the audio must not lose the fact that someone messaged us."""
        # MEDIA_MISSING is never registered, so the fetcher raises.
        response = post_whatsapp(anon_client, whatsapp_voice_payload(media_id="MEDIA_MISSING"))
        assert response.status_code == 200
        assert response.json()["media_failures"] == 1

        message = session.scalar(
            select(Message).where(Message.external_message_id == "wamid.VOICE1")
        )
        assert message is not None, "the message row must survive a media failure"
        assert message.status == "failed"

    def test_invalid_json_is_accepted_not_retried(self, anon_client):
        body = b"this is not json"
        response = anon_client.post(
            "/webhooks/whatsapp",
            content=body,
            headers={"X-Hub-Signature-256": sign_whatsapp(body)},
        )
        assert response.status_code == 200
        assert response.json()["status"] == "ignored"

    def test_delivery_status_updates_the_outbound_message(
        self, anon_client, session, workspace_id, contact, providers
    ):
        from app.services import drafts as drafts_service

        draft = drafts_service.create(
            session,
            workspace_id=workspace_id,
            channel="whatsapp",
            text="Hola",
            recipient="+5491112345678",
            contact_id=contact.id,
        )
        drafts_service.request_approval(session, workspace_id=workspace_id, draft_id=draft.id)
        drafts_service.approve(
            session, workspace_id=workspace_id, draft_id=draft.id, actor="fiodor"
        )
        session.commit()
        message = drafts_service.send(
            session,
            workspace_id=workspace_id,
            draft_id=draft.id,
            sender=providers.whatsapp,
        )
        session.commit()

        payload = {
            "object": "whatsapp_business_account",
            "entry": [
                {
                    "id": "BUSINESS_ID",
                    "changes": [
                        {
                            "field": "messages",
                            "value": {
                                "metadata": {"phone_number_id": "PHONE_ID"},
                                "statuses": [
                                    {
                                        "id": message.external_message_id,
                                        "status": "read",
                                        "recipient_id": "5491112345678",
                                        "timestamp": "1785000200",
                                    }
                                ],
                            },
                        }
                    ],
                }
            ],
        }
        post_whatsapp(anon_client, payload)
        session.refresh(message)
        assert message.status == "read"


def telegram_message(*, user_id=ALLOWED_TELEGRAM_ID, text="Nota rápida", message_id=5001):
    return {
        "update_id": 900001,
        "message": {
            "message_id": message_id,
            "date": 1785000000,
            "from": {"id": user_id, "first_name": "Fiodor", "username": "fiodor"},
            "chat": {"id": user_id, "type": "private"},
            "text": text,
        },
    }


def telegram_voice(*, user_id=ALLOWED_TELEGRAM_ID, file_id="FILE_1", message_id=5002):
    update = telegram_message(user_id=user_id, message_id=message_id)
    del update["message"]["text"]
    update["message"]["voice"] = {
        "file_id": file_id,
        "duration": 7,
        "mime_type": "audio/ogg",
    }
    return update


def post_telegram(client, payload):
    return client.post(
        "/webhooks/telegram",
        json=payload,
        headers={"X-Telegram-Bot-Api-Secret-Token": "test_tg_secret"},
    )


def post_lebleu_telegram(client, payload):
    return client.post(
        "/webhooks/lebleu-telegram",
        json=payload,
        headers={"X-Telegram-Bot-Api-Secret-Token": "test_lebleu_secret"},
    )


def telegram_business_message(
    *,
    connection_id="CONN",
    sender_id=987654321,
    message_id=7001,
    text="Necesito ayuda",
    chat_id=987654321,
):
    return {
        "update_id": 910001,
        "business_message": {
            "business_connection_id": connection_id,
            "message_id": message_id,
            "date": 1785000000,
            "from": {"id": sender_id, "first_name": "María", "username": "maria_g"},
            "chat": {"id": chat_id, "type": "private", "first_name": "María"},
            "text": text,
        },
    }


class TestTelegramAuthorisation:
    def test_wrong_secret_token_rejected(self, anon_client, session, workspace_id):
        response = anon_client.post(
            "/webhooks/telegram",
            json=telegram_message(),
            headers={"X-Telegram-Bot-Api-Secret-Token": "wrong"},
        )
        assert response.status_code == 403
        count = session.scalar(select(func.count()).select_from(Message))
        assert count == 0

    def test_unauthorised_user_is_ignored_silently(
        self, anon_client, session, workspace_id, providers
    ):
        """An unknown sender gets a 200 with no side effects: nothing stored, no reply."""
        response = post_telegram(anon_client, telegram_message(user_id=999999999))
        assert response.status_code == 200
        assert response.json()["reason"] == "unauthorised"

        count = session.scalar(select(func.count()).select_from(Message))
        assert count == 0
        assert providers.telegram.sent == [], "an unauthorised user must get no reply"

    def test_authorised_user_is_accepted(self, anon_client, session, workspace_id):
        response = post_telegram(anon_client, telegram_message())
        assert response.status_code == 200
        assert response.json()["status"] == "ok"

        count = session.scalar(select(func.count()).select_from(Message))
        assert count == 1

    def test_empty_allowlist_denies_everyone(self):
        from app.channels.telegram.handler import is_authorised, parse_update

        update = parse_update(telegram_message())
        assert is_authorised(update, set()) is False

    def test_update_without_a_user_is_denied(self):
        from app.channels.telegram.handler import is_authorised, parse_update

        update = parse_update({"update_id": 1, "message": {"message_id": 1, "chat": {"id": 1}}})
        assert is_authorised(update, {ALLOWED_TELEGRAM_ID}) is False


@pytest.fixture
def telegram_client_messages_enabled(monkeypatch):
    """Enable client Telegram capture before the provider settings are constructed."""
    from app.config import get_settings

    monkeypatch.setenv("TELEGRAM_ACCEPT_CLIENT_PRIVATE_MESSAGES", "true")
    get_settings.cache_clear()
    yield
    get_settings.cache_clear()


class TestTelegramCapture:
    def test_text_note_is_stored(self, anon_client, session, workspace_id):
        post_telegram(anon_client, telegram_message(text="Recordar llamar al escribano"))
        message = session.scalar(select(Message).where(Message.channel == "telegram"))
        assert message.content_text == "Recordar llamar al escribano"

    def test_voice_note_is_downloaded_and_queued_for_transcription(
        self, anon_client, session, workspace_id, providers
    ):
        # The mock Telegram sender needs a file-download stub for this path.
        providers.telegram.get_file_bytes = lambda file_id: AUDIO

        response = post_telegram(anon_client, telegram_voice())
        assert response.status_code == 200
        assert response.json()["transcript_id"] is not None

        from app.models.comms import Attachment

        attachment = session.scalar(select(Attachment))
        assert attachment is not None
        assert providers.storage.get(attachment.storage_key) == AUDIO

    def test_duplicate_telegram_message_id_is_idempotent(self, anon_client, session, workspace_id):
        payload = telegram_message()
        post_telegram(anon_client, payload)
        second = post_telegram(anon_client, payload)
        assert second.json()["duplicate"] is True
        count = session.scalar(select(func.count()).select_from(Message))
        assert count == 1

    def test_message_without_text_or_media_is_ignored(self, anon_client, session):
        update = telegram_message()
        del update["message"]["text"]
        response = post_telegram(anon_client, update)
        assert response.json()["ignored"] is True
        assert session.scalar(select(func.count()).select_from(Message)) == 0


class TestTelegramClientCapture:
    CLIENT_ID = 987654321

    def test_private_client_text_is_captured_when_enabled(
        self, telegram_client_messages_enabled, anon_client, session
    ):
        response = post_telegram(
            anon_client,
            telegram_message(user_id=self.CLIENT_ID, text="/start Necesito ayuda", message_id=6001),
        )

        assert response.status_code == 200
        assert response.json()["status"] == "ok"
        message = session.scalar(
            select(Message).where(Message.external_message_id == f"telegram:{self.CLIENT_ID}:6001")
        )
        assert message.sender_identity == str(self.CLIENT_ID)
        assert message.content_text == "/start Necesito ayuda"
        assert message.contact_id is not None
        contact = session.get(Contact, message.contact_id)
        assert contact is not None
        assert contact.display_name == "Fiodor"
        assert any(
            identity.channel == "telegram" and identity.normalised_value == str(self.CLIENT_ID)
            for identity in contact.identities
        )
        assert message.raw_payload_json["message"]["from"]["username"] == "fiodor"

    def test_private_client_voice_uses_existing_capture_path(
        self, telegram_client_messages_enabled, anon_client, session, providers
    ):
        providers.telegram.get_file_bytes = lambda file_id: AUDIO

        response = post_telegram(
            anon_client, telegram_voice(user_id=self.CLIENT_ID, message_id=6002)
        )

        assert response.status_code == 200
        assert response.json()["transcript_id"] is not None
        message = session.scalar(
            select(Message).where(Message.external_message_id == f"telegram:{self.CLIENT_ID}:6002")
        )
        assert message.sender_identity == str(self.CLIENT_ID)

    def test_duplicate_private_client_message_is_idempotent(
        self, telegram_client_messages_enabled, anon_client, session
    ):
        payload = telegram_message(user_id=self.CLIENT_ID, message_id=6003)
        post_telegram(anon_client, payload)
        second = post_telegram(anon_client, payload)

        assert second.json()["duplicate"] is True
        assert session.scalar(select(func.count()).select_from(Message)) == 1

    @pytest.mark.parametrize("chat_type", ["group", "supergroup", "channel"])
    def test_non_private_client_message_is_ignored(
        self, telegram_client_messages_enabled, anon_client, session, chat_type
    ):
        payload = telegram_message(user_id=self.CLIENT_ID, message_id=6004)
        payload["message"]["chat"]["type"] = chat_type

        response = post_telegram(anon_client, payload)

        assert response.json() == {"status": "ignored", "reason": "non-private chat"}
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_non_admin_callback_is_ignored_when_client_capture_is_enabled(
        self, telegram_client_messages_enabled, anon_client, session, providers
    ):
        callback = TestTelegramApprovalCallbacks()._callback(
            "00000000-0000-0000-0000-000000000001", "approve", user_id=self.CLIENT_ID
        )
        callback["callback_query"]["message"]["chat"]["type"] = "private"

        response = post_telegram(anon_client, callback)

        assert response.json()["reason"] == "unauthorised"
        assert providers.whatsapp.sent == []


class TestTelegramBusinessCapture:
    def _enable_connection(
        self, providers, *, owner=ALLOWED_TELEGRAM_ID, enabled=True, can_reply=True
    ):
        providers.telegram.business_connections["CONN"] = {
            "id": "CONN",
            "is_enabled": enabled,
            "can_reply": can_reply,
            "user": {"id": owner},
        }

    def test_business_update_is_parsed_explicitly(self):
        from app.channels.telegram.handler import parse_update

        update = parse_update(telegram_business_message())
        assert update.kind == "business_message"
        assert update.business_connection_id == "CONN"

    def test_disabled_or_non_admin_connection_is_ignored(self, anon_client, providers, session):
        self._enable_connection(providers, enabled=False)
        assert post_telegram(anon_client, telegram_business_message()).json()["ignored"] is True
        self._enable_connection(providers, owner=999999999)
        assert post_telegram(anon_client, telegram_business_message()).json()["ignored"] is True
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_excluded_business_contact_is_not_captured(self, anon_client, providers, session, workspace):
        self._enable_connection(providers)
        workspace.settings_json = {
            **(workspace.settings_json or {}),
            "telegram_crm_ignore_ids": ["987654321"],
        }
        session.commit()
        response = post_telegram(anon_client, telegram_business_message(message_id=7009))
        assert response.json()["ignored"] is True
        assert response.json()["reason"] == "contact_excluded_from_crm"
        assert session.scalar(select(func.count()).select_from(Message)) == 0

    def test_client_message_and_owner_message_share_business_conversation(
        self, anon_client, providers, session
    ):
        from app.models.enums import Direction

        self._enable_connection(providers)
        incoming = post_telegram(anon_client, telegram_business_message(message_id=7001))
        assert incoming.json()["ignored"] is False
        outgoing = post_telegram(
            anon_client,
            telegram_business_message(
                sender_id=ALLOWED_TELEGRAM_ID,
                chat_id=987654321,
                message_id=7002,
                text="Ya lo reviso",
            ),
        )
        assert outgoing.json()["ignored"] is False
        messages = list(session.scalars(select(Message).order_by(Message.created_at)))
        assert [message.direction for message in messages] == [
            Direction.inbound,
            Direction.outbound,
        ]
        assert messages[0].conversation_id == messages[1].conversation_id
        assert messages[0].external_message_id == "telegram-business:CONN:987654321:7001"
        assert messages[0].raw_payload_json["_fiodor"]["telegram_business"] is True

    def test_two_client_messages_refresh_one_pending_reply(self, anon_client, providers, session):
        from app.worker.handlers import handle_draft_reply

        self._enable_connection(providers)
        post_telegram(anon_client, telegram_business_message(message_id=7010, text="Hola"))
        first_message = session.scalar(
            select(Message).where(Message.external_message_id.endswith(":7010"))
        )
        first = handle_draft_reply(
            session,
            {"message_id": str(first_message.id), "text": "Hola"},
            workspace_id=first_message.workspace_id,
            providers=providers,
        )
        session.flush()

        post_telegram(
            anon_client,
            telegram_business_message(message_id=7011, text="Quiero hacer una visita"),
        )
        second_message = session.scalar(
            select(Message).where(Message.external_message_id.endswith(":7011"))
        )
        second = handle_draft_reply(
            session,
            {"message_id": str(second_message.id), "text": "Quiero hacer una visita"},
            workspace_id=second_message.workspace_id,
            providers=providers,
        )
        session.flush()

        pending = list(session.scalars(select(Draft).where(Draft.status == "pending_approval")))
        assert len(pending) == 1
        assert second["refreshed"] is True
        assert second["draft_id"] == first["draft_id"]
        assert pending[0].reply_to_message_id == second_message.id

    def test_native_owner_reply_closes_pending_crm_reply(self, anon_client, providers, session):
        from app.services import drafts as drafts_service

        self._enable_connection(providers)
        post_telegram(anon_client, telegram_business_message(message_id=7020, text="Hola"))
        incoming = session.scalar(
            select(Message).where(Message.external_message_id.endswith(":7020"))
        )
        draft = drafts_service.create(
            session,
            workspace_id=incoming.workspace_id,
            channel="telegram",
            text="[manual reply required]",
            recipient="987654321",
            contact_id=incoming.contact_id,
            conversation_id=incoming.conversation_id,
            reply_to_message_id=incoming.id,
            provider="manual",
        )
        _, approval = drafts_service.request_approval(
            session, workspace_id=incoming.workspace_id, draft_id=draft.id
        )
        approval.external_ref = "7700"
        session.commit()

        post_telegram(
            anon_client,
            telegram_business_message(
                sender_id=ALLOWED_TELEGRAM_ID,
                chat_id=987654321,
                message_id=7021,
                text="Te respondo por acá",
            ),
        )
        session.refresh(draft)
        session.refresh(approval)
        assert draft.status == "rejected"
        assert draft.rejected_reason == "answered_in_native_telegram"
        assert approval.status == "rejected"

    def test_business_voice_uses_transcription_capture_path(self, anon_client, providers, session):
        self._enable_connection(providers)
        providers.telegram.get_file_bytes = lambda _: AUDIO
        payload = telegram_business_message()
        del payload["business_message"]["text"]
        payload["business_message"]["voice"] = {
            "file_id": "BUSINESS_FILE",
            "mime_type": "audio/ogg",
            "duration": 3,
        }
        response = post_telegram(anon_client, payload)
        assert response.json()["transcript_id"] is not None
        message = session.scalar(select(Message))
        assert message.message_type == MessageType.voice

    def test_normal_chat_ids_include_chat_to_prevent_collisions(self, anon_client, session):
        first = telegram_message(message_id=42)
        second = telegram_message(message_id=42)
        second["message"]["chat"]["id"] = 222333444
        second["message"]["from"]["id"] = ALLOWED_TELEGRAM_ID
        post_telegram(anon_client, first)
        post_telegram(anon_client, second)
        assert session.scalar(select(func.count()).select_from(Message)) == 2


class TestTelegramApprovalCallbacks:
    @pytest.fixture
    def pending_draft(self, session, workspace_id, contact):
        from app.services import drafts as drafts_service

        draft = drafts_service.create(
            session,
            workspace_id=workspace_id,
            channel="whatsapp",
            text="Te confirmo mañana.",
            recipient="+5491112345678",
            contact_id=contact.id,
        )
        drafts_service.request_approval(session, workspace_id=workspace_id, draft_id=draft.id)
        session.commit()
        return draft

    def _callback(self, draft_id, action, user_id=ALLOWED_TELEGRAM_ID):
        return {
            "update_id": 900002,
            "callback_query": {
                "id": "cb-1",
                "from": {"id": user_id, "username": "fiodor"},
                "message": {"message_id": 7001, "chat": {"id": user_id, "type": "private"}},
                "data": f"{action}:{draft_id}",
            },
        }

    def test_approve_button_sends_the_message(self, anon_client, session, pending_draft, providers):
        response = post_telegram(anon_client, self._callback(pending_draft.id, "approve"))
        assert response.status_code == 200
        assert response.json()["sent"] is True
        assert len(providers.whatsapp.sent) == 1
        assert providers.whatsapp.sent[0]["text"] == "Te confirmo mañana."

    def test_reject_button_sends_nothing(self, anon_client, session, pending_draft, providers):
        response = post_telegram(anon_client, self._callback(pending_draft.id, "reject"))
        assert response.json()["action"] == "reject"
        assert providers.whatsapp.sent == []

    def test_double_tap_on_approve_sends_only_once(
        self, anon_client, session, pending_draft, providers
    ):
        """A user tapping twice, or Telegram redelivering, must not double-send."""
        post_telegram(anon_client, self._callback(pending_draft.id, "approve"))
        post_telegram(anon_client, self._callback(pending_draft.id, "approve"))
        assert len(providers.whatsapp.sent) == 1

    def test_unauthorised_user_cannot_approve(self, anon_client, session, pending_draft, providers):
        response = post_telegram(
            anon_client, self._callback(pending_draft.id, "approve", user_id=999999999)
        )
        assert response.json()["reason"] == "unauthorised"
        assert providers.whatsapp.sent == []

    def test_bad_draft_id_is_handled(self, anon_client, session, workspace):
        response = post_telegram(anon_client, self._callback("not-a-uuid", "approve"))
        assert response.json()["handled"] is False

    def test_unknown_action_is_handled(self, anon_client, session, pending_draft, providers):
        response = post_telegram(anon_client, self._callback(pending_draft.id, "detonate"))
        assert response.json()["handled"] is False
        assert providers.whatsapp.sent == []

    def test_admin_reply_to_approval_edits_approves_and_sends_once(
        self, anon_client, session, pending_draft, providers
    ):
        approval = session.scalar(select(Approval).where(Approval.entity_id == pending_draft.id))
        approval.external_ref = "7001"
        session.commit()
        edited = telegram_message(text="Texto corregido", message_id=7002)
        edited["message"]["reply_to_message"] = {"message_id": 7001, "text": "Approval"}

        response = post_telegram(anon_client, edited)
        assert response.json()["action"] == "approve_edited"
        assert providers.whatsapp.sent == [
            {"recipient": "+5491112345678", "text": "Texto corregido"}
        ]
        post_telegram(anon_client, edited)
        assert len(providers.whatsapp.sent) == 1

    def test_unrelated_admin_reply_remains_a_note(self, anon_client, session, providers):
        note = telegram_message(text="Una nota", message_id=7003)
        note["message"]["reply_to_message"] = {"message_id": 9999, "text": "Other"}
        response = post_telegram(anon_client, note)
        assert response.json()["ignored"] is False
        assert session.scalar(select(func.count()).select_from(Message)) == 1
        assert providers.whatsapp.sent == []


class TestOutboundSafetyGuards:
    def test_real_sender_refuses_non_test_recipient_when_disabled(self):
        """With WHATSAPP_ALLOW_REAL_SEND=false, only the test recipient may be messaged."""
        from app.core.errors import ForbiddenError
        from app.providers.messaging import MetaWhatsAppSender

        sender = MetaWhatsAppSender(
            access_token="token",
            phone_number_id="PHONE",
            allow_real_send=False,
            test_recipient="+5491100000000",
        )
        with pytest.raises(ForbiddenError):
            sender.send_text("+5491199999999", "hola")

    def test_real_sender_allows_the_test_recipient(self):
        from app.core.errors import ProviderError
        from app.providers.messaging import MetaWhatsAppSender

        sender = MetaWhatsAppSender(
            access_token="",
            phone_number_id="",
            allow_real_send=False,
            test_recipient="+5491100000000",
        )
        # Passes the recipient guard, then fails on missing credentials — which proves
        # the guard is what blocks the other case, not the missing token.
        with pytest.raises(ProviderError, match="credentials missing"):
            sender.send_text("+5491100000000", "hola")

    def test_real_sender_allows_metas_digit_only_sender_format(self):
        from app.core.errors import ProviderError
        from app.providers.messaging import MetaWhatsAppSender

        sender = MetaWhatsAppSender(
            access_token="",
            phone_number_id="",
            allow_real_send=False,
            test_recipient="+5491100000000",
        )
        with pytest.raises(ProviderError, match="credentials missing"):
            sender.send_text("5491100000000", "hola")

    def test_no_test_recipient_configured_blocks_everything(self):
        from app.core.errors import ForbiddenError
        from app.providers.messaging import MetaWhatsAppSender

        sender = MetaWhatsAppSender(
            access_token="token",
            phone_number_id="PHONE",
            allow_real_send=False,
            test_recipient="",
        )
        with pytest.raises(ForbiddenError):
            sender.send_text("+5491100000000", "hola")


class TestLeBleuTelegramLeadFunnel:
    CLIENT_ID = 987654321

    def test_listing_lookup_keeps_requested_key_on_cold_cache(self, monkeypatch):
        import hashlib
        from app.channels.telegram import handler as tg_handler

        first = {
            "code": "LAP111",
            "sourceUrl": "https://example.test/first",
            "address": "First listing",
        }
        second = {
            "code": "LAP222",
            "sourceUrl": "https://example.test/second",
            "address": "Last listing",
        }

        class Response:
            def raise_for_status(self):
                return None

            def json(self):
                return [first, second]

        monkeypatch.setattr(tg_handler.httpx, "get", lambda *args, **kwargs: Response())
        tg_handler._lebleu_catalog_cache = {"loaded_at": 0.0, "items": {}}

        token = f"LAP111_{hashlib.sha256(first['sourceUrl'].encode()).hexdigest()[:8]}"
        assert tg_handler._lebleu_listing(token)["address"] == "First listing"
        assert tg_handler._lebleu_listing("LAP222")["address"] == "Last listing"

    @staticmethod
    def _callback(data: str, message_id: int, callback_id: str):
        return {
            "update_id": 990000 + message_id,
            "callback_query": {
                "id": callback_id,
                "from": {"id": TestLeBleuTelegramLeadFunnel.CLIENT_ID, "username": "buyer_test"},
                "message": {
                    "message_id": message_id,
                    "chat": {"id": TestLeBleuTelegramLeadFunnel.CLIENT_ID, "type": "private"},
                },
                "data": data,
            },
        }
    def test_funnel_is_idempotent_and_internal_card_never_leaks_to_client(
        self, telegram_client_messages_enabled, anon_client, session, providers, monkeypatch
    ):
        from app.channels.telegram import handler as tg_handler
        from app.config import get_settings
        from app.models.crm import Opportunity

        item = {
            "code": "LHO9879392",
            "operation": "Venta",
            "propertyType": "Casa",
            "address": "Club de Campo Aranzazu",
            "priceAmount": "175000",
            "priceCurrency": "USD",
            "sourceUrl": "https://example.test/aranzazu",
            "imageUrls": [f"https://img.test/{i}.jpg" for i in range(12)],
        }
        monkeypatch.setattr(tg_handler, "_lebleu_listing", lambda token: dict(item))
        monkeypatch.setattr(get_settings(), "whatsapp_test_recipient", "+5491100000000")

        start = telegram_message(
            user_id=self.CLIENT_ID,
            text="/start lb_LHO9879392_deadbeef",
            message_id=8101,
        )
        assert post_lebleu_telegram(anon_client, start).status_code == 200
        # Opening a listing is engagement only. No sales opportunity exists until
        # the person chooses a meaningful action.
        assert session.scalar(select(Opportunity)) is None
        steps = [
            ("lbi:v:LHO9879392_deadbeef", 8201, "cb-intent"),
            ("lbq:timing:week", 8202, "cb-timing"),
        ]
        for data, message_id, callback_id in steps:
            response = post_lebleu_telegram(
                anon_client, self._callback(data, message_id, callback_id)
            )
            assert response.status_code == 200
            assert response.json()["status"] == "ok"

        opportunity = session.scalar(select(Opportunity))
        assert opportunity is not None
        session.refresh(opportunity)
        assert opportunity.stage == "qualifying"
        assert opportunity.probability == 95
        assert opportunity.extra_json["qualification_status"] == "completed"
        assert opportunity.extra_json["temperature"] == "HOT"

        assert len(providers.whatsapp.sent) == 1
        assert "LEAD LE BLEU · HOT" in providers.whatsapp.sent[0]["text"]
        client_texts = [
            x.get("text", "") for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID)
        ]
        assert sum("Запрос у нас" in text for text in client_texts) == 1
        assert not any("LEAD LE BLEU" in text for text in client_texts)
        assert not any("score" in text.lower() for text in client_texts)

        # Telegram may redeliver a callback. It must not duplicate side effects.
        retry = post_lebleu_telegram(
            anon_client,
            self._callback("lbq:timing:week", 8202, "cb-timing-retry"),
        )
        assert retry.status_code == 200
        assert retry.json()["action"] == "already_completed"
        assert len(providers.whatsapp.sent) == 1
        client_texts = [
            x.get("text", "") for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID)
        ]
        assert sum("Запрос у нас" in text for text in client_texts) == 1

    def test_catalog_help_collects_search_request(
        self, telegram_client_messages_enabled, anon_client, session, providers
    ):
        from app.models.crm import Opportunity

        start = telegram_message(
            user_id=self.CLIENT_ID,
            text="/start catalog_help",
            message_id=8301,
        )
        assert post_lebleu_telegram(anon_client, start).status_code == 200

        prompt_texts = [
            x.get("text", "") for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID)
        ]
        assert any("Не нашли подходящий объект?" in text for text in prompt_texts)

        request = telegram_message(
            user_id=self.CLIENT_ID,
            text="Покупка, Belgrano или Núñez, 2–3 комнаты, до USD 180 000, нужен балкон.",
            message_id=8302,
        )
        assert post_lebleu_telegram(anon_client, request).status_code == 200

        opportunity = session.scalar(select(Opportunity))
        assert opportunity is not None
        session.refresh(opportunity)
        assert opportunity.extra_json["request_kind"] == "catalog_no_match"
        assert opportunity.extra_json["qualification_status"] == "completed"
        assert opportunity.probability == 60
        assert "Belgrano" in opportunity.summary_current

        client_texts = [
            x.get("text", "") for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID)
        ]
        assert any("запрос получили" in text.lower() for text in client_texts)

    def test_tracked_start_preserves_attribution_and_emits_engagement(
        self, telegram_client_messages_enabled, anon_client, session, providers, monkeypatch
    ):
        from app.channels.telegram import handler as tg_handler
        from app.models.crm import Opportunity

        tracking = {
            "token": "track123",
            "source": "telegram_catalog",
            "medium": "owned",
            "campaign": "live_catalog",
            "content": "listing",
            "placement": "forum_card",
            "listing_code": "LAP9862077_deadbeef",
            "intent": "listing",
        }
        item = {
            "code": "LAP9862077",
            "operation": "Alquiler",
            "propertyType": "Departamento",
            "address": "Cuba al 2800",
            "priceAmount": "1200",
            "priceCurrency": "USD",
            "sourceUrl": "https://example.test/cuba",
            "imageUrls": ["https://img.test/1.jpg"],
        }
        events = []
        monkeypatch.setattr(tg_handler, "_growth_resolve_tracking", lambda payload, settings: dict(tracking))
        monkeypatch.setattr(tg_handler, "_growth_capture", lambda *args, **kwargs: events.append((args[2], kwargs)))
        monkeypatch.setattr(tg_handler, "_lebleu_listing", lambda token: dict(item))

        start = telegram_message(
            user_id=self.CLIENT_ID,
            text="/start trk_track123",
            message_id=8401,
        )
        assert post_lebleu_telegram(anon_client, start).status_code == 200
        assert session.scalar(select(Opportunity)) is None
        assert [name for name, _ in events] == ["bot_started", "listing_opened"]
        client_messages = [
            x for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID) and x.get("reply_markup")
        ]
        assert client_messages
        webapp_url = client_messages[-1]["reply_markup"]["inline_keyboard"][0][0]["web_app"]["url"]
        assert "listing=LAP9862077" in webapp_url
        assert "trk=track123" in webapp_url

        action = post_lebleu_telegram(
            anon_client,
            self._callback("lbi:q:LAP9862077_deadbeef:track123", 8402, "cb-question"),
        )
        assert action.status_code == 200

        opportunity = session.scalar(select(Opportunity))
        assert opportunity is not None
        session.refresh(opportunity)
        assert opportunity.extra_json["tracking_token"] == "track123"
        assert opportunity.extra_json["tracking_source"] == "telegram_catalog"
        assert opportunity.extra_json["tracking_campaign"] == "live_catalog"
        assert opportunity.extra_json["listing_token"] == "LAP9862077_deadbeef"
        assert opportunity.extra_json["answers"]["intent"] == "question"

    def test_generic_tracked_start_carries_campaign_into_miniapp_url(
        self, telegram_client_messages_enabled, anon_client, providers, monkeypatch
    ):
        from app.channels.telegram import handler as tg_handler

        tracking = {
            "token": "campaign123",
            "source": "telegram_partner",
            "medium": "partner",
            "campaign": "channel_launch",
            "content": "post_a",
            "placement": "partner_channel",
            "listing_code": None,
            "intent": "miniapp",
        }
        monkeypatch.setattr(tg_handler, "_growth_resolve_tracking", lambda payload, settings: dict(tracking))
        monkeypatch.setattr(tg_handler, "_growth_capture", lambda *args, **kwargs: None)

        start = telegram_message(
            user_id=self.CLIENT_ID,
            text="/start trk_campaign123",
            message_id=8501,
        )
        assert post_lebleu_telegram(anon_client, start).status_code == 200

        client_messages = [
            x for x in providers.telegram.sent
            if x.get("recipient") == str(self.CLIENT_ID) and x.get("reply_markup")
        ]
        assert client_messages
        message = client_messages[-1]
        buttons = message["reply_markup"]["inline_keyboard"]
        miniapp_url = buttons[0][0]["web_app"]["url"]
        assert miniapp_url.startswith("https://lebleu-app.srv1636153.hstgr.cloud/")
        assert "trk=campaign123" in miniapp_url
        assert buttons[0][0]["text"] == "Открыть каталог"
        assert len(buttons) == 1
        assert "недвижимость в Буэнос-Айресе на русском" in message["text"]
