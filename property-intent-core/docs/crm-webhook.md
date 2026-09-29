# CRM webhook contract

Property Intent Core can keep the product independent from any agency CRM by emitting a small, versioned lead webhook. The Le Bleu pilot also has a direct Fiodor CRM adapter, but future agencies can connect through this webhook without changing search, attribution or Mini App code.

## Configuration

Set both:

- `CRM_WEBHOOK_URL`
- `CRM_WEBHOOK_SECRET`

If either is empty, webhook delivery is disabled.

## Event

Current event: `lead.saved_search`

Headers:

- `X-Revenue-Event: lead.saved_search`
- `X-Revenue-Signature: sha256=<hex hmac>`
- `Idempotency-Key: saved_search:<uuid>`

The signature is HMAC-SHA256 over the exact UTF-8 JSON request body using `CRM_WEBHOOK_SECRET`.

Example body:

```json
{
  "schema_version": "1.0",
  "event": "lead.saved_search",
  "tenant": "lebleu",
  "idempotency_key": "saved_search:<uuid>",
  "occurred_at": "2026-09-29T00:00:00+00:00",
  "contact": {
    "channel": "telegram",
    "external_id": "123456789",
    "username": "buyer",
    "display_name": "Buyer",
    "language": "ru"
  },
  "lead": {
    "external_id": "<saved-search-uuid>",
    "type": "property_saved_search",
    "label": "Покупка · Palermo · до USD 180000",
    "criteria": {},
    "notification_opt_in": true,
    "matches_now": 4
  },
  "attribution": {
    "token": "<growth-token>",
    "source": "telegram_partner",
    "medium": "partner",
    "campaign": "channel_launch",
    "content": "post_a",
    "placement": "@partner_channel"
  }
}
```

## Delivery semantics

- A user request must not fail because a CRM is unavailable.
- Delivery is retried by `property-intent-reconcile.timer` every five minutes.
- Receivers must use `Idempotency-Key` to make upserts idempotent.
- Only qualified, explicit saved-search intent is sent. Raw Telegram history is not exported.
- Test/operator users are excluded.

## Recommended adapter pattern

For a new agency, keep Growth Core + Property Intent Core unchanged and implement one of:

1. n8n webhook → agency CRM actions.
2. A small custom adapter that validates the HMAC and maps this schema to the CRM API.
3. A native CRM webhook endpoint that accepts the contract directly.

Map the external saved-search UUID to a CRM lead/opportunity external ID so retries update rather than duplicate.
