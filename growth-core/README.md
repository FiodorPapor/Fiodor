# Growth Core

CRM-neutral attribution and funnel measurement for real-estate acquisition.

This service is intentionally separate from any agency CRM. A Telegram bot, Mini App, website, ad campaign, partner channel or CRM adapter can emit the same canonical events. The first tenant is Le Bleu, but tenant identity is data, not code.

## Why

A catalog is not a sales system unless we can answer:

- Which source and campaign produced the person?
- Which listing or search path did they use?
- Did they become a qualified lead?
- Did they request or schedule a viewing?
- Did the opportunity reach reservation / won?
- What did the campaign cost?
- What is CPL / cost per viewing / cost per won deal?

## Attribution contract

Every external acquisition surface gets a deterministic Telegram start link:

`source + medium + campaign + content + placement + listing/intent -> trk_<token>`

Example destinations:

- owned Telegram catalog
- partner Telegram channel
- Telegram Ads campaign
- Instagram / social bio
- website / SEO landing
- referral / partner
- future paid media

The bot resolves `trk_<token>`, records the touch and carries attribution through later funnel events.

## Canonical events

Product / intent:

- `bot_started`
- `catalog_opened`
- `listing_opened`
- `gallery_opened`
- `share_clicked`
- `search_started`
- `search_submitted`
- `notification_opt_in`
- `notification_sent`
- `notification_clicked`
- `availability_requested`
- `question_submitted`
- `viewing_requested`

Commercial:

- `lead_qualified`
- `viewing_scheduled`
- `reservation_started`
- `deal_won`
- `deal_lost`

The top-level commercial funnel is intentionally CRM-neutral:
`bot_started -> lead_qualified -> viewing_scheduled -> reservation_started -> deal_won`.

## Privacy

External user identifiers are HMAC-pseudonymized before storage. Test/operator events can be flagged and are excluded from production metrics by default.

## API

Authenticated with `X-Growth-Key`:

- `POST /v1/links/ensure`
- `GET /v1/links/{token}`
- `POST /v1/events`
- `POST /v1/spend`
- `GET /v1/metrics/funnel`
- `GET /v1/metrics/acquisition`

`GET /health` is public.

## CRM portability

CRM integration is an adapter, not a dependency. Any CRM can map its lifecycle to the canonical events above, for example:

- CRM lead qualified -> `lead_qualified`
- viewing booked -> `viewing_scheduled`
- reservation / offer -> `reservation_started`
- won / closed -> `deal_won`

This lets the same acquisition layer be reused across agencies without rewriting attribution logic.

## Local run

Create a private `.env` with PostgreSQL credentials, service key, HMAC salt and token secret, then:

```bash
docker compose up -d --build
```

Never commit production secrets.
