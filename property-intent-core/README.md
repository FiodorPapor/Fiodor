# Property Intent Core

Portable saved-search, notification and inventory-intent service for real-estate acquisition.

Le Bleu is the first pilot tenant. The service is deliberately separate from the agency CRM: inventory, CRM and acquisition analytics connect through adapters.

## Responsibilities

- expose a normalized property catalog to a client UI
- validate Telegram Mini App init data server-side
- persist saved searches and explicit notification opt-in
- baseline existing matches so users are alerted only when a future object becomes newly relevant
- rematch active saved searches after inventory sync
- send Telegram notifications for new matches
- emit canonical Growth Core events
- optionally sync a qualified saved-search lead to an agency CRM

## API

Public catalog:
- `GET /v1/catalog` returns lightweight cards
- `GET /v1/catalog/{code}` hydrates full gallery and description

Telegram-authenticated:
- `POST /v1/session`
- `POST /v1/events`
- `POST /v1/actions`
- `GET /v1/saved-searches`
- `POST /v1/saved-searches`
- `DELETE /v1/saved-searches/{id}`

Internal:
- `POST /v1/internal/rematch` protected with `X-Intent-Key`

## Product rules

- Notifications require explicit opt-in.
- Saving a search is a meaningful lead event; browsing a card is engagement, not automatically a qualified lead.
- Existing inventory is marked as the baseline when a search is saved.
- A listing code is notified once per saved search. Mere photo/copy fingerprint changes do not produce duplicate alerts.
- Growth/CRM integrations are soft dependencies where possible. Catalog availability must not be held hostage by analytics.
- Operator and QA Telegram IDs are marked as test traffic so production proof metrics stay clean.

## Portability

Another agency needs adapters/config for:
- tenant/brand
- Telegram bot + Mini App URL
- normalized inventory feed
- CRM API
- Growth Core tenant
- operator destination

The saved-search model and event semantics remain unchanged.
