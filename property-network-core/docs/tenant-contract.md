# Tenant contract

A normal tenant must be instantiable without editing application source.

## Public configuration

`GET /v1/config` is intentionally non-secret and returns:

```json
{
  "tenantSlug": "agency_slug",
  "brandName": "Agency Name",
  "brandTagline": "Real estate catalog",
  "brandLogoUrl": "/brand-logo.jpg",
  "botUsername": "AgencyCatalogBot",
  "defaultLanguage": "es",
  "telegramChannelUrl": "",
  "attributionCampaign": "agency_catalog",
  "sourceLabel": "agency_original"
}
```

Rules:

- `telegramChannelUrl` may be empty. The UI must then hide the channel acquisition card.
- `brandLogoUrl` may be empty. The UI must work without an image.
- `defaultLanguage` is applied only when the user has not explicitly selected a language.
- `attributionCampaign` and `sourceLabel` are analytics identifiers, not display copy.
- `tenantSlug` is the current tenant namespace and must stay stable after production launch.

## Private configuration

Secrets remain server-side and are never returned by `/v1/config`:

- Telegram bot token
- service/internal keys
- CRM API credentials and webhook secret
- Growth Core key
- database credentials

## Inventory contract

Inventory adapters write normalized catalog data according to `services/property-intent/docs/catalog-contract.md`. Adapter-specific state and scraping code remain outside Property Intent Core.

## Isolation rule

Any persistence table containing user intent, click, action, delivery, collaboration or audit state must carry a tenant namespace and every read/write path must enforce that namespace server-side. The client may not choose an arbitrary tenant for a persistence operation.

## Pilot

`tenants/lebleu/.env.example` records the non-secret Le Bleu values required to reproduce the current pilot identity. Production secrets are intentionally absent.
