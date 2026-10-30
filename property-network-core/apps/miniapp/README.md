# Property Network Mini App

Tenant-aware consumer property discovery UI for the neutral Property Network platform.

The UI does not own agency inventory, CRM data or acquisition analytics. It consumes Property Intent Core and renders tenant identity from `GET /v1/config`.

## Tenant contract

Runtime branding and acquisition configuration comes from Property Intent Core:

- `tenantSlug`
- `brandName`
- `brandTagline`
- `brandLogoUrl`
- `botUsername`
- `defaultLanguage`
- `telegramChannelUrl`
- `attributionCampaign`
- `sourceLabel`

A Telegram channel is optional. When `telegramChannelUrl` is empty, the channel acquisition card is not rendered.

The static `/brand-logo.jpg` path is a deployment artifact, not a source-code brand dependency. Each tenant deployment may materialize its own asset at that path or provide another `brandLogoUrl`.

## Product boundary

Catalog/search/actions use Property Intent Core. The UI must not import source-specific scraping logic or CRM-specific field mappings.

Inventory records use source-bound `listingToken` identifiers because a raw agency listing code is not globally unique in a multi-source network.

Le Bleu is the first production tenant. Its current public branding remains a tenant configuration and is not the neutral product identity.
