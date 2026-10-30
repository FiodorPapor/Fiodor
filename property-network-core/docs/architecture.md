# Property Network architecture

Status: canonical target architecture as of 2026-10-28. Le Bleu is the live pilot tenant.

## Goal

Turn the proven Le Bleu catalog/intention stack into a neutral real-estate network that can onboard multiple agencies without source-code forks while preserving source ownership, lead attribution and operational accountability.

## Runtime topology

```text
agency/source adapter(s)
        |
        v
normalized catalog contract ----> quality/localization/geo state
        |
        v
Property Intent Core <----------> PostgreSQL
        |     |   \
        |     |    +----> signed CRM adapter/webhook
        |     +---------> Growth Core (external attribution service)
        v
Tenant Mini App
        |
        +----> Telegram bot/private notifications
        +----> optional acquisition/editorial channel
```

Le Bleu-specific scraping, translation jobs and Telegram publishing live under `adapters/lebleu-listing`. They are not dependencies of the neutral domain core.

## Core identities

- **tenant**: commercial/operator boundary that owns branding, bot, CRM adapter and lead routing.
- **source**: origin of inventory. A tenant may expose its own source plus partner sources.
- **listingToken**: globally safe source-bound listing identity. Never assume an agency-local listing code is globally unique.
- **actor**: end user or operator identity in a tenant context.
- **intent**: explicit demand signal such as saved search, availability request, viewing request or question.
- **attribution**: acquisition context carried from placement to downstream lead/deal events.

## Non-negotiable invariants

1. Tenant identity and branding come from configuration, not source-code branches.
2. A tenant cannot read or mutate another tenant's saved searches, actions, clicks or CRM delivery state.
3. Inventory source ownership is preserved even when listings are shown in another tenant's catalog.
4. Telegram channels are optional acquisition surfaces, never catalog state or a required subscription.
5. CRM and Growth Core are adapters/soft dependencies. Catalog browsing must survive their failure.
6. Existing inventory is the baseline for a saved search. Notifications represent newly relevant supply, not repeated content changes.
7. All partner/agency collaboration actions must be auditable and idempotent.
8. Public cutovers are reversible. Le Bleu production remains unchanged until an exact candidate passes contract, browser and data-integrity gates.

## Repository boundaries

- `apps/miniapp`: generic tenant consumer UI.
- `services/property-intent`: domain core and tenant-scoped persistence/API.
- `adapters/lebleu-listing`: first inventory/source adapter.
- `tenants/lebleu`: non-secret pilot configuration and brand assets.
- Growth Core remains a separate service.
- CRM implementations remain separate adapters.

## Evolution path

### Phase 1: tenant and brand separation

Move brand name, logo, default language, optional channel, attribution campaign and source label to runtime config. Preserve Le Bleu output through its tenant config.

### Phase 2: source registry and network catalog

Add explicit source metadata to normalized listings and a registry of participating inventory providers. Catalog policy decides which sources a tenant may expose. Source ownership and contact-routing rules travel with each listing.

### Phase 3: lead routing and attribution

Persist origin tenant, inventory source, placement attribution and responsible destination for every qualified intent. Route once through an idempotent delivery record. Preserve the chain through viewing, reservation and won-deal events.

### Phase 4: collaboration and demand exchange

Represent buyer/tenant demand as a privacy-minimized structured demand card. Agents may publish or match demand to permitted inventory without exposing the end client's direct contact until collaboration rules allow it.

### Phase 5: agency onboarding

One onboarding manifest creates tenant identity, catalog adapter, bot/Mini App config, CRM delivery adapter and Growth Core tenant. No application code changes are required for a normal new agency.
