# Agency onboarding

The reusable product is split into four seams:

1. **Inventory adapter** → normalized catalog contract.
2. **Property Intent Core** → search, saved search, opt-in notifications and reactivation.
3. **Growth Core** → first-party attribution, events, spend and funnel economics.
4. **CRM adapter** → native API mapping or the signed webhook contract.

Le Bleu is the pilot tenant, not a hard dependency.

## Minimum onboarding

### 1. Identity

Choose:

- tenant slug
- brand name
- Telegram bot
- Mini App HTTPS origin
- operator destination

Copy `.env.example` to a private `.env`. Never commit production secrets.

### 2. Inventory

Build one upstream adapter that writes `catalog.json` according to `docs/catalog-contract.md`.

The adapter may read an agency CRM, XML/JSON feed, portal API, database export or another lawful source. Keep source-specific code outside Property Intent Core.

### 3. Growth

Create a Growth Core tenant and use deterministic links for every materially different acquisition placement:

`source + medium + campaign + content + placement + listing/intent`.

Do not compare channels by clicks alone. Carry attribution to qualified lead, scheduled viewing, reservation and won deal.

### 4. CRM

Preferred portable route:

`Property Intent Core -> signed lead.saved_search webhook -> adapter/n8n -> agency CRM`.

The CRM receiver must respect the idempotency key. See `docs/crm-webhook.md`.

If a native adapter is worthwhile, map only explicit CRM lifecycle actions to canonical Growth events. Never infer a viewing or reservation from a vague pipeline stage.

### 5. Notifications

Telegram notification permission is explicit opt-in. Existing inventory is the baseline when a search is saved. Only newly relevant inventory should reactivate the user.

### 6. Deployment

The Docker Compose file supports per-instance configuration:

- `CONTAINER_PREFIX`
- `HOST_PORT`
- `SHARED_NETWORK`
- `CATALOG_HOST_PATH`
- `QUALITY_HOST_PATH`
- `GEO_HOST_PATH`

This allows multiple agency instances on the same host without renaming source code.

### 7. Proof metrics

Start with a clean baseline. Mark operator/QA users as test traffic.

For every campaign capture actual spend only when it is real. Report:

- people / bot starts
- Mini App opens
- qualified leads
- scheduled viewings
- reservations
- won deals
- completed shares / earned acquisition
- CPL
- cost per viewing
- cost per win

Do not backfill invented attribution into a case study.
