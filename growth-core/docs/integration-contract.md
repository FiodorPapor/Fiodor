# Integration contract

Growth Core is the portable measurement layer. Agency-specific CRM and inventory systems are adapters.

## 1. Acquisition link

Create one deterministic tracking link for every materially different acquisition placement.

Required dimensions:

- `tenant`: agency/account
- `source`: platform or partner, e.g. `telegram_ads`, `telegram_partner`, `instagram`, `google`, `referral`
- `medium`: `paid`, `organic`, `partner`, `owned`
- `campaign`: stable campaign name
- `content`: creative or CTA variant
- `placement`: channel, post, ad group, bio, landing placement
- `listing_code` or `intent`: optional destination context

The result is a bot deep link using a compact `trk_<token>` start parameter.

## 2. First-party event capture

When the bot resolves a tracking token, preserve the attribution metadata with the lead/opportunity record. Emit product actions separately from commercial lifecycle events.

Recommended product events:

- bot_started
- listing_opened
- gallery_opened
- search_started / search_submitted
- availability_requested
- question_submitted
- viewing_requested

Commercial events:

- lead_qualified
- viewing_scheduled
- reservation_started
- deal_won / deal_lost

Never infer a commercial event from a vague CRM stage. Map only when the agency system has equivalent semantics.

## 3. CRM adapter

A CRM adapter needs only three responsibilities:

1. Store the Growth tracking token / dimensions on the lead or opportunity.
2. Emit lifecycle events when explicit CRM actions occur.
3. Provide an idempotent external object key so events are not duplicated.

Suggested mapping:

| Canonical event | Example CRM trigger |
| --- | --- |
| lead_qualified | qualification complete / active mandate |
| viewing_scheduled | explicit viewing appointment created |
| reservation_started | reservation / offer / booking explicitly created |
| deal_won | opportunity closed won / operation completed |
| deal_lost | opportunity closed lost |

## 4. Spend adapter

Paid channels import spend independently of conversions:

- source
- medium
- campaign
- placement
- period
- amount + currency
- impressions
- clicks

Zero-conversion spend must remain visible. Do not join spend only to campaigns that already have events.

## 5. Le Bleu pilot

Current pilot wiring:

- forum listing CTA -> tracked Telegram bot deep link
- General “Подобрать под мой запрос” -> tracked Telegram bot deep link
- bot resolves token and records bot/listing/search activity
- qualification emits lead_qualified
- explicit CRM won/lost transitions emit deal_won/deal_lost
- operator/test identity is flagged and excluded from production metrics by default

The publisher uses soft fallback to the legacy listing deep link if Growth Core is unavailable. Analytics may degrade, but catalog publishing must continue.

## 6. Future agency onboarding

To onboard another agency, configure:

- tenant
- bot / Mini App destination
- inventory adapter
- CRM lifecycle adapter
- source/campaign naming
- spend importer

The event schema and reporting layer remain unchanged.
