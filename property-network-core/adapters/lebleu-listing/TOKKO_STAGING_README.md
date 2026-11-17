# Property Network / «Где жить» — Tokko staging 2026-11-17

Status: read-only adapter, offline tested; NOT production. Existing Le Bleu website parser and scheduled publisher remain unchanged.

## Verified findings

- Tokko authentication: server credential outside repo, /etc/fiodor/credentials/tokko_api_key; live page meta.total_count=141.
- Existing live catalog on VPS: 134 property rows at last checkpoint.
- Existing public tokens depend on code and sha256(sourceUrl). Swapping all URLs to Tokko breaks Telegram links, translation and quality data; preserve legacy sourceUrl for verified matches.
- Rafael audit: 25 Tokko rows; 21 reference codes overlap with live catalog, 20 matching visible addresses. LAP7925869 has a marketing paragraph instead of a street address on the old site. Review before mapping. Four more Tokko objects were not in the then-live catalog.
- The public Tokko endpoint returns publicly publishable properties (status 2), not all CRM records. Tokko field deleted_at often means last modified; do not use it to infer a property removal. Inspect inactiveproperty for withdrawals. Tokko latitude/longitude may be inconsistent with its location label.
- GitHub main SHA 6e069d1 is stale versus VPS local git HEAD fd9fde0. This feature branch only adds isolated files and must be rebased onto exact production tree before deployment.

## Implementation

The script scripts/tokko_catalog_sync.py reads key only from protected server file, fetches complete Tokko pages in batches of 20 with bounded timeouts, maps prices, operations, types, photos, addresses and details into current public catalog JSON schema. It strips contact snippets and never serializes producer, lead_receiver_user, branch or raw private Tokko fields. For recognized code+operation+street it preserves existing sourceUrl/slug; all ambiguous matches block cutover. New entries use public ficha.info links and do not trust unverified Tokko GPS.

The script writes only /opt/property-network-tokko-staging/candidate-catalog.json and audit.json. Production catalog is explicitly guarded. It never publishes or modifies the current timer.

Offline tests (5):
python3 -m unittest -v scripts/test_tokko_catalog_sync.py

Staging command after resource and authorization preflight:
python3 scripts/tokko_catalog_sync.py --legacy /opt/lebleu-listing-bridge/public/data/full/catalog.json --output-dir /opt/property-network-tokko-staging

Exit 0 means staging comparison gate passed, NOT permission for public cutover. 2 means mapping threshold failed; 3 means abort.

## Production migration gates

1. Compare all 141 Tokko property IDs and operations against 134 previous catalog items, store crosswalk, review address/code collisions including LAP7925869.
2. Verify old listingToken parity and all existing Telegram and client deep links; preserve translated and reviewed copy and public ownership.
3. Validate prices/currencies, gallery completeness, photos, privacy, category, location and publication rights. New Tokko rows require QA before public appearance.
4. For removals, require healthy complete API snapshots twice and verify with inactiveproperty. Never remove records on upstream errors.
5. Add a reversible source switch to exact live existing sync script, use old established 2-hour timer, fail closed, publisher dry-run and controlled 3–5 object canary. No GitHub Actions or Netlify deploy previews.
6. Backup source catalog, quality/translation cache, Telegram publisher state, DB, registry; perform staged web, agent, saved-search and real Telegram deep-link end-to-end acceptance. Activate only with positive evidence and rollback path.

NEXT_ACTION: run protected all-141 staging audit and reconcile crosswalk on authorized VPS, resolve conflicts, implement reversible pipeline switch, then controlled live cutover after QA. No public catalog source has yet been replaced.
