# Tokko API · «Где жить» production runbook

## Status 2026-11-18 00:50 UTC
**PRODUCTION LIVE.** Source selector is `tokko`, not website. The two-hour `lebleu-listing-sync.timer` now fetches from authenticated Tokko on the VPS and does NOT scrape Le Bleu in this mode. Existing public URLs are retained solely as immutable listing IDs for Telegram and CRM attribution. The API key remains at `/etc/fiodor/credentials/tokko_api_key` and must never be exposed.

### Evidence
- Tokko publicable API: 141 upstream objects. Normalized publication variants originally 146; five independently image-matched physical duplicates suppressed. Exactly 141 canonical catalog cards: 134 legacy preserved plus 7 new.
- Token parity: 134/134 existing code + sha256(sourceUrl) preserved. Prices and currency parity on initial cutover: 134/134.
- Live backend `GET /api/v1/catalog`: 141; two direct detail endpoint smoke checks HTTP 200.
- Publisher: 141 active listings with Telegram message IDs after two safe batches (2 + 5 new); 0 removals or mass media reposts; Telegram topic/category indexes refreshed to 141.
- Full first source timer run: 2026-11-18 00:37:04–00:38:40 UTC, systemd result success, exit 0, low resource use. Subsequent import after cutover matched 141/141, no conflicts; full second production run with deactivation gate should be verified after deploy.
- Watchdog understands Tokko provenance. Service exits 0, status `degraded` with **0 critical issues**, because 26 Russian free-text descriptions still lack human approval and 4 are stale. The app serves structured Russian factual fallback; do not relabel these reviews as approved.
- Saved-search: two opted-in searches have **web-only nonaddressable IDs**, no Telegram recipient, and no configured push/email delivery. Matches remain pending. These are not Tokko API errors; UI should ask users to connect a valid notification channel.

### Code path
- `scripts/tokko_catalog_sync.py`: authenticated read-only paginated Tokko import; full-response validation; safe public fields; compatibility crosswalk; five verified duplicate aliases; preserving text-review fingerprints.
- `scripts/tokko_retire.py`: first absence held; second full successful snapshot >=3600s later allows bounded deactivation, max 5% or minimum 5 records; fail closed for API errors or bulk disappearance.
- `scripts/tokko_promote.py`: fully validated atomic overwrite, sha256-checked backup, preserves public deep-link tokens, rejects ambiguous IDs/unauthorized removals. No-op for identical catalogs.
- `sync.sh`: mode read from `/opt/property-network-tokko-staging/source-mode` (values: `tokko`, `website`). In Tokko mode never invokes site scraper or old image-normalizer, updates source/translation summaries, publisher, navigation and saved-search matches.
- `scripts/telegram-publisher.ts`: first Tokko image URL baseline does not recreate historical posts solely for CDN host changes; per-cycle caps: 2 new, 2 media replacements, 5 text edits, 5 tracked-link edits. `--only-codes` canary skips unrelated deletions. Growth tracking fallback blocked if live growth channel is unavailable.
- `scripts/product-health-watch.py`: Tokko audit instead of stale website visual report. Critical health separated from honest editorial translation warnings.

### Useful checks
```sh
systemctl is-active lebleu-listing-sync.timer
cat /opt/property-network-tokko-staging/source-mode
systemctl show lebleu-listing-sync.service -p Result -p ExecMainStatus
systemctl show lebleu-product-health.service -p Result -p ExecMainStatus
python3 /opt/property-network-tokko-staging/code/tokko_promote.py
python3 -m unittest -q /opt/property-network-tokko-staging/code/test_tokko_catalog_sync.py /opt/property-network-tokko-staging/code/test_tokko_retire.py
curl -fsS https://lebleu-app.srv1636153.hstgr.cloud/api/v1/catalog
```
Avoid printing the Tokko credential in logs or shell history. The published listing JSON and Telegram state are live data, not test fixtures.

### Backups and rollback
Pre-cutover backup: `/opt/property-network-backups/tokko-cutover-20261118T0035Z/`. Every real catalog replacement is also backed up to `/opt/property-network-backups/tokko-catalog/`.

- On a Tokko outage the current mode fails closed and retains the last healthy catalog. Do **not** automatically switch to the website or delete listings.
- For an explicit emergency rollback: stop the sync timer, preserve a current publisher-state snapshot and catalog, review new API-only posts, then select `website` mode and perform a scoped dry-run to ensure historical post/message IDs are protected. Do **not** simply restore the old publisher-state JSON, since that would orphan seven already posted new messages.
- For a bad catalog import, under the sync lock atomically restore the last known-good catalog backup, verify public API and 141 saved listing identities, and then re-run the publisher in dry-run before an apply.
- Source mode switch does not require GitHub Actions or Netlify. GitHub main was behind the VPS canonical code at initial cutover; don't merge without reconciling the live Git history.

### Remaining editorial/product work
1. Review and approve 26 missing + 4 stale RU descriptions; keep structured RU fallbacks until approval.
2. Enable a delivery channel for two anonymous saved-search users or change the UI to distinguish in-app pending matches from push/email/Telegram notifications.
3. Confirm next 02:00 UTC automatic timer run with the two-snapshot retirement gate.
4. Track public Tokko publication changes, any missing rows and safe retirements in audit logs.
