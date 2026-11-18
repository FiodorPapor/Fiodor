#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
LOCK=/run/lock/lebleu-listing-sync.lock
exec 9>"$LOCK"
flock -n 9 || { echo "sync already running"; exit 0; }
cd "$ROOT"

drain_user_delete_queue() {
  if ! python3 - <<'PY'
import json
from pathlib import Path
p=Path("/opt/lebleu-listing-bridge/state/telegram-user-delete-queue.json")
try:
    raw=json.loads(p.read_text())
except Exception:
    raw=[]
raise SystemExit(0 if isinstance(raw,list) and len(raw)>0 else 1)
PY
  then
    return 0
  fi

  echo "[$(date -Is)] Telegram old-message cleanup via User API"
  local was_active=0
  if systemctl is-active --quiet intent-radar.service; then
    was_active=1
    systemctl stop intent-radar.service
  fi
  local rc=0
  timeout 90s /opt/intent-radar/venv/bin/python scripts/drain-user-delete-queue.py || rc=$?
  if [[ "$was_active" -eq 1 ]]; then
    systemctl start intent-radar.service
  fi
  if [[ "$rc" -ne 0 ]]; then
    echo "[$(date -Is)] ERROR Telegram user-delete queue was not fully drained"
    return "$rc"
  fi
}

drain_user_delete_queue
SOURCE_MODE_FILE=/opt/property-network-tokko-staging/source-mode
SOURCE_MODE="$(cat "$SOURCE_MODE_FILE" 2>/dev/null || echo website)"
case "$SOURCE_MODE" in
  website)
    echo "[$(date -Is)] website source refresh (legacy rollback mode)"
    npx tsx scripts/lebleu-telegram-sync.ts --out "$ROOT/public/data/full" --cta @LeBleuArgentinaBot --chat-id @PREVIEW_ONLY
    echo "[$(date -Is)] website catalog visual deduplication"
    timeout 180s node scripts/normalize-catalog-quality.mjs
    ;;
  tokko)
    echo "[$(date -Is)] Tokko authenticated catalog fetch"
    timeout 150s python3 /opt/property-network-tokko-staging/code/tokko_catalog_sync.py \
      --legacy "$ROOT/public/data/full/catalog.json" \
      --output-dir /opt/property-network-tokko-staging/candidate
    echo "[$(date -Is)] Tokko exact-token atomic promotion"
    timeout 20s python3 /opt/property-network-tokko-staging/code/tokko_promote.py --apply
    # No website scraping or large all-photo image hash pass in Tokko mode.
    # Five independently checked physical duplicates are suppressed upstream.
    ;;
  *)
    echo "Invalid source mode (accepted: tokko or website); refusing sync" >&2
    exit 2
    ;;
esac

echo "[$(date -Is)] Russian content candidate refresh"
# Machine translation is staging only. It must never overwrite user-facing
# reviewed Russian copy automatically; new/changed listings use the clean
# structured Russian fallback until the candidate is reviewed.
if [[ "$SOURCE_MODE" == "website" ]]; then
  if ! timeout 150s "$ROOT/.venv-runtime/bin/python" scripts/refresh-ru-content.py; then
    echo "[$(date -Is)] WARN Russian content candidate refresh failed; using reviewed copy / structured fallback"
  fi
else
  # Tokko can add new cards; unreviewed ones use trustworthy RU structured
  # facts. Heavy machine translation is deferred until resource gate GREEN.
  echo "[$(date -Is)] Tokko RU: preserve reviewed copy; structured fallback for new cards"
fi

# Official Argentina Georef reverse-geocoding is enrichment only. Keep the last
# successful cache if the public API is temporarily unavailable.
echo "[$(date -Is)] geo enrichment"
if ! timeout 45s python3 scripts/enrich-geo.py; then
  echo "[$(date -Is)] WARN geo enrichment unavailable; keeping previous cache"
fi

npx tsx scripts/build-preview-data.ts || true
echo "[$(date -Is)] publish start"
# Public Telegram copy uses sourceUrl-bound, human-reviewed Russian content.
# New or changed source fingerprints fall back to clean structured facts until reviewed.
# Publisher checkpoints its state after every object. Bound the whole run so a
# Telegram/network anomaly cannot wedge the sync service forever. A later sync safely resumes.
if ! timeout 600s npx tsx scripts/telegram-publisher.ts --apply \
  --limit-new 2 --limit-reposts 2; then
  echo "[$(date -Is)] ERROR telegram publisher failed or exceeded 10 minutes"
  exit 1
fi
drain_user_delete_queue

echo "[$(date -Is)] catalog navigation refresh"
if ! timeout 60s python3 scripts/update-category-index.py; then
  echo "[$(date -Is)] WARN general catalog index refresh failed"
fi
if ! timeout 90s python3 scripts/update-topic-catalog-pins.py; then
  echo "[$(date -Is)] WARN topic catalog pins refresh failed"
fi

# Saved-search reactivation is deliberately a soft dependency: catalogue sync must
# never fail because the notification service is unavailable.
INTENT_ENV=/opt/property-intent-core/.env
if [[ -r "$INTENT_ENV" ]]; then
  INTENT_KEY="$(grep '^SERVICE_KEY=' "$INTENT_ENV" | cut -d= -f2-)"
  if [[ -n "$INTENT_KEY" ]]; then
    echo "[$(date -Is)] saved-search rematch"
    if ! curl -fsS --max-time 20 -X POST -H "X-Intent-Key: $INTENT_KEY"       http://127.0.0.1:8050/v1/internal/rematch; then
      echo "[$(date -Is)] WARN saved-search rematch unavailable"
    fi
    echo
  fi
fi

echo "[$(date -Is)] sync done"
