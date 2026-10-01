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
echo "[$(date -Is)] scan start"
npx tsx scripts/lebleu-telegram-sync.ts --out "$ROOT/public/data/full" --cta @LeBleuArgentinaBot --chat-id @PREVIEW_ONLY

echo "[$(date -Is)] catalog quality normalization"
timeout 180s node scripts/normalize-catalog-quality.mjs

echo "[$(date -Is)] Russian content candidate refresh"
# Machine translation is staging only. It must never overwrite user-facing
# reviewed Russian copy automatically; new/changed listings use the clean
# structured Russian fallback until the candidate is reviewed.
if ! timeout 150s "$ROOT/.venv-marian/bin/python" scripts/refresh-ru-content.py; then
  echo "[$(date -Is)] WARN Russian content candidate refresh failed; using reviewed copy / structured fallback"
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
if ! timeout 600s npx tsx scripts/telegram-publisher.ts --apply; then
  echo "[$(date -Is)] ERROR telegram publisher failed or exceeded 10 minutes"
  exit 1
fi
drain_user_delete_queue

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
