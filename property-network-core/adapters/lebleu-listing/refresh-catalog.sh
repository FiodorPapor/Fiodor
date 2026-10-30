#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
LOCK=/run/lock/lebleu-catalog-refresh.lock
exec 9>"$LOCK"
flock -n 9 || { echo "catalog refresh already running"; exit 0; }
cd "$ROOT"
echo "[$(date -Is)] Le Bleu catalog-only refresh start"
npx tsx scripts/lebleu-telegram-sync.ts   --out "$ROOT/public/data/full"   --cta @FiodorCRMControlBot   --chat-id @PREVIEW_ONLY
npx tsx scripts/build-preview-data.ts || true
echo "[$(date -Is)] Le Bleu catalog-only refresh done"
