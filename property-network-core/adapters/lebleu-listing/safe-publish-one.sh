#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
CODE="${1:-}"
if [[ -z "$CODE" ]]; then
  echo "usage: $0 LISTING_CODE" >&2
  exit 64
fi
LOG="/tmp/lebleu-publish-${CODE//[^A-Za-z0-9_-]/_}.$$.log"
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT
cd "$ROOT"

echo "[1/3] dry-run $CODE"
if ! timeout 45s npx tsx scripts/telegram-publisher.ts --only-codes "$CODE" >"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi

if ! grep -Eq "RELINK $CODE|EDIT $CODE|REPOST $CODE|NEW $CODE" "$LOG"; then
  echo "already_current=true"
  exit 0
fi

echo "[2/3] apply $CODE"
if ! timeout 75s npx tsx scripts/telegram-publisher.ts --apply --only-codes "$CODE" >"$LOG" 2>&1; then
  tail -100 "$LOG" >&2
  exit 1
fi
tail -35 "$LOG"

echo "[3/3] verify $CODE"
if ! timeout 45s npx tsx scripts/telegram-publisher.ts --only-codes "$CODE" >"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi
if grep -Eq "RELINK $CODE|EDIT $CODE|REPOST $CODE|NEW $CODE" "$LOG"; then
  echo "verification_failed" >&2
  tail -80 "$LOG" >&2
  exit 2
fi
echo "VERIFIED $CODE"
