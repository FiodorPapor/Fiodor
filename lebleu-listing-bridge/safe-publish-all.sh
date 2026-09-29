#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
LOCK=/run/lock/lebleu-listing-sync.lock
LOG=/tmp/lebleu-publish-all.$$.log
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT

exec 9>"$LOCK"
if ! flock -w 20 9; then
  echo "could_not_acquire_publish_lock" >&2
  exit 75
fi
cd "$ROOT"

is_current() {
  timeout 45s npx tsx scripts/telegram-publisher.ts >"$LOG" 2>&1 || return 1
  python3 - "$LOG" <<'PY'
import json,re,sys
text=open(sys.argv[1],encoding="utf-8").read()
m=re.search(r'\{\s*"apply":\s*false,.*?\n\}',text,re.S)
if not m:
    raise SystemExit(2)
data=json.loads(m.group(0))
pending=sum(int(data.get(k,0)) for k in ("created","changed","photosChanged","removed","errors"))
print("preflight",json.dumps({k:data.get(k) for k in ("inventory","created","changed","photosChanged","removed","unchanged","errors")},ensure_ascii=False))
raise SystemExit(0 if pending==0 else 10)
PY
}

for pass_no in 1 2 3 4 5 6; do
  set +e
  is_current
  status=$?
  set -e
  if [[ "$status" -eq 0 ]]; then
    echo "VERIFIED_ALL pass=$pass_no"
    exit 0
  fi
  if [[ "$status" -ne 10 ]]; then
    echo "preflight_failed pass=$pass_no" >&2
    tail -80 "$LOG" >&2
    exit 1
  fi

  echo "apply_pass=$pass_no max_seconds=90"
  set +e
  timeout 90s npx tsx scripts/telegram-publisher.ts --apply >"$LOG" 2>&1
  apply_status=$?
  set -e
  if [[ "$apply_status" -eq 0 ]]; then
    echo "apply_pass=$pass_no completed"
  elif [[ "$apply_status" -eq 124 ]]; then
    echo "apply_pass=$pass_no checkpoint_timeout; resuming from saved state"
  else
    echo "apply_pass=$pass_no failed status=$apply_status" >&2
    tail -100 "$LOG" >&2
    exit "$apply_status"
  fi
  tail -12 "$LOG" || true
done

echo "publisher_not_converged_after_6_passes" >&2
tail -80 "$LOG" >&2
exit 2
