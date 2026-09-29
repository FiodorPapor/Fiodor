#!/usr/bin/env bash
set -euo pipefail
cd /opt/growth-core
LOG=/tmp/growth-core-deploy.$$.log
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT
python3 -m py_compile app/main.py
if ! timeout 120s docker compose build api >"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi
docker compose up -d api >>"$LOG" 2>&1
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 http://127.0.0.1:8040/health >/dev/null 2>&1; then
    echo "growth-core healthy"
    /opt/growth-core/smoke-test.sh
    exit 0
  fi
  sleep 1
done
docker compose ps >&2
docker logs --tail 80 growth-core-api >&2 || true
exit 1
