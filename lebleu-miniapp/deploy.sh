#!/usr/bin/env bash
set -euo pipefail
cd /opt/lebleu-miniapp
LOG=/tmp/lebleu-miniapp-deploy.$$.log
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT
npm run build >"$LOG" 2>&1
if ! timeout 120s docker compose build app >>"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi
docker compose up -d app >>"$LOG" 2>&1
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 https://lebleu-app.srv1636153.hstgr.cloud/ >/dev/null 2>&1; then
    curl -fsS --max-time 3 https://lebleu-app.srv1636153.hstgr.cloud/api/v1/catalog |
      python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["count"]>0; print("lebleu-miniapp healthy",d["count"])'
    exit 0
  fi
  sleep 1
done
docker compose ps >&2
docker logs --tail 80 lebleu-miniapp >&2 || true
exit 1
