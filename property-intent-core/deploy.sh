#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
LOG=/tmp/property-intent-deploy.$$.log
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT

env_value() {
  local key="$1" default="$2" value
  value="$(grep -E "^${key}=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  printf '%s' "${value:-$default}"
}
HOST_PORT="$(env_value HOST_PORT 8050)"
CONTAINER_PREFIX="$(env_value CONTAINER_PREFIX property-intent)"

python3 -m py_compile app/main.py
if ! timeout 120s docker compose build api >"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi
docker compose up -d api >>"$LOG" 2>&1
for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${HOST_PORT}/health" >/dev/null 2>&1; then
    python3 - <<'PY'
import json
import urllib.request
from pathlib import Path

env={}
for raw in Path(".env").read_text().splitlines():
    line=raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key,value=line.split("=",1)
    env[key]=value.strip().strip('"').strip("'")
token=env.get("TELEGRAM_BOT_TOKEN","")
url=env.get("MENU_BUTTON_URL") or env.get("MINIAPP_URL","")
menu_text=env.get("MENU_BUTTON_TEXT","Каталог")
if token and url:
    payload=json.dumps({
        "menu_button":{
            "type":"web_app",
            "text":menu_text,
            "web_app":{"url":url}
        }
    }).encode()
    req=urllib.request.Request(
        f"https://api.telegram.org/bot{token}/setChatMenuButton",
        data=payload,
        headers={"Content-Type":"application/json"},
    )
    with urllib.request.urlopen(req,timeout=8) as response:
        result=json.load(response)
    if not result.get("ok"):
        raise SystemExit("Telegram menu button update failed")
PY
    echo "property-intent-core healthy"
    exit 0
  fi
  sleep 1
done
docker compose ps >&2
docker logs --tail 80 "${CONTAINER_PREFIX}-api" >&2 || true
exit 1
