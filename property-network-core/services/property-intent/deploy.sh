#!/usr/bin/env bash
set -euo pipefail

SOURCE_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RUNTIME_ROOT="${PROPERTY_INTENT_RUNTIME_ROOT:-/opt/property-intent-core}"
ENV_FILE="${PROPERTY_INTENT_ENV_FILE:-$RUNTIME_ROOT/.env}"
COMPOSE_PROJECT="${PROPERTY_INTENT_COMPOSE_PROJECT:-property-intent-core}"
export PROPERTY_INTENT_ENV_FILE="$ENV_FILE"
AGENT_INBOX_SECRET_FILE="${AGENT_INBOX_SECRET_FILE:-/root/.agent-inbox-access}"
if [[ -r "$AGENT_INBOX_SECRET_FILE" ]]; then
  export AGENT_INBOX_PASSWORD="$(tr -d '\r\n' < "$AGENT_INBOX_SECRET_FILE")"
else
  export AGENT_INBOX_PASSWORD=""
fi

LOG=/tmp/property-intent-deploy.$$.log
cleanup(){
  local rc=$?
  if (( rc != 0 )) && [[ -s "$LOG" ]]; then
    echo "property-intent deploy failed; last log lines:" >&2
    tail -120 "$LOG" >&2 || true
  fi
  rm -f "$LOG"
}
trap cleanup EXIT

test -r "$ENV_FILE" || { echo "Runtime env not readable: $ENV_FILE" >&2; exit 1; }
test -f "$SOURCE_ROOT/app/main.py" || { echo "Source app missing: $SOURCE_ROOT/app/main.py" >&2; exit 1; }

# Validate the exact source candidate before touching the runtime tree.
python3 -m py_compile "$SOURCE_ROOT/app/main.py"
python3 - <<'PYGUARD'
import os
from pathlib import Path
env={}
for raw in Path(os.environ['PROPERTY_INTENT_ENV_FILE']).read_text().splitlines():
    if '=' in raw and not raw.lstrip().startswith('#'):
        k,v=raw.split('=',1); env[k.strip()]=v.strip()
def ids(key):
    return {x.strip() for x in env.get(key,'').split(',') if x.strip()}
test_ids=ids('TEST_TELEGRAM_IDS'); internal_ids=ids('INTERNAL_TELEGRAM_IDS')
if test_ids & internal_ids:
    raise SystemExit('TEST_TELEGRAM_IDS and INTERNAL_TELEGRAM_IDS must not overlap')
if env.get('OPERATOR_CHAT_ID','').strip() in test_ids:
    raise SystemExit('OPERATOR_CHAT_ID must not be a synthetic TEST identity')
PYGUARD

# Canonical Git source and live Compose root are intentionally separate.
# Sync only build/runtime source inputs. Never copy or overwrite secrets/state.
if [[ "$(realpath "$SOURCE_ROOT")" != "$(realpath "$RUNTIME_ROOT")" ]]; then
  mkdir -p "$RUNTIME_ROOT/app" "$RUNTIME_ROOT/data"
  rsync -a --delete "$SOURCE_ROOT/app/" "$RUNTIME_ROOT/app/"
  rsync -a --delete "$SOURCE_ROOT/data/" "$RUNTIME_ROOT/data/"
  install -m 0644 "$SOURCE_ROOT/Dockerfile" "$RUNTIME_ROOT/Dockerfile"
  install -m 0644 "$SOURCE_ROOT/requirements.txt" "$RUNTIME_ROOT/requirements.txt"
  install -m 0644 "$SOURCE_ROOT/docker-compose.yml" "$RUNTIME_ROOT/docker-compose.yml"
  install -m 0755 "$SOURCE_ROOT/deploy.sh" "$RUNTIME_ROOT/deploy.sh"
fi

cd "$RUNTIME_ROOT"

env_value() {
  local key="$1" default="$2" value
  value="$(grep -E "^${key}=" "$ENV_FILE" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  printf '%s' "${value:-$default}"
}
HOST_PORT="$(env_value HOST_PORT 8050)"
CONTAINER_PREFIX="$(env_value CONTAINER_PREFIX property-intent)"

compose=(docker compose -p "$COMPOSE_PROJECT" --project-directory "$RUNTIME_ROOT" --env-file "$ENV_FILE" -f "$RUNTIME_ROOT/docker-compose.yml")

if ! timeout 120s "${compose[@]}" build api >"$LOG" 2>&1; then
  exit 1
fi
"${compose[@]}" up -d api >>"$LOG" 2>&1

for _ in $(seq 1 30); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${HOST_PORT}/health" >/dev/null 2>&1; then
    python3 - <<'PY'
import json
import os
import urllib.request
from pathlib import Path

env={}
for raw in Path(os.environ["PROPERTY_INTENT_ENV_FILE"]).read_text().splitlines():
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

"${compose[@]}" ps >&2 || true
docker logs --tail 80 "${CONTAINER_PREFIX}-api" >&2 || true
exit 1
