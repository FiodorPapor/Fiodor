#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
LOCK=/run/lock/lebleu-full-ru-translation.lock
MAX_ITEMS="${LEBLEU_TRANSLATION_BATCH:-2}"
CATALOG="$ROOT/public/data/full/catalog.json"
STATE="$ROOT/state/ru-full-translations.json"
MODEL=/opt/fichaflow-translate/models/translategemma/translategemma-4b-it-Q4_K_M.gguf
LLAMA=/opt/fichaflow-translate/llama.cpp/build/bin/llama-server
PORT=3015
VERSION=translategemma-4b-q4-protected-v3

exec 9>"$LOCK"
flock -n 9 || { echo "translation batch already running"; exit 0; }

pending="$(python3 - "$CATALOG" "$STATE" "$VERSION" <<'PY'
import json,sys
cat=json.load(open(sys.argv[1]))
try: state=json.load(open(sys.argv[2]))
except Exception: state={}
version=sys.argv[3]
n=0
for x in cat:
    src=str(x.get('description') or '').strip()
    if len(src)<35: continue
    url=str(x.get('sourceUrl') or '')
    fp=str(x.get('ruContentFingerprint') or x.get('sourceFingerprint') or '')
    row=state.get(url) or {}
    if row.get('fingerprint')==fp:
        if row.get('status') in {'live_auto','source_missing'}: continue
        if row.get('status')=='needs_review' and row.get('translator')==version: continue
    n+=1
print(n)
PY
)"
if [[ "$pending" -le 0 ]]; then
  echo "translation backlog empty"
  exit 0
fi

echo "translation backlog=$pending batch=$MAX_ITEMS"
if ss -ltnH "sport = :$PORT" | grep -q .; then
  echo "port $PORT already in use; skip to avoid overlapping translator" >&2
  exit 0
fi

TG_PID=""
cleanup() {
  if [[ -n "$TG_PID" ]]; then
    kill "$TG_PID" 2>/dev/null || true
    wait "$TG_PID" 2>/dev/null || true
  fi
}
trap cleanup EXIT INT TERM

"$LLAMA" -m "$MODEL" --host 127.0.0.1 --port "$PORT" -c 3072 -t 2 -np 1 --no-jinja --chat-template gemma >/tmp/lebleu-translategemma.log 2>&1 &
TG_PID=$!
for _ in $(seq 1 50); do
  if curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/health" >/dev/null 2>&1; then break; fi
  if ! kill -0 "$TG_PID" 2>/dev/null; then tail -60 /tmp/lebleu-translategemma.log >&2; exit 1; fi
  sleep 1
done
curl -fsS --max-time 2 "http://127.0.0.1:${PORT}/health" >/dev/null
LEBLEU_TRANSLATION_ENDPOINT="http://127.0.0.1:${PORT}/v1/chat/completions" \
  timeout 480s python3 "$ROOT/scripts/refresh-full-ru-descriptions.py" --max-items "$MAX_ITEMS"
