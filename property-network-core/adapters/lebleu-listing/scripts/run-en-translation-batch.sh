#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/lebleu-listing-bridge
LOCK=/run/lock/lebleu-en-translation.lock
MAX_ITEMS="${LEBLEU_EN_TRANSLATION_BATCH:-8}"
CATALOG="$ROOT/public/data/full/catalog.json"
STATE="$ROOT/state/en-content.json"
VERSION=opus-mt-es-en-v1
exec 9>"$LOCK"
flock -n 9 || { echo "english translation batch already running"; exit 0; }
pending="$(python3 - "$CATALOG" "$STATE" "$VERSION" <<'PY2'
import json,sys
cat=json.load(open(sys.argv[1]))
try: state=json.load(open(sys.argv[2]))
except Exception: state={}
version=sys.argv[3]; n=0
for x in cat:
    src=str(x.get('description') or '').strip(); url=str(x.get('sourceUrl') or ''); fp=str(x.get('sourceFingerprint') or '')
    if not url or len(src)<20: continue
    row=state.get(url) or {}
    if row.get('fingerprint')==fp:
        if row.get('status') in {'live_auto','source_missing'}: continue
        if row.get('status')=='needs_review' and row.get('translator')==version: continue
    n+=1
print(n)
PY2
)"
if [[ "$pending" -le 0 ]]; then echo "english translation backlog empty"; exit 0; fi
echo "english translation backlog=$pending batch=$MAX_ITEMS"
export HF_HOME="$ROOT/.hf-cache"
cd "$ROOT"
timeout 900s .venv-marian/bin/python scripts/refresh-en-content.py --max-items "$MAX_ITEMS"
