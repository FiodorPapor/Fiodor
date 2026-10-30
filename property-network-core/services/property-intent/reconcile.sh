#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ENV="$ROOT/.env"
KEY="$(grep '^SERVICE_KEY=' "$ENV" | cut -d= -f2-)"
PORT="$(grep '^HOST_PORT=' "$ENV" 2>/dev/null | tail -1 | cut -d= -f2- || true)"
PORT="${PORT:-8050}"
test -n "$KEY"
curl -fsS --retry 2 --retry-all-errors --max-time 15   -X POST -H "X-Intent-Key: $KEY"   "http://127.0.0.1:${PORT}/v1/internal/reconcile-integrations"
echo
