#!/usr/bin/env bash
set -euo pipefail
ENV=/opt/property-intent-core/.env
KEY="$(grep '^SERVICE_KEY=' "$ENV" | cut -d= -f2-)"
test -n "$KEY"
curl -fsS --retry 2 --retry-all-errors --max-time 15   -X POST -H "X-Intent-Key: $KEY"   http://127.0.0.1:8050/v1/internal/reconcile-integrations
echo
