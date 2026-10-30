#!/usr/bin/env bash
set -euo pipefail
cleanup() {
  systemctl start intent-radar.service >/dev/null 2>&1 || true
}
trap cleanup EXIT
systemctl stop intent-radar.service
cd /opt/intent-radar
timeout 90s venv/bin/python /opt/lebleu-listing-bridge/scripts/channel-integrity-audit.py "$@"
