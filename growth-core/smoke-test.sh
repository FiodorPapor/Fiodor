#!/usr/bin/env bash
set -euo pipefail
ROOT=/opt/growth-core
set -a
. "$ROOT/.env"
set +a
TENANT="qa_smoke_$$"
cleanup() {
  docker exec -i growth-core-db psql -U "$POSTGRES_USER" -d "$POSTGRES_DB" -v ON_ERROR_STOP=1 -q <<SQL >/dev/null 2>&1 || true
DELETE FROM events WHERE tenant_id=(SELECT id FROM tenants WHERE slug='$TENANT');
DELETE FROM spend WHERE tenant_id=(SELECT id FROM tenants WHERE slug='$TENANT');
DELETE FROM tracking_links WHERE tenant_id=(SELECT id FROM tenants WHERE slug='$TENANT');
DELETE FROM tenants WHERE slug='$TENANT';
SQL
}
trap cleanup EXIT

TENANT="$TENANT" SERVICE_KEY="$SERVICE_KEY" python3 - <<'PY'
import json, os, urllib.parse, urllib.request
from datetime import datetime, timezone

base="http://127.0.0.1:8040"
tenant=os.environ["TENANT"]
key=os.environ["SERVICE_KEY"]

def call(path, payload=None):
    data=None if payload is None else json.dumps(payload).encode()
    req=urllib.request.Request(
        base+path,
        data=data,
        headers={"X-Growth-Key":key,"Content-Type":"application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req,timeout=8) as r:
        return json.load(r)

link=call("/v1/links/ensure",{
    "tenant":tenant,
    "source":"qa_source",
    "medium":"qa",
    "campaign":"qa_campaign",
    "content":"smoke",
    "placement":"smoke",
    "intent":"miniapp",
    "bot_username":"LeBleuArgentinaBot",
})
token=link["token"]
for name in ["bot_started","catalog_opened","lead_qualified","lead_qualified"]:
    call("/v1/events",{
        "tenant":tenant,
        "event_name":name,
        "actor_external_id":"same-person",
        "link_token":token,
        "is_test":True,
    })
call("/v1/spend",{
    "tenant":tenant,
    "source":"qa_source",
    "medium":"qa",
    "campaign":"qa_campaign",
    "period_start":datetime.now(timezone.utc).isoformat(),
    "period_end":datetime.now(timezone.utc).isoformat(),
    "amount":"10",
    "currency":"USD",
})
q=urllib.parse.urlencode({"tenant":tenant,"days":1,"include_test":"true"})
data=call("/v1/metrics/acquisition?"+q)
rows=data["channels"]
assert len(rows)==1, rows
row=rows[0]
assert row["people"]==1, row
assert row["bot_starts"]==1, row
assert row["catalog_opened"]==1, row
assert row["lead_qualified"]==1, row
assert row["start_to_catalog_pct"]==100.0, row
assert row["catalog_to_lead_pct"]==100.0, row
assert row["cost_per_lead"]==10.0, row
print("GROWTH_SMOKE_OK",json.dumps({
    "people":row["people"],
    "starts":row["bot_starts"],
    "catalog":row["catalog_opened"],
    "leads":row["lead_qualified"],
    "start_to_catalog_pct":row["start_to_catalog_pct"],
    "catalog_to_lead_pct":row["catalog_to_lead_pct"],
    "cpl":row["cost_per_lead"],
},sort_keys=True))
PY
