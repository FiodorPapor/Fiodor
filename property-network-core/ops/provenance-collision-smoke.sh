#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
TAG="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo working)"
API_IMAGE="${API_IMAGE:-property-network-intent:provenance-${TAG}}"
API_PORT="${API_PORT:-18051}"
NET="pn-prov-${TAG}"
DB="pn-prov-db-${TAG}"
API="pn-prov-api-${TAG}"
TMP="$(mktemp -d /tmp/pn-provenance.XXXXXX)"
cleanup(){ docker rm -f "$API" "$DB" >/dev/null 2>&1 || true; docker network rm "$NET" >/dev/null 2>&1 || true; rm -rf "$TMP"; }
trap cleanup EXIT
cleanup
mkdir -p "$TMP/catalog" "$TMP/state"
cat >"$TMP/source-registry.json" <<'JSON'
{
  "version": 1,
  "sources": [
    {"sourceId":"source_alpha","sourceSlug":"source_alpha","displayName":"Source Alpha","ownerTenant":"tenant_alpha","adapterType":"fixture","active":true,"leadRouting":"inventory_owner","listingTokenStrategy":"source_local_v1","legacyDefault":true},
    {"sourceId":"source_beta","sourceSlug":"source_beta","displayName":"Source Beta","ownerTenant":"tenant_beta","adapterType":"fixture","active":true,"leadRouting":"inventory_owner","listingTokenStrategy":"source_local_v1"}
  ]
}
JSON
cat >"$TMP/catalog/catalog.json" <<'JSON'
[
  {"sourceId":"source_alpha","sourceLocalId":"123","code":"123","sourceUrl":"https://alpha.invalid/listing/123","sourceFingerprint":"alpha-v1","operation":"Venta","propertyType":"Departamento","address":"Alpha 123","priceAmount":100000,"priceCurrency":"USD","imageUrls":[]},
  {"sourceId":"source_beta","sourceLocalId":"123","code":"123","sourceUrl":"https://beta.invalid/listing/123","sourceFingerprint":"beta-v1","operation":"Venta","propertyType":"Departamento","address":"Beta 123","priceAmount":120000,"priceCurrency":"USD","imageUrls":[]}
]
JSON
printf '{}' >"$TMP/state/quality.json"
printf '{}' >"$TMP/state/geo.json"
printf '{}' >"$TMP/state/ru.json"
printf '{}' >"$TMP/state/en.json"
printf '{"aliases":{}}' >"$TMP/catalog/catalog-aliases.json"

if ! docker image inspect "$API_IMAGE" >/dev/null 2>&1; then
  docker build -t "$API_IMAGE" "$ROOT/services/property-intent"
fi

docker network create "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" --tmpfs /var/lib/postgresql/data:rw,size=256m \
  -e POSTGRES_DB=property_intent -e POSTGRES_USER=intent -e POSTGRES_PASSWORD=smoke postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do docker exec "$DB" pg_isready -U intent -d property_intent >/dev/null 2>&1 && break; sleep 1; done
docker exec "$DB" pg_isready -U intent -d property_intent >/dev/null

docker run -d --name "$API" --network "$NET" -p "127.0.0.1:${API_PORT}:8080" \
  -v "$TMP/catalog:/data/catalog:ro" -v "$TMP/state:/data/state:ro" -v "$TMP/source-registry.json:/data/source-registry.json:ro" \
  -e DATABASE_URL="postgresql+psycopg://intent:smoke@${DB}:5432/property_intent" \
  -e SERVICE_KEY=smoke -e TELEGRAM_BOT_TOKEN=x -e TELEGRAM_BOT_USERNAME=SmokeBot \
  -e TEST_TELEGRAM_IDS=424242 -e SMOKE_USERNAME=property_network_smoke \
  -e GROWTH_CORE_URL=http://127.0.0.1:9 -e GROWTH_CORE_KEY=x -e GROWTH_TENANT=tenant_alpha \
  -e BRAND_NAME=Smoke -e CRM_BASE_URL= -e CRM_API_KEY= -e OPERATOR_CHAT_ID= \
  -e SOURCE_REGISTRY_PATH=/data/source-registry.json \
  -e CATALOG_PATH=/data/catalog/catalog.json -e CATALOG_ALIAS_PATH=/data/catalog/catalog-aliases.json \
  -e QUALITY_PATH=/data/state/quality.json -e GEO_ENRICHMENT_PATH=/data/state/geo.json \
  -e RU_TRANSLATIONS_PATH=/data/state/ru.json -e EN_TRANSLATIONS_PATH=/data/state/en.json \
  "$API_IMAGE" >/dev/null
for _ in $(seq 1 40); do curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 && break; sleep 1; done
curl -fsS "http://127.0.0.1:${API_PORT}/health" | python3 -c 'import json,sys;x=json.load(sys.stdin);assert x["sourceRegistry"]==2,x'

curl -fsS "http://127.0.0.1:${API_PORT}/v1/sources" >"$TMP/sources.json"
curl -fsS "http://127.0.0.1:${API_PORT}/v1/catalog" >"$TMP/catalog.json"
python3 - "$TMP" <<'PY'
import json,sys
p=sys.argv[1]
s=json.load(open(p+'/sources.json')); c=json.load(open(p+'/catalog.json'))
assert s['count']==2 and len(s['sources'])==2,s
assert not any(any(k.lower().endswith(('key','secret','token','password')) for k in x) for x in s['sources']),s
items=c['items']; assert len(items)==2,items
assert [x['code'] for x in items]==['123','123'],items
assert len({x['listingToken'] for x in items})==2,items
assert len({x['globalListingId'] for x in items})==2,items
by={x['sourceId']:x for x in items}
assert by['source_alpha']['inventoryOwnerTenant']=='tenant_alpha',by
assert by['source_beta']['inventoryOwnerTenant']=='tenant_beta',by
open(p+'/token_a','w').write(by['source_alpha']['listingToken'])
open(p+'/token_b','w').write(by['source_beta']['listingToken'])
print('collision_catalog_pass',by['source_alpha']['listingToken'],by['source_beta']['listingToken'])
PY
TA="$(cat "$TMP/token_a")"; TB="$(cat "$TMP/token_b")"
curl -fsS "http://127.0.0.1:${API_PORT}/v1/catalog/${TA}" | python3 -c 'import json,sys;x=json.load(sys.stdin);assert x["sourceId"]=="source_alpha" and x["address"]=="Alpha 123",x'
curl -fsS "http://127.0.0.1:${API_PORT}/v1/catalog/${TB}" | python3 -c 'import json,sys;x=json.load(sys.stdin);assert x["sourceId"]=="source_beta" and x["address"]=="Beta 123",x'
STATUS="$(curl -sS -o /dev/null -w '%{http_code}' "http://127.0.0.1:${API_PORT}/v1/catalog/123")"
[[ "$STATUS" == "404" ]] || { echo "ambiguous plain code must 404, got $STATUS" >&2; exit 1; }

INIT_DATA="$(python3 - <<'PY'
import hashlib,hmac,json,time,urllib.parse
pairs={'auth_date':str(int(time.time())),'query_id':'smoke','user':json.dumps({'id':424242,'first_name':'Smoke','username':'property_network_smoke'},separators=(',',':'))}
check='\n'.join(f'{k}={v}' for k,v in sorted(pairs.items()))
secret=hmac.new(b'WebAppData',b'x',hashlib.sha256).digest()
pairs['hash']=hmac.new(secret,check.encode(),hashlib.sha256).hexdigest()
print(urllib.parse.urlencode(pairs))
PY
)"
SESSION="$(python3 - <<PY
import json
print(json.dumps({'init_data':'''$INIT_DATA'''}))
PY
)"
CLICK_TOKEN="$(curl -fsS -H 'Content-Type: application/json' -d "$SESSION" "http://127.0.0.1:${API_PORT}/v1/session" | python3 -c 'import json,sys;print(json.load(sys.stdin)["outbound_click_token"])')"
for pair in "a:$TA" "b:$TB"; do
  label="${pair%%:*}"; token="${pair#*:}"
  curl -fsS -H 'Content-Type: application/json' -d "$(python3 - <<PY
import json
print(json.dumps({'init_data':'''$INIT_DATA''','listing_code':'$token','action':'availability'}))
PY
)" "http://127.0.0.1:${API_PORT}/v1/actions" >/dev/null
  curl -sS -o /dev/null -D "$TMP/headers-$label" "http://127.0.0.1:${API_PORT}/v1/out/original?listing_code=$token&click_token=$CLICK_TOKEN&click_id=click-${label}-12345678"
  grep -q '^HTTP/.* 302' "$TMP/headers-$label"
done

docker exec -i "$API" python - <<'PY'
from sqlalchemy import select
from app import main
# Simulate historical rows whose listing is no longer present in the live catalog.
legacy_snapshot={"code":"gone","sourceUrl":"https://retired.invalid/listing/gone","address":"Retired 1"}
with main.SessionLocal() as s:
    s.add(main.ListingAction(
        tenant='tenant_alpha', telegram_user_id=424242, listing_token='gone_legacytoken',
        listing_code='gone', action='availability', listing_snapshot_json=legacy_snapshot,
        is_test=True, status='new',
    ))
    s.add(main.OutboundClick(
        tenant='tenant_alpha', click_id='historical-click', telegram_user_id=424242,
        listing_token='gone_legacytoken', listing_code='gone', listing_snapshot_json=legacy_snapshot,
        is_test=True, status='new',
    ))
    s.commit()
main._backfill_listing_provenance()
with main.SessionLocal() as s:
    actions=list(s.scalars(select(main.ListingAction).order_by(main.ListingAction.created_at)))
    clicks=list(s.scalars(select(main.OutboundClick).order_by(main.OutboundClick.created_at)))
    assert len(actions)==3, len(actions)
    assert len(clicks)==3, len(clicks)
    live_actions=[r for r in actions if r.listing_token!='gone_legacytoken']
    by={r.inventory_source_id:r for r in live_actions}
    assert by['source_alpha'].tenant=='tenant_alpha'
    assert by['source_alpha'].inventory_owner_tenant=='tenant_alpha'
    assert by['source_alpha'].routing_mode=='direct_inventory_owner'
    assert by['source_beta'].tenant=='tenant_alpha'
    assert by['source_beta'].inventory_owner_tenant=='tenant_beta'
    assert by['source_beta'].routing_mode=='collaboration_required'
    for row in [*live_actions, *[r for r in clicks if r.listing_token!='gone_legacytoken']]:
        snap=row.listing_snapshot_json
        assert snap['sourceId']==row.inventory_source_id
        assert snap['networkProvenance']['demandTenant']=='tenant_alpha'
        assert snap['networkProvenance']['inventoryOwnerTenant']==row.inventory_owner_tenant
    historical=[r for r in actions+clicks if r.listing_token=='gone_legacytoken']
    assert len(historical)==2
    for row in historical:
        assert row.inventory_source_id=='source_alpha'
        assert row.inventory_owner_tenant=='tenant_alpha'
        snap=row.listing_snapshot_json
        assert snap['sourceId']=='source_alpha'
        assert snap['sourceLocalId']=='gone'
        assert snap['globalListingId'].startswith('listing_')
        assert snap['networkProvenance']['inventoryOwnerTenant']=='tenant_alpha'
    assert {r.inventory_source_id for r in clicks if r.listing_token!='gone_legacytoken'}=={'source_alpha','source_beta'}
print('persistence_routing_pass actions=2 clicks=2 historical_backfill=2')
PY

printf 'PROVENANCE_COLLISION_PASS api_image=%s token_a=%s token_b=%s\n' "$(docker image inspect "$API_IMAGE" --format '{{.Id}}')" "$TA" "$TB"
