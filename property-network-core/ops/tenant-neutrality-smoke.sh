#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CATALOG_HOST_PATH="${CATALOG_HOST_PATH:-/opt/lebleu-listing-bridge/public/data/full}"
STATE_HOST_PATH="${STATE_HOST_PATH:-/opt/lebleu-listing-bridge/state}"
SOURCE_REGISTRY_HOST_PATH="${SOURCE_REGISTRY_HOST_PATH:-$ROOT/tenants/lebleu/source-registry.json}"
PLAYWRIGHT_CWD="${PLAYWRIGHT_CWD:-/opt/rafael-release-f964572f}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
TAG="$(git -C "$ROOT" rev-parse --short HEAD 2>/dev/null || echo working)"
NET="pn-smoke-${TAG}"
DB="pn-smoke-db-${TAG}"
API="pn-smoke-api-${TAG}"
APP="pn-smoke-app-${TAG}"
API_IMAGE="property-network-intent:smoke-${TAG}"
APP_IMAGE="property-network-miniapp:smoke-${TAG}"
API_PORT="${API_PORT:-18050}"
APP_PORT="${APP_PORT:-18080}"
cleanup(){
  docker rm -f "$APP" "$API" "$DB" >/dev/null 2>&1 || true
  docker network rm "$NET" >/dev/null 2>&1 || true
}
trap cleanup EXIT
cleanup

test -s "$CATALOG_HOST_PATH/catalog.json"
test -d "$STATE_HOST_PATH"
test -s "$SOURCE_REGISTRY_HOST_PATH"

echo "[1/6] build exact candidate"
docker build -t "$API_IMAGE" "$ROOT/services/property-intent"
docker build -t "$APP_IMAGE" "$ROOT/apps/miniapp"

echo "[2/6] start isolated tenant"
docker network create "$NET" >/dev/null
docker run -d --name "$DB" --network "$NET" --tmpfs /var/lib/postgresql/data:rw,size=256m \
  -e POSTGRES_DB=property_intent -e POSTGRES_USER=intent -e POSTGRES_PASSWORD=smoke \
  postgres:16-alpine >/dev/null
for _ in $(seq 1 30); do
  docker exec "$DB" pg_isready -U intent -d property_intent >/dev/null 2>&1 && break
  sleep 1
done
docker exec "$DB" pg_isready -U intent -d property_intent >/dev/null

docker run -d --name "$API" --network "$NET" -p "127.0.0.1:${API_PORT}:8080" \
  -v "$CATALOG_HOST_PATH:/data/catalog:ro" -v "$STATE_HOST_PATH:/data/state:ro" -v "$SOURCE_REGISTRY_HOST_PATH:/data/source-registry.json:ro" \
  -e DATABASE_URL="postgresql+psycopg://intent:smoke@${DB}:5432/property_intent" \
  -e SERVICE_KEY=smoke -e TELEGRAM_BOT_TOKEN=x -e TELEGRAM_BOT_USERNAME=CasaNorteBot \
  -e GROWTH_CORE_KEY=test-growth-key -e GROWTH_TENANT=casa_norte \
  -e BRAND_NAME="Casa Norte" -e BRAND_TAGLINE="Propiedades en Buenos Aires" -e BRAND_LOGO_URL= \
  -e SOURCE_REGISTRY_PATH=/data/source-registry.json \
  -e PUBLIC_LANGUAGE_DEFAULT=es -e TELEGRAM_CHANNEL_URL= \
  -e ATTRIBUTION_CAMPAIGN=casa_norte_catalog -e SOURCE_LABEL=partner_inventory \
  -e CATALOG_PATH=/data/catalog/catalog.json -e CATALOG_ALIAS_PATH=/data/catalog/catalog-aliases.json \
  -e QUALITY_PATH=/data/state/ru-content-quality.json -e GEO_ENRICHMENT_PATH=/data/state/geo-enrichment.json \
  -e RU_TRANSLATIONS_PATH=/data/state/ru-full-translations.json -e EN_TRANSLATIONS_PATH=/data/state/en-content.json \
  "$API_IMAGE" >/dev/null
for _ in $(seq 1 40); do
  curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:${API_PORT}/health" >/dev/null

echo "[3/6] assert tenant config and catalog"
curl -fsS "http://127.0.0.1:${API_PORT}/v1/config" | python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x["tenantSlug"]=="casa_norte",x
assert x["brandName"]=="Casa Norte",x
assert x["defaultLanguage"]=="es",x
assert x["telegramChannelUrl"]=="",x
assert x["attributionCampaign"]=="casa_norte_catalog",x
assert x["sourceLabel"]=="partner_inventory",x
print("config_pass")'
curl -fsS "http://127.0.0.1:${API_PORT}/v1/sources" | python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x["count"]==1,x
s=x["sources"][0]
assert s["sourceId"]=="lebleu" and s["ownerTenant"]=="lebleu",x
assert not any(k in s for k in ["listingTokenStrategy","legacyDefault","credentials","apiKey"]),s
print("source_registry_pass")'
curl -fsS "http://127.0.0.1:${API_PORT}/v1/catalog" | python3 -c '
import hashlib,json,sys
x=json.load(sys.stdin)
items=x.get("items",[])
assert x.get("count",0)>0,x
assert x.get("count")==len(items),(x.get("count"),len(items))
assert len({i["globalListingId"] for i in items})==len(items)
for i in items:
    assert i["sourceId"]=="lebleu" and i["inventoryOwnerTenant"]=="lebleu",i
    expected=f"{i["code"]}_{hashlib.sha256(str(i.get("sourceUrl") or "").encode()).hexdigest()[:8]}"
    assert i["listingToken"]==expected,(i["listingToken"],expected)
print("catalog_provenance_token_compat_pass",x["count"])'

echo "[4/6] assert same-origin Mini App proxy"
docker run -d --name "$APP" --network "$NET" -p "127.0.0.1:${APP_PORT}:80" \
  -e "API_UPSTREAM=${API}:8080" "$APP_IMAGE" >/dev/null
for _ in $(seq 1 30); do
  curl -fsS "http://127.0.0.1:${APP_PORT}/" >/dev/null 2>&1 && break
  sleep 1
done
curl -fsS "http://127.0.0.1:${APP_PORT}/" >/dev/null
curl -fsS "http://127.0.0.1:${APP_PORT}/api/v1/config" | python3 -c '
import json,sys
x=json.load(sys.stdin)
assert x["tenantSlug"]=="casa_norte",x
print("proxy_pass")'

echo "[5/6] browser proof when Playwright is available"
if [[ -f "$PLAYWRIGHT_CWD/node_modules/playwright/package.json" ]]; then
  PLAYWRIGHT_CWD="$PLAYWRIGHT_CWD" APP_URL="http://127.0.0.1:${APP_PORT}/" node - <<'NODE'
const { chromium } = require(process.env.PLAYWRIGHT_CWD + '/node_modules/playwright');
(async()=>{
  const browser=await chromium.launch({headless:true});
  const page=await browser.newPage({viewport:{width:390,height:844}});
  const errors=[];
  page.on('console',m=>{if(m.type()==='error') errors.push(m.text())});
  page.on('pageerror',e=>errors.push(String(e)));
  await page.goto(process.env.APP_URL,{waitUntil:'networkidle',timeout:30000});
  await page.waitForFunction(()=>document.querySelector('.brand strong')?.textContent?.includes('Casa Norte'),null,{timeout:15000});
  const r=await page.evaluate(()=>({
    brand:document.querySelector('.brand strong')?.textContent?.trim(),
    lang:document.documentElement.lang,
    count:document.querySelector('.resultCount strong')?.textContent?.trim(),
    channel:document.querySelectorAll('.channelSubscribe').length,
    logos:document.querySelectorAll('.brandLogo').length
  }));
  if(r.brand!=='Casa Norte'||r.lang!=='es'||r.channel!==0||r.logos!==0||Number(r.count)<=0||errors.length){
    throw new Error(JSON.stringify({r,errors}));
  }
  console.log('browser_pass',JSON.stringify(r));
  await browser.close();
})().catch(e=>{console.error(e);process.exit(1)});
NODE
else
  echo "browser_skipped PLAYWRIGHT_CWD=$PLAYWRIGHT_CWD"
fi

echo "[6/6] prove no persistent test volume"
if docker inspect "$DB" --format '{{range .Mounts}}{{if eq .Type "volume"}}{{.Name}}{{println}}{{end}}{{end}}' | grep -q .; then
  echo "unexpected persistent database volume" >&2
  exit 1
fi
printf 'TENANT_NEUTRALITY_PASS stamp=%s api_image=%s app_image=%s\n' "$STAMP" \
  "$(docker image inspect "$API_IMAGE" --format '{{.Id}}')" \
  "$(docker image inspect "$APP_IMAGE" --format '{{.Id}}')"
