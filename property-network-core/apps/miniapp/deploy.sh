#!/usr/bin/env bash
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT"
LOG=/tmp/property-network-miniapp-deploy.$$.log
env_value() {
  local key="$1" default="$2" value
  value="$(grep -E "^${key}=" .env 2>/dev/null | tail -1 | cut -d= -f2- || true)"
  printf '%s' "${value:-$default}"
}
CONTAINER_PREFIX="$(env_value CONTAINER_PREFIX property-network)"
APP_CONTAINER="${CONTAINER_PREFIX}-miniapp"
PUBLIC_HOST="$(env_value PUBLIC_HOST catalog.example.com)"
PUBLIC_BASE="https://${PUBLIC_HOST}"
export PROPERTY_INTENT_ENV="$(env_value PROPERTY_INTENT_ENV /opt/property-intent-core/.env)"
export BRAND_LOGO_TARGET="$ROOT/public/brand-logo.jpg"
export RELEASE_VERSION_PATH="$ROOT/release-version.txt"
export MINIAPP_BASE="$PUBLIC_BASE"
cleanup(){ rm -f "$LOG"; }
trap cleanup EXIT
if ! timeout 20s python3 scripts/fetch-brand-logo.py >>"$LOG" 2>&1; then
  echo "WARN brand logo refresh failed; keeping existing asset" >>"$LOG"
fi
if timeout 20s curl -fsS "https://telegram.org/js/telegram-web-app.js?63" -o public/telegram-web-app.js.tmp; then
  mv public/telegram-web-app.js.tmp public/telegram-web-app.js
elif [[ ! -s public/telegram-web-app.js ]]; then
  echo "Telegram WebApp SDK unavailable and no local copy exists" >&2
  exit 1
else
  echo "WARN Telegram WebApp SDK refresh failed; keeping existing local copy" >>"$LOG"
fi

# Keep immutable chunks from recently deployed releases. Telegram WebViews can stay
# open across a deployment and request a lazy chunk minutes later. Removing that
# hashed file would turn a valid session into a blank screen.
LEGACY_DIR=.deploy-legacy/assets
mkdir -p "$LEGACY_DIR"
LEGACY_PROBE=""
if docker inspect "$APP_CONTAINER" >/dev/null 2>&1; then
  tmp_legacy=$(mktemp -d)
  mkdir -p "$tmp_legacy/assets"
  if docker cp "$APP_CONTAINER":/usr/share/nginx/html/assets/. "$tmp_legacy/assets/" >/dev/null 2>&1; then
    if docker cp "$APP_CONTAINER":/usr/share/nginx/html/release-assets.txt "$tmp_legacy/release-assets.txt" >/dev/null 2>&1; then
      while IFS= read -r name; do
        [[ -n "$name" && -f "$tmp_legacy/assets/$name" ]] && cp -p "$tmp_legacy/assets/$name" "$LEGACY_DIR/$name"
      done < "$tmp_legacy/release-assets.txt"
    else
      # First deploy after this safeguard is introduced: preserve the whole current set.
      cp -p "$tmp_legacy/assets/"* "$LEGACY_DIR/" 2>/dev/null || true
    fi
  fi
  rm -rf "$tmp_legacy"
fi
# Fourteen days comfortably covers suspended Telegram sessions while keeping storage bounded.
find "$LEGACY_DIR" -maxdepth 1 -type f -mtime +14 -delete 2>/dev/null || true
LEGACY_PROBE=$(find "$LEGACY_DIR" -maxdepth 1 -type f -exec basename {} \; | sort | head -1 || true)

npm run build >"$LOG" 2>&1
# Guard the two-step property gallery: overview grid first, then full-screen viewer.
asset_js=$(grep -oE '/assets/index-[A-Za-z0-9_-]+\.js' dist/index.html | head -1)
asset_css=$(grep -oE '/assets/index-[A-Za-z0-9_-]+\.css' dist/index.html | head -1)
grep -q "listing.allPhotos" src/main.tsx
grep -q 'galleryOverviewGrid' "dist${asset_css}"
grep -q 'grid-auto-rows:clamp(122px,37vw,240px)' "dist${asset_css}"
# Guard the content contract: only useful user-facing copy is rendered.
grep -q "listing.about" src/main.tsx
grep -q "listing.description" src/main.tsx
grep -q 'localizedContent' src/main.tsx
! grep -q 'В оригинальном объявлении нет текстового описания' "dist${asset_js}"
! grep -q 'Нажмите на карту' "dist${asset_js}"
# Guard interactive detail-map UX and explicit Google Maps handoff.
detail_map_js=$(find dist/assets -maxdepth 1 -name 'DetailMap-*.js' -exec basename {} \; | head -1)
detail_map_js="/assets/${detail_map_js}"
test -n "${detail_map_js}"
grep -q 'detailMapTools' "dist${asset_css}"
grep -q 'detailMapExpanded' "dist${asset_css}"
grep -q "map.openGoogle" src/DetailMap.tsx
grep -q 'www.google.com/maps/search' "dist${asset_js}"
grep -q '/map/styles/bright' "dist${detail_map_js}"
grep -q "tx('map.myLocation')" src/DetailMap.tsx
grep -q 'detailUserLocationDot' "dist${asset_css}"
grep -q 'detailMapCanvas .ol-zoom' "dist${asset_css}"
grep -q 'display:block!important' "dist${asset_css}"
# Guard multilingual UX: Russian-first entry + manual persisted selection + three locale resources.
grep -Fq "return query||saved||'ru';" src/i18n.ts
grep -Fq "fallbackLng:'ru'" src/i18n.ts
grep -q "LANGUAGE_STORAGE_KEY='property-network.language'" src/i18n.ts
grep -q "LEGACY_LANGUAGE_STORAGE_KEY='lebleu.language'" src/i18n.ts
grep -q "supportedLngs:APP_LANGUAGES" src/i18n.ts
grep -q "localizedContent" src/main.tsx
grep -q "languageSelect" "dist${asset_css}"
grep -q "channelSubscribe" "dist${asset_css}"
grep -q "channel_opened" src/main.tsx
# Guard catalog navigation: every detail opens at the top, while map view keeps modern controls.
grep -q 'detailScrollKeyRef' src/main.tsx
grep -q "window.scrollTo({top:0" src/main.tsx
catalog_map_js=$(find dist/assets -maxdepth 1 -name 'CatalogMap-*.js' -exec basename {} \; | head -1)
catalog_map_js="/assets/${catalog_map_js}"
test -n "${catalog_map_js}"
grep -q '/map/styles/bright' "dist${catalog_map_js}"
grep -q "tx('map.showAll')" src/CatalogMap.tsx
grep -q 'mapListingPreview' "dist${asset_css}"
grep -q 'mapToolStack' "dist${asset_css}"
# Guard catalog-card browsing: lightweight preview carousel plus on-demand full-gallery hydration.
grep -q 'cardCarouselTrack' "dist${asset_js}"
grep -q 'cardCarouselDots' "dist${asset_css}"
grep -q 'hydrateGallery' src/main.tsx
# Guard Telegram Main Mini App startapp routing from pinned/topic links.
grep -q "tgWebAppStartParam" src/main.tsx
# Guard direct Telegram entry: tracked startapp opens a listing/category without the bot-chat hop.
grep -q 'launch-context' src/main.tsx
grep -q 'directStartListing' src/main.tsx
python3 scripts/map-renderer-smoke.py
if ! timeout 120s docker compose build app >>"$LOG" 2>&1; then
  tail -80 "$LOG" >&2
  exit 1
fi
docker compose up -d app >>"$LOG" 2>&1
for _ in $(seq 1 30); do
  if curl -fsS --max-time 3 "$PUBLIC_BASE/" >/dev/null 2>&1; then
    curl -fsS --max-time 3 "$PUBLIC_BASE/api/v1/catalog" |
      python3 -c 'import json,sys; d=json.load(sys.stdin); assert d["count"]>0; print("property-network-miniapp healthy",d["count"])'
    python3 scripts/smoke-test.py
    python3 scripts/map-proxy-smoke.py
    if [[ -n "$LEGACY_PROBE" ]]; then
      curl -fsS --max-time 5 "$PUBLIC_BASE/assets/$LEGACY_PROBE" >/dev/null
      echo "legacy asset healthy $LEGACY_PROBE"
    fi
    grep -q 'vite:preloadError' dist/index.html
    python3 scripts/set-menu-release.py
    exit 0
  fi
  sleep 1
done
docker compose ps >&2
docker logs --tail 80 "$APP_CONTAINER" >&2 || true
exit 1
