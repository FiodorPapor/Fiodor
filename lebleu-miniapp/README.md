# Le Bleu Telegram Mini App

Russian-language property discovery Mini App for the Le Bleu pilot. It is intentionally CRM-neutral at the UI layer: catalogue/search/actions talk to Property Intent Core, which can forward qualified intent into the current CRM adapter or a portable webhook.

## User experience

- fast Telegram-native boot with local vendored WebApp SDK and retry fallback
- Telegram theme/safe-area support, BackButton and haptics
- buy / rent / all segmented control
- full filters: text, multiple neighborhoods, property types, rooms, bedrooms, bathrooms, parking, USD/ARS price range, area range and amenities
- sorting plus active-filter summary
- list / map switch
- MapLibre GL JS map with OpenFreeMap styles, price markers, grouped same-coordinate listings and opt-in geolocation
- lightweight catalogue cards with lazy images
- full listing detail and gallery hydrated on demand
- current Russian semantic description and notes for every live listing
- meaningful actions: availability check, viewing request, question, similar listings and native Telegram share
- saved searches with explicit notification opt-in and automatic rematching on new inventory

## Data/quality guarantees

The public Mini App reads only the normalized canonical catalogue. Le Bleu source duplicates and repeated/near-identical photos are removed upstream before the Mini App and Telegram catalogue are published. Raw source codes are not treated as globally unique; every listing uses a source-bound `listingToken`.

The initial catalogue endpoint returns compact cards. Full galleries/descriptions are fetched only when a listing is opened.

## Current map stack

- `maplibre-gl` v6.x
- bundled worker via Vite `?worker&url`
- OpenFreeMap vector styles
- map bundle lazy-loaded only when the user switches to map mode

## Build / deploy

```bash
npm ci
npm run build
./deploy.sh
```

`deploy.sh` refreshes the brand asset and Telegram WebApp SDK, builds the Vite bundle, recreates the app container and verifies public HTML + catalogue health.

Production secrets are not stored in this repository.
