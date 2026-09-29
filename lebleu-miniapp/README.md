# Le Bleu Telegram Mini App

Russian-language client UI for the Le Bleu property pilot.

## UX

- Telegram theme colors and content safe-area variables
- native Telegram BackButton and haptics
- buy/rent segmented control
- neighborhood, property type, rooms and budget filters
- lightweight catalog cards, lazy-loaded images
- full listing details and gallery hydrated on demand
- explicit actions: ask a question / request a viewing
- saved searches and optional new-match notifications

The initial catalog endpoint intentionally returns only one card image and compact facts. Full galleries/descriptions are fetched only after opening a listing, reducing the initial catalog payload from roughly 497 KB to roughly 95 KB for the current 142-object pilot.

## Build

```bash
npm ci
npm run build
docker compose up -d --build
```

Production secrets are not stored in this repository.
