# Normalized catalog contract

Property Intent Core does not need to know the source portal or agency CRM. An inventory adapter writes a JSON array into the file mounted as `/data/catalog.json`.

## Required per listing

- `code`: stable agency listing ID.
- `sourceUrl`: canonical source URL.
- `sourceFingerprint`: changes when commercially relevant listing data changes.
- `operation`: `Venta` or `Alquiler`.
- `propertyType`: normalized type, e.g. `Departamento`, `Casa`, `PH`, `Cochera`, `Terreno`, `Local`.
- `address`: human-readable location.
- `priceAmount`: numeric value or numeric string.
- `priceCurrency`: normally `USD` or `ARS`.
- `imageUrls`: array of source image URLs.

## Recommended

- `title`
- `slug`
- `description`
- `highlightedFeatures`: array of strings.
- `details.rooms`
- `details.bedrooms`
- `details.totalAreaM2`
- `details.coveredAreaM2`

Example:

```json
[
  {
    "code": "AG-123",
    "sourceUrl": "https://agency.example/property/AG-123",
    "sourceFingerprint": "sha256-or-version",
    "operation": "Venta",
    "propertyType": "Departamento",
    "title": "Departamento 3 ambientes",
    "address": "Palermo, Buenos Aires",
    "priceAmount": 180000,
    "priceCurrency": "USD",
    "description": "Luminoso departamento...",
    "highlightedFeatures": ["Balcón", "Cochera"],
    "details": {
      "rooms": 3,
      "bedrooms": 2,
      "totalAreaM2": 72
    },
    "imageUrls": [
      "https://cdn.example.com/1.jpg"
    ]
  }
]
```

## Optional overlays

The service can also mount:

- `quality.json`: reviewed copy / property-type / detail corrections keyed by `sourceUrl`.
- `geo-enrichment.json`: deterministic location enrichment.

An agency with clean source inventory may provide empty JSON objects for these overlays.

## Adapter rule

Portal/CRM-specific extraction belongs upstream. Keep Property Intent Core on this stable normalized schema so a new agency means a new adapter/configuration, not a fork of matching and saved-search logic.
