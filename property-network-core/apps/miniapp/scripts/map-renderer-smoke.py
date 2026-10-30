#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
pkg=json.loads((ROOT/"package.json").read_text(encoding="utf-8"))
deps=pkg.get("dependencies") or {}

assert "ol" in deps, "OpenLayers dependency missing"
assert "ol-mapbox-style" in deps, "ol-mapbox-style dependency missing"
assert "maplibre-gl" not in deps, "MapLibre GL must not be a required Mini App renderer"

catalog_chunks=sorted((ROOT/"dist/assets").glob("CatalogMap-*.js"))
shared_ol_chunks=sorted((ROOT/"dist/assets").glob("ol-*.js"))
assert catalog_chunks, "CatalogMap production chunk missing"
# Vite may hoist OpenLayers renderer internals into a shared chunk once more than
# one map component is lazy-loaded. Validate the complete map bundle, not a stale
# assumption about which chunk contains the Canvas renderer signature.
chunks=catalog_chunks+shared_ol_chunks
body="\n".join(p.read_text(encoding="utf-8",errors="ignore") for p in chunks)

lower=body.lower()
assert "maplibre-gl" not in lower, "MapLibre leaked into production map chunk"
assert "webgl2" not in lower, "WebGL2 leaked into production map chunk"
assert 'getcontext("webgl' not in lower and "getcontext('webgl" not in lower, "WebGL context path present in map chunk"
assert "canvas" in lower, "Expected Canvas renderer signature not found"

print(json.dumps({
    "ok":True,
    "renderer":"openlayers-canvas",
    "chunks":[p.name for p in chunks],
},sort_keys=True))
