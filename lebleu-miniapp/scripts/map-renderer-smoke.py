#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

ROOT=Path("/opt/lebleu-miniapp")
pkg=json.loads((ROOT/"package.json").read_text(encoding="utf-8"))
deps=pkg.get("dependencies") or {}

assert "ol" in deps, "OpenLayers dependency missing"
assert "ol-mapbox-style" in deps, "ol-mapbox-style dependency missing"
assert "maplibre-gl" not in deps, "MapLibre GL must not be a required Mini App renderer"

chunks=sorted((ROOT/"dist/assets").glob("CatalogMap-*.js"))
assert chunks, "CatalogMap production chunk missing"
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
