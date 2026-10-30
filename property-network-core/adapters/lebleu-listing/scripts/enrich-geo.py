#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.request
from datetime import UTC, datetime
from pathlib import Path

CATALOG = Path("/opt/lebleu-listing-bridge/public/data/full/catalog.json")
OUT = Path("/opt/lebleu-listing-bridge/state/geo-enrichment.json")
API = "https://apis.datos.gob.ar/georef/api/v2.0/ubicacion"
BATCH = 75


def load_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def post_batch(points: list[dict]) -> list[dict]:
    body = json.dumps({
        "ubicaciones": [
            {"lat": p["latitude"], "lon": p["longitude"], "campos": "completo"}
            for p in points
        ]
    }).encode()
    req = urllib.request.Request(
        API,
        data=body,
        headers={
            "Content-Type": "application/json",
            "User-Agent": "RevenueRadar-LeBleu/1.0",
        },
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=25) as response:
        data = json.load(response)
    results = data.get("resultados") or []
    if len(results) != len(points):
        raise RuntimeError(f"Georef returned {len(results)} results for {len(points)} points")
    return results


def entity_name(value) -> str | None:
    if not isinstance(value, dict):
        return None
    name = str(value.get("nombre") or "").strip()
    return name or None


def same_point(entry: dict | None, item: dict) -> bool:
    if not isinstance(entry, dict):
        return False
    try:
        return (
            abs(float(entry.get("latitude")) - float(item["latitude"])) < 1e-8
            and abs(float(entry.get("longitude")) - float(item["longitude"])) < 1e-8
        )
    except (TypeError, ValueError, KeyError):
        return False


def main() -> int:
    raw = json.loads(CATALOG.read_text(encoding="utf-8"))
    points = [
        item for item in raw
        if isinstance(item.get("latitude"), (int, float))
        and isinstance(item.get("longitude"), (int, float))
        and item.get("sourceUrl")
    ]
    if not points:
        raise RuntimeError("catalog has no coordinates; keep previous enrichment")

    previous = load_json(OUT, {})
    previous_entries = previous.get("entries", {}) if isinstance(previous, dict) else {}

    entries: dict[str, dict] = {}
    pending: list[dict] = []
    reused = 0
    for item in points:
        url = item["sourceUrl"]
        cached = previous_entries.get(url)
        if same_point(cached, item):
            entries[url] = cached
            reused += 1
        else:
            pending.append(item)

    queried = 0
    for start in range(0, len(pending), BATCH):
        chunk = pending[start:start + BATCH]
        results = post_batch(chunk)
        queried += len(chunk)
        for item, result in zip(chunk, results, strict=True):
            location = result.get("ubicacion") or {}
            entries[item["sourceUrl"]] = {
                "latitude": item["latitude"],
                "longitude": item["longitude"],
                "province": entity_name(location.get("provincia")),
                "department": entity_name(location.get("departamento")),
                "localGovernment": entity_name(location.get("gobierno_local")),
                "nomenclature": location.get("nomenclatura"),
            }

    payload = {
        "generatedAt": datetime.now(UTC).isoformat(),
        "source": "Argentina Georef v2 /ubicacion",
        "sourceUrl": API,
        "points": len(points),
        "reused": reused,
        "queried": queried,
        "entries": entries,
    }
    OUT.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, OUT)
    print(json.dumps({
        "points": len(points),
        "enriched": len(entries),
        "reused": reused,
        "queried": queried,
    }, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"geo enrichment failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
