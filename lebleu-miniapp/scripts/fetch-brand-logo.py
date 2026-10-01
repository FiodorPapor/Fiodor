#!/usr/bin/env python3
from __future__ import annotations

import json
import urllib.request
from pathlib import Path

ENV = Path("/opt/property-intent-core/.env")
TARGET = Path("/opt/lebleu-miniapp/public/brand-logo.jpg")


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"').strip("'")
    return out


def get_json(url: str) -> dict:
    with urllib.request.urlopen(url, timeout=8) as response:
        return json.load(response)


def main() -> None:
    env = read_env(ENV)
    token = env.get("TELEGRAM_BOT_TOKEN")
    if not token:
        raise SystemExit("TELEGRAM_BOT_TOKEN is not configured")
    base = f"https://api.telegram.org/bot{token}"
    me = get_json(base + "/getMe")["result"]
    photos = get_json(base + f"/getUserProfilePhotos?user_id={me['id']}&limit=1")["result"]
    if not photos.get("photos"):
        raise SystemExit("bot profile has no photo")
    photo = photos["photos"][0][-1]
    file_path = get_json(base + f"/getFile?file_id={photo['file_id']}")["result"]["file_path"]
    url = f"https://api.telegram.org/file/bot{token}/{file_path}"
    TARGET.parent.mkdir(parents=True, exist_ok=True)
    tmp = TARGET.with_suffix(".tmp")
    with urllib.request.urlopen(url, timeout=12) as response:
        tmp.write_bytes(response.read())
    tmp.replace(TARGET)
    print(f"brand logo refreshed: {TARGET.stat().st_size} bytes")


if __name__ == "__main__":
    main()
