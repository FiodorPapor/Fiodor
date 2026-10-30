#!/usr/bin/env python3
import json
import os
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
env_path = Path(os.environ.get("PROPERTY_INTENT_ENV", "/opt/property-intent-core/.env"))
env = {}
for raw in env_path.read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    env[key] = value.strip().strip('"').strip("'")

release_path = Path(os.environ.get("RELEASE_VERSION_PATH", str(ROOT / "release-version.txt")))
release = release_path.read_text().strip()
base = env["MINIAPP_URL"].rstrip("/")
url = f"{base}/?v={release}"
payload = json.dumps({
    "menu_button": {
        "type": "web_app",
        "text": env.get("MENU_BUTTON_TEXT", "Каталог"),
        "web_app": {"url": url},
    }
}).encode()
req = urllib.request.Request(
    f"https://api.telegram.org/bot{env['TELEGRAM_BOT_TOKEN']}/setChatMenuButton",
    data=payload,
    headers={"Content-Type": "application/json"},
)
with urllib.request.urlopen(req, timeout=8) as response:
    data = json.load(response)
if not data.get("ok"):
    raise SystemExit("Telegram menu update failed")

# Keep property-intent deploys pinned to the same released Mini App. Without this,
# a later core deploy could silently restore an old Telegram menu URL from .env.
lines = env_path.read_text().splitlines()
out = []
found = False
for line in lines:
    if line.startswith("MENU_BUTTON_URL="):
        out.append(f"MENU_BUTTON_URL={url}")
        found = True
    else:
        out.append(line)
if not found:
    out.append(f"MENU_BUTTON_URL={url}")
tmp = env_path.with_suffix(".env.tmp-menu-release")
tmp.write_text("\n".join(out) + "\n")
tmp.replace(env_path)
print(url)
