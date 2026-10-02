#!/usr/bin/env python3
import json
import urllib.request
from pathlib import Path

env = {}
for raw in Path("/opt/property-intent-core/.env").read_text().splitlines():
    line = raw.strip()
    if not line or line.startswith("#") or "=" not in line:
        continue
    key, value = line.split("=", 1)
    env[key] = value.strip().strip('"').strip("'")

release = Path("/opt/lebleu-miniapp/release-version.txt").read_text().strip()
base = env["MINIAPP_URL"].rstrip("/")
url = f"{base}/?v={release}"
payload = json.dumps({
    "menu_button": {
        "type": "web_app",
        "text": "Каталог",
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
print(url)
