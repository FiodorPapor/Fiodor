#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("GROWTH_BASE_URL", "http://127.0.0.1:8040").rstrip("/")
TENANT = os.environ.get("GROWTH_TENANT", "lebleu")
KEY = os.environ.get("SERVICE_KEY") or os.environ.get("GROWTH_SERVICE_KEY", "")
BOT_TOKEN = os.environ.get("RADAR_ALERT_BOT_TOKEN") or os.environ.get("RADAR_BOT_TOKEN", "")
CHAT_ID = os.environ.get("RADAR_ALERT_CHAT_ID") or os.environ.get("RADAR_BOT_CHAT_ID", "")


def get(path: str):
    req = urllib.request.Request(
        BASE + path,
        headers={"X-Growth-Key": KEY},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def money(spend: dict) -> str:
    if not spend:
        return "0"
    return ", ".join(f"{cur} {amount:g}" for cur, amount in spend.items())


def fmt_cpl(row: dict) -> str:
    cur = row.get("cost_currency")
    value = row.get("cost_per_lead")
    if cur and value is not None:
        return f"{cur} {value:g}"
    return "—"


def build() -> tuple[str, bool]:
    q = urllib.parse.urlencode({"tenant": TENANT, "days": 1, "include_test": "false"})
    data = get("/v1/metrics/acquisition?" + q)
    rows = data.get("channels") or []
    active = [
        row for row in rows
        if int(row.get("people") or 0)
        or int(row.get("bot_starts") or 0)
        or int(row.get("lead_qualified") or 0)
        or any(float(x or 0) for x in (row.get("spend") or {}).values())
    ]
    if not active:
        return "Le Bleu Growth · за 24 часа нет production-трафика или расходов.", False

    people = sum(int(x.get("people") or 0) for x in active)
    starts = sum(int(x.get("bot_starts") or 0) for x in active)
    leads = sum(int(x.get("lead_qualified") or 0) for x in active)
    views = sum(int(x.get("viewing_requested") or 0) for x in active)
    wins = sum(int(x.get("deal_won") or 0) for x in active)

    lines = [
        "📈 Le Bleu · Growth · 24 часа",
        f"Люди: {people} · bot starts: {starts} · leads: {leads} · запросы просмотра: {views} · сделки: {wins}",
        "",
    ]
    for row in sorted(active, key=lambda x: (int(x.get("lead_qualified") or 0), int(x.get("people") or 0)), reverse=True)[:8]:
        lead_pct = row.get("visitor_to_lead_pct")
        pct = f" · lead {lead_pct:g}%" if lead_pct is not None else ""
        lines.append(
            f"• {row.get('source')} / {row.get('campaign')}: "
            f"{int(row.get('people') or 0)} чел. · {int(row.get('lead_qualified') or 0)} лид."
            f"{pct} · spend {money(row.get('spend') or {})} · CPL {fmt_cpl(row)}"
        )
    return "\n".join(lines), True


def send(text: str) -> None:
    if not BOT_TOKEN or not CHAT_ID:
        raise SystemExit("Radar alert bot/chat is not configured")
    payload = {
        "chat_id": CHAT_ID,
        "text": text,
        "disable_web_page_preview": True,
    }
    req = urllib.request.Request(
        f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage",
        data=json.dumps(payload, ensure_ascii=False).encode("utf-8"),
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        result = json.load(response)
    if not result.get("ok"):
        raise SystemExit("Telegram digest delivery failed")


if __name__ == "__main__":
    text, has_activity = build()
    if "--dry-run" in sys.argv:
        print(text)
    elif has_activity:
        send(text)
        print("growth digest sent")
    else:
        print("growth digest skipped: no production activity")
