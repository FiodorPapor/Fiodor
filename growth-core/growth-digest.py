#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import sys
import urllib.parse
import urllib.request

BASE = os.environ.get("GROWTH_BASE_URL", "http://127.0.0.1:8040").rstrip("/")
TENANT = os.environ.get("GROWTH_TENANT") or os.environ.get("DEFAULT_TENANT", "default")
BRAND = os.environ.get("GROWTH_BRAND_NAME") or "Где жить"
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


def channel_name(row: dict) -> str:
    source = str(row.get("source") or "").strip()
    campaign = str(row.get("campaign") or "").strip()
    labels = {
        ("telegram_miniapp", "miniapp_catalog"): "Telegram Mini App",
        ("web_app", "web_catalog"): "Web / установленное приложение",
        ("telegram_catalog", "live_catalog"): "Telegram-каталог",
        ("telegram_share", "property_share"): "Переходы по расшаренным объектам",
        ("revenue_radar", "radar_catalog_reply"): "Revenue Radar · каталог",
        ("revenue_radar", "radar_listing_match"): "Revenue Radar · подходящий объект",
    }
    return labels.get((source, campaign)) or " / ".join(x for x in (source, campaign) if x) or "Другой источник"


def build() -> tuple[str, bool]:
    q = urllib.parse.urlencode({"tenant": TENANT, "days": 1, "include_test": "false"})
    data = get("/v1/metrics/acquisition?" + q)
    rows = data.get("channels") or []
    active = [
        row for row in rows
        if int(row.get("people") or 0)
        or int(row.get("lead_qualified") or 0)
        or int(row.get("viewing_requested") or 0)
        or int(row.get("deal_won") or 0)
        or any(float(x or 0) for x in (row.get("spend") or {}).values())
    ]
    if not active:
        return f"{BRAND} · за 24 часа новых коммерческих действий нет.", False

    people = sum(int(x.get("people") or 0) for x in active)
    leads = sum(int(x.get("lead_qualified") or 0) for x in active)
    views = sum(int(x.get("viewing_requested") or 0) for x in active)
    wins = sum(int(x.get("deal_won") or 0) for x in active)

    lines = [
        f"📈 {BRAND} · за 24 часа",
        "",
        f"👥 Посетили каталог: {people}",
        f"📩 Целевых обращений: {leads}",
        f"🏠 Запросов на просмотр: {views}",
        f"🤝 Сделок: {wins}",
        "",
        "По источникам:",
    ]
    for row in sorted(active, key=lambda x: (int(x.get("lead_qualified") or 0), int(x.get("viewing_requested") or 0), int(x.get("people") or 0)), reverse=True)[:8]:
        parts = [f"посетители: {int(row.get('people') or 0)}"]
        leads_row = int(row.get("lead_qualified") or 0)
        views_row = int(row.get("viewing_requested") or 0)
        wins_row = int(row.get("deal_won") or 0)
        if leads_row:
            parts.append(f"обращения: {leads_row}")
        if views_row:
            parts.append(f"просмотры: {views_row}")
        if wins_row:
            parts.append(f"сделки: {wins_row}")
        spend = row.get("spend") or {}
        if any(float(x or 0) for x in spend.values()):
            parts.append(f"расходы {money(spend)}")
            cpl = fmt_cpl(row)
            if cpl != "—":
                parts.append(f"CPL {cpl}")
        lines.append(f"• {channel_name(row)}: " + " · ".join(parts))
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
