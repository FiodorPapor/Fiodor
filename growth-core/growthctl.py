#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import sys
import urllib.parse
import urllib.request
from datetime import datetime, time
from pathlib import Path
from zoneinfo import ZoneInfo

ENV_PATH = Path("/opt/growth-core/.env")
BASE = "http://127.0.0.1:8040"


def read_env() -> dict[str, str]:
    out = {}
    for raw in ENV_PATH.read_text().splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"').strip("'")
    return out


def request(path: str, *, method: str = "GET", payload=None):
    env = read_env()
    body = json.dumps(payload).encode() if payload is not None else None
    req = urllib.request.Request(
        BASE + path,
        data=body,
        method=method,
        headers={
            "X-Growth-Key": env["SERVICE_KEY"],
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=10) as response:
        return json.load(response)


def fetch_json(url: str):
    req = urllib.request.Request(url, headers={"User-Agent": "Revenue-Radar-Preflight/1.0"})
    with urllib.request.urlopen(req, timeout=8) as response:
        return json.load(response)


def cmd_link(args):
    payload = {
        "tenant": args.tenant,
        "source": args.source,
        "medium": args.medium,
        "campaign": args.campaign,
        "content": args.content,
        "placement": args.placement,
        "listing_code": args.listing,
        "intent": args.intent,
        "bot_username": args.bot,
        "metadata": {"note": args.note} if args.note else {},
    }
    data = request("/v1/links/ensure", method="POST", payload=payload)
    print(data["telegram_url"])
    print(
        f"token={data['token']} source={data['source']} medium={data['medium']} "
        f"campaign={data['campaign']}"
    )


def cmd_spend(args):
    zone = ZoneInfo(args.timezone)
    day = datetime.strptime(args.date, "%Y-%m-%d").date()
    start = datetime.combine(day, time.min, zone)
    end = datetime.combine(day, time.max, zone)
    payload = {
        "tenant": args.tenant,
        "source": args.source,
        "medium": args.medium,
        "campaign": args.campaign,
        "placement": args.placement,
        "period_start": start.isoformat(),
        "period_end": end.isoformat(),
        "amount": str(args.amount),
        "currency": args.currency,
        "impressions": args.impressions,
        "clicks": args.clicks,
        "metadata": {"note": args.note} if args.note else {},
    }
    data = request("/v1/spend", method="POST", payload=payload)
    print(f"spend recorded id={data['id']}")


def fmt_num(value):
    if value is None:
        return "—"
    if isinstance(value, float):
        return f"{value:.1f}"
    return str(value)


def cmd_report(args):
    q = urllib.parse.urlencode(
        {"tenant": args.tenant, "days": args.days, "include_test": str(args.include_test).lower()}
    )
    data = request("/v1/metrics/acquisition?" + q)
    rows = data["channels"]
    if not rows:
        print(f"{args.tenant}: no production events/spend in last {args.days} days")
        return
    headers = ["source", "medium", "campaign", "people", "starts", "app", "start→app%", "shared", "leads", "app→lead%", "view", "wins", "spend", "CPL"]
    out = []
    for row in rows:
        spend = ",".join(f"{k} {v:g}" for k, v in row["spend"].items()) or "—"
        cpl = (
            f"{row['cost_currency']} {row['cost_per_lead']:g}"
            if row["cost_currency"] and row["cost_per_lead"] is not None
            else "—"
        )
        starts = int(row.get("bot_starts") or 0)
        app_opens = int(row.get("catalog_opened") or 0)
        app_pct = round(app_opens / starts * 100, 1) if starts else None
        out.append([
            row["source"], row["medium"], row["campaign"], row["people"],
            starts, app_opens, fmt_num(row.get("start_to_catalog_pct", app_pct)),
            row.get("share_sent", 0),
            row["lead_qualified"], fmt_num(row.get("catalog_to_lead_pct")),
            row["viewing_requested"], row["deal_won"], spend, cpl,
        ])
    widths = [len(h) for h in headers]
    for row in out:
        for i, cell in enumerate(row):
            widths[i] = max(widths[i], len(str(cell)))
    def line(row):
        return "  ".join(str(cell).ljust(widths[i]) for i, cell in enumerate(row))
    print(line(headers))
    print(line(["-" * w for w in widths]))
    for row in out:
        print(line(row))


def cmd_funnel(args):
    params = {"tenant": args.tenant, "days": args.days, "include_test": str(args.include_test).lower()}
    if args.source:
        params["source"] = args.source
    if args.campaign:
        params["campaign"] = args.campaign
    data = request("/v1/metrics/funnel?" + urllib.parse.urlencode(params))
    for step in data["steps"]:
        print(
            f"{step['event']}: {step['people']} people "
            f"({fmt_num(step['from_start_pct'])}% from start)"
        )


def cmd_preflight(args):
    link = request(
        f"/v1/links/{urllib.parse.quote(args.token)}?"
        + urllib.parse.urlencode({"tenant": args.tenant})
    )
    checks: list[tuple[str, bool, str]] = []

    def add(name: str, ok: bool, detail: str):
        checks.append((name, ok, detail))

    add("tracking", bool(link.get("source") and link.get("campaign")), f"{link.get('source')} / {link.get('campaign')}")
    add("deep_link", f"start=trk_{args.token}" in str(link.get("telegram_url") or ""), str(link.get("telegram_url") or "missing"))
    add("bot", bool(link.get("bot_username")), str(link.get("bot_username") or "missing"))

    service_urls = [
        ("intent", args.intent_health),
        ("crm", args.crm_health),
    ]
    for name, url in service_urls:
        try:
            data = fetch_json(url)
            add(name, str(data.get("status") or "").lower() == "ok", str(data.get("status") or data))
        except Exception as exc:
            add(name, False, f"{type(exc).__name__}: {exc}")

    try:
        catalog = fetch_json(args.catalog_url)
        count = int(catalog.get("count") or 0)
        add("catalog", count > 0, f"{count} objects")
    except Exception as exc:
        add("catalog", False, f"{type(exc).__name__}: {exc}")

    metrics = request(
        "/v1/metrics/acquisition?"
        + urllib.parse.urlencode(
            {"tenant": args.tenant, "days": args.days, "include_test": "false"}
        )
    )
    matching = [
        row
        for row in metrics.get("channels", [])
        if row.get("source") == link.get("source")
        and row.get("medium") == link.get("medium")
        and row.get("campaign") == link.get("campaign")
    ]
    production_people = sum(int(row.get("people") or 0) for row in matching)
    production_spend = sum(
        float(amount or 0)
        for row in matching
        for amount in (row.get("spend") or {}).values()
    )
    clean = production_people == 0 and production_spend == 0
    add(
        "baseline",
        clean or not args.require_clean,
        f"people={production_people}, spend={production_spend:g}",
    )

    metadata = link.get("metadata") or {}
    if metadata:
        print("metadata=" + json.dumps(metadata, ensure_ascii=False, sort_keys=True))
    for name, ok, detail in checks:
        print(f"{'OK' if ok else 'FAIL'}  {name:<10} {detail}")
    ready = all(ok for _, ok, _ in checks)
    print("READY" if ready else "NOT_READY")
    if not ready:
        raise SystemExit(2)


def build_parser():
    env = read_env()
    p = argparse.ArgumentParser(description="Internal CLI for Growth Core")
    p.add_argument("--tenant", default=env.get("DEFAULT_TENANT", "default"))
    sub = p.add_subparsers(dest="command", required=True)

    link = sub.add_parser("link", help="Create/reuse a deterministic acquisition link")
    link.add_argument("--source", required=True)
    link.add_argument("--medium", required=True)
    link.add_argument("--campaign", required=True)
    link.add_argument("--content")
    link.add_argument("--placement")
    link.add_argument("--listing")
    link.add_argument("--intent", default="miniapp")
    link.add_argument("--bot", default=env.get("DEFAULT_BOT_USERNAME", "Bot"))
    link.add_argument("--note")
    link.set_defaults(func=cmd_link)

    spend = sub.add_parser("spend", help="Record campaign spend")
    spend.add_argument("--source", required=True)
    spend.add_argument("--medium", required=True)
    spend.add_argument("--campaign", required=True)
    spend.add_argument("--date", required=True, help="YYYY-MM-DD")
    spend.add_argument("--amount", required=True, type=float)
    spend.add_argument("--currency", default="USD")
    spend.add_argument("--placement")
    spend.add_argument("--impressions", type=int)
    spend.add_argument("--clicks", type=int)
    spend.add_argument("--note")
    spend.add_argument("--timezone", default="America/Argentina/Buenos_Aires")
    spend.set_defaults(func=cmd_spend)

    report = sub.add_parser("report", help="Compare acquisition channels")
    report.add_argument("--days", type=int, default=30)
    report.add_argument("--include-test", action="store_true")
    report.set_defaults(func=cmd_report)

    funnel = sub.add_parser("funnel", help="Show commercial funnel")
    funnel.add_argument("--days", type=int, default=30)
    funnel.add_argument("--source")
    funnel.add_argument("--campaign")
    funnel.add_argument("--include-test", action="store_true")
    funnel.set_defaults(func=cmd_funnel)

    preflight = sub.add_parser("preflight", help="Verify a tracked acquisition campaign before launch")
    preflight.add_argument("--token", required=True)
    preflight.add_argument("--days", type=int, default=30)
    preflight.add_argument("--require-clean", action="store_true")
    preflight.add_argument("--intent-health", default=env.get("PREFLIGHT_INTENT_HEALTH", "http://127.0.0.1:8050/health"))
    preflight.add_argument("--crm-health", default=env.get("PREFLIGHT_CRM_HEALTH", "http://127.0.0.1:8020/health"))
    preflight.add_argument("--catalog-url", default=env.get("PREFLIGHT_CATALOG_URL", "http://127.0.0.1:8050/v1/catalog"))
    preflight.set_defaults(func=cmd_preflight)
    return p


if __name__ == "__main__":
    parser = build_parser()
    args = parser.parse_args()
    try:
        args.func(args)
    except Exception as exc:
        print(f"growthctl error: {exc}", file=sys.stderr)
        raise SystemExit(1)
