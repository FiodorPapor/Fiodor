#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import subprocess
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path("/opt/lebleu-listing-bridge")
CATALOG = ROOT / "public/data/full/catalog.json"
PUBLISHER_STATE = ROOT / "state/telegram-state.json"
GEO_ENRICHMENT = ROOT / "state/geo-enrichment.json"
SOURCE_FAILURES = ROOT / "public/data/full/failures.json"
STATE = ROOT / "state/product-health.json"
ENV = Path("/opt/property-intent-core/.env")
STALE_SECONDS = 3 * 60 * 60


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    if not path.exists():
        return out
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def cmd(*parts: str) -> tuple[int, str]:
    p = subprocess.run(parts, capture_output=True, text=True, timeout=8)
    return p.returncode, (p.stdout or p.stderr or "").strip()


def http_ok(url: str, timeout: float = 4.0) -> bool:
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "LeBleuProductWatch/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    if not token or not chat_id:
        return False
    try:
        body = json.dumps({
            "chat_id": chat_id,
            "text": text,
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=body,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=8) as r:
            return 200 <= r.status < 300
    except Exception:
        return False


def load_json(path: Path, fallback):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return fallback


def main() -> int:
    now = time.time()
    previous = load_json(STATE, {})
    issues: list[str] = []

    rc, active = cmd("systemctl", "is-active", "lebleu-listing-sync.timer")
    if rc != 0 or active != "active":
        issues.append("sync timer не active")

    _, result = cmd("systemctl", "show", "lebleu-listing-sync.service", "--property=Result", "--value")
    if result == "failed":
        issues.append("последний sync завершился failed")

    rc, reconcile_active = cmd("systemctl", "is-active", "property-intent-reconcile.timer")
    if rc != 0 or reconcile_active != "active":
        issues.append("CRM reconcile timer не active")
    _, reconcile_result = cmd(
        "systemctl", "show", "property-intent-reconcile.service", "--property=Result", "--value"
    )
    if reconcile_result == "failed":
        issues.append("последний CRM reconcile завершился failed")

    rc, digest_active = cmd("systemctl", "is-active", "lebleu-growth-digest.timer")
    if rc != 0 or digest_active != "active":
        issues.append("Growth digest timer не active")

    if not CATALOG.exists():
        issues.append("catalog.json отсутствует")
        catalog_count = 0
    else:
        age = now - CATALOG.stat().st_mtime
        if age > STALE_SECONDS:
            issues.append(f"каталог не обновлялся {age / 3600:.1f} ч")
        catalog = load_json(CATALOG, [])
        catalog_count = len(catalog) if isinstance(catalog, list) else 0
        if catalog_count <= 0:
            issues.append("каталог пуст")

    last_good_count = int(previous.get("last_good_catalog_count") or 0)
    if last_good_count and catalog_count < max(20, int(last_good_count * 0.7)):
        issues.append(f"резкое падение inventory: {last_good_count} → {catalog_count}")

    publisher = load_json(PUBLISHER_STATE, {})
    entries = publisher.get("entries") if isinstance(publisher, dict) else {}
    published_count = (
        sum(1 for entry in entries.values() if isinstance(entry, dict) and entry.get("status") == "active")
        if isinstance(entries, dict)
        else 0
    )
    if catalog_count and published_count < int(catalog_count * 0.8):
        issues.append(f"Telegram publisher покрывает только {published_count}/{catalog_count}")

    geo_payload = load_json(GEO_ENRICHMENT, {})
    geo_entries = geo_payload.get("entries", {}) if isinstance(geo_payload, dict) else {}
    geo_count = len(geo_entries) if isinstance(geo_entries, dict) else 0
    if catalog_count and geo_count < int(catalog_count * 0.8):
        issues.append(f"геообогащение покрывает только {geo_count}/{catalog_count}")
    if GEO_ENRICHMENT.exists() and now - GEO_ENRICHMENT.stat().st_mtime > 12 * 60 * 60:
        issues.append("геообогащение не обновлялось более 12 ч")

    source_failures = load_json(SOURCE_FAILURES, [])
    source_failure_count = len(source_failures) if isinstance(source_failures, list) else 0
    # One known broken upstream detail URL should not page the operator.
    if source_failure_count > max(5, int(max(catalog_count, 1) * 0.05)):
        issues.append(f"слишком много upstream failures: {source_failure_count}")

    endpoints = {
        "Property Intent": "http://127.0.0.1:8050/health",
        "Growth Core": "http://127.0.0.1:8040/health",
        "CRM": "http://127.0.0.1:8020/health",
        "Mini App": "https://lebleu-app.srv1636153.hstgr.cloud/",
    }
    for name, url in endpoints.items():
        if not http_ok(url):
            issues.append(f"{name} недоступен")

    current_status = "unhealthy" if issues else "healthy"
    previous_status = previous.get("status")
    previous_issues = previous.get("issues") or []
    env = read_env(ENV)
    token = env.get("TELEGRAM_BOT_TOKEN", "")
    chat_id = env.get("OPERATOR_CHAT_ID", "")

    if issues and (previous_status != "unhealthy" or issues != previous_issues):
        text = "⚠️ Le Bleu product health\n" + "\n".join(f"• {x}" for x in issues)
        send_telegram(token, chat_id, text)
    elif not issues and previous_status == "unhealthy":
        send_telegram(
            token,
            chat_id,
            f"✅ Le Bleu product health восстановлен\nКаталог: {catalog_count} объектов.",
        )

    next_state = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "status": current_status,
        "issues": issues,
        "catalog_count": catalog_count,
        "publisher_count": published_count,
        "geo_count": geo_count,
        "source_failure_count": source_failure_count,
        "last_good_catalog_count": (
            last_good_count
            if any(x.startswith("резкое падение inventory") for x in issues)
            else (catalog_count or last_good_count)
        ),
    }
    STATE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATE.with_suffix(".tmp")
    tmp.write_text(json.dumps(next_state, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    os.replace(tmp, STATE)

    print(json.dumps(next_state, ensure_ascii=False))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())
