#!/usr/bin/env python3
from __future__ import annotations

import json
import os
import re
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
CATALOG_QUALITY = ROOT / "state/catalog-quality.json"
RU_CONTENT_QUALITY = ROOT / "state/ru-content-quality.json"
CATALOG_ALIASES = ROOT / "public/data/full/catalog-aliases.json"
CHANNEL_INTEGRITY = ROOT / "state/channel-integrity.json"
USER_DELETE_QUEUE = ROOT / "state/telegram-user-delete-queue.json"
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


def miniapp_boot_ok(url: str, timeout: float = 4.0) -> tuple[bool, str]:
    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "LeBleuProductWatch/1.0", "Cache-Control": "no-cache"},
        )
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(8192).decode("utf-8", errors="replace")
            cache_control = ",".join(r.headers.get_all("Cache-Control") or []).lower()
            if not (200 <= r.status < 300):
                return False, f"http {r.status}"
            if "Открываем каталог" not in body or "Повторить" not in body:
                return False, "boot fallback marker missing"
            if "no-store" not in cache_control:
                return False, f"html cache policy unsafe: {cache_control or 'missing'}"
            return True, "ok"
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"


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

    stale_repls: list[str] = []
    rc, ps_output = cmd("ps", "-eo", "pid=,etimes=,args=")
    if rc == 0:
        for raw in ps_output.splitlines():
            parts = raw.strip().split(None, 2)
            if len(parts) != 3:
                continue
            pid, age_raw, args = parts
            try:
                age_seconds = int(age_raw)
            except ValueError:
                continue
            if age_seconds >= 300 and re.search(r"(?:^|\s)python(?:3(?:\.\d+)?)?\s+-i(?:\s|$)", args):
                stale_repls.append(f"{pid}:{age_seconds}s")
    if stale_repls:
        issues.append("зависший interactive Python REPL: " + ", ".join(stale_repls[:3]))

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

    catalog: list[dict] = []
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

    quality = load_json(CATALOG_QUALITY, {})
    quality_output_count = int(quality.get("outputCount") or 0) if isinstance(quality, dict) else 0
    quality_input_count = int(quality.get("inputCount") or 0) if isinstance(quality, dict) else 0
    quality_suppressed_count = int(quality.get("suppressedCount") or 0) if isinstance(quality, dict) else 0
    quality_photo_drops = int(quality.get("duplicatePhotosRemoved") or 0) if isinstance(quality, dict) else 0
    quality_image_errors = int(quality.get("imageErrors") or 0) if isinstance(quality, dict) else 0
    quality_version = str(quality.get("version") or "") if isinstance(quality, dict) else ""
    if not quality_version.startswith("dedupe-v3-cross-type-image-verified"):
        issues.append("catalog quality normalizer не v3 cross-type image-verified")
    if catalog_count and quality_output_count != catalog_count:
        issues.append(f"quality report не совпадает с каталогом: {quality_output_count}/{catalog_count}")
    if quality_image_errors > max(3, int(max(quality_input_count, 1) * 0.03)):
        issues.append(f"ошибки image dedupe: {quality_image_errors}")
    if CATALOG_QUALITY.exists() and CATALOG.exists():
        if CATALOG_QUALITY.stat().st_mtime + 5 < CATALOG.stat().st_mtime:
            issues.append("quality report старее catalog.json")

    ru_quality = load_json(RU_CONTENT_QUALITY, {})
    ru_missing = 0
    ru_stale = 0
    ru_non_russian = 0
    ru_unreviewed = 0
    if isinstance(catalog, list) and isinstance(ru_quality, dict):
        for item in catalog:
            row = ru_quality.get(item.get("sourceUrl")) or {}
            summary = str(row.get("summary_ru") or "").strip()
            if not summary:
                ru_missing += 1
                continue
            if row.get("sourceFingerprint") and row.get("sourceFingerprint") != item.get("sourceFingerprint"):
                ru_stale += 1
            if not any("А" <= ch <= "я" or ch in "Ёё" for ch in summary):
                ru_non_russian += 1
            editor = str(row.get("editor") or "")
            if editor and ("auto" in editor.lower() or editor.lower().startswith("local_")):
                ru_unreviewed += 1
    else:
        ru_missing = catalog_count
    if ru_missing or ru_stale or ru_non_russian or ru_unreviewed:
        issues.append(
            "русский контент требует внимания: "
            f"missing={ru_missing}, stale={ru_stale}, non_ru={ru_non_russian}, unreviewed={ru_unreviewed}"
        )

    alias_payload = load_json(CATALOG_ALIASES, {})
    aliases = alias_payload.get("aliases", {}) if isinstance(alias_payload, dict) else {}
    alias_count = len(aliases) if isinstance(aliases, dict) else 0
    if alias_count != quality_suppressed_count:
        issues.append(f"alias map не совпадает с dedupe: {alias_count}/{quality_suppressed_count}")

    channel_integrity = load_json(CHANNEL_INTEGRITY, {})
    if isinstance(channel_integrity, dict) and channel_integrity:
        if not channel_integrity.get("healthy", False):
            issues.append("последний channel integrity audit unhealthy")

    pending_user_deletes = load_json(USER_DELETE_QUEUE, [])
    pending_user_delete_count = (
        len(pending_user_deletes) if isinstance(pending_user_deletes, list) else 0
    )
    if pending_user_delete_count:
        issues.append(f"Telegram cleanup queue не пуст: {pending_user_delete_count}")

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
    }
    for name, url in endpoints.items():
        if not http_ok(url):
            issues.append(f"{name} недоступен")

    miniapp_ok, miniapp_detail = miniapp_boot_ok(
        "https://lebleu-app.srv1636153.hstgr.cloud/?health=1"
    )
    if not miniapp_ok:
        issues.append(f"Mini App boot unhealthy: {miniapp_detail}")

    map_rc, map_detail = cmd("python3", "/opt/lebleu-miniapp/scripts/map-proxy-smoke.py")
    map_proxy_ok = map_rc == 0
    if not map_proxy_ok:
        issues.append(f"Mini App map proxy unhealthy: {map_detail[:180]}")

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
        "quality_version": quality_version,
        "quality_input_count": quality_input_count,
        "quality_output_count": quality_output_count,
        "quality_suppressed_count": quality_suppressed_count,
        "quality_duplicate_photos_removed": quality_photo_drops,
        "quality_image_errors": quality_image_errors,
        "ru_content_missing": ru_missing,
        "ru_content_stale": ru_stale,
        "ru_content_non_russian": ru_non_russian,
        "ru_content_unreviewed": ru_unreviewed,
        "alias_count": alias_count,
        "pending_user_delete_count": pending_user_delete_count,
        "stale_interactive_repl_count": len(stale_repls),
        "map_proxy_healthy": map_proxy_ok,
        "channel_integrity_healthy": (
            channel_integrity.get("healthy") if isinstance(channel_integrity, dict) and channel_integrity else None
        ),
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
