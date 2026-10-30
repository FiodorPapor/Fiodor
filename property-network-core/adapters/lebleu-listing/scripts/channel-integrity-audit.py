#!/usr/bin/env python3
from __future__ import annotations

import argparse
import asyncio
import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

from telethon import TelegramClient

ROOT = Path("/opt/lebleu-listing-bridge")
STATE = ROOT / "state/telegram-state.json"
REPORT = ROOT / "state/channel-integrity.json"
TG_ENV = Path("/opt/intent-radar/.env")
CHANNEL = "lebleu_argentina_ru"
LISTING_THREADS = {5, 6, 7, 8, 9, 10, 11, 12}
PROTECTED_IDS = set(LISTING_THREADS)


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def norm(text: str) -> str:
    value = (text or "").lower()
    value = re.sub(r"https?://\S+", "", value)
    value = re.sub(r"\d+\s*фото в альбоме", "N фото в альбоме", value)
    return re.sub(r"\s+", " ", value).strip()


def listing_like(row: dict) -> bool:
    text = row["text"]
    return bool(
        row["has_media"]
        or "Продажа ·" in text
        or "Аренда ·" in text
        or "Полная галерея" in text
        or "Узнать подробнее" in text
    )


async def scan(client: TelegramClient, entity, known_ids: set[int]) -> dict:
    rows: list[dict] = []
    async for message in client.iter_messages(entity, limit=6000):
        reply = getattr(message, "reply_to", None)
        thread_id = (
            getattr(reply, "reply_to_top_id", None)
            or getattr(reply, "reply_to_msg_id", None)
        )
        rows.append({
            "id": message.id,
            "date": message.date.isoformat() if message.date else None,
            "text": message.raw_text or "",
            "thread_id": thread_id,
            "has_media": bool(message.media),
            "known": message.id in known_ids,
        })

    listing_rows = [row for row in rows if row["thread_id"] in LISTING_THREADS]
    orphan = [
        row for row in listing_rows
        if not row["known"] and row["id"] not in PROTECTED_IDS and listing_like(row)
    ]

    current_caption_groups: dict[str, list[dict]] = defaultdict(list)
    for row in listing_rows:
        if not row["known"]:
            continue
        text = norm(row["text"])
        if text and ("продажа ·" in text or "аренда ·" in text):
            current_caption_groups[text].append(row)
    duplicate_caption_groups = [
        group for group in current_caption_groups.values() if len(group) > 1
    ]

    visible_ids = {row["id"] for row in rows}
    known_missing = sorted(known_ids - visible_ids)
    return {
        "messages_scanned": len(rows),
        "listing_thread_messages": len(listing_rows),
        "state_known_ids": len(known_ids),
        "orphan_listing_like": orphan,
        "duplicate_current_caption_groups": duplicate_caption_groups,
        "known_missing": known_missing,
        "topic_counts": dict(Counter(str(row["thread_id"]) for row in listing_rows)),
    }


async def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cleanup-orphans", action="store_true")
    args = parser.parse_args()

    state = json.loads(STATE.read_text(encoding="utf-8"))
    known_ids: set[int] = set()
    for entry in (state.get("entries") or {}).values():
        if entry.get("status") != "active":
            continue
        known_ids.update(int(x) for x in (entry.get("messageIds") or []))
        if entry.get("ctaMessageId"):
            known_ids.add(int(entry["ctaMessageId"]))

    env = read_env(TG_ENV)
    client = TelegramClient(
        env["TG_SESSION"],
        int(env["TG_API_ID"]),
        env["TG_API_HASH"],
    )
    await client.start()
    entity = await client.get_entity(CHANNEL)

    before = await scan(client, entity, known_ids)
    deleted = 0
    if args.cleanup_orphans and before["orphan_listing_like"]:
        ids = [row["id"] for row in before["orphan_listing_like"]]
        for start in range(0, len(ids), 100):
            batch = ids[start:start + 100]
            await client.delete_messages(entity, batch, revoke=True)
            deleted += len(batch)
        after = await scan(client, entity, known_ids)
    else:
        after = before

    await client.disconnect()

    report = {
        "checked_at": datetime.now(timezone.utc).isoformat(),
        "channel": CHANNEL,
        "cleanup_requested": args.cleanup_orphans,
        "deleted": deleted,
        "before": before,
        "after": after,
        "healthy": (
            len(after["orphan_listing_like"]) == 0
            and len(after["duplicate_current_caption_groups"]) == 0
            and len(after["known_missing"]) == 0
        ),
    }
    REPORT.write_text(json.dumps(report, ensure_ascii=False, indent=2), encoding="utf-8")
    print(json.dumps({
        "healthy": report["healthy"],
        "deleted": deleted,
        "messages_scanned": after["messages_scanned"],
        "listing_thread_messages": after["listing_thread_messages"],
        "state_known_ids": after["state_known_ids"],
        "orphan_listing_like": len(after["orphan_listing_like"]),
        "duplicate_current_caption_groups": len(after["duplicate_current_caption_groups"]),
        "known_missing": len(after["known_missing"]),
    }, ensure_ascii=False))
    return 0 if report["healthy"] else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
