#!/usr/bin/env python3
from __future__ import annotations

import asyncio
import json
from pathlib import Path

from telethon import TelegramClient

ROOT = Path("/opt/lebleu-listing-bridge")
QUEUE = ROOT / "state/telegram-user-delete-queue.json"
TG_ENV = Path("/opt/intent-radar/.env")
PUBLISHER_ENV = ROOT / "publisher.env"


def read_env(path: Path) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def read_queue() -> list[int]:
    try:
        raw = json.loads(QUEUE.read_text(encoding="utf-8"))
    except Exception:
        return []
    if not isinstance(raw, list):
        return []
    return sorted({int(x) for x in raw if str(x).lstrip("-").isdigit()})


def write_queue(ids: list[int]) -> None:
    tmp = QUEUE.with_suffix(".tmp")
    tmp.write_text(json.dumps(ids, indent=2) + "\n", encoding="utf-8")
    tmp.replace(QUEUE)


async def main() -> int:
    ids = read_queue()
    if not ids:
        print("user_delete_queue empty")
        return 0

    tg = read_env(TG_ENV)
    pub = read_env(PUBLISHER_ENV)
    channel = pub.get("TELEGRAM_CHANNEL", "@lebleu_argentina_ru")

    client = TelegramClient(
        tg["TG_SESSION"],
        int(tg["TG_API_ID"]),
        tg["TG_API_HASH"],
    )
    await client.start()
    entity = await client.get_entity(channel)

    existing: list[int] = []
    for message_id in ids:
        message = await client.get_messages(entity, ids=message_id)
        if message:
            existing.append(message_id)

    if existing:
        for start in range(0, len(existing), 100):
            await client.delete_messages(entity, existing[start:start + 100], revoke=True)

    remaining: list[int] = []
    for message_id in ids:
        message = await client.get_messages(entity, ids=message_id)
        if message:
            remaining.append(message_id)

    await client.disconnect()
    write_queue(remaining)
    print(json.dumps({
        "queued": len(ids),
        "existing": len(existing),
        "deleted": len(existing) - len(remaining),
        "remaining": len(remaining),
    }))
    return 0 if not remaining else 2


if __name__ == "__main__":
    raise SystemExit(asyncio.run(main()))
