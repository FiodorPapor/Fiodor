# Revenue Radar

Production code for the additive Telegram Revenue Radar running on `srv1636153`.

## Runtime layers

- `live_watcher/radar.py`: Telethon ingestion. Captures human Telegram messages into the existing raw/intelligence stores, polls public groups incrementally with per-source cursors, and discovers new public Argentina sources periodically.
- `broad_radar.py`: broad commercial detector. Tails `raw_messages` by an immutable raw ID cursor and processes each message once. It keeps permissive buyer, investor, renter, pre-intent, owner and partner candidates in a separate review queue.
- `radar_bot.py`: operator UI for the dedicated Telegram bot. Review state is persistent, so reviewed/noise candidates do not return to the new queue.
- `systemd/`: production service units.

## Design constraints

This layer is additive. It does not replace the legacy watcher, scoring, n8n workflows, CRM tables or Le Bleu publisher.

Recall and precision are separated: deterministic retrieval/classification is intentionally broad, while Telegram delivery and human review are ranked and stateful. Raw Telegram streams are not sent to third-party AI services.

Secrets and Telegram session files live only on the VPS and are never committed.
