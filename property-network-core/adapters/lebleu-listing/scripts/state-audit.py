#!/usr/bin/env python3
import json, re, sys
from pathlib import Path
ROOT=Path("/opt/lebleu-listing-bridge")
cat=json.loads((ROOT/"public/data/full/catalog.json").read_text())
state=json.loads((ROOT/"state/telegram-state.json").read_text())
entries=state.get("entries",{})
errors=[]
modes={}
for item in cat:
    url=item["sourceUrl"]
    e=entries.get(url)
    if not e:
        errors.append(f"MISSING_STATE {item.get('code')}")
        continue
    if e.get("status")!="active":
        errors.append(f"NOT_ACTIVE {item.get('code')} {e.get('status')}")
    n=len(item.get("imageUrls") or [])
    desired="album" if n>=2 else ("media" if n==1 else "text")
    if e.get("mode")!=desired:
        errors.append(f"MODE {item.get('code')} current={e.get('mode')} desired={desired}")
    if e.get("mode")=="album":
        if not e.get("ctaMessageId"):
            errors.append(f"NO_CTA {item.get('code')}")
        if not (2 <= len(e.get("messageIds") or []) <= 4):
            errors.append(f"ALBUM_COUNT {item.get('code')} {len(e.get('messageIds') or [])}")
    caption=e.get("caption") or ""
    for pat in ["&quot;","моноэколог","стальной душ","площадка для морож","смывн","тепловой водопровод"]:
        if pat.lower() in caption.lower():
            errors.append(f"BAD_TEXT {item.get('code')} {pat}")
    modes[e.get("mode")]=modes.get(e.get("mode"),0)+1
extra=[u for u in entries if u not in {x["sourceUrl"] for x in cat} and entries[u].get("status")=="active"]
if extra: errors.append(f"EXTRA_ACTIVE {len(extra)}")
print(json.dumps({"catalog":len(cat),"state":len(entries),"modes":modes,"errors":len(errors)},ensure_ascii=False))
for x in errors[:100]: print(x)
sys.exit(1 if errors else 0)
