#!/usr/bin/env python3
import json, re, sys
from pathlib import Path

ROOT=Path("/opt/lebleu-listing-bridge")
catalog=json.loads((ROOT/"public/data/full/catalog.json").read_text(encoding="utf-8"))
quality=json.loads((ROOT/"state/ru-content-quality.json").read_text(encoding="utf-8"))
bad_patterns=[
    r"&quot;", r"&amp;", r"моноэколог", r"тепловой водопровод",
    r"стальной душ", r"арендуемых помещ", r"площадка для морож",
    r"смывн", r"Plaste", r"\?\?\?",
]
errors=[]
for item in catalog:
    # A reviewed Russian editorial summary is required only when the source
    # listing actually contains descriptive text. Source-missing listings use
    # current structured facts and must not be reported as stale translation work.
    if not str(item.get("description") or "").strip():
        continue
    url=item["sourceUrl"]
    q=quality.get(url)
    if not q:
        errors.append(f"MISSING {item.get('code')} {url}")
        continue
    reviewed_fp=q.get("ruContentFingerprint") or q.get("sourceFingerprint")
    current_fp=item.get("ruContentFingerprint") or item.get("sourceFingerprint")
    if reviewed_fp != current_fp:
        errors.append(f"STALE {item.get('code')} {url}")
    text=(q.get("summary_ru") or "")+" "+" ".join(q.get("notes_ru") or [])
    if not (q.get("summary_ru") or "").strip():
        errors.append(f"EMPTY {item.get('code')} {url}")
    for pattern in bad_patterns:
        if re.search(pattern,text,re.I):
            errors.append(f"BAD_TEXT {item.get('code')} {pattern}")
if errors:
    print("\n".join(errors))
    sys.exit(1)
print(json.dumps({"catalog":len(catalog),"reviewed":len(quality),"errors":0},ensure_ascii=False))
