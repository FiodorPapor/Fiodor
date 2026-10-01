#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import re
import time
import urllib.parse
import urllib.request
from pathlib import Path

INTENT_BASE="http://127.0.0.1:8050"
ENV=Path("/opt/property-intent-core/.env")


def env_map():
    out={}
    for raw in ENV.read_text(encoding="utf-8").splitlines():
        line=raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k,v=line.split("=",1)
        out[k]=v.strip().strip('"').strip("'")
    return out


def request(path, payload=None):
    data=None if payload is None else json.dumps(payload,ensure_ascii=False).encode("utf-8")
    req=urllib.request.Request(
        INTENT_BASE+path,
        data=data,
        headers={"Content-Type":"application/json"},
        method="POST" if payload is not None else "GET",
    )
    with urllib.request.urlopen(req,timeout=10) as r:
        return json.load(r)


def signed_init_data(token:str, user_id:int)->str:
    user={"id":user_id,"first_name":"QA","username":"lebleu_smoke"}
    pairs={
        "auth_date":str(int(time.time())),
        "query_id":"LEBLEU_SMOKE",
        "user":json.dumps(user,separators=(",",":"),ensure_ascii=False),
    }
    check="\n".join(f"{k}={v}" for k,v in sorted(pairs.items()))
    secret=hmac.new(b"WebAppData",token.encode(),hashlib.sha256).digest()
    pairs["hash"]=hmac.new(secret,check.encode(),hashlib.sha256).hexdigest()
    return urllib.parse.urlencode(pairs)


def main():
    env=env_map()
    ids=[x.strip() for x in env.get("TEST_TELEGRAM_IDS","").split(",") if x.strip().lstrip("-").isdigit()]
    if not ids:
        raise SystemExit("TEST_TELEGRAM_IDS is required for semantic smoke test")
    init_data=signed_init_data(env["TELEGRAM_BOT_TOKEN"],int(ids[0]))

    catalog=request("/v1/catalog")
    items=catalog.get("items") or []
    assert len(items)>=20, f"catalog too small: {len(items)}"

    tokens=[str(x.get("listingToken") or "") for x in items]
    assert all(tokens), "missing listingToken"
    assert len(tokens)==len(set(tokens)), "duplicate listingToken"

    missing_ru=[x.get("listingToken") for x in items if not re.search(r"[А-Яа-яЁё]",x.get("description") or "")]
    assert not missing_ru, f"non-Russian descriptions: {missing_ru[:5]}"

    missing_geo=[x.get("listingToken") for x in items if x.get("latitude") is None or x.get("longitude") is None]
    assert not missing_geo, f"missing coordinates: {missing_geo[:5]}"

    property_types=sorted({str(x.get("propertyType") or "") for x in items if x.get("propertyType")})
    neighborhoods=catalog.get("neighborhoods") or []
    assert len(property_types)>=3, f"property types unexpectedly thin: {property_types}"
    assert len(neighborhoods)>=5, f"neighborhoods unexpectedly thin: {len(neighborhoods)}"

    listing=next((x for x in items if x.get("images")),items[0])
    code=listing["listingToken"]
    full=request("/v1/catalog/"+urllib.parse.quote(code,safe=""))
    assert full.get("listingToken")==code
    assert re.search(r"[А-Яа-яЁё]",full.get("description") or "")
    assert len(full.get("images") or [])>=1

    action_results={}
    for action in ("availability","viewing","share"):
        result=request("/v1/actions",{
            "init_data":init_data,
            "listing_code":code,
            "action":action,
        })
        assert result.get("ok") is True, (action,result)
        action_results[action]="ok"

    result=request("/v1/actions",{
        "init_data":init_data,
        "listing_code":code,
        "action":"question",
        "message":"QA smoke test. Ignore.",
    })
    assert result.get("ok") is True
    action_results["question"]="ok"

    print(json.dumps({
        "ok":True,
        "catalog":len(items),
        "russian":len(items)-len(missing_ru),
        "geo":len(items)-len(missing_geo),
        "property_types":len(property_types),
        "neighborhoods":len(neighborhoods),
        "detail_photos":len(full.get("images") or []),
        "actions":action_results,
    },ensure_ascii=False,sort_keys=True))


if __name__=="__main__":
    main()
