#!/usr/bin/env python3
from __future__ import annotations

import hashlib
import hmac
import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

INTENT_BASE=os.environ.get("INTENT_BASE", "http://127.0.0.1:8050").rstrip("/")
ENV=Path(os.environ.get("INTENT_ENV_PATH", "/opt/property-intent-core/.env"))


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
    user={"id":user_id,"first_name":"QA","username":"property_network_smoke"}
    pairs={
        "auth_date":str(int(time.time())),
        "query_id":"PROPERTY_NETWORK_SMOKE",
        "signature":"qa-third-party-signature-field",
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
    session_info=request("/v1/session",{"init_data":init_data})
    click_token=session_info.get("outbound_click_token")
    assert click_token, session_info
    public_config=request("/v1/config")
    source_label=public_config.get("sourceLabel") or "original_source"

    catalog=request("/v1/catalog")
    items=catalog.get("items") or []
    assert len(items)>=20, f"catalog too small: {len(items)}"

    tokens=[str(x.get("listingToken") or "") for x in items]
    assert all(tokens), "missing listingToken"
    assert len(tokens)==len(set(tokens)), "duplicate listingToken"

    bad_ru=[x.get("listingToken") for x in items if (x.get("description") or "").strip() and not re.search(r"[А-Яа-яЁё]",x.get("description") or "")]
    assert not bad_ru, f"non-Russian user-facing descriptions: {bad_ru[:5]}"
    missing_context=[x.get("listingToken") for x in items if not re.search(r"[А-Яа-яЁё]",(x.get("description") or "")+(x.get("summary") or ""))]
    assert not missing_context, f"listing has neither Russian description nor Russian factual summary: {missing_context[:5]}"
    # A reviewed editorial summary and a full source translation are distinct content layers.
    # Regress if the API ever starts presenting the former as the latter again.
    assert not any(x.get("descriptionKind")=="reviewed_summary" for x in items), "reviewed summary leaked into description layer"
    reviewed_summaries=[x for x in items if x.get("summaryKind")=="reviewed_summary"]
    assert len(reviewed_summaries)>=100, f"reviewed-summary coverage unexpectedly low: {len(reviewed_summaries)}"

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
    assert re.search(r"[А-Яа-яЁё]",(full.get("description") or "")+(full.get("summary") or ""))
    assert full.get("descriptionKind") in {"source_translation","source_missing","translation_pending"}
    assert len(full.get("images") or [])>=1

    action_results={}
    click_id="qa-smoke-redirect-"+str(int(time.time()*1000))
    redirect_url=INTENT_BASE+"/v1/out/original?"+urllib.parse.urlencode({
        "listing_code":code,"click_token":click_token,"click_id":click_id
    })
    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self,req,fp,code,msg,headers,newurl):
            return None
    try:
        urllib.request.build_opener(NoRedirect).open(redirect_url,timeout=10)
        raise AssertionError("expected redirect")
    except urllib.error.HTTPError as exc:
        assert exc.code==302, exc
        location=exc.headers.get("Location") or ""
        assert "utm_source=telegram" in location and "utm_medium=miniapp" in location and "lb_click=" in location, location
    action_results["original_redirect"]="ok"
    tracked=request("/v1/events",{
        "init_data":init_data,
        "event_name":"original_opened",
        "listing_code":code,
        "properties":{"click_id":"qa-smoke-original","destination":source_label},
    })
    assert tracked.get("ok") is True, tracked
    assert tracked.get("crm_fact_id") is None, tracked
    action_results["original_tracking"]="ok"
    first_viewing_id=None
    for action in ("availability","viewing","share"):
        result=request("/v1/actions",{
            "init_data":init_data,
            "listing_code":code,
            "action":action,
        })
        assert result.get("ok") is True, (action,result)
        if action != "share":
            assert result.get("action_id"), (action,result)
            assert result.get("delivery_message"), (action,result)
            assert result.get("test_mode") is True, (action,result)
        if action == "viewing":
            first_viewing_id=result.get("action_id")
        action_results[action]="ok"

    duplicate=request("/v1/actions",{
        "init_data":init_data,
        "listing_code":code,
        "action":"viewing",
    })
    assert duplicate.get("ok") is True and duplicate.get("duplicate") is True, duplicate
    assert duplicate.get("action_id")==first_viewing_id, duplicate
    action_results["viewing_dedupe"]="ok"

    result=request("/v1/actions",{
        "init_data":init_data,
        "listing_code":code,
        "action":"question",
        "message":"QA smoke test. Ignore.",
    })
    assert result.get("ok") is True
    assert result.get("action_id") and result.get("delivery_message") and result.get("test_mode") is True
    action_results["question"]="ok"

    print(json.dumps({
        "ok":True,
        "catalog":len(items),
        "russian_context":len(items)-len(missing_context),
        "geo":len(items)-len(missing_geo),
        "property_types":len(property_types),
        "neighborhoods":len(neighborhoods),
        "detail_photos":len(full.get("images") or []),
        "actions":action_results,
    },ensure_ascii=False,sort_keys=True))


if __name__=="__main__":
    main()
