#!/usr/bin/env python3
from __future__ import annotations

import json
import math
import re
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

CATALOG=Path("/opt/lebleu-listing-bridge/public/data/full/catalog.json")
GEO=Path("/opt/lebleu-listing-bridge/state/geo-enrichment.json")
API="https://apis.datos.gob.ar/georef/api/v2.0/direcciones"


def load(path:Path):
    return json.loads(path.read_text(encoding="utf-8"))


def norm_address(value:str)->str:
    s=str(value or "").strip()
    s=re.sub(r"\bal\s+(\d+)",r"\1",s,flags=re.I)
    s=re.sub(r"\be\s*/\s*", " entre ", s, flags=re.I)
    s=re.sub(r"\besq\.?\b", " esquina ", s, flags=re.I)
    s=re.sub(r"\s+"," ",s)
    return s


def distance_m(a_lat:float,a_lon:float,b_lat:float,b_lon:float)->float:
    r=6371000.0
    p1,p2=math.radians(a_lat),math.radians(b_lat)
    dp=math.radians(b_lat-a_lat)
    dl=math.radians(b_lon-a_lon)
    h=math.sin(dp/2)**2+math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return 2*r*math.asin(min(1,math.sqrt(h)))


def query(address:str,province:str|None,department:str|None):
    params={"direccion":address,"max":1}
    if province: params["provincia"]=province
    if department and not department.lower().startswith("comuna "):
        params["departamento"]=department
    url=API+"?"+urllib.parse.urlencode(params)
    req=urllib.request.Request(url,headers={"User-Agent":"RevenueRadar-LeBleu/1.0"})
    with urllib.request.urlopen(req,timeout=12) as response:
        data=json.load(response)
    rows=data.get("direcciones") or []
    return rows[0] if rows else None


def main():
    catalog=load(CATALOG)
    payload=load(GEO)
    entries=payload.get("entries") or {}
    by_point=defaultdict(list)
    for item in catalog:
        lat=item.get("latitude")
        lon=item.get("longitude")
        if isinstance(lat,(int,float)) and isinstance(lon,(int,float)):
            by_point[(round(float(lat),5),round(float(lon),5))].append(item)

    suspicious=set()
    for group in by_point.values():
        addresses={norm_address(x.get("address") or "").lower() for x in group if x.get("address")}
        if len(group)>1 and len(addresses)>1:
            suspicious.update(x.get("sourceUrl") for x in group if x.get("sourceUrl"))

    attempted=0
    refined=0
    rejected=0
    errors=0
    for item in catalog:
        source=item.get("sourceUrl")
        if source not in suspicious:
            continue
        address=norm_address(item.get("address") or "")
        entry=entries.get(source)
        if not address or not isinstance(entry,dict):
            continue
        source_lat=item.get("latitude")
        source_lon=item.get("longitude")
        if not isinstance(source_lat,(int,float)) or not isinstance(source_lon,(int,float)):
            continue
        attempted+=1
        try:
            hit=query(address,entry.get("province"),entry.get("department"))
        except Exception:
            errors+=1
            continue
        if not hit:
            rejected+=1
            continue
        location=hit.get("ubicacion") or {}
        lat=location.get("lat")
        lon=location.get("lon")
        if not isinstance(lat,(int,float)) or not isinstance(lon,(int,float)):
            rejected+=1
            continue
        distance=distance_m(float(source_lat),float(source_lon),float(lat),float(lon))
        limit=18000 if entry.get("province")=="Ciudad Autónoma de Buenos Aires" else 30000
        if distance>limit:
            rejected+=1
            continue
        entry["sourceLatitude"]=source_lat
        entry["sourceLongitude"]=source_lon
        entry["latitude"]=lat
        entry["longitude"]=lon
        entry["coordinateSource"]="georef_direcciones"
        entry["normalizedAddress"]=hit.get("nomenclatura")
        entry["addressDistanceM"]=round(distance)
        refined+=1
