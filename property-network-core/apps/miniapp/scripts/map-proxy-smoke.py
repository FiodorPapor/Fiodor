#!/usr/bin/env python3
import json
import math
import os
import urllib.parse
import urllib.request

BASE=os.environ.get("MINIAPP_BASE", "https://catalog.example.com").rstrip("/")

def get(path,timeout=12):
    req=urllib.request.Request(BASE+path,headers={"User-Agent":"PropertyNetworkMapSmoke/1.0"})
    with urllib.request.urlopen(req,timeout=timeout) as response:
        body=response.read()
        if response.status!=200:
            raise RuntimeError(f"{path}: HTTP {response.status}")
        return body

styles={}
for style_name in ("positron","bright"):
    styles[style_name]=json.loads(get(f"/map/styles/{style_name}"))
    if style_name=="bright":
        ids=[str(x.get("id","")) for x in styles[style_name].get("layers",[])]
        if not any("building" in x.lower() for x in ids):
            raise SystemExit("bright style missing building layer")
        if not any("poi" in x.lower() for x in ids):
            raise SystemExit("bright style missing POI layer")
style=styles["bright"]
source_url=((style.get("sources") or {}).get("openmaptiles") or {}).get("url")
if not source_url:
    # OpenFreeMap may use another source key. Take the first TileJSON source.
    source_url=next((v.get("url") for v in (style.get("sources") or {}).values() if isinstance(v,dict) and v.get("url")),None)
if not source_url:
    raise SystemExit("map style has no TileJSON source")
parsed=urllib.parse.urlparse(source_url)
tilejson_path=parsed.path or source_url
tilejson=json.loads(get(tilejson_path))
template=(tilejson.get("tiles") or [None])[0]
if not template:
    raise SystemExit("TileJSON has no tiles template")

z=10
lon=-58.43
lat=-34.60
n=2**z
x=int((lon+180.0)/360.0*n)
lat_rad=math.radians(lat)
y=int((1.0-math.asinh(math.tan(lat_rad))/math.pi)/2.0*n)
path=template.replace("{z}",str(z)).replace("{x}",str(x)).replace("{y}",str(y))
if path.startswith("http://") or path.startswith("https://"):
    parsed=urllib.parse.urlparse(path)
    path=parsed.path+("?"+parsed.query if parsed.query else "")
body=get(path)
if len(body)<500:
    raise SystemExit(f"map tile unexpectedly small: {len(body)} bytes")
print(json.dumps({"ok":True,"styles":["positron","bright"],"detail_style_has_buildings":True,"detail_style_has_poi":True,"tile":path,"bytes":len(body)}))
