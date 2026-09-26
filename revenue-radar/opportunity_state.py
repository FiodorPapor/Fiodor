#!/usr/bin/env python3
import argparse, hashlib, json, os, sqlite3, sys, urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from zoneinfo import ZoneInfo

DB_PATH = os.environ.get("RR_OPPORTUNITY_DB", "/opt/intent-radar/data/opportunities.sqlite3")
TZ = ZoneInfo(os.environ.get("RR_TIMEZONE", "America/Argentina/Buenos_Aires"))
TERMINAL = {"WON", "LOST", "ARCHIVED"}
STAGES = {"NEW","REVIEW","CONTACT","REPLIED","QUALIFIED","NURTURE","WON","LOST","ARCHIVED"}
PRIORITIES = {"HIGH","MEDIUM","LOW"}
KINDS = {"BUYER","PRE_INTENT","OWNER_DIRECT","OWNER_RENTAL","SELLER_LISTING","SUPPLY","RENTER","INVESTOR","PARTNER","RELOCATION","CONTENT","OTHER"}

def now_utc():
    return datetime.now(timezone.utc)

def iso(dt):
    if not dt:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=TZ)
    return dt.astimezone(timezone.utc).isoformat(timespec="seconds")

def local(dt_text):
    if not dt_text:
        return ""
    return datetime.fromisoformat(dt_text).astimezone(TZ).strftime("%Y-%m-%d %H:%M")

def parse_due(value):
    if not value:
        return None
    raw = value.strip().lower()
    base = datetime.now(TZ)
    if raw == "today":
        dt = base.replace(hour=10, minute=0, second=0, microsecond=0)
    elif raw == "tomorrow":
        dt = (base + timedelta(days=1)).replace(hour=10, minute=0, second=0, microsecond=0)
    else:
        try:
            dt = datetime.fromisoformat(value)
            if len(value) == 10:
                dt = dt.replace(hour=10)
        except ValueError:
            raise SystemExit(f"Invalid due date: {value}. Use ISO date/time, today or tomorrow.")
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=TZ)
    return iso(dt)

def connect():
    Path(DB_PATH).parent.mkdir(parents=True, exist_ok=True)
    con = sqlite3.connect(DB_PATH)
    con.row_factory = sqlite3.Row
    con.execute("PRAGMA foreign_keys=ON")
    con.execute("PRAGMA journal_mode=WAL")
    init_db(con)
    return con

def init_db(con):
    con.executescript("""
    CREATE TABLE IF NOT EXISTS people(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      platform TEXT NOT NULL DEFAULT 'telegram',
      identity_key TEXT NOT NULL UNIQUE,
      platform_user_id TEXT,
      username TEXT,
      display_name TEXT,
      first_seen TEXT NOT NULL,
      last_seen TEXT NOT NULL,
      notes TEXT
    );
    CREATE TABLE IF NOT EXISTS signals(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      source_key TEXT NOT NULL UNIQUE,
      person_id INTEGER NOT NULL REFERENCES people(id),
      occurred_at TEXT,
      source_title TEXT,
      category TEXT,
      score INTEGER,
      risk TEXT,
      text TEXT,
      link TEXT,
      reasons TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_signals_person ON signals(person_id, occurred_at DESC);
    CREATE TABLE IF NOT EXISTS opportunities(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      person_id INTEGER NOT NULL REFERENCES people(id),
      kind TEXT NOT NULL,
      title TEXT NOT NULL,
      stage TEXT NOT NULL DEFAULT 'REVIEW',
      priority TEXT NOT NULL DEFAULT 'MEDIUM',
      confidence TEXT,
      summary TEXT,
      crm_id TEXT,
      crm_synced_at TEXT,
      archived_reason TEXT,
      created_at TEXT NOT NULL,
      updated_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_opps_person ON opportunities(person_id, updated_at DESC);
    CREATE TABLE IF NOT EXISTS opportunity_signals(
      opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
      signal_id INTEGER NOT NULL REFERENCES signals(id) ON DELETE CASCADE,
      PRIMARY KEY(opportunity_id, signal_id)
    );
    CREATE TABLE IF NOT EXISTS actions(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      opportunity_id INTEGER NOT NULL REFERENCES opportunities(id) ON DELETE CASCADE,
      action_type TEXT NOT NULL DEFAULT 'FOLLOW_UP',
      description TEXT NOT NULL,
      due_at TEXT,
      status TEXT NOT NULL DEFAULT 'OPEN',
      completed_at TEXT,
      outcome TEXT,
      created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_actions_due ON actions(status, due_at);
    CREATE TABLE IF NOT EXISTS audit(
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      occurred_at TEXT NOT NULL,
      entity_type TEXT NOT NULL,
      entity_id INTEGER,
      event TEXT NOT NULL,
      data TEXT
    );
    """)
    con.commit()

def audit(con, entity_type, entity_id, event, data=None):
    con.execute("INSERT INTO audit(occurred_at,entity_type,entity_id,event,data) VALUES(?,?,?,?,?)",
                (iso(now_utc()), entity_type, entity_id, event, json.dumps(data or {}, ensure_ascii=False)))
    con.commit()

def clean_username(value):
    v = (value or "").strip()
    return v[1:] if v.startswith("@") else v

def identity_key(platform, identity, platform_user_id=None):
    if platform_user_id:
        return f"{platform}:id:{platform_user_id}"
    i = clean_username(identity).lower()
    if not i:
        raise SystemExit("identity or platform-user-id is required")
    return f"{platform}:user:{i}"

def upsert_person(con, platform="telegram", identity="", platform_user_id=None, username=None, name=None, notes=None):
    key = identity_key(platform, identity or username or name, platform_user_id)
    ts = iso(now_utc())
    row = con.execute("SELECT * FROM people WHERE identity_key=?", (key,)).fetchone()
    if not row and platform_user_id and username:
        row = con.execute("SELECT * FROM people WHERE platform=? AND lower(COALESCE(username,''))=lower(?) ORDER BY id LIMIT 1",
                          (platform, clean_username(username))).fetchone()
        if row:
            con.execute("UPDATE people SET identity_key=? WHERE id=?", (key, row["id"]))
            con.commit()
    if row:
        con.execute("""UPDATE people SET platform_user_id=COALESCE(?,platform_user_id),
                     username=COALESCE(NULLIF(?,''),username), display_name=COALESCE(NULLIF(?,''),display_name),
                     notes=COALESCE(NULLIF(?,''),notes), last_seen=? WHERE id=?""",
                    (platform_user_id, clean_username(username), name, notes, ts, row["id"]))
        con.commit()
        return row["id"]
    cur = con.execute("""INSERT INTO people(platform,identity_key,platform_user_id,username,display_name,first_seen,last_seen,notes)
                      VALUES(?,?,?,?,?,?,?,?)""",
                      (platform, key, platform_user_id, clean_username(username or identity), name, ts, ts, notes))
    con.commit()
    return cur.lastrowid

def signal_key(link, platform, person_id, occurred_at, text):
    if link:
        return link.strip()
    raw = "|".join([platform, str(person_id), occurred_at or "", text or ""])
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()

def add_signal(con, person_id, platform="telegram", occurred_at=None, source_title=None, category=None,
               score=None, risk=None, text=None, link=None, reasons=None):
    sk = signal_key(link, platform, person_id, occurred_at, text)
    existing = con.execute("SELECT id FROM signals WHERE source_key=?", (sk,)).fetchone()
    if existing:
        return existing["id"], False
    cur = con.execute("""INSERT INTO signals(source_key,person_id,occurred_at,source_title,category,score,risk,text,link,reasons,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?,?)""",
                      (sk, person_id, occurred_at, source_title, category, score, risk, text, link,
                       json.dumps(reasons or [], ensure_ascii=False), iso(now_utc())))
    con.commit()
    return cur.lastrowid, True

def active_opportunity(con, person_id, kind):
    return con.execute("SELECT * FROM opportunities WHERE person_id=? AND kind=? AND stage NOT IN ('WON','LOST','ARCHIVED') ORDER BY id DESC LIMIT 1",
                       (person_id, kind)).fetchone()

def add_or_update_opportunity(con, person_id, kind, title, stage="REVIEW", priority="MEDIUM",
                              confidence=None, summary=None, signal_id=None):
    kind, stage, priority = kind.upper(), stage.upper(), priority.upper()
    if kind not in KINDS: raise SystemExit(f"Unknown kind {kind}")
    if stage not in STAGES: raise SystemExit(f"Unknown stage {stage}")
    if priority not in PRIORITIES: raise SystemExit(f"Unknown priority {priority}")
    ts = iso(now_utc())
    opp = active_opportunity(con, person_id, kind)
    if opp:
        con.execute("""UPDATE opportunities SET title=COALESCE(NULLIF(?,''),title),stage=?,priority=?,
                     confidence=COALESCE(NULLIF(?,''),confidence),summary=COALESCE(NULLIF(?,''),summary),updated_at=?,
                     crm_synced_at=NULL WHERE id=?""", (title, stage, priority, confidence, summary, ts, opp["id"]))
        oid = opp["id"]; event = "updated"
    else:
        cur = con.execute("""INSERT INTO opportunities(person_id,kind,title,stage,priority,confidence,summary,created_at,updated_at)
                           VALUES(?,?,?,?,?,?,?,?,?)""",
                          (person_id, kind, title, stage, priority, confidence, summary, ts, ts))
        oid = cur.lastrowid; event = "created"
    if signal_id:
        con.execute("INSERT OR IGNORE INTO opportunity_signals(opportunity_id,signal_id) VALUES(?,?)", (oid, signal_id))
    con.commit()
    audit(con, "opportunity", oid, event, {"stage":stage,"priority":priority,"kind":kind})
    return oid

def open_action(con, opportunity_id):
    return con.execute("SELECT * FROM actions WHERE opportunity_id=? AND status='OPEN' ORDER BY due_at IS NULL,due_at,id LIMIT 1",
                       (opportunity_id,)).fetchone()

def add_action(con, opportunity_id, description, due=None, action_type="FOLLOW_UP"):
    if not description:
        return None
    due_at = parse_due(due) if due else None
    cur = con.execute("""INSERT INTO actions(opportunity_id,action_type,description,due_at,status,created_at)
                       VALUES(?,?,?,?, 'OPEN', ?)""",
                      (opportunity_id, action_type.upper(), description, due_at, iso(now_utc())))
    con.commit()
    audit(con, "action", cur.lastrowid, "created", {"opportunity_id":opportunity_id,"due_at":due_at})
    return cur.lastrowid

def person_label(row):
    return ("@" + row["username"]) if row["username"] else (row["display_name"] or row["identity_key"])

def show_opportunity(con, oid):
    o = con.execute("""SELECT o.*,p.username,p.display_name,p.identity_key FROM opportunities o
                     JOIN people p ON p.id=o.person_id WHERE o.id=?""",(oid,)).fetchone()
    if not o: raise SystemExit(f"Opportunity {oid} not found")
    a = open_action(con, oid)
    sigs = con.execute("""SELECT s.* FROM signals s JOIN opportunity_signals os ON os.signal_id=s.id
                        WHERE os.opportunity_id=? ORDER BY s.occurred_at DESC,s.id DESC LIMIT 8""",(oid,)).fetchall()
    print(f"#{o['id']} {person_label(o)} · {o['kind']} · {o['stage']} · {o['priority']}")
    print(o["title"])
    if o["summary"]: print(f"Summary: {o['summary']}")
    if a: print(f"Next: [{a['id']}] {local(a['due_at']) or 'unscheduled'} · {a['description']}")
    if o["archived_reason"]: print(f"Closed: {o['archived_reason']}")
    if o["crm_id"]: print(f"CRM: {o['crm_id']} · synced {local(o['crm_synced_at'])}")
    for s in sigs:
        print(f"  signal {s['id']} · {s['category'] or '-'} · {s['score'] or '-'} · {s['occurred_at'] or '-'}")
        print(f"    {((s['text'] or '').replace(chr(10),' '))[:180]}")
        if s["link"]: print(f"    {s['link']}")

def cmd_add(args):
    con=connect()
    pid=upsert_person(con,args.platform,args.identity,args.platform_user_id,args.username,args.name,args.person_notes)
    sid=None
    if args.source_link or args.source_text:
        sid,_=add_signal(con,pid,args.platform,args.source_date,args.source_title,args.signal_category,args.score,args.risk,args.source_text,args.source_link,args.reasons)
    title=args.title or f"{args.kind.upper()} · {args.name or args.username or args.identity}"
    oid=add_or_update_opportunity(con,pid,args.kind,title,args.stage,args.priority,args.confidence,args.summary,sid)
    if args.next_action:
        current=open_action(con,oid)
        if current and args.replace_action:
            con.execute("UPDATE actions SET status='CANCELED',completed_at=?,outcome='Replaced by newer next action' WHERE id=?",
                        (iso(now_utc()), current["id"])); con.commit()
        if not current or args.replace_action:
            add_action(con,oid,args.next_action,args.due,args.action_type)
    show_opportunity(con,oid)

def queue_rows(con, mode="today", days=7):
    now=datetime.now(TZ)
    today0=now.replace(hour=0,minute=0,second=0,microsecond=0)
    tomorrow0=today0+timedelta(days=1)
    next0=tomorrow0+timedelta(days=1)
    horizon=today0+timedelta(days=days+1)
    base="""SELECT a.id action_id,a.description,a.due_at,o.id opportunity_id,o.kind,o.stage,o.priority,o.title,
                  p.username,p.display_name,p.identity_key
           FROM actions a JOIN opportunities o ON o.id=a.opportunity_id JOIN people p ON p.id=o.person_id
           WHERE a.status='OPEN' AND o.stage NOT IN ('WON','LOST','ARCHIVED') """
    params=[]
    if mode=="overdue":
        base+=" AND a.due_at IS NOT NULL AND a.due_at < ?"; params=[iso(today0)]
    elif mode=="today":
        base+=" AND a.due_at >= ? AND a.due_at < ?"; params=[iso(today0),iso(tomorrow0)]
    elif mode=="tomorrow":
        base+=" AND a.due_at >= ? AND a.due_at < ?"; params=[iso(tomorrow0),iso(next0)]
    elif mode=="upcoming":
        base+=" AND a.due_at >= ? AND a.due_at < ?"; params=[iso(today0),iso(horizon)]
    elif mode=="all":
        pass
    else: raise SystemExit("mode must be overdue|today|tomorrow|upcoming|all")
    base+=" ORDER BY CASE o.priority WHEN 'HIGH' THEN 0 WHEN 'MEDIUM' THEN 1 ELSE 2 END, a.due_at IS NULL,a.due_at,o.updated_at DESC"
    return con.execute(base,params).fetchall()

def cmd_queue(args):
    con=connect(); rows=queue_rows(con,args.mode,args.days)
    if args.json:
        print(json.dumps([dict(r) for r in rows],ensure_ascii=False,indent=2)); return
    print(f"Revenue Radar queue · {args.mode} · {len(rows)}")
    for r in rows:
        print(f"#{r['opportunity_id']} [{r['priority']}] {person_label(r)} · {r['kind']} · {r['stage']}")
        print(f"  {local(r['due_at']) or 'unscheduled'} · {r['description']} · action:{r['action_id']}")
    missing=con.execute("""SELECT o.id,o.kind,o.stage,o.priority,o.title,p.username,p.display_name,p.identity_key
      FROM opportunities o JOIN people p ON p.id=o.person_id
      WHERE o.stage NOT IN ('WON','LOST','ARCHIVED')
      AND NOT EXISTS(SELECT 1 FROM actions a WHERE a.opportunity_id=o.id AND a.status='OPEN')
      ORDER BY o.updated_at DESC""").fetchall()
    if missing:
        print(f"\nNeeds decision / no open next action · {len(missing)}")
        for r in missing:
            print(f"#{r['id']} [{r['priority']}] {person_label(r)} · {r['kind']} · {r['stage']} · {r['title']}")

def cmd_show(args):
    con=connect(); target=args.target
    if target.isdigit(): return show_opportunity(con,int(target))
    u=clean_username(target).lower()
    row=con.execute("""SELECT o.id FROM opportunities o JOIN people p ON p.id=o.person_id
                     WHERE lower(COALESCE(p.username,''))=? OR lower(p.identity_key) LIKE ?
                     ORDER BY o.updated_at DESC LIMIT 1""",(u,f"%{u}%")).fetchone()
    if not row: raise SystemExit(f"No opportunity for {target}")
    show_opportunity(con,row["id"])

def cmd_set(args):
    con=connect(); o=con.execute("SELECT * FROM opportunities WHERE id=?",(args.id,)).fetchone()
    if not o: raise SystemExit("Opportunity not found")
    stage=(args.stage or o["stage"]).upper(); priority=(args.priority or o["priority"]).upper()
    if stage not in STAGES: raise SystemExit("Invalid stage")
    if priority not in PRIORITIES: raise SystemExit("Invalid priority")
    ts=iso(now_utc())
    con.execute("""UPDATE opportunities SET stage=?,priority=?,summary=COALESCE(?,summary),
                 archived_reason=COALESCE(?,archived_reason),updated_at=?,crm_synced_at=NULL WHERE id=?""",
                (stage,priority,args.summary,args.reason,ts,args.id)); con.commit()
    if args.next_action:
        if args.replace_action:
            con.execute("UPDATE actions SET status='CANCELED',completed_at=?,outcome='Replaced by newer next action' WHERE opportunity_id=? AND status='OPEN'",
                        (ts,args.id)); con.commit()
        add_action(con,args.id,args.next_action,args.due,args.action_type)
    audit(con,"opportunity",args.id,"state_changed",{"stage":stage,"priority":priority})
    show_opportunity(con,args.id)

def cmd_done(args):
    con=connect(); a=con.execute("SELECT * FROM actions WHERE id=?",(args.action_id,)).fetchone()
    if not a: raise SystemExit("Action not found")
    ts=iso(now_utc())
    con.execute("UPDATE actions SET status='DONE',completed_at=?,outcome=? WHERE id=?",(ts,args.outcome,args.action_id))
    con.execute("UPDATE opportunities SET updated_at=?,crm_synced_at=NULL WHERE id=?",(ts,a["opportunity_id"])); con.commit()
    if args.stage:
        con.execute("UPDATE opportunities SET stage=?,updated_at=? WHERE id=?", (args.stage.upper(),ts,a["opportunity_id"])); con.commit()
    if args.next_action: add_action(con,a["opportunity_id"],args.next_action,args.due,args.action_type)
    audit(con,"action",args.action_id,"completed",{"outcome":args.outcome})
    show_opportunity(con,a["opportunity_id"])

def cmd_archive(args):
    con=connect(); ts=iso(now_utc())
    con.execute("UPDATE opportunities SET stage='ARCHIVED',archived_reason=?,updated_at=?,crm_synced_at=NULL WHERE id=?",(args.reason,ts,args.id))
    con.execute("UPDATE actions SET status='CANCELED',completed_at=?,outcome='Opportunity archived' WHERE opportunity_id=? AND status='OPEN'",(ts,args.id))
    con.commit(); audit(con,"opportunity",args.id,"archived",{"reason":args.reason}); show_opportunity(con,args.id)

def build_crm_payload(con, oid):
    o=con.execute("""SELECT o.*,p.username,p.display_name,p.identity_key,p.platform_user_id FROM opportunities o
                   JOIN people p ON p.id=o.person_id WHERE o.id=?""",(oid,)).fetchone()
    if not o: raise SystemExit("Opportunity not found")
    a=open_action(con,oid)
    sigs=con.execute("""SELECT s.* FROM signals s JOIN opportunity_signals os ON os.signal_id=s.id
                      WHERE os.opportunity_id=? ORDER BY s.occurred_at DESC,s.id DESC""",(oid,)).fetchall()
    max_score=max([s["score"] or 0 for s in sigs] or [0])
    username=o["username"] or ""; tg=("https://t.me/"+username) if username else ""
    notes=[o["summary"] or ""]+[s["link"] for s in sigs[:3] if s["link"]]
    next_date=""
    if a and a["due_at"]: next_date=datetime.fromisoformat(a["due_at"]).astimezone(TZ).date().isoformat()
    cat={"HIGH":"A","MEDIUM":"B","LOW":"C"}[o["priority"]]
    potential={"HIGH":"Muy alto","MEDIUM":"Alto","LOW":"Medio"}[o["priority"]]
    contact_id=f"RR-CNT-{o['person_id']:04d}"; opp_id=f"RR-OPP-{o['id']:04d}"
    stamp=datetime.now(TZ).strftime("%Y-%m-%d %H:%M:%S")
    return {
      "contact":{
        "nombre":o["display_name"] or (("@"+username) if username else o["identity_key"]),
        "categoria":cat,"tipo":f"{o['kind']} / Revenue Radar","segmento":o["kind"],
        "organizacion":"","rol":"","zona":"Argentina","potencial":potential,"etapa":o["stage"],
        "telefono":"","whatsapp_url":"","email":"","instagram":"","linkedin":"","facebook":"",
        "telegram":tg,"web":"","contacto_directo":tg,
        "proxima_accion":a["description"] if a else "",
        "fecha_proxima_accion":next_date,"mensaje_sugerido":"",
        "notas":" | ".join(x for x in notes if x),"estado":"Activo","responsable":"Fiodor",
        "score":max_score,"id":contact_id,"creado_el":stamp,"actualizado_el":stamp
      },
      "opportunity":{
        "id":opp_id,"titulo":o["title"],"contacto_id":contact_id,"propiedad_id":"",
        "tipo":o["kind"],"etapa":o["stage"],"prioridad":o["priority"],
        "valor_estimado_usd":"","probabilidad":"","responsable":"Fiodor",
        "proximo_paso":a["description"] if a else "","fecha_proximo_paso":next_date,
        "notas":" | ".join(x for x in notes if x),
        "creado_el":o["created_at"],"actualizado_el":stamp
      },
      "meta":{"opportunity_id":o["id"],"crm_id":opp_id}
    }

def cmd_sync(args):
    con=connect()
    ids=[args.id] if args.id else [r["id"] for r in con.execute("""SELECT id FROM opportunities
      WHERE stage NOT IN ('ARCHIVED','LOST') AND (crm_synced_at IS NULL OR updated_at>crm_synced_at)
      ORDER BY updated_at""").fetchall()]
    if not ids: print("CRM sync: nothing pending"); return
    url=os.environ.get("RR_CRM_WEBHOOK_URL","")
    if not url and not args.dry_run: raise SystemExit("RR_CRM_WEBHOOK_URL is not configured")
    for oid in ids:
        payload=build_crm_payload(con,oid)
        if args.dry_run:
            print(json.dumps(payload,ensure_ascii=False,indent=2)); continue
        req=urllib.request.Request(url,data=json.dumps(payload,ensure_ascii=False).encode(),
             headers={"Content-Type":"application/json","User-Agent":"RevenueRadar/1.0"},method="POST")
        with urllib.request.urlopen(req,timeout=30) as resp:
            body=resp.read().decode("utf-8","replace")
            if resp.status>=300: raise RuntimeError(f"sync failed {resp.status}: {body[:300]}")
        ts=iso(now_utc())
        con.execute("UPDATE opportunities SET crm_id=?,crm_synced_at=? WHERE id=?",(payload["meta"]["crm_id"],ts,oid)); con.commit()
        audit(con,"opportunity",oid,"crm_synced",{"crm_id":payload["meta"]["crm_id"]})
        print(f"Synced opportunity #{oid} -> {payload['meta']['crm_id']}")

def cmd_mark_synced(args):
    con=connect()
    o=con.execute("SELECT id FROM opportunities WHERE id=?", (args.id,)).fetchone()
    if not o: raise SystemExit("Opportunity not found")
    crm_id=args.crm_id or f"RR-OPP-{args.id:04d}"
    ts=iso(now_utc())
    con.execute("UPDATE opportunities SET crm_id=?,crm_synced_at=? WHERE id=?", (crm_id,ts,args.id))
    con.commit()
    audit(con,"opportunity",args.id,"crm_synced_external",{"crm_id":crm_id})
    print(f"Marked opportunity #{args.id} synced -> {crm_id}")

def cmd_doctor(args):
    con=connect()
    bad=con.execute("""SELECT o.id,o.stage,o.title,p.username,p.display_name,p.identity_key FROM opportunities o
      JOIN people p ON p.id=o.person_id
      WHERE o.stage IN ('CONTACT','REPLIED','QUALIFIED','NURTURE')
      AND NOT EXISTS(SELECT 1 FROM actions a WHERE a.opportunity_id=o.id AND a.status='OPEN')""").fetchall()
    dup=con.execute("""SELECT identity_key,COUNT(*) n FROM people GROUP BY identity_key HAVING n>1""").fetchall()
    print(f"DB: {DB_PATH}")
    for t in ("people","signals","opportunities","actions"):
        n=con.execute("SELECT COUNT(*) FROM "+t).fetchone()[0]
        print(f"{t}: {n}")
    print(f"invariant violations: {len(bad)}")
    for r in bad: print(f"  #{r['id']} {person_label(r)} · {r['stage']} · no open next action")
    print(f"duplicate people keys: {len(dup)}")
    pending=con.execute("SELECT COUNT(*) FROM opportunities WHERE crm_synced_at IS NULL OR updated_at>crm_synced_at").fetchone()[0]
    print(f"CRM pending: {pending}")
    sys.exit(2 if bad or dup else 0)

def ingest_live_signal(*, platform="telegram", identity="", platform_user_id=None, username=None, name=None,
                       occurred_at=None, source_title=None, category=None, score=None, text=None, link=None, reasons=None):
    con=connect()
    pid=upsert_person(con,platform,identity,platform_user_id,username,name)
    return add_signal(con,pid,platform,occurred_at,source_title,category,score,None,text,link,reasons)

def parser():
    p=argparse.ArgumentParser(prog="opportunity_state.py")
    sp=p.add_subparsers(dest="cmd",required=True)
    a=sp.add_parser("add")
    a.add_argument("--identity",default=""); a.add_argument("--platform",default="telegram"); a.add_argument("--platform-user-id")
    a.add_argument("--username"); a.add_argument("--name"); a.add_argument("--person-notes")
    a.add_argument("--kind",required=True); a.add_argument("--title"); a.add_argument("--stage",default="REVIEW"); a.add_argument("--priority",default="MEDIUM")
    a.add_argument("--confidence"); a.add_argument("--summary"); a.add_argument("--risk")
    a.add_argument("--source-link"); a.add_argument("--source-text"); a.add_argument("--source-date"); a.add_argument("--source-title")
    a.add_argument("--signal-category"); a.add_argument("--score",type=int); a.add_argument("--reasons",action="append")
    a.add_argument("--next-action"); a.add_argument("--due"); a.add_argument("--action-type",default="FOLLOW_UP"); a.add_argument("--replace-action",action="store_true")
    a.set_defaults(func=cmd_add)
    q=sp.add_parser("queue"); q.add_argument("mode",nargs="?",default="today"); q.add_argument("--days",type=int,default=7); q.add_argument("--json",action="store_true"); q.set_defaults(func=cmd_queue)
    s=sp.add_parser("show"); s.add_argument("target"); s.set_defaults(func=cmd_show)
    st=sp.add_parser("set"); st.add_argument("id",type=int); st.add_argument("--stage"); st.add_argument("--priority"); st.add_argument("--summary"); st.add_argument("--reason")
    st.add_argument("--next-action"); st.add_argument("--due"); st.add_argument("--action-type",default="FOLLOW_UP"); st.add_argument("--replace-action",action="store_true"); st.set_defaults(func=cmd_set)
    d=sp.add_parser("done"); d.add_argument("action_id",type=int); d.add_argument("--outcome",default=""); d.add_argument("--stage"); d.add_argument("--next-action"); d.add_argument("--due"); d.add_argument("--action-type",default="FOLLOW_UP"); d.set_defaults(func=cmd_done)
    ar=sp.add_parser("archive"); ar.add_argument("id",type=int); ar.add_argument("--reason",required=True); ar.set_defaults(func=cmd_archive)
    sy=sp.add_parser("sync"); sy.add_argument("id",type=int,nargs="?"); sy.add_argument("--dry-run",action="store_true"); sy.set_defaults(func=cmd_sync)
    ms=sp.add_parser("mark-synced"); ms.add_argument("id",type=int); ms.add_argument("--crm-id"); ms.set_defaults(func=cmd_mark_synced)
    dr=sp.add_parser("doctor"); dr.set_defaults(func=cmd_doctor)
    return p

if __name__=="__main__":
    args=parser().parse_args(); args.func(args)
