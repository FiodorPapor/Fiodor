#!/usr/bin/env python3
"""Fail-closed, atomic Tokko candidate promotion; no Telegram writes."""
import argparse
import hashlib
import json
import os
import shutil
import stat
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path

def digest(b):
    return hashlib.sha256(b).hexdigest()

def token(item):
    return str(item.get('code') or '') + '_' + digest(str(item.get('sourceUrl') or '').encode())[:8]

def check(old, new, audit):
    problems=[]
    if not isinstance(old,list) or not isinstance(new,list) or not isinstance(audit,dict):
        return ['invalid_json_types']
    if not audit.get('ready_for_cutover') or audit.get('match_conflicts'):
        problems.append('tokko_stage_gate_failed')
    if audit.get('candidate_rows') != len(new) or audit.get('legacy_catalog') != len(old):
        problems.append('staging_size_mismatch')
    max_safe_removals = max(5, int(len(old)*0.05+0.999))
    if len(new) < len(old)-max_safe_removals or len(new) > len(old)+20:
        problems.append('unsafe_catalog_count_delta')
    old_index={(x.get('code'),x.get('operation')):x for x in old}
    new_index={(x.get('code'),x.get('operation')):x for x in new}
    if len(old_index)!=len(old) or len(new_index)!=len(new):
        problems.append('code_operation_collision')
    if len(set(token(x) for x in new))!=len(new):
        problems.append('public_token_collision')
    missing=set(old_index)-set(new_index)
    confirmed=audit.get('confirmed_retirements') or []
    allowed = {
        (str(x.get('code') or ''),str(x.get('operation') or ''))
        for x in confirmed if isinstance(x,dict)
        and int(x.get('snapshots',0))>=2 and int(x.get('seconds_absent',0))>=3600
    }
    if missing != allowed or len(missing)>max_safe_removals:
        problems.append('retirement_confirmation_mismatch:'+str(len(missing)))
    for key,previous in old_index.items():
        if key not in new_index:
            continue
        current=new_index[key]
        if token(previous)!=token(current):
            problems.append('public_token_changed:'+str(key[0])[:45])
        if previous.get('sourceUrl')!=current.get('sourceUrl'):
            problems.append('source_url_changed:'+str(key[0])[:45])
    for x in new:
        if not all([x.get('code'),x.get('operation'),x.get('sourceUrl'),
                    x.get('priceAmount'),x.get('priceCurrency'),x.get('imageUrls')]):
            problems.append('incomplete_public_card')
            break
        if not x.get('tokkoSnapshotFingerprint'):
            problems.append('missing_tokko_fingerprint')
            break
        if any(k in x for k in ('branch','producer','lead_receiver_user','contact_phone','api_key')):
            problems.append('private_tokko_field_leak')
            break
    return problems

def execute(args):
    live=Path(args.live)
    candidate=Path(args.candidate)
    report=Path(args.audit)
    old_bytes=live.read_bytes()
    new_bytes=candidate.read_bytes()
    audit=json.loads(report.read_text())
    old=json.loads(old_bytes)
    new=json.loads(new_bytes)
    problems=check(old,new,audit)
    info={'mode':'apply' if args.apply else 'dry_run',
          'old_count':len(old),'new_count':len(new),'old_sha256':digest(old_bytes),
          'candidate_sha256':digest(new_bytes),'issues':problems}
    if problems:
        print(json.dumps(info,ensure_ascii=False))
        return 2
    if not args.apply:
        print(json.dumps(info,ensure_ascii=False))
        return 0
    backups=Path(args.backups)
    backups.mkdir(parents=True,exist_ok=True)
    stamp=datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')
    backup=backups/('catalog-pre-tokko-'+stamp+'-'+digest(old_bytes)[:12]+'.json')
    if backup.exists():
        raise RuntimeError('backup_already_exists')
    with backup.open('xb') as stream:
        stream.write(old_bytes)
        stream.flush()
        os.fsync(stream.fileno())
    if backup.read_bytes()!=old_bytes:
        raise RuntimeError('backup_check_failed')
    # Race guard: if any other writer changed the file, NEVER replace it.
    if live.read_bytes()!=old_bytes:
        raise RuntimeError('catalog_modified_during_promotion')
    fd,tmp=tempfile.mkstemp(prefix='.tokko-next-',dir=str(live.parent))
    try:
        os.fchmod(fd,stat.S_IMODE(live.stat().st_mode))
        with os.fdopen(fd,'wb') as target:
            target.write(new_bytes)
            target.flush()
            os.fsync(target.fileno())
        os.replace(tmp,live)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)
    if live.read_bytes()!=new_bytes:
        raise RuntimeError('atomic_readback_failed')
    info['backup']=str(backup)
    info['applied_sha256']=digest(live.read_bytes())
    print(json.dumps(info,ensure_ascii=False))
    return 0

if __name__=='__main__':
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--live',default='/opt/lebleu-listing-bridge/public/data/full/catalog.json')
    p.add_argument('--candidate',default='/opt/property-network-tokko-staging/candidate/candidate-catalog.json')
    p.add_argument('--audit',default='/opt/property-network-tokko-staging/candidate/audit.json')
    p.add_argument('--backups',default='/opt/property-network-backups/tokko-catalog')
    p.add_argument('--apply',action='store_true')
    a=p.parse_args()
    try:
        sys.exit(execute(a))
    except Exception as exc:
        print('Tokko promote aborted safely: '+type(exc).__name__,file=sys.stderr)
        sys.exit(3)
