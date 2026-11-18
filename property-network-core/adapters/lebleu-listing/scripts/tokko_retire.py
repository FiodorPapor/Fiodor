#!/usr/bin/env python3
"""Confirm Tokko removals across two complete healthy API snapshots.

First absence is retained in public catalog with existing links. After a
second independent snapshot at least one hour later, remove a small
previously confirmed subset. Network failures never advance retirement.
"""
import argparse
import json
import os
import tempfile
import time
from pathlib import Path

DEFAULT_ROOT = Path('/opt/property-network-tokko-staging')
DEFAULT_CATALOG = Path('/opt/lebleu-listing-bridge/public/data/full/catalog.json')


def identity(item):
    return (str(item.get('code') or '').strip(), str(item.get('operation') or '').strip())


def stable_key(item):
    return json.dumps(identity(item), ensure_ascii=False, separators=(',', ':'))


def atomic(path, payload):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix='.tokko-pending-', dir=str(path.parent))
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, 'w', encoding='utf-8') as writer:
            json.dump(payload, writer, ensure_ascii=False, indent=2)
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(temp, path)
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def reconcile(legacy, candidate, audit, prior, now, min_age=3600, max_fraction=0.05):
    if not audit.get('ready_for_cutover') or audit.get('match_conflicts'):
        raise ValueError('tokko_source_quality_gate_failed')
    if int(audit.get('candidate_rows', -1)) != len(candidate) or int(audit.get('legacy_catalog', -1)) != len(legacy):
        raise ValueError('tokko_stage_size_mismatch')
    new_index={identity(x): x for x in candidate}
    old_index={identity(x): x for x in legacy}
    if len(new_index) != len(candidate) or len(old_index) != len(legacy):
        raise ValueError('code_operation_collision')
    previous = prior if isinstance(prior, dict) else {}
    updated={}
    held=[]
    retired=[]
    maximum=max(5, int(len(legacy)*max_fraction+0.999))
    for key,old in old_index.items():
        if key in new_index:
            continue
        if not old.get('tokkoSnapshotFingerprint'):
            raise ValueError('legacy_item_without_prior_tokko_baseline')
        marker=stable_key(old)
        entry=previous.get(marker) if isinstance(previous.get(marker),dict) else {}
        first=float(entry.get('first_absent_at',now))
        count=max(0, int(entry.get('consecutive_absences',0)))+1
        if first>now:
            first=now
            count=1
        updated[marker]={'first_absent_at':first,'last_absent_at':now,
                         'consecutive_absences':count}
        if count>=2 and now-first>=min_age:
            retired.append({'code':key[0],'operation':key[1],
                            'sourceUrl':old.get('sourceUrl'),
                            'snapshots':count, 'seconds_absent':int(now-first)})
        else:
            held.append(old)
    # Protect against accidental mass retirement even on two snapshots.
    if len(retired)>maximum:
        raise ValueError('tokko_retirement_batch_too_large')
    candidate = candidate + held
    audit = dict(audit)
    audit['candidate_rows']=len(candidate)
    audit['held_until_confirmed']=[{'code':x.get('code'),'operation':x.get('operation')} for x in held]
    audit['confirmed_retirements']=retired
    audit['retirement_policy']='at_least_2_healthy_snapshots_min_3600s_and_max_5_percent'
    if len({identity(x) for x in candidate})!=len(candidate):
        raise ValueError('candidate_duplicate_after_hold')
    if len(candidate)<len(legacy)-maximum:
        raise ValueError('catalog_below_retirement_safety_floor')
    return candidate,audit,updated


def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('--legacy',default=str(DEFAULT_CATALOG))
    parser.add_argument('--candidate',default=str(DEFAULT_ROOT/'candidate/candidate-catalog.json'))
    parser.add_argument('--audit',default=str(DEFAULT_ROOT/'candidate/audit.json'))
    parser.add_argument('--state',default=str(DEFAULT_ROOT/'retire-state.json'))
    args=parser.parse_args()
    legacy=json.loads(Path(args.legacy).read_text())
    candidate=json.loads(Path(args.candidate).read_text())
    audit=json.loads(Path(args.audit).read_text())
    state_path=Path(args.state)
    state=json.loads(state_path.read_text()) if state_path.exists() else {}
    new,report,updated=reconcile(legacy,candidate,audit,state,time.time())
    atomic(args.candidate,new)
    atomic(args.audit,report)
    atomic(args.state,updated)
    print(json.dumps({'candidate_rows':len(new),
                      'held_missing':len(report['held_until_confirmed']),
                      'confirmed_retirements':len(report['confirmed_retirements']),
                      'policy':report['retirement_policy']}))
    return 0


if __name__=='__main__':
    try:
        raise SystemExit(main())
    except Exception as error:
        # Deliberately do not include upstream URLs or sensitive payloads.
        print('Tokko retirement gate aborted: '+type(error).__name__,file=__import__('sys').stderr)
        raise SystemExit(2)
