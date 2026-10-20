#!/usr/bin/env python3
"""Create the requested 60-window, dev-derived mutation set only."""
from __future__ import annotations
import copy, json, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from decider.prompt import FEW_SHOT_EXAMPLES

rows=[json.loads(x) for x in (ROOT/'data/golden/dev.jsonl').read_text().splitlines() if x.strip()]
excluded={x['id'] for x in FEW_SHOT_EXAMPLES}
attacks=[r for r in rows if r['label']=='speak' and r['id'] not in excluded]
def choose(kind, count):
    vals=[r for r in attacks if r.get('kind')==kind]
    return sorted(vals,key=lambda r:r['id'])[:count]

out=[]
# 20 double URL encoded traversal / SQL injection dev attacks.
src=choose('path_traversal',17)+choose('sqli',3)
for i,row in enumerate(src,1):
    ev=copy.deepcopy(row['events'])
    for e in ev:
        for field in ('path','query'):
            value=e.get(field)
            if isinstance(value,str) and value:
                # Encode dots/slashes, then encode the percent signs a second time.
                once=value.replace('..','%2e%2e').replace('/','%2f').replace('\\','%5c')
                e[field]=once.replace('%','%25')
    out.append({'id':f'evasion-v1-double-url-{i:02d}','label':'speak','kind':row['kind'],'hard':True,'family':'double_url_encoding','source_dev_id':row['id'],'events':ev})

# 20 SQL injection attacks with mixed case and SQL comment separators.
for i,row in enumerate(choose('sqli',20),1):
    ev=copy.deepcopy(row['events'])
    for e in ev:
        for field in ('path','query'):
            value=e.get(field)
            if not isinstance(value,str): continue
            value=value.replace('UNION SELECT','uNiOn/**/SeLeCt').replace('union select','uNiOn/**/SeLeCt')
            value=value.replace(' OR 1=1',' oR/**/1=1').replace(' or 1=1',' oR/**/1=1')
            e[field]=value
    # Ensure an executable, comment-obfuscated condition even when source bytes
    # use a different encoding or quoting convention.
    target=next((e for e in ev if e.get('event_type') != 'auth'),ev[0])
    target['query']=(str(target.get('query') or '').rstrip('&')+'&' if target.get('query') else '')+'id=1/**/oR/**/1=1'
    out.append({'id':f'evasion-v1-case-comment-{i:02d}','label':'speak','kind':'sqli','hard':True,'family':'case_comment_obfuscation','source_dev_id':row['id'],'events':ev})

# 20 coordinated brute-force episodes diluted across five source IPs and five minutes.
ips=['192.0.2.21','192.0.2.22','192.0.2.23','192.0.2.24','192.0.2.25']
for i,row in enumerate(choose('brute_force',20),1):
    ev=copy.deepcopy(row['events'])
    base=datetime.fromisoformat(ev[0]['timestamp'].replace('Z','+00:00'))
    for j,e in enumerate(ev):
        e['src_ip']=ips[j%len(ips)]
        e['timestamp']=(base+timedelta(seconds=j*15)).astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    out.append({'id':f'evasion-v1-slow-5ip-{i:02d}','label':'speak','kind':'brute_force','hard':True,'family':'slow_rate_5plus_ips','source_dev_id':row['id'],'events':ev})

assert len(out)==60
path=ROOT/'eval/runs/evasion-v1-dev.json'
path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({'artifact':str(path.relative_to(ROOT)),'windows':len(out),'families':{name:sum(x['family']==name for x in out) for name in sorted({x['family'] for x in out})},'source_dev_ids':[x['source_dev_id'] for x in out]},indent=2))
