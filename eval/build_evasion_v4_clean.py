#!/usr/bin/env python3
"""Build a clean v4 revision from its frozen dev sources; no detector scoring."""
from __future__ import annotations
import copy, hashlib, json, random, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from urllib.parse import quote
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from eval.run_metadata import snapshot
SEED=20261023
source_path=ROOT/'eval/runs/evasion-v4-dev.json'
source=json.loads(source_path.read_text(encoding='utf-8'))
source_by_id={row['id']:row for row in [json.loads(line) for line in (ROOT/'data/golden/dev.jsonl').read_text().splitlines() if line.strip()]}
rng=random.Random(SEED)
old_source_ids=set()
for version in ('v1','v2','v3'):
    payload=json.loads((ROOT/f'eval/runs/evasion-{version}-dev.json').read_text())
    payload=payload.get('attacks',[]) if isinstance(payload,dict) else payload
    old_source_ids.update(row.get('source_dev_id') for row in payload)
mutations=[]

def clean_events(source_id, target_index):
    events=copy.deepcopy(source_by_id[source_id]['events'])
    for i,event in enumerate(events):
        event['event_type']='web'; event.pop('result',None); event['status']=200
        event['username']=None; event['path']='/catalog/item'; event['query']=f'item=record-{target_index}-{i}'
        event['user_agent']='Mozilla/5.0 (clean evasion fixture)'
    return events

slow_rows=[x for x in source['attacks'] if x['family'].startswith('slow_rate_')]
for index,row in enumerate(slow_rows,1):
    events=copy.deepcopy(source_by_id[row['source_dev_id']]['events'])
    spacing=row['spacing_minutes']; base=datetime.fromisoformat(events[0]['timestamp'].replace('Z','+00:00'))
    for n,event in enumerate(events):
        event.update({'event_type':'auth','result':'fail','status':401,'path':'/auth/login','query':'',
                      'username':f'acct-v4r-{index:02d}-{n%5}','src_ip':f'198.51.100.{20+n%14}',
                      'user_agent':'Mozilla/5.0 (clean auth fixture)'})
        event['timestamp']=(base+timedelta(minutes=spacing*n)).astimezone(timezone.utc).isoformat().replace('+00:00','Z')
    mutations.append({'id':f'evasion-v4-clean-slow-{spacing:02d}m-{index:02d}','label':'speak','kind':'credential_stuffing','hard':True,
                      'family':f'slow_rate_{spacing}m_rotating_users_14ip','spacing_minutes':spacing,'source_dev_id':row['source_dev_id'],'events':events})

payload_rows=[x for x in source['attacks'] if not x['family'].startswith('slow_rate_')]
by_family={name:[x for x in payload_rows if x['family'].startswith(name)] for name in ('nested_triple_encoding','html_entity_encoding','unicode_escape_encoding','sql_keyword_splitting','comment_case_obfuscation')}
for family_index,family in enumerate(by_family):
    rows=by_family[family]
    for local,row in enumerate(rows,1):
        index=family_index*8+local
        target_index=rng.randrange(20)
        events=clean_events(row['source_dev_id'],index)
        target=events[target_index]
        marker=f'clean-v4r-{family_index+1}-{local:02d}'
        family_name=family
        if family=='nested_triple_encoding':
            depth=3 if local<=4 else 4
            value=f"id=7' UNION SELECT '{marker}' --"
            for _ in range(depth): value=quote(value,safe='')
            target['query']='lookup='+value; family_name+=f'_{depth}pass'
        elif family=='html_entity_encoding':
            target['query']=f"lookup=&#39; OR &#55;=&#55; -- {marker}"
        elif family=='unicode_escape_encoding':
            target['query']=rf"lookup=\u0027%20OR%20\u0037=\u0037%20--%20{marker}"
        elif family=='sql_keyword_splitting':
            target['query']=f"lookup=7%20UN/**/ION/**/SEL/**/ECT%20'{marker}'%20--"
        else:
            target['query']=f"lookup=7%20uN/**/iOn%20SeLeCt%20'{marker}'%20/*case*/--"
        mutations.append({'id':f'evasion-v4-clean-{family_name}-{local:02d}','label':'speak','kind':'sqli','hard':True,
                          'family':family_name,'source_dev_id':row['source_dev_id'],'target_event_index':target_index,'events':events})

assert len(mutations)==60 and len({m['source_dev_id'] for m in mutations})==60
assert len({m['source_dev_id'] for m in mutations}&old_source_ids)==0
assert all(len(m['events'])==20 for m in mutations)
spacing_counts={str(s):sum(m.get('spacing_minutes')==s for m in mutations) for s in (15,30,45,60)}
assert spacing_counts=={'15':5,'30':5,'45':5,'60':5}
payload_hash=hashlib.sha256(json.dumps(mutations,sort_keys=True,separators=(',',':'),ensure_ascii=False).encode()).hexdigest()
out={'freeze_metadata':{'set':'evasion-v4-clean-revision','revision_of':'e4756fdb','seed':SEED,
    'scope':'dev-only; same 60 disjoint source windows as frozen v4, with all non-target payloads neutralized',
    'normalization_cases':'fresh payload markers and values; 3/4 URL passes, entities, Unicode escapes, split keywords, case/comment variants',
    'spacing_counts_minutes':spacing_counts,'unique_source_count':60,'mutation_payload_sha256':payload_hash,
    'detector_scoring_performed':False,'config_snapshot':snapshot(seed=SEED)},'attacks':mutations}
path=ROOT/'eval/runs/evasion-v4-clean-dev.json'; path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps({'artifact':str(path.relative_to(ROOT)),'count':len(mutations),'families':{f:sum(m['family'].startswith(f) for m in mutations) for f in by_family},
                  'spacing_counts_minutes':spacing_counts,'payload_sha256':payload_hash,'score_performed':False},indent=2))
