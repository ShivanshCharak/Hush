#!/usr/bin/env python3
"""Freeze 60 fresh dev-only evasion-v4 attacks. This generator never scores a detector."""
from __future__ import annotations
import copy, hashlib, json, random, sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from eval.run_metadata import snapshot

SEED=20261022
DEV=ROOT/"data/golden/dev.jsonl"
EXCLUDED_IDS={"sim-dev-hard_benign-0005","sim-dev-hard_benign-0030","modsec:03-Aug-2025:000020","modsec:09-Aug-2025:001940","sim-dev-none-0133","modsec:07-Aug-2025:000140"}
rows=[json.loads(line) for line in DEV.read_text(encoding="utf-8").splitlines() if line.strip()]
old_source_ids=set()
for version in ("v1","v2","v3"):
    path=ROOT/f"eval/runs/evasion-{version}-dev.json"
    if path.exists():
        content=json.loads(path.read_text(encoding="utf-8"))
        content=content.get("attacks",[]) if isinstance(content,dict) else content
        old_source_ids.update(item.get("source_dev_id") for item in content)
candidates=[row for row in rows if row["label"]=="speak" and row["id"] not in old_source_ids|EXCLUDED_IDS]
rng=random.Random(SEED)
selected=rng.sample(sorted(candidates,key=lambda row:row["id"]),60)
source_hash=hashlib.sha256(DEV.read_bytes()).hexdigest()
mutations=[]

def auth_slow(row,index,spacing):
    events=copy.deepcopy(row["events"])
    base=datetime.fromisoformat(events[0]["timestamp"].replace("Z","+00:00"))
    for n,event in enumerate(events):
        event.update({"event_type":"auth","result":"fail","status":401,"path":"/auth/login",
                      "username":f"acct-v4-{index:02d}-{n%4}","src_ip":f"198.51.100.{10+n%12}"})
        event["timestamp"]=(base+timedelta(minutes=spacing*n)).astimezone(timezone.utc).isoformat().replace("+00:00","Z")
    return {"id":f"evasion-v4-slow-{spacing:02d}m-{index:02d}","label":"speak","kind":"credential_stuffing","hard":True,
            "family":f"slow_rate_{spacing}m_rotating_users_12ip","spacing_minutes":spacing,"source_dev_id":row["id"],"events":events}

slow_sources=selected[:20]
for i,(row,spacing) in enumerate(zip(slow_sources,[15]*5+[30]*5+[45]*5+[60]*5),1):
    mutations.append(auth_slow(row,i,spacing))

payload_plan=[("nested_triple_encoding",8),("html_entity_encoding",8),("unicode_escape_encoding",8),("sql_keyword_splitting",8),("comment_case_obfuscation",8)]
for family_index,(family,count) in enumerate(payload_plan):
    for local_index,row in enumerate(selected[20+family_index*count:20+(family_index+1)*count],1):
        events=copy.deepcopy(row["events"])
        target=next((e for e in events if e.get("event_type")!="auth"),events[-1])
        case_id=family_index*count+local_index
        marker=f"v4-{family_index+1}-{local_index:02d}"
        family_name=family
        if family_name=="nested_triple_encoding":
            payload=f"id=1' UNION SELECT '{marker}' --"
            depth=3 if local_index<=4 else 4
            for _ in range(depth): payload=__import__("urllib.parse",fromlist=["quote"]).quote(payload,safe="")
            target["query"]="lookup="+payload
            target["path"]="/catalog/item"
            family_name+=f"_{depth}pass"
        elif family_name=="html_entity_encoding":
            target["query"]=f"lookup=&#39; OR &#57;=&#57; -- {marker}&view=&lt;img src=x onerror=alert(4)&gt;"
            target["path"]="/catalog/search"
        elif family_name=="unicode_escape_encoding":
            target["query"]=rf"lookup=\u0027%20OR%20\u0039=\u0039%20--%20{marker}"
            target["path"]=r"/catalog/\u002e\u002e/records"
        elif family_name=="sql_keyword_splitting":
            target["query"]=f"lookup=1%20UN/**/ION/**/SEL/**/ECT%20'{marker}'%20--"
            target["path"]="/catalog/item"
        else:
            target["query"]=f"lookup=1%20uN/**/iOn%20SeLeCt%20'{marker}'%20/*v4*/--"
            target["path"]="/catalog/item"
        mutations.append({"id":f"evasion-v4-{family_name}-{local_index:02d}","label":"speak","kind":"sqli","hard":True,
                          "family":family_name,"source_dev_id":row["id"],"events":events})

assert len(mutations)==60 and len({m["source_dev_id"] for m in mutations})==60
assert len({m["source_dev_id"] for m in mutations}&old_source_ids)==0
assert all(len(m["events"])==20 for m in mutations)
assert {n:sum(m.get("spacing_minutes")==n for m in mutations) for n in (15,30,45,60)}=={15:5,30:5,45:5,60:5}
attack_bytes=json.dumps(mutations,sort_keys=True,separators=(",",":"),ensure_ascii=False).encode()
out={"freeze_metadata":{"set":"evasion-v4","seed":SEED,"scope":"dev-only mutations from data/golden/dev.jsonl",
                       "source_dev_sha256":source_hash,"mutation_payload_sha256":hashlib.sha256(attack_bytes).hexdigest(),
                       "unique_dev_source_count":len({m["source_dev_id"] for m in mutations}),
                       "previous_v1_v3_source_reuse":0,"detector_scoring_performed":False,
                       "spacing_counts_minutes":{"15":5,"30":5,"45":5,"60":5},
                       "families":{m["family"]:sum(x["family"]==m["family"] for x in mutations) for m in mutations},
                       "normalization_contract_to_evaluate":["repeated URL decode up to 3 passes","HTML entity decode","Unicode escape decode","SQL comment stripping","whitespace collapse"],
                       "config_snapshot":snapshot(seed=SEED)},"attacks":mutations}
path=ROOT/"eval/runs/evasion-v4-dev.json"
path.write_text(json.dumps(out,indent=2,sort_keys=True)+"\n",encoding="utf-8")
print(json.dumps({"artifact":str(path.relative_to(ROOT)),"attacks":len(mutations),"spacing_counts_minutes":out["freeze_metadata"]["spacing_counts_minutes"],
                  "families":out["freeze_metadata"]["families"],"source_hash":source_hash,
                  "mutation_payload_sha256":out["freeze_metadata"]["mutation_payload_sha256"],"old_source_reuse":0,"scoring_performed":False},indent=2))
