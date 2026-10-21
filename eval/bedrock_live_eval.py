#!/usr/bin/env python3
"""Live Bedrock review of exactly 20 emitted alerts from dev streams only."""
from __future__ import annotations
import json, math, os, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pipeline.run import process
from explain.bedrock import BedrockExplainer
from eval.run_metadata import snapshot

def read(path): return [json.loads(x) for x in path.read_text().splitlines() if x.strip()]
def main():
    if os.environ.get("HUSH_BEDROCK_CONFIRMED") != "1":
        raise SystemExit("Wait for the user to confirm Bedrock credentials work, then set HUSH_BEDROCK_CONFIRMED=1")
    if not os.environ.get("BEDROCK_MODEL_ID") or not os.environ.get("AWS_REGION"):
        raise SystemExit("Set BEDROCK_MODEL_ID and AWS_REGION (user selected Claude Haiku 4.5 / us-west-2)")
    manifest=json.loads((ROOT/"data/streams/manifest.json").read_text())
    samples=[]
    for sid in manifest["dev_streams"]:
        events=read(ROOT/manifest["streams"][sid]["path"])
        trace=process(events,explainer=BedrockExplainer(model_id=""))
        byid={int(e["event_id"]):e for e in events}
        for row in trace:
            if not row.get("gate_emit"): continue
            window=[byid[i] for i in range(int(row["event_start"]),int(row["event_end"])+1) if i in byid]
            samples.append((sid,row,window))
            if len(samples)==20: break
        if len(samples)==20: break
    if len(samples)!=20: raise SystemExit(f"Only {len(samples)} emitted alerts available")
    exp=BedrockExplainer(timeout=30)
    rubric=[]; valid_entities=entities=0
    for sid,row,events in samples:
        decision={"speak":True,"kind":row["kind"],"evidence_ids":row["evidence_ids"]}
        explanation=exp.explain(decision,events)
        ids=set(explanation.get("evidence_ids",[])); allowed_ids={int(e["event_id"]) for e in events}
        cited=[e for e in events if int(e["event_id"]) in ids]
        cited_entities={str(e[k]) for e in cited for k in ("src_ip","username","path") if e.get(k)}
        all_entities={str(e[k]) for e in events for k in ("src_ip","username","path") if e.get(k)}
        text=" ".join(str(explanation.get(k,"")) for k in ("summary","suggested_action"))
        mentioned={entity for entity in all_entities if entity in text}; entities+=len(mentioned); valid_entities+=len(mentioned & cited_entities)
        valid_ids=bool(ids) and ids<=allowed_ids
        rubric.append({"alert_id":row["alert_id"],"stream":sid,"kind":row["kind"],"explanation_source":explanation.get("source"),"evidence_ids_valid":valid_ids,"entities_grounded":mentioned<=cited_entities,"rating_rubric":{"factuality_1_to_5":None,"evidence_quality_1_to_5":None,"actionability_1_to_5":None,"clarity_1_to_5":None},"review_notes":"Pending human rating"})
    ms=sorted(exp.invocation_latencies_ms)
    p95=ms[max(0,math.ceil(.95*len(ms))-1)] if ms else None
    entity_rate=valid_entities/entities if entities else 1.0
    valid_id_count=sum(x["evidence_ids_valid"] for x in rubric)
    report={"created_at":datetime.now(timezone.utc).isoformat(),"scope":"20 emitted alerts from dev streams only","model_id":exp.model_id,"region":os.environ["AWS_REGION"],"alert_count":20,"bedrock_call_count":exp.invocation_count,"call_count_equals_alert_count":exp.invocation_count==20,"latency_ms":{"p95":p95,"samples":len(ms)},"grounding":{"valid_evidence_id_alerts":valid_id_count,"alerts":20,"evidence_ids_all_valid":valid_id_count==20,"grounded_entity_mentions":valid_entities,"mentioned_entity_mentions":entities,"entity_grounding_rate":entity_rate,"entity_grounding_target":0.98,"entity_grounding_passed":entity_rate>=0.98},"template_fallbacks":len(exp.invocation_errors),"bedrock_errors":exp.invocation_errors[:5],"ratings":"human rubric sheet emitted beside report; scores pending","config_snapshot":snapshot()}
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out=ROOT/f"eval/runs/bedrock-live-{stamp}.json"; sheet=out.with_name(out.stem+"-ratings.jsonl")
    out.write_text(json.dumps(report,indent=2)+"\n"); sheet.write_text(json.dumps({"record_type":"run_metadata","config_snapshot":report["config_snapshot"],"created_at":report["created_at"]})+"\n"+"".join(json.dumps(x)+"\n" for x in rubric))
    print(json.dumps({"artifact":str(out),"ratings_sheet":str(sheet),"summary":report},indent=2))
if __name__=="__main__": main()
