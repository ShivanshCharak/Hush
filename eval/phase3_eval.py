#!/usr/bin/env python3
"""Dev-stream evaluation for Phase 3. Uses dev streams 01-03 only."""
from __future__ import annotations
import json, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from pipeline.run import process
from explain.bedrock import BedrockExplainer
from explain.template import explain as template_explain

def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]
def seconds(event, fallback):
    try:
        dt=datetime.fromisoformat(str(event["timestamp"]).replace("Z","+00:00"))
        if dt.tzinfo is None: dt=dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError,KeyError): return fallback/5

class FailingBedrockClient:
    def __init__(self): self.calls=0
    def invoke_model(self, **kwargs):
        self.calls+=1
        raise TimeoutError("injected Bedrock timeout")

class CountingExplainer:
    def __init__(self): self.calls=0
    def explain(self, decision, events):
        self.calls+=1
        return template_explain(decision, events)

def explanation_checks(sample_trace, sample_events):
    emitted=[row for row in sample_trace if row["gate_emit"]]
    calls=CountingExplainer()
    parity_trace=process(sample_events, explainer=calls, use_model=False)
    parity_emitted=sum(row["gate_emit"] for row in parity_trace)
    first_five=emitted[:5]
    failing_client=FailingBedrockClient()
    fallback_results=[]
    event_by_id={int(e["event_id"]):e for e in sample_events}
    for row in first_five:
        window=[event_by_id[i] for i in range(int(row["event_start"]),int(row["event_end"])+1) if i in event_by_id]
        decision={"speak":True,"kind":row["kind"],"evidence_ids":row["evidence_ids"]}
        result=BedrockExplainer(model_id="injected-test-model",client=failing_client).explain(decision,window)
        fallback_results.append(result.get("source")=="template" and bool(result.get("evidence_ids")))
    return {"pipeline_explainer_calls":calls.calls,"emitted_alerts":parity_emitted,
            "call_parity":calls.calls==parity_emitted,
            "injected_timeout_alerts":len(first_five),"fallback_template_alerts":sum(fallback_results),
            "fallback_pass":len(first_five)>=5 and all(fallback_results),"injected_client_calls":failing_client.calls}

def evaluate():
    manifest=json.loads((ROOT/"data/streams/manifest.json").read_text())
    reports=[]; total_episodes=detected=false_alerts=dupes=0; delays=[]; budget_violations=unaccounted=grounding_failures=alerts_without_explanation=0
    entity_mentions=grounded_mentions=0
    first_stream_events=None; first_stream_trace=None; all_alert_samples=[]
    for sid in manifest["dev_streams"]:
        info=manifest["streams"][sid]; events=read_jsonl(ROOT/info["path"]); trace=process(events,use_model=False)
        if first_stream_events is None: first_stream_events,first_stream_trace=events,trace
        attacks=[e for e in info["episodes"] if not e.get("hard_benign")]
        benign=[e for e in info["episodes"] if e.get("hard_benign")]
        episode_hits=[]
        for ep in attacks:
            hits=[r for r in trace if r["gate_emit"] and int(r["event_end"])>=int(ep["start_idx"]) and int(r["event_start"])<int(ep["end_idx"])]
            if hits:
                episode_hits.append((ep,hits)); detected+=1
                delays.append(max(0,int(hits[0]["event_end"])-int(ep["start_idx"])+1))
            total_episodes+=1
        false=sum(1 for r in trace if r["gate_emit"] and not any(int(r["event_start"])<int(ep["end_idx"]) and int(r["event_end"])>=int(ep["start_idx"]) for ep in attacks))
        false_alerts+=false
        dupes+=sum(max(0,len(hits)-1) for _,hits in episode_hits)
        emitted=[r for r in trace if r["gate_emit"]]
        alerts_without_explanation+=sum(1 for r in emitted if r["explanation"] is None)
        for r in trace:
            if r["speak"] and r["gate_reason"] not in {"emitted","cooldown","duplicate","interrupt_budget","below_confidence_threshold"}: unaccounted+=1
            if r["explanation"]:
                ids=set(r["explanation"].get("evidence_ids",[])); event_slice=[e for e in events if int(r["event_start"])<=int(e["event_id"])<=int(r["event_end"])]
                if not ids or not ids <= {int(e["event_id"]) for e in event_slice}: grounding_failures+=1
                text=" ".join(str(r["explanation"].get(k,"")) for k in ("summary","suggested_action"))
                cited=[e for e in event_slice if int(e.get("event_id",-1)) in ids]
                candidates={str(e.get(k)) for e in event_slice for k in ("src_ip","username","path") if e.get(k)}
                for entity in candidates:
                    if entity in text:
                        entity_mentions+=1
                        if any(entity==str(e.get(k)) for e in cited for k in ("src_ip","username","path")): grounded_mentions+=1
                all_alert_samples.append((r,event_slice))
        timeline=sorted((seconds(events[min(max(0,int(r["event_end"])),len(events)-1)],int(r["event_end"])),r) for r in trace if r["gate_emit"])
        left=0
        for i,(now,_) in enumerate(timeline):
            while now-timeline[left][0]>=600: left+=1
            if i-left+1>6: budget_violations+=1
        reports.append({"stream":sid,"episodes_detected":len(episode_hits),"attack_episodes":len(attacks),"false_alerts":false,"emitted_alerts":len(emitted),"decider_speaks":sum(r["speak"] for r in trace)})
    def ratio(n,d): return n/d if d else 0
    checks=explanation_checks(first_stream_trace,first_stream_events)
    return {"phase":"3","data_scope":"dev streams 01-03 only","streams":reports,
      "episode_recall":{"numerator":detected,"denominator":total_episodes,"value":ratio(detected,total_episodes),"target":">=21/24"},
      "false_alerts":{"value":false_alerts,"target":"<=3"},"duplicate_alerts":{"value":dupes,"detected_episodes":detected,"per_detected_episode":ratio(dupes,detected),"target":"<=1.5 alerts/episode"},
      "median_time_to_detect_events":sorted(delays)[len(delays)//2] if delays else None,"budget_violations":budget_violations,
      "unaccounted_speaks":unaccounted,"evidence_id_grounding_failures":grounding_failures,
      "entity_grounding":{"grounded_mentions":grounded_mentions,"mentioned_entities":entity_mentions,"rate":grounded_mentions/entity_mentions if entity_mentions else 1.0,"target":">=0.98"},
      "emitted_without_explanation":alerts_without_explanation,
      "explanation_mode":"deterministic template (Bedrock disabled); Bedrock call parity not measured",
      "injected_explainer_checks":checks,
      "manual_quality":"pending owner review; a 20-alert rating sheet is emitted beside this report",
      "live_bedrock_latency_and_quality":"not measured; injected clients do not make AWS calls",
      "gate":"not passed; manual quality scoring and live Bedrock checks remain outstanding"}

if __name__=="__main__":
    report=evaluate(); out=ROOT/"eval/runs"/f"phase3-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"; out.parent.mkdir(exist_ok=True)
    out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    manifest=json.loads((ROOT/"data/streams/manifest.json").read_text())
    review=[]
    for sid in manifest["dev_streams"]:
        events=read_jsonl(ROOT/manifest["streams"][sid]["path"]); trace=process(events,use_model=False)
        for row in (x for x in trace if x["gate_emit"]):
            window=[e for e in events if int(row["event_start"])<=int(e["event_id"])<=int(row["event_end"])]
            review.append({"alert_id":row["alert_id"],"stream":sid,"kind":row["kind"],"summary":row["explanation"]["summary"],"suggested_action":row["explanation"]["suggested_action"],"evidence_ids":row["evidence_ids"],"events":[{"event_id":e.get("event_id"),"src_ip":e.get("src_ip"),"username":e.get("username"),"path":e.get("path"),"query":e.get("query"),"status":e.get("status"),"result":e.get("result"),"is_cited":int(e["event_id"]) in set(row["evidence_ids"])} for e in window],"score_correct_kind":None,"score_evidence_use":None,"score_actionability":None,"notes":""})
            if len(review)>=20: break
        if len(review)>=20: break
    review_path=out.with_name(out.stem+"-manual-review.jsonl")
    review_path.write_text("".join(json.dumps(row,ensure_ascii=False)+"\n" for row in review),encoding="utf-8")
    print(json.dumps({"artifact":str(out),"manual_review_sheet":str(review_path),"summary":report},indent=2))
