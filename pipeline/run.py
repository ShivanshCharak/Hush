#!/usr/bin/env python3
"""Process event JSONL in non-overlapping 20-event windows and write a decision trace."""
from __future__ import annotations
import argparse, json, sys, time
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from baseline.rules import predict as rules_predict
from decider.decide import OllamaDecider
from decider.prefilter import keep_event
from decider.window import WINDOW_SIZE, make_window
from explain.bedrock import BedrockExplainer
from explain.template import explain as template_explain
from gate.gate import AlertGate

def seconds(event, fallback):
    try: return datetime.fromisoformat(str(event["timestamp"]).replace("Z","+00:00")).timestamp()
    except (ValueError,KeyError): return float(fallback)

def process(events, *, gate=None, decider=None, explainer=None, use_model=False):
    gate=gate or AlertGate(); decider=decider or OllamaDecider()
    out=[]
    for start in range(0,len(events),WINDOW_SIZE):
        chunk=events[start:start+WINDOW_SIZE]
        if not chunk: continue
        window=make_window(chunk,require_full=False)
        candidate=any(keep_event(e) for e in chunk)
        decision=(decider.decide(window) if use_model and candidate else rules_predict(chunk) if candidate else {"speak":False,"kind":"none","evidence_ids":[],"confidence":0.0,"skip_reason":"prefilter"})
        decision.setdefault("confidence",None)
        end=seconds(chunk[-1],start+len(chunk)-1)
        fingerprint=f"{chunk[0].get('session_id')}:{chunk[0].get('event_id')}:{chunk[-1].get('event_id')}:{decision.get('kind')}"
        gated=gate.evaluate(decision,chunk,now=end,alert_fingerprint=fingerprint)
        explanation=None
        if gated["emit"]:
            explanation=(explainer.explain(decision,chunk) if explainer else template_explain(decision,chunk))
        out.append({"session_id":chunk[0].get("session_id"),"event_start":chunk[0].get("event_id"),"event_end":chunk[-1].get("event_id"),
          "speak":bool(decision.get("speak")),"kind":decision.get("kind","none"),"confidence":decision.get("confidence"),
          "evidence_ids":decision.get("evidence_ids",[]),"gate_emit":gated["emit"],"gate_reason":gated["reason"],"alert_id":fingerprint if gated["emit"] else None,
          "explanation":explanation,"model_called":bool(decision.get("model_called",False)),"latency_ms":decision.get("latency_ms",0.0)})
    return out

def main():
    p=argparse.ArgumentParser(); p.add_argument("input",type=Path); p.add_argument("--trace",type=Path,default=Path("trace.jsonl")); p.add_argument("--model",action="store_true"); p.add_argument("--bedrock",action="store_true"); a=p.parse_args()
    events=[json.loads(line) for line in a.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows=process(events,use_model=a.model,explainer=BedrockExplainer() if a.bedrock else None)
    a.trace.parent.mkdir(parents=True,exist_ok=True); a.trace.write_text("".join(json.dumps(row,separators=(",",":"))+"\n" for row in rows),encoding="utf-8")
    print(json.dumps({"windows":len(rows),"decider_speaks":sum(x["speak"] for x in rows),"emitted":sum(x["gate_emit"] for x in rows),"suppressed":sum(x["speak"] and not x["gate_emit"] for x in rows),"trace":str(a.trace)}))
if __name__=="__main__": main()
