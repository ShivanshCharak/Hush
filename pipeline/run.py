#!/usr/bin/env python3
"""Process event JSONL in non-overlapping 20-event windows and write a decision trace."""
from __future__ import annotations
import argparse, copy, hashlib, json, os, sys, time
from datetime import datetime
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from baseline.rules import predict as rules_predict
from decider.decide import OllamaDecider
from decider.prefilter import keep_event
from decider.window import WINDOW_SIZE, make_window
from explain.bedrock import BedrockExplainer
from gate.gate import AlertGate

def seconds(event, fallback):
    try: return datetime.fromisoformat(str(event["timestamp"]).replace("Z","+00:00")).timestamp()
    except (ValueError,KeyError): return float(fallback)

def candidate_keys(window):
    """Return confirmed (source, kind) candidates supported by this window."""
    checks=window.get("header",{}).get("pattern_checks",{})
    pairs=set()
    for field,kind in (("brute_force_candidates","brute_force"),("credential_stuffing_candidates","credential_stuffing"),("priv_esc_candidates","priv_esc"),("scanner_recon_candidates","scanner_recon")):
        for item in checks.get(field,[]):
            if item.get("confirmed"):
                pairs.add((str(item.get("src_ip","unknown")),kind))
    event_by_id={int(e.get("event_id",-1)):e for e in window.get("events",[])}
    for kind,ids in checks.get("payload_signature_event_ids",{}).items():
        for event_id in ids:
            event=event_by_id.get(int(event_id))
            if event is not None:
                pairs.add((str(event.get("src_ip","unknown")),str(kind)))
    return pairs

def call_model_for_window(window, rule_decision):
    """Route only weak/authorized candidates and selected no-candidate windows."""
    checks=window.get("header",{}).get("pattern_checks",{})
    behavioral=[item for field in ("brute_force_candidates","credential_stuffing_candidates","priv_esc_candidates","scanner_recon_candidates") for item in checks.get(field,[]) if item.get("confirmed")]
    authorized=any(item.get("authorized_source") for item in behavioral)
    weak=any(item in checks.get("scanner_recon_candidates",[]) for item in behavioral)
    payload=any(bool(ids) for ids in checks.get("payload_signature_event_ids",{}).values())
    high_4xx=float(window.get("header",{}).get("four_xx_rate",0) or 0)>=0.75
    # Payload signatures and confirmed auth/profile candidates are strong enough
    # for the transparent rules to speak without a model call.
    strong=bool(rule_decision.get("speak")) and (payload or any(
        item.get("confirmed") for field in ("brute_force_candidates","credential_stuffing_candidates","priv_esc_candidates")
        for item in checks.get(field,[])
    )) and not authorized
    if strong:
        return False, "strong_rule"
    if authorized or weak:
        return True, "authorized_or_weak_candidate"
    if not behavioral and (payload or high_4xx):
        return True, "no_candidate_payload_or_high_4xx"
    return False, "rules_only"

def process(events, *, gate=None, decider=None, explainer=None, use_model=True, enable_decision_cache=True, enable_cooldown=True, cooldown_seconds=None):
    gate=gate or AlertGate(confidence_threshold=float(os.environ.get("DECIDER_CONFIDENCE_THRESHOLD", "0.0")))
    decider=decider or OllamaDecider()
    explainer=explainer or BedrockExplainer()
    cache={}
    last_call_by_candidate={}
    cooldown_seconds=float(cooldown_seconds if cooldown_seconds is not None else os.environ.get("DECIDER_COOLDOWN_SECONDS","300"))
    out=[]
    for start in range(0,len(events),WINDOW_SIZE):
        chunk=events[start:start+WINDOW_SIZE]
        if not chunk: continue
        window=make_window(chunk,require_full=False)
        candidate=any(keep_event(event) for event in chunk)
        end=seconds(chunk[-1],start+len(chunk)-1)
        if use_model:
            digest=hashlib.sha256(json.dumps(chunk,sort_keys=True,separators=(",",":"),ensure_ascii=False,default=str).encode("utf-8")).hexdigest()
            keys=candidate_keys(window)
            rule_decision=rules_predict(chunk)
            should_call,call_reason=call_model_for_window(window,rule_decision)
            if not should_call:
                decision=rule_decision
                decision.update({"model_called":False,"skip_reason":call_reason if candidate else "prefilter"})
            elif enable_decision_cache and digest in cache:
                decision=copy.deepcopy(cache[digest])
                decision.update({"model_called":False,"skip_reason":"decision_cache"})
            elif enable_cooldown and keys and all(end-last_call_by_candidate.get(key,float("-inf"))<cooldown_seconds for key in keys):
                decision={"speak":False,"kind":"none","evidence_ids":[],"confidence":0.0,"model_called":False,"skip_reason":"candidate_cooldown"}
            else:
                decision=decider.decide(window)
                if enable_decision_cache:
                    cache[digest]=copy.deepcopy(decision)
                if enable_cooldown:
                    for key in keys:
                        last_call_by_candidate[key]=end
        else:
            decision=rules_predict(chunk)
        decision.setdefault("confidence",None)
        fingerprint=f"{chunk[0].get('session_id')}:{chunk[0].get('event_id')}:{chunk[-1].get('event_id')}:{decision.get('kind')}"
        gated=gate.evaluate(decision,chunk,now=end,alert_fingerprint=fingerprint)
        explanation=None
        if gated["emit"]:
            explanation=explainer.explain(decision,chunk)
        out.append({"session_id":chunk[0].get("session_id"),"event_start":chunk[0].get("event_id"),"event_end":chunk[-1].get("event_id"),
          "speak":bool(decision.get("speak")),"kind":decision.get("kind","none"),"confidence":decision.get("confidence"),
          "evidence_ids":decision.get("evidence_ids",[]),"gate_emit":gated["emit"],"gate_reason":gated["reason"],"gate_budget_count":gated.get("budget_count"),"alert_id":fingerprint if gated["emit"] else None,
          "explanation":explanation,"model_called":bool(decision.get("model_called",False)),"latency_ms":decision.get("latency_ms",0.0),
          "skip_reason":decision.get("skip_reason")})
    return out

def main():
    p=argparse.ArgumentParser(); p.add_argument("input",type=Path); p.add_argument("--trace",type=Path,default=Path("trace.jsonl")); p.add_argument("--rules",action="store_true",help="use the rules baseline instead of the model"); p.add_argument("--bedrock",action="store_true"); p.add_argument("--no-decision-cache",action="store_true"); p.add_argument("--no-cooldown",action="store_true"); a=p.parse_args()
    events=[json.loads(line) for line in a.input.read_text(encoding="utf-8").splitlines() if line.strip()]
    rows=process(events,use_model=not a.rules,explainer=BedrockExplainer() if a.bedrock else None,enable_decision_cache=not a.no_decision_cache,enable_cooldown=not a.no_cooldown)
    a.trace.parent.mkdir(parents=True,exist_ok=True); a.trace.write_text("".join(json.dumps(row,separators=(",",":"))+"\n" for row in rows),encoding="utf-8")
    print(json.dumps({"windows":len(rows),"decider_speaks":sum(x["speak"] for x in rows),"emitted":sum(x["gate_emit"] for x in rows),"suppressed":sum(x["speak"] and not x["gate_emit"] for x in rows),"trace":str(a.trace)}))
if __name__=="__main__": main()
