#!/usr/bin/env python3
"""Post-hoc local-model reviewer check on emitted dev alerts and prior hard-benign false speaks."""
from __future__ import annotations
import json, sys
from datetime import datetime, timezone
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from decider.decide import OllamaDecider
from decider.window import make_window
from eval.run_metadata import snapshot
from pipeline.run import process
from explain.bedrock import BedrockExplainer

FALSE_SPEAK_IDS={"sim-dev-hard_benign-0005","sim-dev-hard_benign-0010","sim-dev-hard_benign-0015",
                 "sim-dev-hard_benign-0020","sim-dev-hard_benign-0025","sim-dev-hard_benign-0030","sim-dev-hard_benign-0035"}

def read_jsonl(path):
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]

def remove_allowlist_flag(window):
    for field in window["header"].get("pattern_checks", {}).values():
        if isinstance(field,list):
            for candidate in field:
                candidate.pop("authorized_source",None)

def main():
    manifest=json.loads((ROOT/"data/streams/manifest.json").read_text())
    decider=OllamaDecider()
    reviewed=[]
    attack_alerts=0
    for stream_id in manifest["dev_streams"]:
        info=manifest["streams"][stream_id]
        events=read_jsonl(ROOT/info["path"])
        by_id={int(event["event_id"]):event for event in events}
        trace=process(events,explainer=BedrockExplainer(model_id=""))
        attack_episodes=[episode for episode in info["episodes"] if not episode.get("hard_benign")]
        for row in (item for item in trace if item["gate_emit"]):
            start,end=int(row["event_start"]),int(row["event_end"])
            window=make_window([by_id[event_id] for event_id in range(start,end+1) if event_id in by_id],require_full=False)
            is_attack=any(start<int(ep["end_idx"]) and end>=int(ep["start_idx"]) for ep in attack_episodes)
            try:
                verdict=decider.decide(window)
                reviewed.append({"alert_id":row["alert_id"],"stream":stream_id,"cohort":"attack" if is_attack else "benign",
                                 "kind":row["kind"],"review":"confirm" if verdict["speak"] else "contest","error":None})
                attack_alerts+=int(is_attack)
            except Exception as exc:
                reviewed.append({"alert_id":row["alert_id"],"stream":stream_id,"cohort":"attack" if is_attack else "benign",
                                 "kind":row["kind"],"review":"error","error":f"{type(exc).__name__}: {exc}"})

    golden=read_jsonl(ROOT/"data/golden/dev.jsonl")
    hard_benign=[row for row in golden if row.get("id") in FALSE_SPEAK_IDS]
    if len(hard_benign)!=7: raise RuntimeError(f"expected 7 historical hard-benign windows, found {len(hard_benign)}")
    for row in hard_benign:
        window=make_window(row["events"])
        remove_allowlist_flag(window)
        try:
            verdict=decider.decide(window)
            reviewed.append({"alert_id":row["id"],"stream":"golden-dev","cohort":"benign_allowlist_flag_removed",
                             "kind":"scanner_recon","review":"confirm" if verdict["speak"] else "contest","error":None})
        except Exception as exc:
            reviewed.append({"alert_id":row["id"],"stream":"golden-dev","cohort":"benign_allowlist_flag_removed",
                             "kind":"scanner_recon","review":"error","error":f"{type(exc).__name__}: {exc}"})

    def cohort_stats(cohort):
        rows=[row for row in reviewed if row["cohort"]==cohort]
        valid=[row for row in rows if row["review"] in {"confirm","contest"}]
        return {"total":len(rows),"valid_reviews":len(valid),"confirm":sum(row["review"]=="confirm" for row in valid),
                "contest":sum(row["review"]=="contest" for row in valid),"errors":sum(row["review"]=="error" for row in rows),
                "contested_rate":sum(row["review"]=="contest" for row in valid)/len(valid) if valid else None}
    attacks=cohort_stats("attack")
    benign=cohort_stats("benign_allowlist_flag_removed")
    separate=bool(attacks["contested_rate"] is not None and benign["contested_rate"] is not None and benign["contested_rate"]>attacks["contested_rate"])
    report={"created_at":datetime.now(timezone.utc).isoformat(),"scope":"dev streams 01-03 emitted alerts plus seven historical hard-benign windows only",
            "model":decider.model,"review_role":"post-hoc utility measurement; results never alter rule/gate emissions",
            "emitted_attack_alerts":attacks,"hard_benign_allowlist_flag_removed":benign,
            "contested_rate_difference_benign_minus_attack":(benign["contested_rate"]-attacks["contested_rate"] if attacks["contested_rate"] is not None and benign["contested_rate"] is not None else None),
            "separates_cohorts":separate,"badge_recommendation":"keep" if separate else "remove confirmed/contested status; retain model only for explanations",
            "records":reviewed,"config_snapshot":snapshot()}
    stamp=datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out=ROOT/f"eval/runs/reviewer-value-{stamp}.json"
    out.write_text(json.dumps(report,indent=2)+"\n",encoding="utf-8")
    print(json.dumps({"artifact":str(out.relative_to(ROOT)),"attack_alerts":attacks,"hard_benign":benign,
                      "contested_rate_difference":report["contested_rate_difference_benign_minus_attack"],
                      "separates_cohorts":separate,"badge_recommendation":report["badge_recommendation"]},indent=2))

if __name__=="__main__": main()
