#!/usr/bin/env python3
"""Requested dev-only qwen measurement run; never reads held-out/test inputs."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import math
from pathlib import Path
import random
import sys
import time

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from baseline.rules import predict as predict_rules
from decider.decide import InferenceError, OllamaDecider, confidence_from_logprobs
from decider.prompt import CONFIRM_SCHEMA_MODE, FEWSHOT_ENABLED, FEW_SHOT_EXAMPLES, PROMPT_FORMAT_VERSION, confirmed_kinds
from decider.window import PATTERN_CHECK_VERSION, make_window

RUNS = ROOT / "eval/runs"
FEWSHOT_IDS = {item["id"] for item in FEW_SHOT_EXAMPLES}


def read_rows():
    return [json.loads(line) for line in (ROOT / "data/golden/dev.jsonl").read_text(encoding="utf-8").splitlines() if line.strip()]


def quantile(values, p):
    if not values:
        return None
    values = sorted(values)
    x = (len(values) - 1) * p
    lo, hi = math.floor(x), math.ceil(x)
    return values[lo] if lo == hi else values[lo] * (hi-x) + values[hi] * (x-lo)


def auc(labels, scores):
    pos = [x for y, x in zip(labels, scores) if y]
    neg = [x for y, x in zip(labels, scores) if not y]
    if not pos or not neg:
        return None
    return sum(1 if p > n else .5 if p == n else 0 for p in pos for n in neg) / (len(pos)*len(neg))


def token_norm(token):
    return str(token or "").strip().strip(' \t\r\n"').strip(',:} ').lower()


def old_confidence(token_info):
    if not isinstance(token_info, dict):
        return None
    scores = {}
    for item in [token_info, *(token_info.get("top_logprobs") or [])]:
        if isinstance(item, dict) and token_norm(item.get("token")) in ("true", "false") and isinstance(item.get("logprob"), (int, float)):
            scores[token_norm(item.get("token"))] = float(item["logprob"])
    if not {"true", "false"} <= scores.keys():
        return None
    odds = scores["true"] - scores["false"]
    return 1/(1+math.exp(-odds)) if odds >= 0 else math.exp(odds)/(1+math.exp(odds))


def candidate_score(row):
    return float(len(confirmed_kinds(make_window(row["events"]))))


def select_stratified(rows, n=60):
    pool = [r for r in rows if r["id"] not in FEWSHOT_IDS]
    strata = {}
    for row in pool:
        key = (row["label"], bool(row.get("hard")), row.get("kind"))
        strata.setdefault(key, []).append(row)
    # Proportional allocation by stratum with deterministic tie breaking.
    total = len(pool)
    alloc = {k: int(n * len(v) / total) for k, v in strata.items()}
    remainder = n - sum(alloc.values())
    for k in sorted(strata, key=lambda x: (-(n*len(strata[x])/total-alloc[x]), str(x)))[:remainder]:
        alloc[k] += 1
    selected = []
    for key in sorted(strata, key=str):
        values = sorted(strata[key], key=lambda r: r["id"])
        random.Random("phase2-60-" + repr(key)).shuffle(values)
        selected.extend(values[:alloc[key]])
    return sorted(selected, key=lambda r: r["id"])


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--model", required=True)
    ap.add_argument("--sample60", action="store_true")
    ap.add_argument("--include-fewshot", action="store_true", help="include the explicitly selected few-shot rows in a requested run")
    ap.add_argument("--profile20", action="store_true")
    ap.add_argument("--evasion-input", type=Path)
    ap.add_argument("--window-ids-from", type=Path, help="reuse an existing artifact's exact window IDs")
    ap.add_argument("--run-tag", default="", help="suffix for a distinct experimental artifact")
    args = ap.parse_args()
    rows = json.loads(args.evasion_input.read_text()) if args.evasion_input else read_rows()
    if args.sample60:
        rows = select_stratified(rows, 60)
    elif not args.include_fewshot:
        rows = [r for r in rows if r["id"] not in FEWSHOT_IDS]
    if args.profile20:
        rows = rows[:20]
    if args.window_ids_from:
        source = json.loads(args.window_ids_from.read_text())
        by_id = {row["id"]: row for row in rows}
        rows = [by_id[window_id] for window_id in source["window_ids"] if window_id in by_id]
        if len(rows) != len(source["window_ids"]):
            raise ValueError("window ID source includes IDs unavailable in the selected dev input")
    slug = args.model.replace(":", "-").replace("/", "-")
    name = ("evasion-" if args.evasion_input else "phase2-requested-") + slug + ("-sample60" if args.sample60 else "") + ("-profile20" if args.profile20 else "")
    if args.run_tag:
        name += "-" + args.run_tag
    path = RUNS / f"{name}.json"
    partial = RUNS / f".{name}.checkpoint.json"
    RUNS.mkdir(parents=True, exist_ok=True)
    preds = {}
    if partial.exists():
        try:
            prev = json.loads(partial.read_text())
            if prev.get("model") == args.model and prev.get("prompt_format") == PROMPT_FORMAT_VERSION:
                preds = {p["id"]: p for p in prev["predictions"]}
        except (OSError, ValueError, KeyError, TypeError):
            pass
    decider = OllamaDecider(model=args.model, timeout=180)
    per_call = []
    err = None
    for idx, row in enumerate(rows):
        if row["id"] in preds:
            continue
        t0 = time.perf_counter()
        try:
            out = decider.decide(make_window(row["events"]))
        except (InferenceError, ValueError) as exc:
            err = f"{row['id']}: {exc}"
            break
        out["id"] = row["id"]
        out["client_total_ms"] = (time.perf_counter()-t0)*1000
        preds[row["id"]] = out
        partial.write_text(json.dumps({"model": args.model, "prompt_format": PROMPT_FORMAT_VERSION, "predictions": [preds[r["id"]] for r in rows if r["id"] in preds]}, indent=2)+"\n")
    ordered = [preds[r["id"]] for r in rows if r["id"] in preds]
    if err or len(ordered) != len(rows):
        result = {"status":"incomplete", "error":err or "interrupted", "model":args.model, "completed":len(ordered),"requested":len(rows),"checkpoint":str(partial)}
        path.write_text(json.dumps(result,indent=2)+"\n")
        print(json.dumps(result))
        return 2

    # Class labels are binary attack vs benign; ambiguous rows excluded from AUROC.
    labels, called_scores, evidence_scores, old_scores = [], [], [], []
    for row, pred in zip(rows, ordered):
        if row["label"] not in ("speak", "silent"):
            continue
        labels.append(row["label"] == "speak")
        conf = pred.get("confidence")
        if conf is not None:
            called_scores.append((row["label"] == "speak", float(conf)))
        evidence_scores.append((row["label"] == "speak", float(conf) if conf is not None else candidate_score(row)))
        old = old_confidence(pred.get("speak_token_logprobs"))
        old_scores.append((row["label"] == "speak", float(old) if old is not None else 0.0))
    auc_called = auc([x[0] for x in called_scores],[x[1] for x in called_scores])
    auc_evidence = auc([x[0] for x in evidence_scores],[x[1] for x in evidence_scores])
    auc_old = auc([x[0] for x in old_scores],[x[1] for x in old_scores])

    def calc(group):
        attacks=[(r,p) for r,p in group if r["label"]=="speak"]
        benign=[(r,p) for r,p in group if r["label"]=="silent"]
        hard=[(r,p) for r,p in benign if r.get("hard")]
        normal=[(r,p) for r,p in benign if not r.get("hard")]
        tp=sum(bool(p["speak"]) for _,p in attacks)
        return {"windows":len(group),"attack_recall":{"n":tp,"d":len(attacks),"value":tp/len(attacks) if attacks else None},
                "hard_benign_false_speaks":{"n":sum(bool(p["speak"]) for _,p in hard),"d":len(hard)},
                "normal_benign_false_speaks":{"n":sum(bool(p["speak"]) for _,p in normal),"d":len(normal)},
                "kind_accuracy":{"n":sum(r.get("kind")==p.get("kind") for r,p in attacks if p["speak"]),"d":sum(bool(p["speak"]) for _,p in attacks)}}
    grouped={}
    for candidate in (True,False):
        grouped["confirmed_candidate" if candidate else "no_confirmed_candidate"] = calc([(r,p) for r,p in zip(rows,ordered) if bool(candidate_score(r))==candidate])
    overall=calc(list(zip(rows,ordered)))
    baseline=[predict_rules(r["events"]) for r in rows]
    hard_attacks=[(r,b,p) for r,b,p in zip(rows,baseline,ordered) if r["label"]=="speak" and r.get("hard")]
    missed=[(r,b,p) for r,b,p in zip(rows,baseline,ordered) if r["label"]=="speak" and not b["speak"]]
    lat=[float(p.get("latency_ms",p["client_total_ms"])) for p in ordered]
    prompt_tok=[float(p["prompt_eval_count"]) for p in ordered if p.get("prompt_eval_count") is not None]
    timing_fields={
      "prompt_eval_ms":[(p.get("prompt_eval_duration_ns") or 0)/1e6 for p in ordered],
      "eval_ms":[(p.get("eval_duration_ns") or 0)/1e6 for p in ordered],
      "total_ms":[float(p.get("latency_ms",p["client_total_ms"])) for p in ordered]}
    result={"status":"complete","model":args.model,"created_at":datetime.now(timezone.utc).isoformat(),"data_scope":"dev only","prompt_format_version":PROMPT_FORMAT_VERSION,"candidate_confirm_only":CONFIRM_SCHEMA_MODE,"fewshot_enabled":FEWSHOT_ENABLED,"context_tokens":4096,"rows":len(rows),"window_ids":[r["id"] for r in rows],"fewshot_excluded_ids":sorted(FEWSHOT_IDS),
      "overall":overall,"by_candidate":grouped,"candidate_evidence_score_definition":"number of distinct confirmed kinds in the code-computed window header","baseline_attack_recall":{"n":sum(bool(b["speak"]) for r,b in zip(rows,baseline) if r["label"]=="speak"),"d":sum(r["label"]=="speak" for r in rows)},"baseline_missed_attacks_caught":{"n":sum(bool(p["speak"]) for _,_,p in missed),"d":len(missed),"ids":[r["id"] for r,_,p in missed if p["speak"]]},
      "hard_attack_recall":{"n":sum(bool(p["speak"]) for _,_,p in hard_attacks),"d":len(hard_attacks)},
      "benign_no_candidate_false_speaks":sum(bool(p["speak"]) for r,p in zip(rows,ordered) if r["label"]=="silent" and not candidate_score(r)),
      "auroc":{"model_called_only":auc_called,"all_windows_candidate_evidence_for_missing":auc_evidence,"old_overwrite_and_missing_zero":auc_old,"confidence_definition":"sum exp(logprob) over true token variants divided by summed true plus summed false token-variant probability; implemented as sigmoid(logsumexp(true)-logsumexp(false))"},
      "auroc_window_counts":{"model_called_only":len(called_scores),"all_windows_binary_scored":len(evidence_scores),"old_definition":len(old_scores),"model_calls":sum(bool(p.get("model_called",True)) for p in ordered),"model_skips":sum(not bool(p.get("model_called",True)) for p in ordered)},
      "prompt_tokens":{"p50":quantile(prompt_tok,.5),"p95":quantile(prompt_tok,.95),"n":len(prompt_tok)},
      "timing_ms":{k:{"p50":quantile(v,.5),"p95":quantile(v,.95),"n":len(v)} for k,v in timing_fields.items()},
      "window_predictions":[{"id":r["id"],"label":r["label"],"expected_kind":r.get("kind"),"hard":bool(r.get("hard")),"has_confirmed_candidate":bool(candidate_score(r)),"speak":bool(p.get("speak")),"kind":p.get("kind"),"confidence":p.get("confidence"),"model_called":bool(p.get("model_called",True))} for r,p in zip(rows,ordered)],
      "per_call":[{"id":r["id"],"prompt_tokens":p.get("prompt_eval_count"),"prompt_eval_ms":(p.get("prompt_eval_duration_ns") or 0)/1e6,"eval_tokens":p.get("eval_count"),"eval_ms":(p.get("eval_duration_ns") or 0)/1e6,"load_ms":(p.get("load_duration_ns") or 0)/1e6,"total_ms":p.get("latency_ms",p["client_total_ms"])} for r,p in zip(rows,ordered)]}
    path.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    partial.unlink(missing_ok=True)
    print(json.dumps({"artifact":str(path.relative_to(ROOT)),"status":"complete","model":args.model,"rows":len(rows),"overall":overall,"by_candidate":grouped,"auc":result["auroc"],"timing":result["timing_ms"]},indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
