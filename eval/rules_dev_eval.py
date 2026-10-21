#!/usr/bin/env python3
"""Dev-only deterministic rules and historical-header audit."""
from __future__ import annotations

import json
import sys
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from baseline.rules import predict
from decider.window import compute_header
from eval.run_metadata import snapshot
from eval.phase3_eval import evaluate as evaluate_dev_streams


def main() -> None:
    rows = [json.loads(line) for line in (ROOT / "data/golden/dev.jsonl").read_text().splitlines() if line.strip()]
    attacks = benign_hard = benign_normal = correct = 0
    total_attacks = hard_fp = normal_fp = 0
    kind_counts: dict[str, dict[str, int]] = defaultdict(lambda: {"detected": 0, "total": 0, "kind_correct": 0})
    for row in rows:
        decision = predict(row["events"])
        if row["label"] == "speak":
            per_kind = kind_counts[row["kind"]]
            per_kind["total"] += 1
            per_kind["detected"] += int(bool(decision["speak"]))
            per_kind["kind_correct"] += int(bool(decision["speak"]) and decision["kind"] == row.get("kind"))
            total_attacks += 1
            attacks += int(bool(decision["speak"]))
            correct += int(bool(decision["speak"]) and decision["kind"] == row.get("kind"))
        elif row["label"] == "silent":
            if row.get("hard"):
                benign_hard += 1
                hard_fp += int(bool(decision["speak"]))
            else:
                benign_normal += 1
                normal_fp += int(bool(decision["speak"]))

    def eval_mutations(name: str) -> dict:
        payload = json.loads((ROOT / f"eval/runs/{name}-dev.json").read_text())
        rows = payload.get("attacks", []) if isinstance(payload, dict) else payload
        families: dict[str, dict[str, int]] = defaultdict(lambda: {"detected": 0, "total": 0})
        slow_samples = []
        for row in rows:
            stats = families[row["family"]]
            stats["total"] += 1
            decision = predict(row["events"])
            stats["detected"] += int(bool(decision["speak"]))
            if "slow_rate" in row["family"]:
                auth = [event for event in row["events"] if event.get("event_type") == "auth"]
                times = [datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) for event in auth]
                latest = max(times)
                recent = [(event, when) for event, when in zip(auth, times) if (latest - when).total_seconds() <= 3600]
                slow_samples.append({"id": row["id"], "spacing_minutes": row.get("spacing_minutes"),
                                     "failures_in_latest_60m": len(recent),
                                     "distinct_sources_in_latest_60m": len({event.get("src_ip") for event, _ in recent}),
                                     "decision": bool(decision["speak"]), "kind": decision["kind"]})
        return {"families": families, "slow_window_samples": slow_samples}

    evasion_v1 = eval_mutations("evasion-v1")
    evasion_v2 = eval_mutations("evasion-v2")
    evasion_v3 = eval_mutations("evasion-v3")
    evasion_v4_original = eval_mutations("evasion-v4")
    evasion_v4 = eval_mutations("evasion-v4-clean")
    stream_eval = evaluate_dev_streams()
    pre_fix_path = ROOT / "eval/runs/dev-rules-20261020T181310Z.json"
    pre_fix = json.loads(pre_fix_path.read_text(encoding="utf-8"))
    last_pre_normalization_path = ROOT / "eval/runs/dev-rules-20261021T041605Z.json"
    last_pre_normalization = json.loads(last_pre_normalization_path.read_text(encoding="utf-8"))

    old8 = json.loads((ROOT / "eval/runs/phase2-20261020T033832Z.json").read_text())["decider"]["window_predictions"]
    hardbenign8 = [row for row in old8 if row.get("label") == "silent" and row.get("hard")]
    hardbenign_false = [row for row in hardbenign8 if row.get("speak")]
    historical_header_audit = []
    for row in hardbenign_false:
        checks = row.get("pattern_checks", {})
        candidates = [candidate for field in ("brute_force_candidates", "distributed_brute_force_candidates", "credential_stuffing_candidates", "priv_esc_candidates", "scanner_recon_candidates") for candidate in checks.get(field, [])]
        source_flags = [candidate.get("authorized_source") for candidate in candidates]
        historical_header_audit.append({"id": row["id"], "authorized_source_flag_present": any(flag is not None for flag in source_flags),
                                        "authorized_source_flag_values": source_flags, "returned_speak": row.get("speak"),
                                        "returned_kind": row.get("kind"), "raw_model_output": row.get("raw_model_output")})

    report = {
        "phase": "dev-rules-and-audit", "created_at": datetime.now(timezone.utc).isoformat(),
        "data_scope": "data/golden/dev.jsonl, dev streams 01-03, and frozen dev-only evasion sets v1-v4; historical dev-only 8B artifact",
        "metrics": {"attack_recall": {"n": attacks, "d": total_attacks}, "kind_accuracy": {"n": correct, "d": attacks},
                    "hard_benign_false_speaks": {"n": hard_fp, "d": benign_hard}, "normal_benign_false_speaks": {"n": normal_fp, "d": benign_normal}},
        "per_kind_dev_recall": kind_counts,
        "evasion_v1_rules_recall": evasion_v1["families"],
        "evasion_v1_pre_normalization_reference": last_pre_normalization["evasion_v1_rules_recall"],
        "evasion_v2_pre_fix_reference": {"artifact": str(pre_fix_path.relative_to(ROOT)),
                                         "evasion_v2_rules_recall": pre_fix["evasion_v2_rules_recall"]},
        "evasion_v2_rules_recall_after_60m_change": evasion_v2["families"],
        "evasion_v3_rules_recall": evasion_v3["families"],
        "evasion_v3_pre_normalization_reference": last_pre_normalization["evasion_v3_rules_recall"],
        "evasion_v3_slow_rate_window_samples": evasion_v3["slow_window_samples"],
        "evasion_v4_post_normalization_recall": evasion_v4["families"],
        "evasion_v4_original_fixture_recall_invalid_due_to_source_payload_contamination": evasion_v4_original["families"],
        "evasion_v4_slow_rate_window_samples": evasion_v4["slow_window_samples"],
        "dev_streams_01_03_false_alerts": {item["stream"]: item["false_alerts"] for item in stream_eval["streams"]},
        "distributed_rule": "same username; failures from >=3 distinct sources in trailing 60m; no success for that username in the interval",
        "spacing_hypothesis": {"hypothesis": "A 10-minute cross-IP rolling feature misses events spaced 30 minutes apart.",
                               "window_changed_from_10m_to_60m": True,
                               "interpretation": "The frozen evasion-v3 file records each slow attempt's 15/30/45-minute spacing; see per-spacing family recall and latest-60m source counts."},
        "historical_8b_hard_benign_false_speaks": {"n": len(hardbenign_false), "details": historical_header_audit},
        "credential_stuffing_rule": "auth endpoint; rolling 60m; >=4 distinct failed usernames, >=2 distinct source IPs, >=4 failed attempts; successes/attempts <=0.25",
        "normalization": "up to 3 repeated URL-decode passes, HTML entity and Unicode escape decode, SQL comment stripping, whitespace collapse",
        "config_snapshot": snapshot(),
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "eval/runs" / f"dev-rules-{stamp}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(out.relative_to(ROOT)), "metrics": report["metrics"], "per_kind_dev_recall": kind_counts,
                      "evasion_v1_rules_recall": evasion_v1["families"],
                      "evasion_v2_pre_fix_reference": pre_fix["evasion_v2_rules_recall"],
                      "evasion_v2_rules_recall_after_60m_change": evasion_v2["families"],
                      "evasion_v3_rules_recall": evasion_v3["families"],
                      "evasion_v4_post_normalization_recall": evasion_v4["families"],
                      "evasion_v4_original_fixture_recall_invalid": evasion_v4_original["families"],
                      "dev_streams_01_03_false_alerts": report["dev_streams_01_03_false_alerts"],
                      "historical_8b_false_speaks": len(hardbenign_false)}, indent=2))


if __name__ == "__main__":
    main()
