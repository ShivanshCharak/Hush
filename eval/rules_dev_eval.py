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


def main() -> None:
    rows = [json.loads(line) for line in (ROOT / "data/golden/dev.jsonl").read_text().splitlines() if line.strip()]
    attacks = benign_hard = benign_normal = correct = 0
    total_attacks = hard_fp = normal_fp = 0
    for row in rows:
        decision = predict(row["events"])
        if row["label"] == "speak":
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

    evasion = json.loads((ROOT / "eval/runs/evasion-v2-dev.json").read_text())
    families: dict[str, dict[str, int]] = defaultdict(lambda: {"detected": 0, "total": 0})
    slow_window_samples = []
    for row in evasion:
        stats = families[row["family"]]
        stats["total"] += 1
        stats["detected"] += int(bool(predict(row["events"])["speak"]))
        if row["family"] == "slow_rate_10ip_30m_rotating_users":
            events = [event for event in row["events"] if event.get("event_type") == "auth"]
            timestamps = [datetime.fromisoformat(event["timestamp"].replace("Z", "+00:00")) for event in events]
            latest = max(timestamps)
            within_10m = sum((latest - when).total_seconds() <= 600 for when in timestamps)
            slow_window_samples.append({"id": row["id"], "auth_failures": len(events), "spacing_minutes": 30,
                                        "failures_in_latest_10m": within_10m,
                                        "decision": predict(row["events"])["speak"]})

    old8 = json.loads((ROOT / "eval/runs/phase2-20261020T033832Z.json").read_text())["decider"]["window_predictions"]
    hardbenign8 = [row for row in old8 if row.get("label") == "silent" and row.get("hard")]
    hardbenign_false = [row for row in hardbenign8 if row.get("speak")]
    historical_header_audit = []
    for row in hardbenign_false:
        checks = row.get("pattern_checks", {})
        candidates = [candidate for field in ("brute_force_candidates", "credential_stuffing_candidates", "priv_esc_candidates", "scanner_recon_candidates") for candidate in checks.get(field, [])]
        source_flags = [candidate.get("authorized_source") for candidate in candidates]
        historical_header_audit.append({"id": row["id"], "authorized_source_flag_present": any(flag is not None for flag in source_flags),
                                        "authorized_source_flag_values": source_flags, "returned_speak": row.get("speak"),
                                        "returned_kind": row.get("kind"), "raw_model_output": row.get("raw_model_output")})

    report = {
        "phase": "dev-rules-and-audit", "created_at": datetime.now(timezone.utc).isoformat(),
        "data_scope": "data/golden/dev.jsonl and evasion-v2 dev mutation set; historical dev-only 8B artifact",
        "metrics": {"attack_recall": {"n": attacks, "d": total_attacks}, "kind_accuracy": {"n": correct, "d": attacks},
                    "hard_benign_false_speaks": {"n": hard_fp, "d": benign_hard}, "normal_benign_false_speaks": {"n": normal_fp, "d": benign_normal}},
        "evasion_v2_rules_recall": families,
        "spacing_hypothesis": {"hypothesis": "A 10-minute rolling feature misses attempts spaced 30 minutes apart.",
                               "window_changed": False, "examples": slow_window_samples,
                               "interpretation": "In each 20-event slow-rate case, only the latest event falls in the latest 10 minutes; the rule recall is reported separately above."},
        "historical_8b_hard_benign_false_speaks": {"n": len(hardbenign_false), "details": historical_header_audit},
        "config_snapshot": snapshot(model="qwen3:8b"),
    }
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "eval/runs" / f"dev-rules-{stamp}.json"
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(out.relative_to(ROOT)), "metrics": report["metrics"], "evasion_v2_rules_recall": families,
                      "historical_8b_false_speaks": len(hardbenign_false)}, indent=2))


if __name__ == "__main__":
    main()
