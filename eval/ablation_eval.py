#!/usr/bin/env python3
"""Compare frozen rule ablations on dev streams 01-03 only."""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from types import SimpleNamespace
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from baseline import rules as current_rules
from eval.run_metadata import snapshot
from explain.bedrock import BedrockExplainer
from explain.template import explain as template_explain
from gate.gate import AlertGate

NAIVE_RULES_COMMIT = "489e860b^"
WINDOW_SIZE = 20
DEV_STREAMS = ("stream_01", "stream_02", "stream_03")


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    return [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines() if line.strip()]


def load_naive_rules() -> SimpleNamespace:
    source = subprocess.run(
        ["git", "show", f"{NAIVE_RULES_COMMIT}:baseline/rules.py"],
        cwd=ROOT, capture_output=True, text=True, check=True,
    ).stdout
    module = SimpleNamespace()
    namespace = vars(module)
    namespace.update({"__name__": "ablation_naive_rules", "__file__": "baseline/rules.py"})
    exec(compile(source, f"{NAIVE_RULES_COMMIT}:baseline/rules.py", "exec"), namespace)
    namespace["authorized_source"] = lambda _source, _scope: False
    return module


def legacy_url_only(event: dict[str, Any]) -> str:
    return naive_rules.decoded_request(event)


def event_seconds(event: dict[str, Any], fallback: int) -> float:
    try:
        value = datetime.fromisoformat(str(event["timestamp"]).replace("Z", "+00:00"))
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.timestamp()
    except (KeyError, ValueError):
        return fallback / 5.0


def evaluate_variant(
    name: str,
    predict: Callable[[list[dict[str, Any]]], dict[str, Any]],
    streams: dict[str, tuple[list[dict[str, Any]], list[dict[str, Any]]]],
    explainer: Any | None = None,
) -> dict[str, Any]:
    stream_reports = []
    totals = Counter()
    kind_counts: Counter[str] = Counter()
    for stream_id in DEV_STREAMS:
        events, episodes = streams[stream_id]
        attack_episodes = [ep for ep in episodes if not ep.get("hard_benign")]
        benign_episodes = [ep for ep in episodes if ep.get("hard_benign")]
        gate = AlertGate(confidence_threshold=float(os.environ.get("DECIDER_CONFIDENCE_THRESHOLD", "0.0")))
        emitted: list[dict[str, Any]] = []
        speaks = 0
        for offset in range(0, len(events), WINDOW_SIZE):
            window = events[offset:offset + WINDOW_SIZE]
            if not window:
                continue
            decision = predict(window)
            speaks += int(bool(decision.get("speak")))
            now = event_seconds(window[-1], offset + len(window) - 1)
            key = f"{stream_id}:{window[0].get('event_id')}:{window[-1].get('event_id')}:{decision.get('kind')}"
            result = gate.evaluate(decision, window, now=now, alert_fingerprint=key)
            if not result["emit"]:
                continue
            record = {"event_start": int(window[0]["event_id"]), "event_end": int(window[-1]["event_id"]),
                      "kind": decision.get("kind", "none"), "events": window, "decision": decision}
            if explainer is not None:
                record["explanation"] = explainer.explain(decision, window)
            elif name == "E":
                record["explanation"] = template_explain(decision, window)
            emitted.append(record)
            kind_counts[str(decision.get("kind", "none"))] += 1

        def overlaps(record: dict[str, Any], episode: dict[str, Any]) -> bool:
            return record["event_end"] >= int(episode["start_idx"]) and record["event_start"] < int(episode["end_idx"])

        detected = sum(any(overlaps(alert, episode) for alert in emitted) for episode in attack_episodes)
        benign_false = sum(any(overlaps(alert, episode) for alert in emitted) for episode in benign_episodes)
        false_alerts = sum(not any(overlaps(alert, episode) for episode in attack_episodes) for alert in emitted)
        stream_reports.append({"stream": stream_id, "attack_episodes_detected": detected,
                               "attack_episodes": len(attack_episodes), "hard_benign_episodes_alerted": benign_false,
                               "hard_benign_episodes": len(benign_episodes), "false_alerts": false_alerts,
                               "rule_speaks": speaks, "emitted_alerts": len(emitted)})
        totals.update({"attack_episodes_detected": detected, "attack_episodes": len(attack_episodes),
                       "hard_benign_episodes_alerted": benign_false, "hard_benign_episodes": len(benign_episodes),
                       "false_alerts": false_alerts, "rule_speaks": speaks, "emitted_alerts": len(emitted)})
    return {"streams": stream_reports, "totals": dict(totals), "emitted_kinds": dict(kind_counts)}


def evaluate_lookalikes(
    rows: list[dict[str, Any]], predict: Callable[[list[dict[str, Any]]], dict[str, Any]]
) -> dict[str, Any]:
    by_category: dict[str, dict[str, int]] = {}
    for row in rows:
        category = str(row["provenance"]["variant"])
        category_result = by_category.setdefault(category, {"false_speaks": 0, "windows": 0})
        decision = predict(row["events"])
        category_result["windows"] += 1
        category_result["false_speaks"] += int(bool(decision.get("speak")))
    return {"categories": by_category,
            "false_speaks": sum(value["false_speaks"] for value in by_category.values()),
            "windows": sum(value["windows"] for value in by_category.values())}


def neutralize_modsecurity(events: list[dict[str, Any]], source_dataset: str | None = None) -> list[dict[str, Any]]:
    """Copy events and remove response-status signal from marked ModSecurity records."""
    return [{**event, "status": 200} if source_dataset == "zenodo:17178461"
            or event.get("provenance", {}).get("source_dataset") == "zenodo:17178461" else event
            for event in events]


def evaluate_status_sensitivity(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Compare standard and status-neutral decisions on labeled dev attacks only."""
    per_kind: dict[str, Counter[str]] = {}
    changed: list[dict[str, Any]] = []
    sqli_other_kind: list[dict[str, Any]] = []
    for row in rows:
        if row.get("label") != "speak":
            continue
        kind = str(row["kind"])
        standard = current_rules.predict(row["events"])
        source = row.get("provenance", {}).get("source_dataset")
        neutral = current_rules.predict(neutralize_modsecurity(row["events"], source))
        counts = per_kind.setdefault(kind, Counter())
        counts["n"] += 1
        for mode, decision in (("standard", standard), ("neutral", neutral)):
            counts[f"{mode}_speak"] += int(bool(decision.get("speak")))
            counts[f"{mode}_matching_kind"] += int(bool(decision.get("speak")) and decision.get("kind") == kind)
        if bool(standard.get("speak")) != bool(neutral.get("speak")) or (
            standard.get("speak") and neutral.get("speak") and standard.get("kind") != neutral.get("kind")
        ):
            changed.append({"id": row["id"], "true_kind": kind,
                            "standard_kind": standard.get("kind"), "standard_rule": standard.get("reason"),
                            "neutral_kind": neutral.get("kind"), "neutral_rule": neutral.get("reason")})
        if kind == "sqli" and standard.get("speak") and standard.get("kind") != kind:
            sqli_other_kind.append({"id": row["id"], "kind": standard.get("kind"), "rule": standard.get("reason")})
    overall = Counter()
    for counts in per_kind.values():
        overall.update(counts)
    return {"overall": dict(overall), "per_kind": {k: dict(v) for k, v in sorted(per_kind.items())},
            "changed_windows": changed, "sqli_spoken_as_other_kind": sqli_other_kind}


def evaluate_mutations(name: str, predict: Callable[[list[dict[str, Any]]], dict[str, Any]]) -> dict[str, Any]:
    payload = json.loads((ROOT / f"eval/runs/{name}-dev.json").read_text(encoding="utf-8"))
    rows = payload.get("attacks", []) if isinstance(payload, dict) else payload
    families: dict[str, Counter[str]] = {}
    for row in rows:
        result = predict(row["events"])
        stats = families.setdefault(str(row["family"]), Counter())
        stats["total"] += 1
        stats["detected"] += int(bool(result.get("speak")))
    return {key: dict(value) for key, value in families.items()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dry-run", action="store_true", help="Never call Bedrock; use templates for E")
    parser.add_argument("--real-bedrock", action="store_true", help="Use Bedrock for E after explicit user confirmation")
    parser.add_argument("--seed", type=int, default=20261021)
    args = parser.parse_args()
    if args.real_bedrock and (os.environ.get("HUSH_BEDROCK_CONFIRMED") != "1" or not os.environ.get("BEDROCK_MODEL_ID")):
        parser.error("--real-bedrock requires user confirmation via HUSH_BEDROCK_CONFIRMED=1 and BEDROCK_MODEL_ID")
    if args.dry_run and args.real_bedrock:
        parser.error("choose either --dry-run or --real-bedrock")
    if not args.dry_run and not args.real_bedrock:
        args.dry_run = True

    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    if tuple(manifest.get("dev_streams", [])) != DEV_STREAMS:
        raise RuntimeError(f"expected only dev streams {DEV_STREAMS}; manifest says {manifest.get('dev_streams')}")
    streams = {
        stream_id: (read_jsonl(ROOT / manifest["streams"][stream_id]["path"]), manifest["streams"][stream_id]["episodes"])
        for stream_id in DEV_STREAMS
    }
    lookalike_sets = {}
    for version in ("v1", "v2"):
        lookalike_path = ROOT / f"eval/fixtures/benign-lookalike-{version}.jsonl"
        if lookalike_path.exists():
            lookalikes = read_jsonl(lookalike_path)
            if len(lookalikes) != 60:
                raise RuntimeError(f"expected 60 frozen benign-lookalike-{version} windows, found {len(lookalikes)}")
            lookalike_sets[version] = lookalikes
    if "v1" not in lookalike_sets:
        raise RuntimeError("frozen benign-lookalike-v1 fixture is required")

    global naive_rules
    naive_rules = load_naive_rules()
    original_auth = current_rules.authorized_source
    original_normalizer = current_rules.normalize_request
    original_sqli = current_rules.SQLI
    variants: dict[str, dict[str, Any]] = {}
    dev_rows = read_jsonl(ROOT / "data/golden/dev.jsonl")
    try:
        variants["A"] = evaluate_variant("A", naive_rules.predict, streams)
        for version, lookalikes in lookalike_sets.items():
            variants["A"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, naive_rules.predict)

        current_rules.authorized_source = lambda _source, _scope: False
        current_rules.normalize_request = legacy_url_only
        current_rules.SQLI = naive_rules.SQLI
        variants["B"] = evaluate_variant("B", current_rules.predict, streams)
        for version, lookalikes in lookalike_sets.items():
            variants["B"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, current_rules.predict)

        current_rules.normalize_request = original_normalizer
        current_rules.SQLI = original_sqli
        variants["C"] = evaluate_variant("C", current_rules.predict, streams)
        for version, lookalikes in lookalike_sets.items():
            variants["C"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, current_rules.predict)

        current_rules.authorized_source = original_auth
        variants["D"] = evaluate_variant("D", current_rules.predict, streams)
        for version, lookalikes in lookalike_sets.items():
            variants["D"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, current_rules.predict)

        bedrock = BedrockExplainer() if args.real_bedrock else None
        variants["E"] = evaluate_variant("E", current_rules.predict, streams, explainer=bedrock)
        for version, lookalikes in lookalike_sets.items():
            variants["E"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, current_rules.predict)
        neutral_predict = lambda events: current_rules.predict(neutralize_modsecurity(events))
        variants["F_status_neutral"] = {
            "golden_dev_sensitivity": evaluate_status_sensitivity(dev_rows),
            "streams": evaluate_variant("F_status_neutral", neutral_predict, streams),
            "evasion_v1": evaluate_mutations("evasion-v1", neutral_predict),
            "evasion_v2": evaluate_mutations("evasion-v2", neutral_predict),
            "evasion_v3": evaluate_mutations("evasion-v3", neutral_predict),
            "evasion_v4": evaluate_mutations("evasion-v4-clean", neutral_predict),
        }
        for version, lookalikes in lookalike_sets.items():
            variants["F_status_neutral"][f"benign_lookalike_{version}"] = evaluate_lookalikes(lookalikes, neutral_predict)
    finally:
        current_rules.authorized_source = original_auth
        current_rules.normalize_request = original_normalizer
        current_rules.SQLI = original_sqli

    report = {
        "phase": "ablation-A-E",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data_scope": "dev streams 01-03 plus any frozen benign-lookalike-v1/v2 files present; no test/held-out",
        "dry_run": args.dry_run,
        "bedrock_explanations": "pending; E uses template proxy and makes zero live calls" if not args.real_bedrock else "live Bedrock, explanation-only",
        "bedrock_call_count": bedrock.invocation_count if args.real_bedrock else 0,
        "bedrock_alert_call_parity": (bedrock.invocation_count == variants["E"]["totals"]["emitted_alerts"]) if args.real_bedrock else None,
        "bedrock_latency_p95_ms": (sorted(bedrock.invocation_latencies_ms)[max(0, int(len(bedrock.invocation_latencies_ms) * 0.95 + 0.999999) - 1)]
                                    if args.real_bedrock and bedrock.invocation_latencies_ms else None),
        "variants": variants,
        "config_snapshot": snapshot(seed=args.seed),
    }
    out = ROOT / "eval/runs" / f"ablation-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(out.relative_to(ROOT)), "dry_run": report["dry_run"],
                      "variants": {key: ({"totals": value["totals"], **{name: result for name, result in value.items() if name.startswith("benign_lookalike_")}}
                                           if "totals" in value else value) for key, value in variants.items()},
                      "bedrock_call_count": report["bedrock_call_count"]}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
