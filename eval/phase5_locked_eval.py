#!/usr/bin/env python3
"""One-shot Phase 5 locked evaluation. Do not invoke except for the authorized run."""
from __future__ import annotations

import hashlib
import json
import argparse
import subprocess
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path
from statistics import median
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from baseline import rules as current_rules
from eval.ablation_eval import (evaluate_mutations, evaluate_lookalikes,
                                load_naive_rules, neutralize_modsecurity, read_jsonl)
from eval.check_locked_run import check as check_locked_run
from eval.locked_run_state import finish_attempt, start_attempt
from eval.run_metadata import snapshot
from explain.template import explain as template_explain
from gate.gate import AlertGate

WINDOW = 20
COUNTER = ROOT / "eval/locked-run-counter.json"


def sha(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for block in iter(lambda: f.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def ratio(n: int, d: int) -> float | None:
    return n / d if d else None


def metric(n: int, d: int) -> dict[str, Any]:
    return {"numerator": n, "denominator": d, "value": ratio(n, d)}


def is_modsec(row: dict[str, Any]) -> bool:
    return row.get("provenance", {}).get("source_dataset") == "zenodo:17178461"


def make_variants() -> tuple[dict[str, Callable], dict[str, dict[str, Any]]]:
    naive = load_naive_rules()
    original = (current_rules.authorized_source, current_rules.normalize_request, current_rules.SQLI)
    variants: dict[str, Callable] = {}
    definitions: dict[str, dict[str, Any]] = {}
    try:
        variants["A"] = naive.predict
        definitions["A"] = {"name": "frozen naive rules", "allowlist": "disabled", "normalization": "legacy URL only"}
        legacy_normalizer = lambda event: naive.decoded_request(event)
        current_rules.authorized_source = lambda _source, _scope: False
        current_rules.normalize_request = legacy_normalizer
        current_rules.SQLI = naive.SQLI
        def with_rule_state(decision: Callable, *, auth: Callable, normalizer: Callable, sqli: Any) -> Callable:
            def run(events: list[dict[str, Any]]) -> dict[str, Any]:
                before = (current_rules.authorized_source, current_rules.normalize_request, current_rules.SQLI)
                try:
                    current_rules.authorized_source, current_rules.normalize_request, current_rules.SQLI = auth, normalizer, sqli
                    return decision(events)
                finally:
                    current_rules.authorized_source, current_rules.normalize_request, current_rules.SQLI = before
            return run
        no_auth = lambda _source, _scope: False
        variants["B"] = with_rule_state(current_rules.predict, auth=no_auth, normalizer=legacy_normalizer, sqli=naive.SQLI)
        definitions["B"] = {"name": "cross-IP and stuffing rules", "allowlist": "disabled", "normalization": "legacy URL only"}
        current_rules.normalize_request = original[1]
        current_rules.SQLI = original[2]
        variants["C"] = with_rule_state(current_rules.predict, auth=no_auth, normalizer=original[1], sqli=original[2])
        definitions["C"] = {"name": "B plus normalization", "allowlist": "disabled", "normalization": "current"}
        current_rules.authorized_source = original[0]
        variants["D"] = with_rule_state(current_rules.predict, auth=original[0], normalizer=original[1], sqli=original[2])
        variants["E"] = with_rule_state(current_rules.predict, auth=original[0], normalizer=original[1], sqli=original[2])
        definitions["D"] = {"name": "C plus allowlist", "allowlist": "enabled", "explanation": "none"}
        definitions["E"] = {"name": "D plus template explainer", "allowlist": "enabled", "explanation": "deterministic template"}
        variants["F"] = lambda events: with_rule_state(current_rules.predict, auth=original[0], normalizer=original[1], sqli=original[2])(neutralize_modsecurity(events))
        definitions["F"] = {"name": "D with ModSecurity status neutralized", "allowlist": "enabled", "status_neutral": True}
    finally:
        current_rules.authorized_source, current_rules.normalize_request, current_rules.SQLI = original
    return variants, definitions


def score_golden(rows: list[dict[str, Any]], predict: Callable, mode: str) -> dict[str, Any]:
    attack = [r for r in rows if r.get("label") == "speak"]
    benign = [r for r in rows if r.get("label") != "speak"]
    simulated_benign = [r for r in benign if not is_modsec(r)]
    outcomes = []
    for row in rows:
        events = row["events"]
        # F's predictor is the same final ruleset; only ModSecurity-marked events are altered.
        if mode == "status_neutral":
            source = row.get("provenance", {}).get("source_dataset")
            decision = predict(neutralize_modsecurity(events, source) if is_modsec(row) else events)
        else:
            decision = predict(events)
        outcomes.append((row, decision))
    by = [(r, d) for r, d in outcomes if r.get("label") == "speak"]
    spoken = [(r, d) for r, d in outcomes if d.get("speak")]
    matching = [(r, d) for r, d in by if d.get("speak") and d.get("kind") == r.get("kind")]
    kind_acc = sum(d.get("kind") == r.get("kind") for r, d in spoken if r.get("label") == "speak")
    source = {}
    for label, predicate in (("modsecurity_derived", is_modsec), ("simulator_generated", lambda r: not is_modsec(r))):
        subset = [r for r in attack if predicate(r)]
        hit = sum(bool(d.get("speak")) for r, d in by if predicate(r))
        kinds: dict[str, Any] = {}
        for kind in sorted({r["kind"] for r in subset}):
            kr = [r for r in subset if r["kind"] == kind]
            kh = sum(bool(d.get("speak")) for r, d in by if predicate(r) and r["kind"] == kind)
            km = sum(bool(d.get("speak")) and d.get("kind") == kind for r, d in by if predicate(r) and r["kind"] == kind)
            kinds[kind] = {"n": len(kr), "speak_recall": metric(kh, len(kr)), "matching_kind_recall": metric(km, len(kr))}
        source[label] = {"n": len(subset), "speak_recall": metric(hit, len(subset)), "per_kind": kinds}
    hard_a = [(r, d) for r, d in outcomes if r.get("label") == "speak" and r.get("hard")]
    hard_b = [(r, d) for r, d in outcomes if r.get("label") != "speak" and r.get("hard")]
    return {
        "attack_recall_speak": metric(sum(bool(d.get("speak")) for _, d in by), len(attack)),
        "kind_accuracy_among_spoken_attacks": metric(kind_acc, sum(bool(d.get("speak")) for r, d in by)),
        "matching_kind_recall": metric(sum(bool(d.get("speak")) and d.get("kind") == r.get("kind") for r, d in by), len(attack)),
        "benign_false_speaks": metric(sum(bool(d.get("speak")) for r, d in outcomes if r.get("label") != "speak"), len(benign)),
        "simulated_benign_false_speaks": metric(sum(bool(d.get("speak")) for r, d in outcomes if r.get("label") != "speak" and not is_modsec(r)), len(simulated_benign)),
        "precision": metric(sum(r.get("label") == "speak" for r, d in spoken), len(spoken)),
        "source_split": source,
        "hard_attack_recall": metric(sum(bool(d.get("speak")) for _, d in hard_a), len(hard_a)),
        "hard_benign_false_speaks": metric(sum(bool(d.get("speak")) for _, d in hard_b), len(hard_b)),
        "counts": {"attack": len(attack), "benign": len(benign), "spoken_attack": sum(bool(d.get("speak")) for _, d in by), "all_speaks": len(spoken)},
    }


def evaluate_streams(predict: Callable, manifest: dict[str, Any], stream_ids: list[str], *, use_template: bool = False) -> dict[str, Any]:
    per_stream = []
    all_delays: list[int] = []
    totals = Counter()
    for sid in stream_ids:
        info = manifest["streams"][sid]
        events = read_jsonl(ROOT / info["path"])
        attacks = [ep for ep in info["episodes"] if not ep.get("hard_benign")]
        hard_benign = [ep for ep in info["episodes"] if ep.get("hard_benign")]
        alerts = []
        speaks = 0
        evidence_checked = evidence_valid = entity_mentions = grounded_mentions = 0
        gate = AlertGate(confidence_threshold=0.0)
        for offset in range(0, len(events), WINDOW):
            window = events[offset:offset + WINDOW]
            decision = predict(window)
            speaks += int(bool(decision.get("speak")))
            event_end = int(window[-1].get("event_id", offset + WINDOW - 1))
            event_start = int(window[0].get("event_id", offset))
            try:
                parsed = datetime.fromisoformat(str(window[-1].get("timestamp", "")).replace("Z", "+00:00"))
                now = parsed.timestamp()
            except ValueError:
                now = offset / 5.0
            result = gate.evaluate(decision, window, now=now, alert_fingerprint=f"{sid}:{event_start}:{event_end}:{decision.get('kind')}")
            if result["emit"]:
                alert = {"event_start": event_start, "event_end": event_end, "kind": decision.get("kind"), "events": window}
                if use_template:
                    # E's explanation is recorded for emitted alerts only; it cannot affect the decision.
                    alert["explanation"] = template_explain(decision, window)
                    evidence_checked += 1
                    evidence = set(alert["explanation"].get("evidence_ids", []))
                    window_ids = {int(e.get("event_id", -1)) for e in window}
                    evidence_valid += int(bool(evidence) and evidence <= window_ids)
                    text = " ".join(str(alert["explanation"].get(k, "")) for k in ("summary", "suggested_action"))
                    all_entities = {str(e[k]) for e in window for k in ("src_ip", "username", "path") if e.get(k)}
                    cited_entities = {str(e[k]) for e in window if int(e.get("event_id", -1)) in evidence for k in ("src_ip", "username", "path") if e.get(k)}
                    mentioned = {entity for entity in all_entities if entity in text}
                    entity_mentions += len(mentioned)
                    grounded_mentions += sum(entity in cited_entities for entity in mentioned)
                alerts.append(alert)
        hits_by_episode = []
        episode_delays = []
        for ep in attacks:
            hits = [a for a in alerts if a["event_end"] >= int(ep["start_idx"]) and a["event_start"] < int(ep["end_idx"])]
            hits_by_episode.append(hits)
            if hits:
                episode_delays.append(max(0, min(a["event_end"] for a in hits) - int(ep["start_idx"]) + 1))
        false_alerts = sum(not any(a["event_end"] >= int(ep["start_idx"]) and a["event_start"] < int(ep["end_idx"]) for ep in attacks) for a in alerts)
        hard_benign_alerted = sum(any(a["event_end"] >= int(ep["start_idx"]) and a["event_start"] < int(ep["end_idx"]) for a in alerts) for ep in hard_benign)
        dupes = sum(max(0, len(hits) - 1) for hits in hits_by_episode)
        detected = sum(bool(h) for h in hits_by_episode)
        all_delays.extend(episode_delays)
        row = {"stream": sid, "episode_recall": metric(detected, len(attacks)), "false_alerts": false_alerts,
               "hard_benign_episodes_alerted": hard_benign_alerted, "hard_benign_episodes": len(hard_benign),
               "duplicates": dupes, "emitted_alerts": len(alerts), "rule_speaks": speaks,
               "median_time_to_detect_events": median(episode_delays) if episode_delays else None}
        per_stream.append(row)
        totals.update({"detected": detected, "episodes": len(attacks), "false_alerts": false_alerts,
                       "hard_benign_episodes_alerted": hard_benign_alerted, "hard_benign_episodes": len(hard_benign),
                       "duplicates": dupes, "emitted_alerts": len(alerts), "rule_speaks": speaks})
    result = {"streams": per_stream, "episode_recall": metric(totals["detected"], totals["episodes"]),
            "false_alerts": totals["false_alerts"], "duplicates": totals["duplicates"],
            "hard_benign_episodes_alerted": totals["hard_benign_episodes_alerted"], "hard_benign_episodes": totals["hard_benign_episodes"],
            "duplicates_per_detected_episode": ratio(totals["duplicates"], totals["detected"]),
            "median_time_to_detect_events": median(all_delays) if all_delays else None,
            "totals": dict(totals), "episode_matching_rule": "alert window overlaps labeled episode interval: alert.end >= episode.start_idx and alert.start < episode.end_idx; earliest overlapping alert end defines delay"}
    if use_template:
        result["explanation_grounding"] = {"evidence_valid_alerts": evidence_valid, "alerts_checked": evidence_checked,
                                            "evidence_valid_rate": ratio(evidence_valid, evidence_checked),
                                            "grounded_entity_mentions": grounded_mentions, "entity_mentions": entity_mentions,
                                            "entity_grounding_rate": ratio(grounded_mentions, entity_mentions) if entity_mentions else 1.0}
    return result


def score_fixture(rows: list[dict[str, Any]], predict: Callable) -> dict[str, Any]:
    totals: Counter[str] = Counter()
    families: dict[str, Counter[str]] = defaultdict(Counter)
    for row in rows:
        d = predict(row["events"])
        fam = str(row.get("family", row.get("provenance", {}).get("variant", "unknown")))
        totals["windows"] += 1
        totals["speaks"] += int(bool(d.get("speak")))
        families[fam]["n"] += 1
        families[fam]["speaks"] += int(bool(d.get("speak")))
    return {"false_speaks": metric(totals["speaks"], totals["windows"]), "per_family": {k: metric(v["speaks"], v["n"]) for k,v in sorted(families.items())}}


def fill_readme_table(readme_path: Path, report: dict[str, Any], artifact_name: str) -> None:
    """Fill the final-target table from variant E; safe for dry runs with a scratch README."""
    if report.get("data_scope") == "dev dry run":
        measured = {"Attack recall": "dev-only; locked denominator not evaluated",
                    "Benign false-speak rate vs simulated benign traffic": "dev-only; locked denominator not evaluated",
                    "Precision": "dev-only; locked denominator not evaluated",
                    "Hard-attack recall": "dev-only; locked denominator not evaluated",
                    "Hard-benign false-speak vs simulated benign traffic": "dev-only; locked denominator not evaluated",
                    "Kind accuracy": "dev-only; locked denominator not evaluated",
                    "Episode recall": "dev streams 01–03 only",
                    "False alerts on held-out streams": "dev streams 01–03 only",
                    "Duplicate alerts per detected episode": "dev streams 01–03 only",
                    "Median time-to-detect": "dev streams 01–03 only",
                    "Injection robustness": "pending: not part of the locked run",
                    "Explanation grounding": "template-mode grounding checks in run artifact",
                    "Decision latency": "pending: not part of the locked run"}
    else:
        e = report["variants"]["E"]
        g, h = e["golden_test"], e["held_out_streams"]
        f = report["variants"]["F"]
        def pair(key: str, obj: dict[str, Any], *, passed: bool = True) -> str:
            m = obj[key]
            value = f"{m['numerator']}/{m['denominator']}"
            return value if passed else f"MISSED {value}"
        e_attack = g["attack_recall_speak"]
        e_benign = g["simulated_benign_false_speaks"]
        e_precision = g["precision"]
        e_hard_attack = g["hard_attack_recall"]
        e_hard_benign = g["hard_benign_false_speaks"]
        e_kind = g["kind_accuracy_among_spoken_attacks"]
        f_g, f_h = f["golden_test"], f["held_out_streams"]
        grounding = e["held_out_streams"].get("explanation_grounding", {})
        assessment = report.get("target_assessment", {})
        def with_mode(std: str, neutral: str) -> str:
            return f"standard {std}; status-neutral {neutral} (see {artifact_name})"
        measured = {
            "Attack recall": with_mode(pair("attack_recall_speak", g, passed=assessment.get("attack_recall_standard", {}).get("pass", False)), pair("attack_recall_speak", f_g, passed=assessment.get("attack_recall_status_neutral", {}).get("pass", False))),
            "Benign false-speak rate vs simulated benign traffic": with_mode(pair("simulated_benign_false_speaks", g, passed=assessment.get("benign_false_speaks_standard", {}).get("pass", False)), pair("simulated_benign_false_speaks", f_g, passed=assessment.get("benign_false_speaks_status_neutral", {}).get("pass", False))),
            "Precision": with_mode(pair("precision", g, passed=assessment.get("precision_standard", {}).get("pass", False)), pair("precision", f_g, passed=assessment.get("precision_status_neutral", {}).get("pass", False))),
            "Hard-attack recall": with_mode(pair("hard_attack_recall", g, passed=assessment.get("hard_attack_standard", {}).get("pass", False)), pair("hard_attack_recall", f_g, passed=assessment.get("hard_attack_status_neutral", {}).get("pass", False))),
            "Hard-benign false-speak vs simulated benign traffic": with_mode(pair("hard_benign_false_speaks", g, passed=assessment.get("hard_benign_standard", {}).get("pass", False)), pair("hard_benign_false_speaks", f_g, passed=assessment.get("hard_benign_status_neutral", {}).get("pass", False))),
            "Kind accuracy": with_mode(pair("kind_accuracy_among_spoken_attacks", g, passed=assessment.get("kind_accuracy_standard", {}).get("pass", False)), pair("kind_accuracy_among_spoken_attacks", f_g, passed=assessment.get("kind_accuracy_status_neutral", {}).get("pass", False))),
            "Episode recall": with_mode(pair("episode_recall", h, passed=assessment.get("episode_recall_standard", {}).get("pass", False)), pair("episode_recall", f_h, passed=assessment.get("episode_recall_status_neutral", {}).get("pass", False))),
            "False alerts on held-out streams": with_mode(str(h["false_alerts"]), str(f_h["false_alerts"])),
            "Duplicate alerts per detected episode": with_mode(f"{h['duplicates']}/{h['totals']['detected']}", f"{f_h['duplicates']}/{f_h['totals']['detected']}"),
            "Median time-to-detect": with_mode(f"{h['median_time_to_detect_events']} events", f"{f_h['median_time_to_detect_events']} events"),
            "Injection robustness": "pending: not part of the locked run",
            "Explanation grounding": f"evidence IDs {grounding.get('evidence_valid_alerts',0)}/{grounding.get('alerts_checked',0)}; entity grounding {grounding.get('grounded_entity_mentions',0)}/{grounding.get('entity_mentions',0)} (template; see {artifact_name})",
            "Decision latency": "pending: not part of the locked run"}
    lines = readme_path.read_text(encoding="utf-8").splitlines()
    in_targets = False
    output = []
    for line in lines:
        if line.startswith("## Locked final targets"):
            in_targets = True
        elif in_targets and line.startswith("## "):
            in_targets = False
        if in_targets and line.startswith("|") and "|" in line[1:]:
            cols = [c.strip() for c in line.strip().strip("|").split("|")]
            if len(cols) == 3 and cols[0] in measured and cols[0] != "Metric":
                line = f"| {cols[0]} | {cols[1]} | {measured[cols[0]]} |"
        output.append(line)
    appendix = ["", "### Phase 5 detailed results", "", f"Run artifact: `{artifact_name}`. `MISSED` marks a failed target.", ""]
    if report.get("data_scope") == "dev dry run":
        appendix += ["This is a dev-only harness dry run. It did not access the locked golden test set or held-out streams."]
    else:
        appendix += ["#### Golden test source split", "", "| Source | Kind | n | Speak recall | Matching-kind recall |", "|---|---|---:|---:|---:|"]
        for mode, key in (("standard", "E"), ("status-neutral", "F")):
            for source, block in report["variants"][key]["golden_test"]["source_split"].items():
                for kind, values in block["per_kind"].items():
                    sr, mr = values["speak_recall"], values["matching_kind_recall"]
                    appendix.append(f"| {mode} · {source} | {kind} | {values['n']} | {sr['numerator']}/{sr['denominator']} | {mr['numerator']}/{mr['denominator']} |")
        appendix += ["", "#### A–F ablation on held-out streams", "", "| Variant | Golden speak recall | Kind accuracy | Matching-kind recall | Held-out episode recall | False alerts | Duplicates | Median detect events |", "|---|---:|---:|---:|---:|---:|---:|---:|"]
        for variant, values in report["variants"].items():
            g, h = values["golden_test"], values["held_out_streams"]
            appendix.append(f"| {variant} | {g['attack_recall_speak']['numerator']}/{g['attack_recall_speak']['denominator']} | {g['kind_accuracy_among_spoken_attacks']['numerator']}/{g['kind_accuracy_among_spoken_attacks']['denominator']} | {g['matching_kind_recall']['numerator']}/{g['matching_kind_recall']['denominator']} | {h['episode_recall']['numerator']}/{h['episode_recall']['denominator']} | {h['false_alerts']} | {h['duplicates']} | {h['median_time_to_detect_events']} |")
        appendix += ["", "#### Held-out stream detail (simulator-generated)", "", "| Variant | Stream | Episode recall | False alerts | Duplicates | Median detect events |", "|---|---|---:|---:|---:|---:|"]
        for variant in ("E", "F"):
            for stream in report["variants"][variant]["held_out_streams"]["streams"]:
                recall = stream["episode_recall"]
                appendix.append(f"| {variant} | {stream['stream']} | {recall['numerator']}/{recall['denominator']} | {stream['false_alerts']} | {stream['duplicates']} | {stream['median_time_to_detect_events']} |")
        appendix += ["", "#### Evasion and lookalike results", "", "| Variant | Fixture | Family / category | Detected false speaks / n |", "|---|---|---|---:|"]
        for variant, values in report["variants"].items():
            for fixture, families in values["evasion"].items():
                for family, result in families["per_family"].items():
                    appendix.append(f"| {variant} | {fixture} | {family} | {result['numerator']}/{result['denominator']} |")
            for fixture, families in values["lookalikes"].items():
                for family, result in families["per_family"].items():
                    appendix.append(f"| {variant} | lookalike-{fixture} | {family} | {result['numerator']}/{result['denominator']} |")
        appendix += ["", f"Bedrock metrics: {report['bedrock_metrics']}."]
    # Replace a previous generated appendix or insert before the next top-level README section.
    lines = output
    output = []
    i = 0
    while i < len(lines):
        if lines[i].startswith("### Phase 5 detailed results"):
            i += 1
            while i < len(lines) and not lines[i].startswith("## "):
                i += 1
            continue
        output.append(lines[i]); i += 1
    insert_at = next((i for i, line in enumerate(output) if line.startswith("## Results so far")), len(output))
    output[insert_at:insert_at] = appendix
    tmp = readme_path.with_name(readme_path.name + ".tmp")
    tmp.write_text("\n".join(output) + "\n", encoding="utf-8")
    tmp.replace(readme_path)


def assess_targets(variants: dict[str, Any]) -> dict[str, Any]:
    assessments: dict[str, Any] = {}
    misses = []
    standard = variants["E"]["golden_test"]
    neutral = variants["F"]["golden_test"]
    baseline_hard = variants["A"]["golden_test"]["hard_attack_recall"]
    target_specs = (
        ("attack_recall", "attack_recall_speak", lambda m, v: v >= 0.90, ">= 87/96"),
        ("benign_false_speaks", "simulated_benign_false_speaks", lambda m, v: m["numerator"] <= 6 and m["denominator"] == 120, "<= 6/120"),
        ("precision", "precision", lambda m, v: v >= 0.90, ">= 0.90"),
        ("hard_benign", "hard_benign_false_speaks", lambda m, v: m["numerator"] <= 2 and m["denominator"] == 24, "<= 2/24"),
        ("kind_accuracy", "kind_accuracy_among_spoken_attacks", lambda m, v: v >= 0.85, ">= 0.85"),
    )
    for mode, metrics in (("standard", standard), ("status_neutral", neutral)):
        for name, metric_key, predicate, target in target_specs:
            m = metrics[metric_key]
            value = m["value"]
            passed = bool(predicate(m, value))
            key = f"{name}_{mode}"
            assessments[key] = {"pass": passed, "measured": f"{m['numerator']}/{m['denominator']}", "target": target}
            if not passed:
                misses.append({"metric": name, "mode": mode, "measured": f"{m['numerator']}/{m['denominator']}", "target": target})
        hard = metrics["hard_attack_recall"]
        delta = (hard["value"] or 0) - (baseline_hard["value"] or 0)
        passed = hard["numerator"] >= 11 and hard["denominator"] == 14 and delta >= 0.20
        key = f"hard_attack_{mode}"
        assessments[key] = {"pass": passed, "measured": f"{hard['numerator']}/{hard['denominator']}",
                            "baseline": f"{baseline_hard['numerator']}/{baseline_hard['denominator']}",
                            "delta_percentage_points": round(delta * 100, 2), "target": ">=11/14 and >=20 percentage points above A"}
        if not passed:
            misses.append({"metric": "hard_attack", "mode": mode, "measured": f"{hard['numerator']}/{hard['denominator']}; delta {delta:.4f}", "target": assessments[key]["target"]})
    for mode, block in (("standard", variants["E"]["held_out_streams"]), ("status_neutral", variants["F"]["held_out_streams"])):
        checks = [
            ("episode_recall", block["episode_recall"]["numerator"] >= 14, f"{block['episode_recall']['numerator']}/{block['episode_recall']['denominator']}", ">=14/16"),
            ("false_alerts", block["false_alerts"] <= 2, str(block["false_alerts"]), "<=2"),
            ("duplicates_per_detected_episode", (block["duplicates_per_detected_episode"] or 0) <= 1.5, f"{block['duplicates']}/{block['totals']['detected']}", "<=1.5"),
            ("median_time_to_detect", (block["median_time_to_detect_events"] or 0) <= 40, f"{block['median_time_to_detect_events']} events", "<=40 events"),
        ]
        for name, passed, measured_value, target in checks:
            key=f"{name}_{mode}"; assessments[key]={"pass":bool(passed),"measured":measured_value,"target":target}
            if not passed: misses.append({"metric":name,"mode":mode,"measured":measured_value,"target":target})
    grounding=variants["E"]["held_out_streams"].get("explanation_grounding", {})
    evidence_ok = grounding.get("evidence_valid_rate") == 1.0
    entity_ok = (grounding.get("entity_grounding_rate") or 0) >= 0.98
    for name, passed, measured_value, target in (
        ("evidence_id_grounding", evidence_ok, f"{grounding.get('evidence_valid_alerts',0)}/{grounding.get('alerts_checked',0)}", "100% valid"),
        ("entity_grounding", entity_ok, f"{grounding.get('grounded_entity_mentions',0)}/{grounding.get('entity_mentions',0)}", ">=98% grounded")):
        assessments[name] = {"pass": bool(passed), "measured": measured_value, "target": target}
        if not passed: misses.append({"metric":name,"mode":"template","measured":measured_value,"target":target})
    assessments["injection_robustness"] = {"pass": None, "measured": "pending: not part of the locked run", "target": ">=29/30 attacks; <=1/20 benign; 0 canary leaks"}
    assessments["decision_latency"] = {"pass": None, "measured": "pending: not part of the locked run", "target": "p50<=400ms; p95<=1.2s"}
    return {"checks": assessments, "misses": misses}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--dev-dry-run", action="store_true", help="Use only golden dev and streams 01-03; no locked paths are opened")
    args = parser.parse_args()
    counter_path = ROOT / "eval/locked-run-counter.json"
    run_dir = ROOT / "eval/runs"
    if args.dev_dry_run:
        # The harness is invoked from an isolated scratch checkout; only this
        # checkout's counter is reset for the dry run.
        counter_path.write_text(json.dumps({"phase5_attempts": 0, "phase5_runs_that_wrote_metrics": 0,
                                            "phase5_locked_run_count": 0, "phase5_authorized": True}, indent=2) + "\n")
    guard = check_locked_run(ROOT, counter_path) if counter_path.is_relative_to(ROOT) else {"pass": True}
    if not guard["pass"]:
        raise RuntimeError(f"locked-run guard failed: {guard}")
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    if not args.dev_dry_run and state.get("phase5_authorized") is not True:
        raise RuntimeError("Phase 5 has not been authorized")
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = run_dir / f"final-{stamp}.json"
    attempt = run_dir / f"final-{stamp}-attempts.json"
    start_attempt(counter_path, attempt, stamp)
    reports: dict[str, Any] = {}
    metrics_written = False
    try:
        manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
        variants, definitions = make_variants()
        data_scope = "dev dry run" if args.dev_dry_run else "locked golden test and held-out streams 04-05"
        golden_path = ROOT / "data/golden/dev.jsonl" if args.dev_dry_run else ROOT / "data/golden/test.jsonl"
        stream_ids = manifest["dev_streams"] if args.dev_dry_run else manifest["held_out_streams"]
        test_rows = read_jsonl(golden_path)
        lookalikes = {v: read_jsonl(ROOT / f"eval/fixtures/benign-lookalike-{v}.jsonl") for v in ("v1", "v2")}
        evasion_files = {"v1":"evasion-v1-dev.json", "v2":"evasion-v2-dev.json", "v3":"evasion-v3-dev.json", "v4":"evasion-v4-clean-dev.json"}
        evasion_rows = {k: json.loads((ROOT / "eval/runs" / v).read_text(encoding="utf-8")) for k,v in evasion_files.items()}
        evasion_rows = {k:(v.get("attacks", []) if isinstance(v,dict) else v) for k,v in evasion_rows.items()}
        for name, predict in variants.items():
            neutral = name == "F"
            mode = "status_neutral" if neutral else "standard"
            golden = score_golden(test_rows, predict, mode)
            stream_predict = predict
            held = evaluate_streams(stream_predict, manifest, stream_ids, use_template=(name == "E"))
            reports[name] = {"definition": definitions[name], "golden_test": golden, "held_out_streams": held,
                             "evasion": {k: score_fixture(v, predict) for k,v in evasion_rows.items()},
                             "lookalikes": {k: score_fixture(v, predict) for k,v in lookalikes.items()},
                             "ablation_streams": evaluate_streams(stream_predict, manifest, manifest["dev_streams"], use_template=(name == "E"))}
            if name == "E":
                reports[name]["template_explanations"] = "template explainer called for emitted alerts on stream replays; no Bedrock or local model"
        assessment = assess_targets(reports) if not args.dev_dry_run else None
        created = datetime.now(timezone.utc).isoformat()
        data_paths = (["data/golden/dev.jsonl", "data/streams/manifest.json", *[manifest["streams"][sid]["path"] for sid in manifest["dev_streams"]]] if args.dev_dry_run else
                      ["data/golden/test.jsonl", "data/streams/manifest.json", *[manifest["streams"][sid]["path"] for sid in manifest["held_out_streams"]]])
        data_paths += ["eval/runs/evasion-v1-dev.json", "eval/runs/evasion-v2-dev.json", "eval/runs/evasion-v3-dev.json", "eval/runs/evasion-v4-clean-dev.json",
                      "eval/fixtures/benign-lookalike-v1.jsonl", "eval/fixtures/benign-lookalike-v2.jsonl", "config/authorized_sources.json"]
        config = snapshot(include_phase1_inputs=not args.dev_dry_run)
        head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
        tags = subprocess.run(["git", "tag", "--points-at", "HEAD"], cwd=ROOT, capture_output=True, text=True, check=True).stdout.splitlines()
        config.update({"code_commit_sha": head, "lock_tag": next((t for t in tags if t.startswith("lock-")), None),
                       "detector_file_hashes_sha256": {p: sha(ROOT / p) for p in ("baseline/rules.py", "pipeline/run.py", "gate/gate.py", "explain/template.py", "config/authorized_sources.json")},
                       "allowlist_sha256": sha(ROOT / "config/authorized_sources.json"),
                       "data_hashes_sha256": {p: sha(ROOT / p) for p in data_paths},
                       "run_mode": "dev dry run; variants A-F; template explanations; no Bedrock; no Qwen/Ollama" if args.dev_dry_run else "single locked Phase 5; variants A-F; template explanations; no Bedrock; no Qwen/Ollama"})
        report = {"phase": "5", "created_at": created, "run_id": stamp, "status": "complete", "data_scope": data_scope, "variants": reports,
                  "targets": {"attack_recall": ">=87/96", "benign_false_speaks": "<=6/120", "precision": ">=0.90", "hard_attack_recall": ">=11/14 and >=20 percentage points above baseline", "hard_benign_false_speaks": "<=2/24", "kind_accuracy": ">=0.85", "episode_recall": ">=14/16", "false_alerts": "<=2", "duplicates_per_detected_episode": "<=1.5", "median_time_to_detect_events": "<=40"},
                  "bedrock_metrics": "pending: not part of the locked run", "config_snapshot": config}
        if assessment is not None:
            report["target_assessment"] = assessment["checks"]
            report["misses"] = assessment["misses"]
        with out.open("x", encoding="utf-8") as f:
            json.dump(report, f, indent=2); f.write("\n")
        metrics_written = True
        finish_attempt(counter_path, attempt, metrics_written=True, artifact=str(out))
        fill_readme_table(ROOT / "README.md", report, out.name)
        summary_variants = {}
        for k, v in reports.items():
            g, h = v["golden_test"], v["held_out_streams"]
            summary_variants[k] = {
                "golden_attack_recall_speak": g["attack_recall_speak"],
                "golden_kind_accuracy": g["kind_accuracy_among_spoken_attacks"],
                "golden_matching_kind_recall": g["matching_kind_recall"],
                "golden_simulated_benign_false_speaks": g["simulated_benign_false_speaks"],
                "golden_hard_attack_recall": g["hard_attack_recall"],
                "golden_hard_benign_false_speaks": g["hard_benign_false_speaks"],
                "held_out_episode_recall": h["episode_recall"], "held_out_false_alerts": h["false_alerts"],
                "held_out_duplicates": h["duplicates"], "held_out_median_time_to_detect_events": h["median_time_to_detect_events"],
                "evasion": {fixture: values["false_speaks"] for fixture, values in v["evasion"].items()},
                "lookalikes": {fixture: values["false_speaks"] for fixture, values in v["lookalikes"].items()},
            }
        print(json.dumps({"artifact": str(out), "run_id": stamp, "data_scope": data_scope,
                          "variants": summary_variants,
                          "target_assessment": report.get("target_assessment", "dev only; targets not applied"),
                          "misses": report.get("misses", []),
                          "bedrock_metrics":"pending: not part of the locked run"}, indent=2))
        return 0
    except Exception as exc:
        error = f"{type(exc).__name__}: {exc}"
        finish_attempt(counter_path, attempt, metrics_written=metrics_written or out.exists(), error=error,
                       artifact=str(out) if out.exists() else None)
        raise


if __name__ == "__main__":
    raise SystemExit(main())
