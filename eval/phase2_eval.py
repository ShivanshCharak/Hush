#!/usr/bin/env python3
"""Evaluate Phase 2 baseline, prefilter, and local Decider on dev data only."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import math
import os
from pathlib import Path
import sys
import time
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from baseline.rules import predict as predict_rules
from decider.decide import InferenceError, MODEL_CONTEXT_TOKENS, OllamaDecider, SCHEMA, validate_decision
from decider.prefilter import keep_event
from decider.prompt import PROMPT_FORMAT_VERSION, SYSTEM_PROMPT
from decider.window import PATTERN_CHECK_VERSION, make_window
from eval.run_metadata import snapshot

CHECKPOINT_PATH = ROOT / "eval/runs/.phase2_checkpoint.json"


def checkpoint_fingerprint(rows: list[dict[str, Any]], model: str) -> str:
    payload = {
        "rows": rows,
        "model": model,
        "system_prompt": SYSTEM_PROMPT,
        "prompt_format_version": PROMPT_FORMAT_VERSION,
        "pattern_check_version": PATTERN_CHECK_VERSION,
        "model_context_tokens": MODEL_CONTEXT_TOKENS,
        "schema": SCHEMA,
    }
    encoded = json.dumps(payload, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()


def load_checkpoint(rows: list[dict[str, Any]], fingerprint: str) -> list[dict[str, Any]]:
    if not CHECKPOINT_PATH.exists():
        return []
    try:
        checkpoint = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
        predictions = checkpoint["predictions"]
        matches = checkpoint.get("fingerprint") == fingerprint and isinstance(predictions, list)
        matches = matches and len(predictions) <= len(rows)
        if matches:
            for row, prediction in zip(rows, predictions):
                if not isinstance(prediction, dict) or prediction.get("id") != row.get("id"):
                    matches = False
                    break
                if not {"schema_repairs", "confidence", "latency_ms"} <= set(prediction):
                    matches = False
                    break
                validate_decision(
                    {key: prediction[key] for key in ("speak", "kind", "evidence_ids")},
                    row["events"],
                )
        if matches:
            return predictions
    except (OSError, AttributeError, KeyError, TypeError, ValueError, json.JSONDecodeError):
        pass
    CHECKPOINT_PATH.unlink(missing_ok=True)
    return []


def save_checkpoint(fingerprint: str, predictions: list[dict[str, Any]]) -> None:
    CHECKPOINT_PATH.parent.mkdir(parents=True, exist_ok=True)
    temporary_path = CHECKPOINT_PATH.with_suffix(".tmp")
    temporary_path.write_text(
        json.dumps({"fingerprint": fingerprint, "predictions": predictions}, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    temporary_path.replace(CHECKPOINT_PATH)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    with path.open(encoding="utf-8") as stream:
        return [json.loads(line) for line in stream if line.strip()]


def ratio(numerator: int, denominator: int) -> float:
    return numerator / denominator if denominator else 0.0


def binary_metrics(rows: list[dict[str, Any]], predictions: list[dict[str, Any]]) -> dict[str, Any]:
    scored = [(row, pred) for row, pred in zip(rows, predictions) if row["label"] in ("speak", "silent")]
    attacks = [(row, pred) for row, pred in scored if row["label"] == "speak"]
    benign = [(row, pred) for row, pred in scored if row["label"] == "silent"]
    tp = sum(bool(pred["speak"]) for _, pred in attacks)
    fp = sum(bool(pred["speak"]) for _, pred in benign)
    predicted_positive = tp + fp
    return {
        "scored_windows": len(scored),
        "attack_recall": {"numerator": tp, "denominator": len(attacks), "value": ratio(tp, len(attacks))},
        "benign_false_speak": {"numerator": fp, "denominator": len(benign), "value": ratio(fp, len(benign))},
        "precision": {"numerator": tp, "denominator": predicted_positive, "value": ratio(tp, predicted_positive)},
        "true_positives": tp,
        "false_positives": fp,
    }


def auroc(labels: list[bool], scores: list[float]) -> float | None:
    positives = [score for label, score in zip(labels, scores) if label]
    negatives = [score for label, score in zip(labels, scores) if not label]
    if not positives or not negatives:
        return None
    wins = sum(1.0 if pos > neg else 0.5 if pos == neg else 0.0 for pos in positives for neg in negatives)
    return wins / (len(positives) * len(negatives))


def prefilter_report() -> dict[str, Any]:
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    stream_results = {}
    total = kept = 0
    episode_results = []
    for stream_id in manifest["dev_streams"]:
        info = manifest["streams"][stream_id]
        events = read_jsonl(ROOT / info["path"])
        kept_ids = {int(event["event_id"]) for event in events if keep_event(event)}
        total += len(events)
        kept += len(kept_ids)
        attacks = [episode for episode in info["episodes"] if not episode["hard_benign"]]
        preserved = 0
        for episode in attacks:
            has_kept = any(index in kept_ids for index in range(int(episode["start_idx"]), int(episode["end_idx"])))
            preserved += has_kept
            episode_results.append({"episode_id": episode["episode_id"], "preserved": has_kept})
        stream_results[stream_id] = {"events": len(events), "kept_events": len(kept_ids), "attack_episodes_preserved": preserved, "attack_episodes": len(attacks)}
    dropped_rate = 1 - ratio(kept, total)
    preserved_count = sum(item["preserved"] for item in episode_results)
    return {
        "events": total,
        "kept_events": kept,
        "dropped_rate": dropped_rate,
        "attack_episodes_preserved": preserved_count,
        "attack_episodes": len(episode_results),
        "stream_results": stream_results,
        "pass": dropped_rate >= 0.90 and preserved_count == len(episode_results) == 24,
    }


def quantile(values: list[float], probability: float) -> float | None:
    if not values:
        return None
    ordered = sorted(values)
    position = (len(ordered) - 1) * probability
    lower = math.floor(position)
    upper = math.ceil(position)
    if lower == upper:
        return ordered[lower]
    return ordered[lower] * (upper - position) + ordered[upper] * (position - lower)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--model", default=None, help="Ollama model name (default: DECIDER_MODEL or qwen3:1.7b)")
    parser.add_argument(
        "--timeout-seconds",
        type=float,
        default=float(os.environ.get("DECIDER_TIMEOUT_SECONDS", "120")),
        help="Per-window Ollama request timeout (default: DECIDER_TIMEOUT_SECONDS or 120)",
    )
    parser.add_argument("--skip-model", action="store_true", help="Record baseline and prefilter only")
    parser.add_argument("--fresh", action="store_true", help="Discard any compatible partial checkpoint and start model inference from the first window")
    args = parser.parse_args()

    rows = read_jsonl(ROOT / "data/golden/dev.jsonl")
    baseline_predictions = [predict_rules(row["events"]) for row in rows]
    baseline_metrics = binary_metrics(rows, baseline_predictions)
    baseline_hard = [
        (row, prediction)
        for row, prediction in zip(rows, baseline_predictions)
        if row["label"] == "speak" and row["hard"]
    ]
    baseline_metrics["hard_attacks"] = {
        "numerator": sum(bool(prediction["speak"]) for _, prediction in baseline_hard),
        "denominator": len(baseline_hard),
        "recall": ratio(sum(bool(prediction["speak"]) for _, prediction in baseline_hard), len(baseline_hard)),
        "spec_target_denominator": 21,
        "dataset_denominator_matches_spec": len(baseline_hard) == 21,
    }
    baseline = {
        "metrics": baseline_metrics,
        "thresholds": {
            "brute_force": "at least 5 failures from one IP, with no matching success in window",
            "credential_stuffing": "at least 4 failures and 4 distinct usernames from one IP",
            "sensitive_path_scan": "at least 3 sensitive-path probes from one IP",
            "generic_scan": "at least 75% 4xx plus 5 distinct paths from one IP",
            "priv_esc": "at least 5 distinct /api/users/{id}/profile paths from one IP",
            "payload_signatures": "decoded SQLi, XSS, or traversal signature",
        },
    }
    prefilter = prefilter_report()

    model_report: dict[str, Any] = {"status": "not_run", "model": args.model or "qwen3:1.7b"}
    model_checks: dict[str, Any] = {}
    if args.skip_model:
        model_report["status"] = "skipped_by_argument"
    else:
        model_name = args.model or "qwen3:1.7b"
        decider = OllamaDecider(model=model_name, timeout=args.timeout_seconds)
        fingerprint = checkpoint_fingerprint(rows, model_name)
        predictions = [] if args.fresh else load_checkpoint(rows, fingerprint)
        resumed_windows = len(predictions)
        if args.fresh:
            CHECKPOINT_PATH.unlink(missing_ok=True)
        model_error = None
        failed_window_id = None
        for index, row in enumerate(rows):
            if index < len(predictions):
                continue
            try:
                output = decider.decide(make_window(row["events"]))
                validate_decision({key: output[key] for key in ("speak", "kind", "evidence_ids")}, row["events"])
                predictions.append({**output, "id": row["id"]})
                save_checkpoint(fingerprint, predictions)
            except (InferenceError, ValueError) as exc:
                model_error = str(exc)
                failed_window_id = row.get("id")
                break
        if model_error:
            model_report.update({"status": "incomplete", "error": model_error, "failed_window_id": failed_window_id, "completed_windows": len(predictions), "requested_windows": len(rows), "resumed_windows": resumed_windows, "checkpoint": str(CHECKPOINT_PATH.relative_to(ROOT)) if predictions else None, "timeout_seconds": args.timeout_seconds})
            for check in ("schema_validity", "attack_recall", "benign_false_speak", "hard_attacks", "hard_benign", "kind_accuracy", "confidence_quality", "latency", "ambiguous_speak_rate"):
                model_checks[check] = {"status": "blocked", "reason": "local model inference did not complete"}
        else:
            latencies = [float(pred["latency_ms"]) for pred in predictions]
            confidence_values = [float(pred["confidence"]) if pred["confidence"] is not None else float("nan") for pred in predictions]
            metrics = binary_metrics(rows, predictions)
            hard_pairs = [(row, pred) for row, pred in zip(rows, predictions) if row["label"] == "speak" and row["hard"]]
            hard_baseline_by_id = {row["id"]: pred for row, pred in zip(rows, baseline_predictions)}
            benign_hard = [(row, pred) for row, pred in zip(rows, predictions) if row["label"] == "silent" and row["hard"]]
            true_positives = [(row, pred) for row, pred in zip(rows, predictions) if row["label"] == "speak" and pred["speak"]]
            kind_correct = sum(row["kind"] == pred["kind"] for row, pred in true_positives)
            ambiguous = [(row, pred) for row, pred in zip(rows, predictions) if row["label"] == "ambiguous"]
            scored_confidence = [
                (row["label"] == "speak", confidence_values[index])
                for index, row in enumerate(rows)
                if row["label"] in ("speak", "silent") and not math.isnan(confidence_values[index])
            ]
            scored_count = sum(row["label"] in ("speak", "silent") for row in rows)
            schema_repair_rows = [
                {"id": row["id"], "repairs": pred["schema_repairs"]}
                for row, pred in zip(rows, predictions)
                if pred.get("schema_repairs")
            ]
            confidence_auc = auroc(
                [label for label, _ in scored_confidence],
                [score for _, score in scored_confidence],
            )
            model_report.update({
                "status": "complete",
                "timeout_seconds": args.timeout_seconds,
                "resumed_windows": resumed_windows,
                "model_calls": sum(bool(pred.get("model_called", True)) for pred in predictions),
                "model_skipped_windows": sum(not bool(pred.get("model_called", True)) for pred in predictions),
                "metrics": metrics,
                "kind_distribution": {
                    kind: sum(pred["kind"] == kind for pred in predictions)
                    for kind in sorted({pred["kind"] for pred in predictions})
                },
                "schema_repairs": schema_repair_rows,
                "window_predictions": [
                    {
                        "id": row["id"],
                        "label": row["label"],
                        "expected_kind": row.get("kind"),
                        "hard": bool(row.get("hard", False)),
                        "speak": pred["speak"],
                        "kind": pred["kind"],
                        "evidence_ids": pred["evidence_ids"],
                        "schema_repairs": pred.get("schema_repairs", []),
                        "confidence": pred["confidence"],
                        "latency_ms": pred["latency_ms"],
                        "model_called": pred.get("model_called", True),
                        "skip_reason": pred.get("skip_reason"),
                        "prompt_eval_count": pred.get("prompt_eval_count"),
                        "prompt_eval_duration_ns": pred.get("prompt_eval_duration_ns"),
                        "speak_token_logprobs": pred.get("speak_token_logprobs"),
                        "model_context_tokens": pred.get("model_context_tokens"),
                        "pattern_checks": make_window(row["events"])["header"]["pattern_checks"],
                        "raw_model_output": pred.get("raw_model_output"),
                    }
                    for row, pred in zip(rows, predictions)
                ],
                "hard_attacks": {"numerator": sum(bool(pred["speak"]) for _, pred in hard_pairs), "denominator": len(hard_pairs)},
                "hard_benign_false_speak": {"numerator": sum(bool(pred["speak"]) for _, pred in benign_hard), "denominator": len(benign_hard)},
                "kind_accuracy": {"numerator": kind_correct, "denominator": len(true_positives), "value": ratio(kind_correct, len(true_positives))},
                "confidence_auroc": confidence_auc,
                "confidence_scored_windows": len(scored_confidence),
                "latency_ms": {"p50": quantile(latencies, 0.50), "p95": quantile(latencies, 0.95), "windows": len(latencies)},
                "model_call_latency_ms": {
                    "p50": quantile([float(pred["latency_ms"]) for pred in predictions if pred.get("model_called", True)], 0.50),
                    "p95": quantile([float(pred["latency_ms"]) for pred in predictions if pred.get("model_called", True)], 0.95),
                    "windows": sum(bool(pred.get("model_called", True)) for pred in predictions),
                },
                "prompt_eval_count": {
                    "p50": quantile([float(pred["prompt_eval_count"]) for pred in predictions if pred.get("prompt_eval_count") is not None], 0.50),
                    "p95": quantile([float(pred["prompt_eval_count"]) for pred in predictions if pred.get("prompt_eval_count") is not None], 0.95),
                    "windows": sum(pred.get("prompt_eval_count") is not None for pred in predictions),
                    "context_tokens": next((pred.get("model_context_tokens") for pred in predictions if pred.get("model_context_tokens") is not None), None),
                },
                "ambiguous_speak_rate": {"numerator": sum(bool(pred["speak"]) for _, pred in ambiguous), "denominator": len(ambiguous)},
            })
            model_checks = {
                "schema_validity": {
                    "status": "pass" if len(predictions) == len(rows) and not schema_repair_rows else "fail",
                    "valid_without_repair": len(predictions) - len(schema_repair_rows),
                    "repaired": len(schema_repair_rows),
                    "total": len(rows),
                },
                "attack_recall": {"status": "pass" if metrics["attack_recall"]["value"] >= 0.85 else "fail", **metrics["attack_recall"]},
                "benign_false_speak": {"status": "pass" if metrics["benign_false_speak"]["value"] <= 0.08 else "fail", **metrics["benign_false_speak"]},
                "hard_attacks": (
                    {
                        "status": "blocked",
                        "reason": f"dev data has {len(hard_pairs)} hard attacks; the locked Phase 2 target is defined on 21",
                        **model_report["hard_attacks"],
                    }
                    if len(hard_pairs) != 21
                    else {
                        "status": "pass" if (
                            sum(bool(pred["speak"]) for _, pred in hard_pairs) >= 14
                            and ratio(sum(bool(pred["speak"]) for _, pred in hard_pairs), len(hard_pairs))
                            - ratio(sum(bool(hard_baseline_by_id[row["id"]]["speak"]) for row, _ in hard_pairs), len(hard_pairs)) >= 0.20
                        ) else "fail",
                        **model_report["hard_attacks"],
                        "baseline_same_windows": sum(bool(hard_baseline_by_id[row["id"]]["speak"]) for row, _ in hard_pairs),
                        "baseline_denominator": len(hard_pairs),
                    }
                ),
                "hard_benign": {"status": "pass" if model_report["hard_benign_false_speak"]["numerator"] <= 5 else "fail", **model_report["hard_benign_false_speak"]},
                "kind_accuracy": {"status": "pass" if model_report["kind_accuracy"]["value"] >= 0.80 else "fail", **model_report["kind_accuracy"]},
                "confidence_quality": {
                    "status": "pass" if confidence_auc is not None and confidence_auc >= 0.93 and len(scored_confidence) == scored_count else "fail",
                    "auroc": confidence_auc,
                    "scored_windows": len(scored_confidence),
                    "required_windows": scored_count,
                },
                "latency": {"status": "pass" if model_report["latency_ms"]["p50"] <= 400 and model_report["latency_ms"]["p95"] <= 1200 else "fail", **model_report["latency_ms"]},
                "ambiguous_speak_rate": {"status": "reported", **model_report["ambiguous_speak_rate"]},
            }

    checks = {
        "baseline_recorded": {"status": "pass", "scored_windows": baseline_metrics["scored_windows"]},
        "prefilter": {"status": "pass" if prefilter["pass"] else "fail", **prefilter},
        **model_checks,
    }
    gate_names = (
        "baseline_recorded",
        "prefilter",
        "schema_validity",
        "attack_recall",
        "benign_false_speak",
        "hard_attacks",
        "hard_benign",
        "kind_accuracy",
        "confidence_quality",
        "latency",
    )
    complete = all(checks.get(name, {}).get("status") == "pass" for name in gate_names)
    report = {
        "phase": 2,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "data_scope": "dev only",
        "input": "data/golden/dev.jsonl and data/streams/stream_01..03.jsonl only",
        "baseline": baseline,
        "prefilter": prefilter,
        "decider": model_report,
        "checks": checks,
        "phase2_complete": complete,
        "notes": [
            "No test windows or held-out streams were read.",
            "The dev data contains 29 hard attack windows; the Phase 2 specification expects 21. Results retain the observed denominator and flag the mismatch.",
        ],
        "config_snapshot": snapshot(model=args.model or "qwen3:1.7b"),
    }
    runs_dir = ROOT / "eval/runs"
    runs_dir.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    run_path = runs_dir / f"phase2-{stamp}.json"
    run_path.write_text(json.dumps(report, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    if model_report.get("status") == "complete":
        CHECKPOINT_PATH.unlink(missing_ok=True)
    print(json.dumps({"run": str(run_path.relative_to(ROOT)), "phase2_complete": complete, "checks": checks, "baseline": baseline_metrics, "decider": model_report}, indent=2))
    return 0 if complete else 1


if __name__ == "__main__":
    raise SystemExit(main())
