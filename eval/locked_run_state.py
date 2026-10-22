#!/usr/bin/env python3
"""Maintain the Phase 5 attempt/metrics ledger from attempt artifacts."""
from __future__ import annotations

import argparse
import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_COUNTER = ROOT / "eval/locked-run-counter.json"


def reconcile(counter_path: Path, runs_dir: Path) -> dict:
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    files = sorted(runs_dir.glob("final-*-attempts.json"))
    attempts = 0
    metrics_runs = 0
    for path in files:
        entry = json.loads(path.read_text(encoding="utf-8"))
        for attempt in entry.get("attempts", []):
            attempts += 1
            metrics_runs += int(bool(attempt.get("metrics_written")))
    state["phase5_attempts"] = attempts
    state["phase5_runs_that_wrote_metrics"] = metrics_runs
    # Preserve the legacy key as a compatibility alias for runs that wrote metrics.
    state["phase5_locked_run_count"] = metrics_runs
    state["note"] = "Attempt count is independent of completed metric-writing runs; reconciled from final attempt logs."
    counter_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def start_attempt(counter_path: Path, attempt_path: Path, run_id: str) -> dict:
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    if state.get("phase5_authorized") is not True:
        raise RuntimeError("Phase 5 has not been authorized")
    if int(state.get("phase5_runs_that_wrote_metrics", state.get("phase5_locked_run_count", -1))) != 0:
        raise RuntimeError("a Phase 5 run has already written metrics")
    if attempt_path.exists():
        raise FileExistsError(f"refusing to overwrite {attempt_path}")
    entry = {"phase": "5", "run_id": run_id, "status": "running",
             "attempts": [{"attempt": 1, "status": "started", "error": None, "metrics_written": False}]}
    attempt_path.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
    state["phase5_attempts"] = int(state.get("phase5_attempts", 0)) + 1
    counter_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return entry


def finish_attempt(counter_path: Path, attempt_path: Path, *, metrics_written: bool, error: str | None = None,
                   artifact: str | None = None) -> dict:
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    entry = json.loads(attempt_path.read_text(encoding="utf-8"))
    attempt = entry["attempts"][-1]
    attempt["status"] = "complete" if metrics_written else "crashed"
    attempt["error"] = error
    attempt["metrics_written"] = bool(metrics_written)
    if artifact:
        attempt["artifact"] = artifact
    entry["status"] = attempt["status"]
    attempt_path.write_text(json.dumps(entry, indent=2) + "\n", encoding="utf-8")
    runs = int(state.get("phase5_runs_that_wrote_metrics", state.get("phase5_locked_run_count", 0)))
    if metrics_written:
        runs += 1
    state["phase5_runs_that_wrote_metrics"] = runs
    state["phase5_locked_run_count"] = runs
    counter_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return entry


def authorize(counter_path: Path) -> dict:
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    if int(state.get("phase5_runs_that_wrote_metrics", state.get("phase5_locked_run_count", -1))) != 0:
        raise RuntimeError("cannot authorize after a run has written metrics")
    state["phase5_authorized"] = True
    state["note"] = "Phase 5 run authorized by explicit user instruction; attempts and metric-writing runs are tracked separately."
    counter_path.write_text(json.dumps(state, indent=2) + "\n", encoding="utf-8")
    return state


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("action", choices=("reconcile", "authorize"))
    parser.add_argument("--counter", type=Path, default=DEFAULT_COUNTER)
    parser.add_argument("--runs-dir", type=Path, default=ROOT / "eval/runs")
    args = parser.parse_args()
    result = reconcile(args.counter, args.runs_dir) if args.action == "reconcile" else authorize(args.counter)
    print(json.dumps(result, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
