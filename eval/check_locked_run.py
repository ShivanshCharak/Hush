#!/usr/bin/env python3
"""Fail closed on prior metrics or worktree changes outside the run ledger."""
from __future__ import annotations

import argparse
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def check(root: Path, counter_path: Path) -> dict:
    root = root.resolve()
    counter_path = counter_path.resolve()
    try:
        counter_rel = counter_path.relative_to(root).as_posix()
    except ValueError as exc:
        raise ValueError("counter must live inside the checked repository") from exc
    state = json.loads(counter_path.read_text(encoding="utf-8"))
    attempts = int(state.get("phase5_attempts", 0))
    metrics_runs = state.get("phase5_runs_that_wrote_metrics")
    if metrics_runs is None:
        metrics_runs = state.get("phase5_locked_run_count", -1)
    metrics_runs = int(metrics_runs)
    status = subprocess.run(["git", "status", "--porcelain", "--untracked-files=all"], cwd=root,
                            capture_output=True, text=True, check=True).stdout.splitlines()
    unexpected = []
    allowed = []
    for line in status:
        path = line[3:]
        is_counter = path == counter_rel
        is_attempt = (path.startswith("eval/runs/final-") and path.endswith("-attempts.json")
                      and "/" not in path[len("eval/runs/"):])
        (allowed if is_counter or is_attempt else unexpected).append(path)
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=root, capture_output=True, text=True, check=True).stdout.strip()
    tags = subprocess.run(["git", "tag", "--list", "lock-*"], cwd=root, capture_output=True, text=True, check=True).stdout.splitlines()
    tagged_at_head = any(subprocess.run(["git", "rev-list", "-n", "1", tag], cwd=root, capture_output=True,
                                         text=True, check=True).stdout.strip() == head for tag in tags)
    result = {"check": "phase5_locked_run_guard", "attempts_recorded": attempts,
              "runs_that_wrote_metrics": metrics_runs, "runs_that_wrote_metrics_zero": metrics_runs == 0,
              "lock_tag_at_head": tagged_at_head, "allowed_changed_paths": allowed,
              "unexpected_changed_paths": unexpected, "worktree_changes_limited_to_run_ledger": not unexpected}
    result["pass"] = metrics_runs == 0 and tagged_at_head and not unexpected
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    parser.add_argument("--counter", type=Path, default=ROOT / "eval/locked-run-counter.json")
    args = parser.parse_args()
    report = check(args.root, args.counter)
    print(json.dumps(report, indent=2))
    return 0 if report["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
