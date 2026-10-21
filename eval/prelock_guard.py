#!/usr/bin/env python3
"""Pre-lock checks without opening locked dataset contents."""
from __future__ import annotations

import json
from pathlib import Path
import subprocess

ROOT = Path(__file__).resolve().parents[1]
LOCKED = ("data/golden/test.jsonl", "data/streams/stream_04.jsonl", "data/streams/stream_05.jsonl")
PHASE1 = ROOT / "eval/runs/phase1-20261021T062137Z.json"
COUNTER = ROOT / "eval/locked-run-counter.json"
VERSION = ROOT / "data/VERSION"
ALLOWED_UNTRACKED = {"trial.rs"}


def git(*args: str) -> str:
    return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()


def main() -> int:
    checks: dict[str, object] = {}
    counter = json.loads(COUNTER.read_text(encoding="utf-8"))
    checks["counter_zero_and_locked"] = counter.get("phase5_locked_run_count") == 0 and counter.get("phase5_authorized") is False
    head = git("rev-parse", "HEAD")
    tags = [line.split()[0] for line in git("tag", "--list", "lock-*").splitlines() if line.strip()]
    checks["lock_tag_at_head"] = any(git("rev-list", "-n", "1", tag) == head for tag in tags)
    porcelain = git("status", "--porcelain", "--untracked-files=all").splitlines()
    unexpected = [line for line in porcelain if not (line.startswith("?? ") and line[3:] in ALLOWED_UNTRACKED)]
    checks["tracked_tree_clean_except_allowlisted_untracked"] = not unexpected
    checks["allowed_untracked"] = [line[3:] for line in porcelain if line.startswith("?? ")]

    version_hashes = {}
    for line in VERSION.read_text(encoding="utf-8").splitlines():
        digest, path = line.split("  ", 1)
        version_hashes[path] = digest
    report = json.loads(PHASE1.read_text(encoding="utf-8"))
    recorded_hashes = report.get("config_snapshot", {}).get("data_hashes_sha256", {})
    lock_check = next((item for item in report.get("checks", []) if item.get("name") == "check_lock"), {})
    matching = {path: version_hashes.get(path) == recorded_hashes.get(path) for path in LOCKED}
    checks["phase1_lock_check_passed"] = lock_check.get("pass") is True
    checks["recorded_hashes_match_VERSION"] = all(matching.values())
    checks["recorded_hash_match_by_path"] = matching
    checks["locked_modes_read_only"] = all((ROOT / path).stat().st_mode & 0o222 == 0 for path in LOCKED)
    checks["hash_check_method"] = "cross-checked committed Phase 1 recorded SHA-256 values against data/VERSION; locked file contents were not opened"
    result = {"head": head, "lock_tags": tags, "checks": checks,
              "pass": all(value for key, value in checks.items() if key not in ("allowed_untracked", "recorded_hash_match_by_path", "hash_check_method"))}
    print(json.dumps(result, indent=2))
    return 0 if result["pass"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
