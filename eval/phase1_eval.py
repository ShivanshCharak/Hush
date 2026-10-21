#!/usr/bin/env python3
"""Evaluate the Phase 1 data, split, replay, and annotation gates."""

from __future__ import annotations

import argparse
from collections import Counter
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from eval.run_metadata import snapshot
EXPECTED = {
    "dev": {
        "none": 144,
        "hard_benign": 36,
        "brute_force": 24,
        "credential_stuffing": 24,
        "sqli": 24,
        "xss": 18,
        "path_traversal": 18,
        "priv_esc": 18,
        "scanner_recon": 18,
        "ambiguous": 36,
    },
    "test": {
        "none": 96,
        "hard_benign": 24,
        "brute_force": 16,
        "credential_stuffing": 16,
        "sqli": 16,
        "xss": 12,
        "path_traversal": 12,
        "priv_esc": 12,
        "scanner_recon": 12,
        "ambiguous": 24,
    },
}


def load_jsonl(path: Path) -> list[dict[str, object]]:
    rows = []
    with path.open(encoding="utf-8") as stream:
        for line_number, line in enumerate(stream, start=1):
            if not line.strip():
                raise ValueError(f"blank line in {path}:{line_number}")
            rows.append(json.loads(line))
    return rows


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def expected_kind(row: dict[str, object]) -> str:
    if row["label"] == "ambiguous":
        return "ambiguous"
    if row["hard"] and row["kind"] == "none":
        return "hard_benign"
    return str(row["kind"])


def check_counts() -> tuple[bool, dict[str, object]]:
    detail = {}
    ok = True
    for split in ("dev", "test"):
        path = ROOT / f"data/golden/{split}.jsonl"
        rows = load_jsonl(path)
        actual = Counter(expected_kind(row) for row in rows)
        expected = Counter(EXPECTED[split])
        split_ok = len(rows) == sum(expected.values()) and actual == expected
        ok &= split_ok
        detail[split] = {"rows": len(rows), "counts": dict(actual), "pass": split_ok}
    return ok, detail


def check_session_leakage() -> tuple[bool, dict[str, object]]:
    dev = {str(row["session_id"]) for row in load_jsonl(ROOT / "data/golden/dev.jsonl")}
    test = {str(row["session_id"]) for row in load_jsonl(ROOT / "data/golden/test.jsonl")}
    overlap = sorted(dev & test)
    return not overlap, {"shared_sessions": overlap, "pass": not overlap}


def check_real_share() -> tuple[bool, dict[str, object]]:
    rows = load_jsonl(ROOT / "data/golden/dev.jsonl") + load_jsonl(ROOT / "data/golden/test.jsonl")
    attacks = [row for row in rows if row["label"] == "speak"]
    real = [row for row in attacks if row.get("provenance", {}).get("source_dataset") == "zenodo:17178461"]
    ok = len(attacks) == 240 and len(real) >= 120
    return ok, {"real_attack_windows": len(real), "attack_windows": len(attacks), "pass": ok}


def check_annotation() -> tuple[bool, dict[str, object]]:
    template = ROOT / "data/annotations/second_annotator_filled.jsonl"
    key_path = ROOT / "data/annotations/second_annotator_key.json"
    if not template.exists() or not key_path.exists():
        return False, {"reason": "second annotator file is not filled", "pass": False}
    submitted = load_jsonl(template)
    key = json.loads(key_path.read_text(encoding="utf-8"))
    expected_rows = key["review_map"]
    if len(submitted) != 100 or len({row.get("review_id") for row in submitted}) != 100:
        return False, {"reason": "expected 100 unique review IDs", "rows": len(submitted), "pass": False}
    if {row["review_id"] for row in submitted} != set(expected_rows):
        return False, {"reason": "review IDs do not match the blind sample", "pass": False}
    gold_rows = {
        row["id"]: row
        for split in ("dev", "test")
        for row in load_jsonl(ROOT / f"data/golden/{split}.jsonl")
    }
    submitted_by_id = {row["review_id"]: row for row in submitted}
    y_primary, y_second = [], []
    incomplete = []
    for review_id, window_id in expected_rows.items():
        answer = submitted_by_id[review_id]
        label = answer.get("label")
        kind = answer.get("kind")
        if label not in ("speak", "silent", "ambiguous") or kind not in (*ATTACK_KINDS, "none", "ambiguous"):
            incomplete.append(review_id)
            continue
        primary = gold_rows[window_id]["label"]
        if primary in ("speak", "silent") and label in ("speak", "silent"):
            y_primary.append(primary)
            y_second.append(label)
    if incomplete:
        return False, {"reason": "some labels or kinds are blank/invalid", "incomplete_review_ids": incomplete, "pass": False}
    if len(y_primary) < 60:
        return False, {"reason": "fewer than 60 non-ambiguous pairs", "eligible_pairs": len(y_primary), "pass": False}
    observed = sum(a == b for a, b in zip(y_primary, y_second)) / len(y_primary)
    primary_counts = Counter(y_primary)
    second_counts = Counter(y_second)
    expected_agreement = sum(primary_counts[label] * second_counts[label] for label in ("speak", "silent")) / (len(y_primary) ** 2)
    kappa = 1.0 if expected_agreement == 1.0 and observed == 1.0 else (observed - expected_agreement) / (1 - expected_agreement)
    ok = kappa >= 0.70
    return ok, {"eligible_pairs": len(y_primary), "cohen_kappa": round(kappa, 4), "pass": ok}


def check_streams() -> tuple[bool, dict[str, object]]:
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    attack_counts = Counter()
    issues = []
    total_episodes = total_hard_benign = 0
    for stream_id, info in manifest["streams"].items():
        events = load_jsonl(ROOT / info["path"])
        episodes = info["episodes"]
        attacks = [episode for episode in episodes if not episode["hard_benign"]]
        hard_benign = [episode for episode in episodes if episode["hard_benign"]]
        total_episodes += len(attacks)
        total_hard_benign += len(hard_benign)
        attack_counts.update(str(episode["kind"]) for episode in attacks)
        if len(events) != 10_000 or len(attacks) != 8 or len(hard_benign) != 3:
            issues.append(stream_id)
    kinds_ok = all(attack_counts[kind] >= 4 for kind in ATTACK_KINDS)
    ok = len(manifest["streams"]) == 5 and total_episodes == 40 and total_hard_benign == 15 and kinds_ok and not issues
    return ok, {"stream_count": len(manifest["streams"]), "attack_episodes": total_episodes, "hard_benign_episodes": total_hard_benign, "attack_kinds": dict(attack_counts), "invalid_streams": issues, "pass": ok}


ATTACK_KINDS = ("brute_force", "credential_stuffing", "sqli", "xss", "path_traversal", "priv_esc", "scanner_recon")


def check_parse_validity() -> tuple[bool, dict[str, object]]:
    files = [ROOT / f"data/golden/{split}.jsonl" for split in ("dev", "test")]
    files.extend(ROOT / f"data/streams/stream_{i:02d}.jsonl" for i in range(1, 6))
    rows = 0
    for path in files:
        rows += len(load_jsonl(path))
    errors_path = ROOT / "data/external/modsecurity_events.errors.jsonl"
    errors = sum(1 for line in errors_path.open(encoding="utf-8") if line.strip())
    ok = errors == 0
    return ok, {"jsonl_rows_checked": rows, "modsecurity_parse_errors": errors, "pass": ok}


def check_determinism() -> tuple[bool, dict[str, object]]:
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    config = ROOT / "sim/scenarios.json"
    with tempfile.TemporaryDirectory(prefix="phase1-replay-") as temporary:
        subprocess.run(
            [sys.executable, str(ROOT / "sim/build_streams.py"), "--config", str(config), "--output-dir", temporary],
            check=True,
            capture_output=True,
            text=True,
        )
        matching = all(
            sha256(Path(temporary) / f"{stream_id}.jsonl") == info["sha256"]
            for stream_id, info in manifest["streams"].items()
        )
    return matching, {"replay_hashes_match": matching, "pass": matching}


def check_lock() -> tuple[bool, dict[str, object]]:
    version = ROOT / "data/VERSION"
    if not version.exists():
        return False, {"reason": "data/VERSION missing", "pass": False}
    entries = {}
    for line in version.read_text(encoding="utf-8").splitlines():
        digest, path = line.split("  ", 1)
        entries[path] = digest
    locked = ["data/golden/test.jsonl", "data/streams/stream_04.jsonl", "data/streams/stream_05.jsonl"]
    errors = []
    for rel_path in locked:
        path = ROOT / rel_path
        if rel_path not in entries or not path.exists() or entries.get(rel_path) != sha256(path):
            errors.append(f"hash missing or changed: {rel_path}")
        if path.exists() and path.stat().st_mode & 0o222:
            errors.append(f"write permission remains: {rel_path}")
    return not errors, {"locked_files": locked, "issues": errors, "pass": not errors}


def main() -> int:
    checks = [
        check_counts,
        check_session_leakage,
        check_real_share,
        check_annotation,
        check_streams,
        check_parse_validity,
        check_determinism,
        check_lock,
    ]
    results = []
    for index, check in enumerate(checks, start=1):
        try:
            passed, detail = check()
        except Exception as exc:
            passed, detail = False, {"error": f"{type(exc).__name__}: {exc}", "pass": False}
        results.append({"check": index, "name": check.__name__, **detail, "pass": passed})
    report = {"phase": "1", "created_at": datetime.now(timezone.utc).isoformat(),
              "data_scope": "Phase 1 integrity checks; includes locked test/held-out hashes",
              "passed": sum(bool(item["pass"]) for item in results), "total": len(results),
              "phase1_complete": all(item["pass"] for item in results), "checks": results,
              "config_snapshot": snapshot(include_phase1_inputs=True)}
    out = ROOT / "eval/runs" / f"phase1-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"artifact": str(out.relative_to(ROOT)), **report}, indent=2))
    return 0 if report["phase1_complete"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
