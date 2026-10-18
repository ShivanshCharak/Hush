#!/usr/bin/env python3
"""Build provisional golden windows and a blind second-annotator packet."""

from __future__ import annotations

import argparse
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sim"))
from select_real_windows import event_kinds  # noqa: E402
from simulate import ATTACK_KINDS, generate_window  # noqa: E402

DEFAULT_CONFIG = ROOT / "sim/scenarios.json"
DEFAULT_REAL = ROOT / "data/annotations/real_candidates.jsonl"
DEFAULT_OUTPUT = ROOT / "data/golden"
DEFAULT_REVIEW = ROOT / "data/annotations"
SEED = 20261018
SPLIT_COUNTS = {
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
HARD_BENIGN_VARIANTS = ("typo_then_success", "load_test", "health_check", "search_terms", "authorized_scanner")


def stable_seed(*parts: object) -> int:
    raw = ":".join(str(part) for part in (SEED, *parts)).encode("utf-8")
    return int.from_bytes(hashlib.sha256(raw).digest()[:8], "big")


def read_jsonl(path: Path) -> list[dict[str, object]]:
    return [json.loads(line) for line in path.open(encoding="utf-8") if line.strip()]


def select_ambiguous(
    source_path: Path,
    real_candidates: list[dict[str, object]],
) -> dict[str, list[dict[str, object]]]:
    sessions: dict[str, list[dict[str, object]]] = defaultdict(list)
    for line in source_path.open(encoding="utf-8"):
        event = json.loads(line)
        sessions[str(event["session_id"])].append(event)
    selected_real = {str(c["candidate_id"]) for c in real_candidates}
    day_split: dict[str, str] = {}
    for candidate in real_candidates:
        day_split[str(candidate["session_id"])] = str(candidate["split"])
    result: dict[str, list[dict[str, object]]] = {"dev": [], "test": []}
    for day, events in sessions.items():
        split = day_split.get(day)
        if split is None:
            continue
        for start in range(0, len(events) - 19, 20):
            candidate_id = f"modsec:{day}:{start:06d}"
            if candidate_id in selected_real:
                continue
            window = events[start:start + 20]
            kinds = set().union(*(event_kinds(event) for event in window))
            if len(kinds) == 1:
                continue
            evidence = [
                event["event_id"]
                for event in window
                if event_kinds(event)
            ]
            result[split].append({
                "candidate_id": candidate_id,
                "split": split,
                "session_id": day,
                "events": [{key: event.get(key) for key in (
                    "event_id", "session_id", "timestamp", "src_ip", "event_type", "method", "path",
                    "query", "status", "bytes", "user_agent", "referer",
                )} for event in window],
                "source_provenance": {
                    "source_dataset": "zenodo:17178461",
                    "source_session": day,
                    "first_event_id": window[0]["event_id"],
                    "last_event_id": window[-1]["event_id"],
                    "candidate_evidence_event_ids": evidence,
                },
            })
    return result


def take_round_robin(items: list[dict[str, object]], count: int, seed: int) -> list[dict[str, object]]:
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)
    for item in items:
        grouped[str(item["session_id"])].append(item)
    rng = random.Random(seed)
    days = sorted(grouped)
    rng.shuffle(days)
    for day in days:
        rng.shuffle(grouped[day])
    output = []
    while len(output) < count:
        added = False
        for day in days:
            if grouped[day]:
                output.append(grouped[day].pop())
                added = True
                if len(output) == count:
                    break
        if not added:
            raise ValueError(f"Requested {count} ambiguous windows, found only {len(output)}")
    return output


def record_from_real(candidate: dict[str, object], window_id: str) -> dict[str, object]:
    kind = str(candidate["suggested_kind"])
    return {
        "id": window_id,
        "session_id": candidate["session_id"],
        "split": candidate["split"],
        "label": "speak",
        "kind": kind,
        "hard": bool(candidate["hard"]),
        "events": candidate["events"],
        "evidence_event_ids": candidate["evidence_event_ids"],
        "annotation_evidence": candidate["annotation_evidence"],
        "annotator_votes": {
            "primary": {
                "label": "speak",
                "kind": kind,
                "reviewer": "provisional_tag_screen",
                "basis": "exclusive explicit ModSecurity tag candidate; human confirmation pending",
            },
            "second": None,
        },
        "annotation_status": "provisional_human_review_pending",
        "provenance": candidate["provenance"],
    }


def record_from_ambiguous(candidate: dict[str, object], window_id: str) -> dict[str, object]:
    return {
        "id": window_id,
        "session_id": candidate["session_id"],
        "split": candidate["split"],
        "label": "ambiguous",
        "kind": "ambiguous",
        "hard": False,
        "events": candidate["events"],
        "evidence_event_ids": candidate["source_provenance"]["candidate_evidence_event_ids"],
        "annotator_votes": {
            "primary": {
                "label": "ambiguous",
                "kind": "ambiguous",
                "reviewer": "provisional_tag_screen",
                "basis": "no mapped kind or multiple mapped kinds in the window",
            },
            "second": None,
        },
        "annotation_status": "provisional_human_review_pending",
        "provenance": candidate["source_provenance"],
    }


def build(config_path: Path, real_path: Path, source_path: Path, output_dir: Path, review_dir: Path) -> dict[str, object]:
    config = json.loads(config_path.read_text(encoding="utf-8"))
    real = read_jsonl(real_path)
    ambiguous_pool = select_ambiguous(source_path, real)
    records: dict[str, list[dict[str, object]]] = {"dev": [], "test": []}
    next_synthetic_event = {"dev": 0, "test": 0}
    start_by_split = {
        "dev": datetime(2025, 10, 1, 8, tzinfo=timezone.utc),
        "test": datetime(2025, 10, 2, 8, tzinfo=timezone.utc),
    }

    for split in ("dev", "test"):
        for candidate in [item for item in real if item["split"] == split]:
            records[split].append(record_from_real(candidate, str(candidate["candidate_id"])))
        ambiguous_needed = SPLIT_COUNTS[split]["ambiguous"]
        for candidate in take_round_robin(ambiguous_pool[split], ambiguous_needed, stable_seed(split, "ambiguous")):
            records[split].append(record_from_ambiguous(candidate, str(candidate["candidate_id"])))

    for split in ("dev", "test"):
        for class_name, total in SPLIT_COUNTS[split].items():
            real_count = sum(1 for row in records[split] if row["kind"] == class_name)
            synthetic_needed = total - real_count
            if synthetic_needed < 0:
                raise ValueError(f"Source candidates exceed {split} quota for {class_name}")
            for sample_index in range(synthetic_needed):
                session_id = f"golden-sim-{split}"
                event_id = next_synthetic_event[split]
                next_synthetic_event[split] += 20
                start = start_by_split[split] + timedelta(seconds=event_id / 5)
                variant = "standard"
                hard = False
                label = "speak"
                kind = class_name
                if class_name == "none":
                    label, kind = "silent", "none"
                elif class_name == "hard_benign":
                    label, kind, hard = "silent", "none", True
                    variant = HARD_BENIGN_VARIANTS[sample_index % len(HARD_BENIGN_VARIANTS)]
                elif class_name == "credential_stuffing":
                    global_index = sample_index + (0 if split == "dev" else SPLIT_COUNTS["dev"][class_name])
                    if global_index < 20:
                        variant, hard = "low_slow", True
                window_events = generate_window(
                    kind=class_name,
                    session_id=session_id,
                    start_event_id=event_id,
                    start=start,
                    seed=stable_seed(split, class_name, sample_index),
                    events_per_second=int(config["events_per_second"]),
                    variant=variant,
                )
                records[split].append({
                    "id": f"sim-{split}-{class_name}-{sample_index + 1:04d}",
                    "session_id": session_id,
                    "split": split,
                    "label": label,
                    "kind": kind,
                    "hard": hard,
                    "events": window_events,
                    "evidence_event_ids": [],
                    "annotator_votes": {
                        "primary": {
                            "label": label,
                            "kind": kind,
                            "reviewer": "scenario_oracle",
                            "basis": "known simulator scenario",
                        },
                        "second": None,
                    },
                    "annotation_status": "scenario_ground_truth",
                    "provenance": {
                        "source_dataset": "simulator",
                        "scenario": class_name,
                        "variant": variant,
                        "seed": stable_seed(split, class_name, sample_index),
                    },
                })

    for split in ("dev", "test"):
        random.Random(stable_seed(split, "row-order")).shuffle(records[split])
        output_dir.mkdir(parents=True, exist_ok=True)
        path = output_dir / f"{split}.jsonl"
        if path.exists():
            path.chmod(0o644)
        with path.open("w", encoding="utf-8", newline="\n") as out:
            for row in records[split]:
                out.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")

    # The independent reviewer sees only event payloads and blank response fields.
    dev_rows = records["dev"]
    sample_rng = random.Random(stable_seed("second-annotator-sample"))
    review_selection: list[dict[str, object]] = []
    review_groups = (
        ("benign", [r for r in dev_rows if r["kind"] == "none" and not r["hard"]], 20),
        ("hard_benign", [r for r in dev_rows if r["kind"] == "none" and r["hard"]], 20),
        ("ambiguous", [r for r in dev_rows if r["label"] == "ambiguous"], 20),
    )
    for group_name, group_rows, count in review_groups:
        if len(group_rows) < count:
            raise ValueError(f"Not enough {group_name} windows for second review")
        review_selection.extend(sample_rng.sample(group_rows, count))
    attack_counts = {
        "brute_force": 6,
        "credential_stuffing": 6,
        "sqli": 6,
        "xss": 6,
        "path_traversal": 6,
        "priv_esc": 5,
        "scanner_recon": 5,
    }
    for attack_kind, count in attack_counts.items():
        group_rows = [r for r in dev_rows if r["label"] == "speak" and r["kind"] == attack_kind]
        review_selection.extend(sample_rng.sample(group_rows, count))
    sample_rng.shuffle(review_selection)
    review_dir.mkdir(parents=True, exist_ok=True)
    review_path = review_dir / "second_annotator_template.jsonl"
    with review_path.open("w", encoding="utf-8", newline="\n") as out:
        for index, row in enumerate(review_selection, start=1):
            review = {
                "review_id": f"R{index:03d}",
                "events": row["events"],
                "label": None,
                "kind": None,
                "evidence_event_ids": [],
                "note": "",
            }
            out.write(json.dumps(review, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    key_path = review_dir / "second_annotator_key.json"
    key_path.write_text(json.dumps({
        "seed": stable_seed("second-annotator-sample"),
        "review_count": len(review_selection),
        "review_map": {f"R{index:03d}": row["id"] for index, row in enumerate(review_selection, start=1)},
        "groups": {name: count for name, _, count in review_groups},
        "attack_counts": attack_counts,
        "instruction": "Do not use this key while independently labeling the template.",
    }, indent=2) + "\n", encoding="utf-8")

    summary = {
        "seed": SEED,
        "counts_by_split": {
            split: dict(Counter(str(row["kind"]) for row in rows))
            for split, rows in records.items()
        },
        "real_attack_windows": sum(row["provenance"].get("source_dataset") == "zenodo:17178461" and row["label"] == "speak" for rows in records.values() for row in rows),
        "encoded_sqli_hard_windows": sum(row["kind"] == "sqli" and row["hard"] for rows in records.values() for row in rows),
        "low_slow_stuffing_hard_windows": sum(row["kind"] == "credential_stuffing" and row["hard"] for rows in records.values() for row in rows),
        "review_template": str(review_path),
        "review_template_rows": len(review_selection),
        "status": "provisional_until_second_annotator_review",
    }
    (output_dir / "draft_manifest.json").write_text(json.dumps(summary, indent=2) + "\n", encoding="utf-8")
    return summary


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--real-candidates", type=Path, default=DEFAULT_REAL)
    parser.add_argument("--source", type=Path, default=ROOT / "data/external/modsecurity_events.jsonl")
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    parser.add_argument("--review-dir", type=Path, default=DEFAULT_REVIEW)
    args = parser.parse_args()
    print(json.dumps(build(args.config, args.real_candidates, args.source, args.output_dir, args.review_dir), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
