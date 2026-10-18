#!/usr/bin/env python3
"""Select session-separated ModSecurity candidate windows for human review."""

from __future__ import annotations

import argparse
from collections import defaultdict
import hashlib
import json
from pathlib import Path
import random
import re

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_INPUT = ROOT / "data/external/modsecurity_events.jsonl"
DEFAULT_OUTPUT = ROOT / "data/annotations/real_candidates.jsonl"
SEED = 20261018
CLASS_QUOTAS = {"sqli": 40, "xss": 20, "path_traversal": 30, "scanner_recon": 30}
SPLIT_QUOTAS = {
    "dev": {"sqli": 24, "xss": 12, "path_traversal": 18, "scanner_recon": 18},
    "test": {"sqli": 16, "xss": 8, "path_traversal": 12, "scanner_recon": 12},
}
SQLI_ENCODED_QUOTA = {"dev": 9, "test": 6}
TAG_RULES = {
    "sqli": ("sql_injection", "attack-sqli"),
    "xss": ("/xss", "attack-xss"),
    "path_traversal": ("/dir_traversal",),
    "scanner_recon": ("security_scanner", "attack-reputation-scanner"),
}


def event_kinds(event: dict[str, object]) -> set[str]:
    tags = {
        str(tag).lower()
        for rule in event.get("modsecurity", {}).get("rules", [])
        for tag in rule.get("tags", [])
    }
    return {
        kind
        for kind, needles in TAG_RULES.items()
        if any(needle in tag for needle in needles for tag in tags)
    }


def project_event(event: dict[str, object]) -> dict[str, object]:
    keys = (
        "event_id",
        "session_id",
        "timestamp",
        "src_ip",
        "method",
        "path",
        "query",
        "status",
        "bytes",
        "user_agent",
        "referer",
    )
    projected = {key: event.get(key) for key in keys}
    projected["event_type"] = "web"
    return projected


def load_candidates(input_path: Path) -> dict[str, list[dict[str, object]]]:
    sessions: dict[str, list[dict[str, object]]] = defaultdict(list)
    for line in input_path.open(encoding="utf-8"):
        event = json.loads(line)
        sessions[str(event["session_id"])].append(event)
    by_day: dict[str, list[dict[str, object]]] = defaultdict(list)
    for session_id, events in sessions.items():
        for start in range(0, len(events) - 19, 20):
            window = events[start:start + 20]
            kinds_by_event = [event_kinds(event) for event in window]
            kinds = set().union(*kinds_by_event)
            if len(kinds) != 1:
                continue
            kind = next(iter(kinds))
            evidence = [
                event
                for event, event_kind_set in zip(window, kinds_by_event)
                if kind in event_kind_set
            ]
            encoded = kind == "sqli" and any(
                re.search(r"%(?:[0-9a-fA-F]{2})", f"{event.get('path') or ''}?{event.get('query') or ''}")
                for event in evidence
            )
            by_day[session_id].append({
                "candidate_id": f"modsec:{session_id}:{start:06d}",
                "session_id": session_id,
                "source_start": start,
                "kind": kind,
                "encoded": encoded,
                "evidence_event_ids": [event["event_id"] for event in evidence],
                "annotation_evidence": [
                    {
                        "event_id": event["event_id"],
                        "rules": [
                            {
                                "id": rule.get("id"),
                                "message": rule.get("message"),
                                "tags": rule.get("tags", []),
                                "matched_data": rule.get("matched_data", []),
                            }
                            for rule in event.get("modsecurity", {}).get("rules", [])
                            if event_kinds({"modsecurity": {"rules": [rule]}})
                        ],
                    }
                    for event in evidence
                ],
                "events": [project_event(event) for event in window],
                "rules": sorted({
                    str(rule.get("id"))
                    for event in evidence
                    for rule in event.get("modsecurity", {}).get("rules", [])
                    if rule.get("id") is not None
                }),
            })
    return by_day


def round_robin(candidates: list[dict[str, object]], count: int, rng: random.Random) -> list[dict[str, object]]:
    by_day: dict[str, list[dict[str, object]]] = defaultdict(list)
    for candidate in candidates:
        by_day[str(candidate["session_id"])].append(candidate)
    for items in by_day.values():
        rng.shuffle(items)
    days = sorted(by_day)
    rng.shuffle(days)
    chosen = []
    while len(chosen) < count:
        progressed = False
        for day in days:
            if by_day[day]:
                chosen.append(by_day[day].pop())
                progressed = True
                if len(chosen) == count:
                    break
        if not progressed:
            raise ValueError(f"Only {len(chosen)} of {count} requested windows were available")
    return chosen


def make_selection(by_day: dict[str, list[dict[str, object]]]) -> tuple[list[dict[str, object]], dict[str, list[str]]]:
    days = sorted(by_day)
    all_candidates = [candidate for candidates in by_day.values() for candidate in candidates]
    rng = random.Random(SEED)
    day_sets: dict[str, list[str]] | None = None
    for _ in range(100_000):
        dev_days = set(rng.sample(days, len(days) // 2))
        test_days = set(days) - dev_days
        split_days = {"dev": dev_days, "test": test_days}
        enough = True
        for split, selected_days in split_days.items():
            for kind, count in SPLIT_QUOTAS[split].items():
                pool = [c for c in all_candidates if c["kind"] == kind and c["session_id"] in selected_days]
                required = SQLI_ENCODED_QUOTA[split] if kind == "sqli" else 0
                if len(pool) < count or sum(bool(c["encoded"]) for c in pool) < required:
                    enough = False
                    break
            if not enough:
                break
        if enough:
            day_sets = {name: sorted(values) for name, values in split_days.items()}
            break
    if day_sets is None:
        raise ValueError("Could not find a 15/15 date split that supports the real-window quotas")

    selected = []
    used_ids: set[str] = set()
    for split in ("dev", "test"):
        selected_days = set(day_sets[split])
        for kind, count in SPLIT_QUOTAS[split].items():
            pool = [c for c in all_candidates if c["kind"] == kind and c["session_id"] in selected_days]
            rng_for_kind = random.Random(SEED + (0 if split == "dev" else 1) + len(kind))
            if kind == "sqli":
                hard_count = SQLI_ENCODED_QUOTA[split]
                chosen = round_robin([c for c in pool if c["encoded"]], hard_count, rng_for_kind)
                chosen_ids = {str(c["candidate_id"]) for c in chosen}
                normal_pool = [
                    c for c in pool
                    if str(c["candidate_id"]) not in chosen_ids and not c["encoded"]
                ]
                chosen.extend(round_robin(normal_pool, count - hard_count, rng_for_kind))
            else:
                chosen = round_robin(pool, count, rng_for_kind)
            for candidate in chosen:
                if candidate["candidate_id"] in used_ids:
                    continue
                used_ids.add(str(candidate["candidate_id"]))
                selected.append({
                    **candidate,
                    "split": split,
                    "suggested_label": "attack",
                    "suggested_kind": kind,
                    "hard": bool(kind == "sqli" and candidate["encoded"]),
                    "review_status": "pending_independent_review",
                    "provenance": {
                        "source_dataset": "zenodo:17178461",
                        "source_session": candidate["session_id"],
                        "first_event_id": candidate["events"][0]["event_id"],
                        "last_event_id": candidate["events"][-1]["event_id"],
                    },
                })
    return sorted(selected, key=lambda item: (str(item["split"]), str(item["candidate_id"]))), day_sets


def write_selection(input_path: Path, output_path: Path) -> dict[str, object]:
    by_day = load_candidates(input_path)
    selected, day_sets = make_selection(by_day)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="\n") as out:
        for candidate in selected:
            out.write(json.dumps(candidate, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    return {
        "input_sha256": hashlib.sha256(input_path.read_bytes()).hexdigest(),
        "candidate_windows": len(selected),
        "counts_by_split_and_kind": {
            split: {
                kind: sum(c["split"] == split and c["suggested_kind"] == kind for c in selected)
                for kind in CLASS_QUOTAS
            }
            for split in ("dev", "test")
        },
        "encoded_sqli": sum(c["suggested_kind"] == "sqli" and c["hard"] for c in selected),
        "day_split": day_sets,
        "output": str(output_path),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--input", type=Path, default=DEFAULT_INPUT)
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    print(json.dumps(write_selection(args.input, args.output), indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
