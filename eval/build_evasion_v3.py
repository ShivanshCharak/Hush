#!/usr/bin/env python3
"""Freeze 60 new, deterministic dev-only evasion mutations; performs no scoring."""
from __future__ import annotations

import copy
import hashlib
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from decider.prompt import FEW_SHOT_EXAMPLES

DEV_PATH = ROOT / "data/golden/dev.jsonl"
rows = [json.loads(line) for line in DEV_PATH.read_text(encoding="utf-8").splitlines() if line.strip()]
fewshot_ids = {row["id"] for row in FEW_SHOT_EXAMPLES}
attacks = [row for row in rows if row["label"] == "speak" and row["id"] not in fewshot_ids]
used: set[str] = set()


def take(kinds: tuple[str, ...], count: int) -> list[dict]:
    selected = [row for row in sorted(attacks, key=lambda row: row["id"])
                if row.get("kind") in kinds and row["id"] not in used][:count]
    if len(selected) != count:
        raise RuntimeError(f"not enough unused source attacks for {kinds}: wanted {count}, got {len(selected)}")
    used.update(row["id"] for row in selected)
    return selected


out: list[dict] = []
source_ips = [f"203.0.113.{octet}" for octet in range(10, 30)]
spacing_plan = [15] * 7 + [30] * 7 + [45] * 6
slow_sources = take(("brute_force",), 20)
for index, (row, spacing) in enumerate(zip(slow_sources, spacing_plan), 1):
    events = copy.deepcopy(row["events"])
    base = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
    for attempt, event in enumerate(events):
        event["event_type"] = "auth"
        event["result"] = "fail"
        event["status"] = 401
        event["src_ip"] = source_ips[attempt % len(source_ips)]
        # The account rotates on every attempt. Repeated accounts therefore
        # recur from distinct sources at a spacing-dependent interval.
        event["username"] = f"v3-user-{index:02d}-{attempt % 2}"
        event["timestamp"] = (base + timedelta(minutes=spacing * attempt)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    out.append({"id": f"evasion-v3-slow-{spacing:02d}m-{index:02d}", "label": "speak", "kind": "brute_force", "hard": True,
                "family": f"slow_rate_{spacing}m_rotating_usernames_20ip", "spacing_minutes": spacing,
                "source_dev_id": row["id"], "events": events})

# New payload encodings not covered by URL-decoding alone: HTML entities and
# literal JSON-style Unicode escapes in request parameters.
encoding_sources = take(("sqli",), 10) + take(("xss", "path_traversal"), 10)
for index, row in enumerate(encoding_sources, 1):
    events = copy.deepcopy(row["events"])
    target = next((event for event in events if event.get("event_type") != "auth"), events[0])
    if index % 2:
        variant = "html_entity"
        target["query"] = "probe=&#x27; OR &#49;=&#49; --&payload=&lt;svg/onload&#x3d;alert(1)&gt;"
        target["path"] = str(target.get("path") or "/") + "/%26%23x2e%3B"
    else:
        variant = "unicode_escape"
        target["query"] = r"probe=\u0027%20OR%20\u0031=\u0031--&payload=\u003csvg/onload=alert(1)\u003e"
        target["path"] = str(target.get("path") or "/") + r"/\u002e\u002e/"
    out.append({"id": f"evasion-v3-encoding-{index:02d}", "label": "speak", "kind": row["kind"], "hard": True,
                "family": f"encoding_{variant}", "source_dev_id": row["id"], "events": events})

# Parser-confusion variants use comments inside SQL keywords and path segment
# parameters/separator ambiguity, distinct from v1/v2's comment separators.
parser_sources = take(("sqli",), 10) + take(("path_traversal",), 10)
for index, row in enumerate(parser_sources, 1):
    events = copy.deepcopy(row["events"])
    target = next((event for event in events if event.get("event_type") != "auth"), events[0])
    if row["kind"] == "sqli":
        target["query"] = "id=1%20UN/**/ION%20SE/**/LECT%20NULL%20--&q=1%3BWAITFOR%20DELAY%20'0:0:1'"
        family = "parser_sql_keyword_splitting"
    else:
        target["path"] = "/api/files/..;/%2f..%3b/%2fetc/passwd"
        target["query"] = "download=1;path=..%3b%2f..%3b%2fetc/passwd"
        family = "parser_path_separator_confusion"
    out.append({"id": f"evasion-v3-parser-{index:02d}", "label": "speak", "kind": row["kind"], "hard": True,
                "family": family, "source_dev_id": row["id"], "events": events})

assert len(out) == 60 and len(used) == 60
assert all(len(item["events"]) == 20 for item in out)
assert {spacing: spacing_plan.count(spacing) for spacing in (15, 30, 45)} == {15: 7, 30: 7, 45: 6}
source_hash = hashlib.sha256(DEV_PATH.read_bytes()).hexdigest()
for index, item in enumerate(out):
    item["mutation_seed"] = 20261021
    item["data_source_sha256"] = source_hash
    item["mutation_index"] = index

path = ROOT / "eval/runs/evasion-v3-dev.json"
path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n", encoding="utf-8")
print(json.dumps({"artifact": str(path.relative_to(ROOT)), "windows": len(out), "source_windows": len(used),
                  "spacing_counts": {str(spacing): spacing_plan.count(spacing) for spacing in (15, 30, 45)},
                  "families": {family: sum(item["family"] == family for item in out)
                               for family in sorted({item["family"] for item in out})},
                  "source_dev_sha256": source_hash, "detector_scoring_performed": False}, indent=2))
