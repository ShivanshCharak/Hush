#!/usr/bin/env python3
"""Build 60 new dev-derived mutations for the evasion-v2 detector challenge."""
from __future__ import annotations

import copy
import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from decider.prompt import FEW_SHOT_EXAMPLES

rows = [json.loads(line) for line in (ROOT / "data/golden/dev.jsonl").read_text().splitlines() if line.strip()]
excluded = {item["id"] for item in FEW_SHOT_EXAMPLES}
attacks = [row for row in rows if row["label"] == "speak" and row["id"] not in excluded]
used: set[str] = set()


def take(kind: str, count: int) -> list[dict]:
    selected = [r for r in sorted(attacks, key=lambda r: r["id"]) if r.get("kind") == kind and r["id"] not in used][:count]
    if len(selected) != count:
        raise RuntimeError(f"not enough unused {kind} sources for {count} mutations")
    used.update(r["id"] for r in selected)
    return selected


out: list[dict] = []

# 20 coordinated attacks spread over ten sources, with 30-minute gaps and
# username rotation. Each window retains the episode's original event shape.
ips = [f"203.0.113.{i}" for i in range(10, 20)]
for index, row in enumerate(take("brute_force", 20), 1):
    events = copy.deepcopy(row["events"])
    base = datetime.fromisoformat(events[0]["timestamp"].replace("Z", "+00:00"))
    for j, event in enumerate(events):
        event["src_ip"] = ips[j % len(ips)]
        event["username"] = f"v2-user-{index:02d}-{j % 5:02d}"
        event["timestamp"] = (base + timedelta(minutes=30 * j)).astimezone(timezone.utc).isoformat().replace("+00:00", "Z")
    out.append({"id": f"evasion-v2-slow-10ip-{index:02d}", "label": "speak", "kind": "brute_force", "hard": True,
                "family": "slow_rate_10ip_30m_rotating_users", "source_dev_id": row["id"], "events": events})

# 20 triple-encoded traversal or SQL probes with mixed separator casing.
sources = take("path_traversal", 10) + take("sqli", 10)
for index, row in enumerate(sources, 1):
    events = copy.deepcopy(row["events"])
    for event in events:
        for field in ("path", "query"):
            value = event.get(field)
            if isinstance(value, str) and value:
                value = value.replace("..", "%252e%252e").replace("/", "%252f").replace("\\", "%255c")
                value = value.replace("%", "%25")
                event[field] = value
    out.append({"id": f"evasion-v2-triple-encode-{index:02d}", "label": "speak", "kind": row["kind"], "hard": True,
                "family": "triple_encoding", "source_dev_id": row["id"], "events": events})

# 20 fresh parser-confusion SQLi/XSS variants: semicolon entities, nested
# comments, tab separators and HTML entity encoded script delimiters.
sources = take("sqli", 10) + take("xss", 10)
for index, row in enumerate(sources, 1):
    events = copy.deepcopy(row["events"])
    for event in events:
        for field in ("path", "query"):
            value = event.get(field)
            if not isinstance(value, str):
                continue
            value = value.replace("UNION SELECT", "UnIoN/**/SeLeCt").replace("union select", "uNiOn/**/sElEcT")
            value = value.replace(" OR ", "%09oR/**/%09").replace(" or ", "%09oR/**/%09")
            value = value.replace("<script", "&lt;script").replace("</script", "&lt;/script")
            value = value.replace("javascript:", "java&#x73;cript&#58;").replace("onerror=", "onerror&#61;")
            event[field] = value
    target = next((event for event in events if event.get("event_type") != "auth"), events[0])
    if row["kind"] == "sqli":
        target["query"] = (str(target.get("query") or "").rstrip("&") + "&" if target.get("query") else "") + "q=1%09oR/**/%091=1"
    else:
        target["query"] = (str(target.get("query") or "").rstrip("&") + "&" if target.get("query") else "") + "q=java&#x73;cript&#58;alert(1)"
    out.append({"id": f"evasion-v2-parser-obfuscation-{index:02d}", "label": "speak", "kind": row["kind"], "hard": True,
                "family": "parser_obfuscation", "source_dev_id": row["id"], "events": events})

assert len(out) == 60 and len(used) == 60
path = ROOT / "eval/runs/evasion-v2-dev.json"
path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print(json.dumps({"artifact": str(path.relative_to(ROOT)), "windows": len(out), "unique_source_dev_ids": len(used),
                  "families": {name: sum(item["family"] == name for item in out) for name in sorted({item["family"] for item in out})}}, indent=2))
