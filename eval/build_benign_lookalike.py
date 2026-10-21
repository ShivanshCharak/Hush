#!/usr/bin/env python3
"""Build the frozen benign-lookalike-v1 dev fixture; does not invoke rules."""
from __future__ import annotations

import base64
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import sys
from urllib.parse import quote

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sim"))
from simulate import web_event

SEED = 20261022
CATEGORIES = (
    "sql_keywords_in_search",
    "apostrophes_in_names",
    "html_tags_in_comment_text",
    "traversal_looking_document_titles",
    "long_encoded_parameters",
)
COUNT_PER_CATEGORY = 12


def content(category: str, index: int) -> tuple[str, str, str]:
    if category == "sql_keywords_in_search":
        return "/search", f"q=select+union+jack+books+where+to+find+local+history+{index}", "Search for a book title containing database vocabulary"
    if category == "apostrophes_in_names":
        name = ("O'Reilly", "D'Angelo", "L'Enfant", "St. John's")[index % 4]
        return "/directory/search", f"name={quote(name, safe='')}", "Search a people directory by a legitimate surname"
    if category == "html_tags_in_comment_text":
        comment = f"Example markup: &lt;script&gt;alert('ticket {index}')&lt;/script&gt; is shown as text"
        return "/support/tickets", f"comment={quote(comment, safe='')}", "Ticket comment quotes escaped code as literal documentation"
    if category == "traversal_looking_document_titles":
        title = f"..%2Fannual-reports%2F{2020 + index % 7}-summary"
        return "/documents/search", f"title={title}", "A catalog title includes a relative-path notation as ordinary text"
    benign_json = json.dumps({"view": "preferences", "theme": "light", "recent": [f"report-{index}", "annual-summary"]}, separators=(",", ":"))
    encoded = base64.urlsafe_b64encode((benign_json + " " + ("display-preference " * 18)).encode()).decode().rstrip("=")
    return "/settings/import", f"payload={encoded}", "An opaque encoded preferences export is carried as data"


def build() -> list[dict]:
    rows = []
    start = datetime(2026, 10, 22, 9, tzinfo=timezone.utc)
    for category_index, category in enumerate(CATEGORIES):
        for index in range(COUNT_PER_CATEGORY):
            window_index = category_index * COUNT_PER_CATEGORY + index
            session = f"benign-lookalike-v1-{window_index + 1:03d}"
            rng = random.Random(SEED + window_index)
            path, query, context = content(category, index)
            events = []
            for offset in range(20):
                event_id = (window_index + 1) * 1000 + offset
                when = (start + timedelta(seconds=window_index * 5 + offset / 5)).isoformat().replace("+00:00", "Z")
                event = web_event(event_id, session, when, rng, src_ip=f"198.51.100.{20 + index}",
                                  method="GET" if category != "html_tags_in_comment_text" else "POST",
                                  path=path, query=query, status=200,
                                  user_agent="Mozilla/5.0 Chrome/128.0", referer="https://portal.example/")
                if category == "html_tags_in_comment_text":
                    event["method"] = "POST"
                events.append(event)
            rows.append({
                "id": f"lookalike-v1-{window_index + 1:03d}",
                "session_id": session,
                "split": "dev",
                "label": "silent",
                "kind": "none",
                "hard": False,
                "events": events,
                "evidence_event_ids": [],
                "annotator_votes": {"primary": {"label": "silent", "kind": "none", "reviewer": "scenario_oracle", "basis": context}, "second": None},
                "annotation_status": "scenario_ground_truth",
                "provenance": {"source_dataset": "simulator", "scenario": "benign_lookalike", "variant": category, "seed": SEED + window_index},
            })
    return rows


def main() -> int:
    output = ROOT / "eval/fixtures/benign-lookalike-v1.jsonl"
    output.parent.mkdir(parents=True, exist_ok=True)
    rows = build()
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    digest = hashlib.sha256(output.read_bytes()).hexdigest()
    print(json.dumps({"artifact": str(output.relative_to(ROOT)), "windows": len(rows),
                      "events": sum(len(row["events"]) for row in rows), "categories": {name: sum(row["provenance"]["variant"] == name for row in rows) for name in CATEGORIES},
                      "sha256": digest, "rules_invoked": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
