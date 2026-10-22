#!/usr/bin/env python3
"""Freeze 60 fresh dev-only benign lookalike windows without running a detector."""
from __future__ import annotations

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

SEED = 20261023
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
        return "/catalog/search", f"query=union+of+poets+select+an+edition+{index}", "Search a library catalog for a book with SQL-like vocabulary"
    if category == "apostrophes_in_names":
        name = ("O'Connor", "D'Arcy", "N'Dour", "St. Mary's")[index % 4]
        return "/members/find", f"display_name={quote(name, safe='')}", "Find a member by an ordinary apostrophe-bearing name"
    if category == "html_tags_in_comment_text":
        comment = f"For the help article, display &lt;script&gt;alert('sample {index}')&lt;/script&gt; as quoted text"
        return "/help/comments", f"body={quote(comment, safe='')}", "Comment field discusses escaped example markup as plain text"
    if category == "traversal_looking_document_titles":
        title = f"..%2Fminutes%2F{2018 + index % 8}-approved-copy"
        return "/library/documents/search", f"title={title}", "A document title uses relative-path notation as literal catalog text"
    value = json.dumps({"screen": "account", "theme": "contrast", "pinned": [f"guide-{index}", "meeting-notes"]}, separators=(",", ":"))
    encoded = __import__("base64").urlsafe_b64encode((value + " " + ("reading-setting " * 19)).encode()).decode().rstrip("=")
    return "/account/preferences/import", f"data={encoded}", "A long opaque preference export is uploaded as data"


def build() -> list[dict]:
    rows = []
    start = datetime(2026, 10, 23, 9, tzinfo=timezone.utc)
    for category_index, category in enumerate(CATEGORIES):
        for index in range(COUNT_PER_CATEGORY):
            window_index = category_index * COUNT_PER_CATEGORY + index
            session = f"benign-lookalike-v2-{window_index + 1:03d}"
            rng = random.Random(SEED + window_index)
            path, query, basis = content(category, index)
            events = []
            for offset in range(20):
                event_id = (window_index + 1) * 1000 + offset
                when = (start + timedelta(seconds=window_index * 5 + offset / 5)).isoformat().replace("+00:00", "Z")
                events.append(web_event(event_id, session, when, rng, src_ip=f"198.51.100.{40 + index}",
                                        method="POST" if category == "html_tags_in_comment_text" else "GET",
                                        path=path, query=query, status=200,
                                        user_agent="Mozilla/5.0 Chrome/129.0", referer="https://library.example/"))
            rows.append({
                "id": f"lookalike-v2-{window_index + 1:03d}", "session_id": session,
                "split": "dev", "label": "silent", "kind": "none", "hard": False,
                "events": events, "evidence_event_ids": [],
                "annotator_votes": {"primary": {"label": "silent", "kind": "none", "reviewer": "scenario_oracle", "basis": basis}, "second": None},
                "annotation_status": "scenario_ground_truth",
                "provenance": {"source_dataset": "simulator", "scenario": "benign_lookalike", "variant": category, "seed": SEED + window_index},
            })
    return rows


def main() -> int:
    output = ROOT / "eval/fixtures/benign-lookalike-v2.jsonl"
    rows = build()
    with output.open("w", encoding="utf-8", newline="\n") as stream:
        for row in rows:
            stream.write(json.dumps(row, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
    print(json.dumps({"artifact": str(output.relative_to(ROOT)), "windows": len(rows), "events": sum(len(row["events"]) for row in rows),
                      "categories": {name: sum(row["provenance"]["variant"] == name for row in rows) for name in CATEGORIES},
                      "seed": SEED, "sha256": hashlib.sha256(output.read_bytes()).hexdigest(), "detector_invoked": False}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
