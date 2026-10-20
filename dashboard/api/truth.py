"""Read-only episode overlay data for explicitly enabled demo mode."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]


def episodes(stream_id: str) -> list[dict]:
    if stream_id not in {"stream_01", "stream_02", "stream_03"}:
        raise ValueError("truth overlay is available only for dev streams")
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    return [dict(row) for row in manifest["streams"][stream_id]["episodes"]]
