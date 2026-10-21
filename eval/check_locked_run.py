#!/usr/bin/env python3
"""Fail closed when Phase 5 is locked or any locked run was recorded."""
from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COUNTER = ROOT / "eval/locked-run-counter.json"


def main() -> int:
    state = json.loads(COUNTER.read_text(encoding="utf-8"))
    count = int(state.get("phase5_locked_run_count", -1))
    authorized = state.get("phase5_authorized")
    passed = count == 0 and authorized is False
    report = {"check": "phase5_locked_run_counter", "counter": count,
              "phase5_authorized": authorized, "pass": passed}
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    raise SystemExit(main())
