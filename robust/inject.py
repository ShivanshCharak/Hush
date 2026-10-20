#!/usr/bin/env python3
"""Create a deterministic 50-window prompt-injection robustness corpus from dev labels."""
from __future__ import annotations

import argparse
import json
import random
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from baseline.rules import predict as rules_predict
def load_payloads() -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}
    active: str | None = None
    for line in (ROOT / "robust/payloads.yaml").read_text(encoding="utf-8").splitlines():
        if line and not line.startswith(" ") and line.endswith(":"):
            active = line[:-1]
            result[active] = []
        elif active and line.strip().startswith("- "):
            result[active].append(json.loads(line.strip()[2:]))
    if set(result) != {"silence", "page_oncall", "canary"} or any(len(values) != 6 for values in result.values()):
        raise ValueError("payloads.yaml must define six strings for silence, page_oncall, and canary")
    return result


def windows(path: Path) -> list[list[dict]]:
    events = [json.loads(line) for line in path.read_text().splitlines() if line.strip()]
    return [events[index:index + 20] for index in range(0, len(events) - 19, 20)]


def build(seed: int = 20261020) -> list[dict]:
    rng = random.Random(seed)
    payloads = load_payloads()
    labeled = [json.loads(line) for line in (ROOT / "data/golden/dev.jsonl").read_text().splitlines() if line.strip()]
    attacks = [row for row in labeled if row.get("label") == "speak" and rules_predict(row.get("events", [])).get("speak")]
    benign = [row for row in labeled if row.get("label") == "silent" and not rules_predict(row.get("events", [])).get("speak")]
    if len(attacks) < 30 or len(benign) < 20:
        raise ValueError("dev labels do not contain the required 30 attack and 20 benign windows")
    selected = [("attack", row) for row in rng.sample(attacks, 30)] + [("benign", row) for row in rng.sample(benign, 20)]
    result = []
    for index, (class_name, row) in enumerate(selected):
        kind = "silence" if class_name == "attack" else "page_oncall"
        payload = payloads[kind][index % len(payloads[kind])]
        events = row.get("events", row.get("window", {}).get("events", []))
        if not events:
            raise ValueError("unrecognized dev window schema")
        injected = [dict(event) for event in events]
        field = ("user_agent", "query", "referer")[index % 3]
        event = injected[index % len(injected)]
        event[field] = f"{event.get(field) or ''} {payload}".strip()
        result.append({"case_id": f"injected-{index + 1:02d}", "class": class_name,
                       "payload_family": kind, "source_window": row.get("id"),
                       "selection_basis": "transparent baseline outcome before injection", "events": injected})
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path, default=ROOT / "robust/injected_windows.jsonl")
    parser.add_argument("--seed", type=int, default=20261020)
    args = parser.parse_args()
    cases = build(args.seed)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text("".join(json.dumps(case, separators=(",", ":")) + "\n" for case in cases))
    print(json.dumps({"cases": len(cases), "attacks": sum(c["class"] == "attack" for c in cases),
                      "benign": sum(c["class"] == "benign" for c in cases), "output": str(args.output)}))


if __name__ == "__main__":
    main()
