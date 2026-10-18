#!/usr/bin/env python3
"""Build deterministic replay streams and their episode manifest."""

from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import json
from pathlib import Path
import random
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "sim"))
from simulate import ATTACK_KINDS, event_time, generate_stream_episode, hard_benign_event, normal_event  # noqa: E402

DEFAULT_CONFIG = ROOT / "sim/scenarios.json"
DEFAULT_OUTPUT = ROOT / "data/streams"
HARD_BENIGN_VARIANTS = ("typo_then_success", "load_test", "health_check", "search_terms", "authorized_scanner")


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def build(config: dict[str, object], output_dir: Path) -> dict[str, object]:
    seed = int(config["seed"])
    stream_count = int(config["stream_count"])
    count = int(config["events_per_stream"])
    rate = int(config["events_per_second"])
    output_dir.mkdir(parents=True, exist_ok=True)
    manifest: dict[str, object] = {
        "seed": seed,
        "events_per_second": rate,
        "events_per_stream": count,
        "dev_streams": [f"stream_{i:02d}" for i in range(1, min(3, stream_count) + 1)],
        "held_out_streams": [f"stream_{i:02d}" for i in range(4, stream_count + 1)],
        "streams": {},
    }
    global_episode = 0
    for stream_index in range(stream_count):
        stream_id = f"stream_{stream_index + 1:02d}"
        rng = random.Random(seed + stream_index)
        start = datetime(2025, 9, 1 + stream_index, 8 + (stream_index * 3) % 12, tzinfo=timezone.utc)
        events = [
            normal_event(i, stream_id, event_time(start, i, rate), rng)
            for i in range(count)
        ]
        episodes: list[dict[str, object]] = []
        attack_positions = [1000 + slot * 1000 for slot in range(8)]
        for slot, start_idx in enumerate(attack_positions):
            kind = ATTACK_KINDS[(stream_index * 3 + slot) % len(ATTACK_KINDS)]
            hard = kind == "credential_stuffing" and global_episode % 2 == 0
            variant = "low_slow" if hard else "standard"
            episode_seed = seed + 100_000 + global_episode
            injected = generate_stream_episode(
                kind=kind,
                session_id=stream_id,
                start_event_id=start_idx,
                start=start,
                seed=episode_seed,
                events_per_second=rate,
                variant=variant,
            )
            events[start_idx:start_idx + len(injected)] = injected
            episodes.append({
                "episode_id": f"{stream_id}-attack-{slot + 1:02d}",
                "start_idx": start_idx,
                "end_idx": start_idx + len(injected),
                "kind": kind,
                "source": "scripted",
                "hard": hard,
                "hard_benign": False,
                "variant": variant,
            })
            global_episode += 1
        for slot, start_idx in enumerate((500, 4500, 8500)):
            variant = HARD_BENIGN_VARIANTS[(stream_index * 3 + slot) % len(HARD_BENIGN_VARIANTS)]
            for offset in range(20):
                event_id = start_idx + offset
                event = hard_benign_event(
                    variant,
                    event_id,
                    stream_id,
                    event_time(start, event_id, rate),
                    rng,
                    offset,
                )
                events[event_id] = event
            episodes.append({
                "episode_id": f"{stream_id}-hard-benign-{slot + 1:02d}",
                "start_idx": start_idx,
                "end_idx": start_idx + 20,
                "kind": "none",
                "source": "scripted",
                "hard": True,
                "hard_benign": True,
                "variant": variant,
            })
        episodes.sort(key=lambda item: int(item["start_idx"]))
        output_path = output_dir / f"{stream_id}.jsonl"
        if output_path.exists():
            output_path.chmod(0o644)
        with output_path.open("w", encoding="utf-8", newline="\n") as out:
            for event in events:
                out.write(json.dumps(event, ensure_ascii=False, separators=(",", ":"), sort_keys=True) + "\n")
        manifest["streams"][stream_id] = {
            "path": str(output_path.relative_to(ROOT)) if output_path.is_relative_to(ROOT) else str(output_path),
            "sha256": sha256(output_path),
            "events": len(events),
            "role": "dev" if stream_index < 3 else "held_out",
            "episodes": episodes,
        }
    manifest_path = output_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    return manifest


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", type=Path, default=DEFAULT_CONFIG)
    parser.add_argument("--output-dir", type=Path, default=DEFAULT_OUTPUT)
    args = parser.parse_args()
    config = json.loads(args.config.read_text(encoding="utf-8"))
    manifest = build(config, args.output_dir)
    print(json.dumps({"streams": len(manifest["streams"]), "manifest": str(args.output_dir / "manifest.json")}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
