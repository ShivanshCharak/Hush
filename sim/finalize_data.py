#!/usr/bin/env python3
"""Lock held-out artifacts and write hashes for all Phase 1 datasets."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def finalize(root: Path = ROOT) -> Path:
    held_out = [
        root / "data/golden/test.jsonl",
        root / "data/streams/stream_04.jsonl",
        root / "data/streams/stream_05.jsonl",
    ]
    for path in held_out:
        if not path.exists():
            raise FileNotFoundError(path)
        path.chmod(0o444)
    files = []
    for base in (root / "data", root / "sim/capture/external"):
        for path in base.rglob("*"):
            if path.is_file() and path.name != "VERSION" and "annotations" not in path.parts:
                files.append(path)
    lines = [f"{sha256(path)}  {path.relative_to(root).as_posix()}" for path in sorted(files)]
    version_path = root / "data/VERSION"
    version_path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return version_path


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args()
    print(finalize(args.root))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
