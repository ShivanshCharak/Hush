"""Reproducibility metadata shared by generated evaluation run files."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def snapshot(*, model: str | None = None, seed: int | None = None) -> dict:
    from decider.prompt import FEWSHOT_ENABLED, PROMPT_FORMAT_VERSION, SYSTEM_PROMPT
    prompt_material = SYSTEM_PROMPT + ("\n" + (ROOT / "decider/fewshot_dev.json").read_text(encoding="utf-8") if FEWSHOT_ENABLED else "")
    model_name = model or os.environ.get("DECIDER_MODEL", "qwen3:1.7b")
    model_digest = None
    try:
        result = subprocess.run(["ollama", "show", model_name, "--modelfile"], capture_output=True, text=True, timeout=3, check=True)
        model_digest = hashlib.sha256(result.stdout.encode()).hexdigest()
    except (OSError, subprocess.SubprocessError):
        pass
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    dev_stream_paths = [manifest["streams"][sid]["path"] for sid in manifest["dev_streams"]]
    data_paths = ("data/golden/dev.jsonl", "data/streams/manifest.json", *dev_stream_paths,
                  "eval/runs/evasion-v2-dev.json", "config/authorized_sources.json")
    return {
        "prompt_hash_sha256": hashlib.sha256(prompt_material.encode()).hexdigest(),
        "prompt_format_version": PROMPT_FORMAT_VERSION,
        "model": model_name,
        "model_digest_sha256": model_digest,
        "model_digest_status": "available" if model_digest else "unavailable",
        "thresholds": {
            "brute_force": "one source and one account; >=5 failures in rolling 60s; no matching success in window",
            "credential_stuffing": ">=4 failures across >=4 usernames from one source in rolling 60s",
            "sensitive_path_scan": ">=3 sensitive-path probes from one source",
            "generic_scan": ">=75% 4xx and >=5 distinct paths from one source",
            "priv_esc_proxy": ">=5 distinct profile IDs from one source",
            "payload_signatures": "SQLi/XSS/traversal signatures after up to 3 URL decodes",
            "authorized_sources": "config/authorized_sources.json source + scope + unexpired grant",
            "window_size_events": 20,
            "window_spacing_seconds": 600,
        },
        "seeds": {"evaluation_seed": seed},
        "data_hashes_sha256": {path: _sha256(ROOT / path) for path in data_paths},
    }
