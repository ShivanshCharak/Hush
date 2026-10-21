"""Reproducibility metadata shared by generated evaluation run files."""
from __future__ import annotations

import hashlib
import json
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def _sha256(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def snapshot(*, model: str | None = None, seed: int | None = None, include_phase1_inputs: bool = False) -> dict:
    from decider.prompt import FEWSHOT_ENABLED, PROMPT_FORMAT_VERSION, SYSTEM_PROMPT
    from decider.window import PATTERN_CHECK_VERSION
    prompt_material = SYSTEM_PROMPT + ("\n" + (ROOT / "decider/fewshot_dev.json").read_text(encoding="utf-8") if FEWSHOT_ENABLED else "")
    # Local model identity is recorded only for explicit study runs. Normal
    # rules/Bedrock pipeline metadata never probes the Ollama service.
    model_name = model
    model_digest = None
    if model_name:
        try:
            result = subprocess.run(["ollama", "show", model_name, "--modelfile"], capture_output=True, text=True, timeout=3, check=True)
            model_digest = hashlib.sha256(result.stdout.encode()).hexdigest()
        except (OSError, subprocess.SubprocessError):
            pass
    manifest = json.loads((ROOT / "data/streams/manifest.json").read_text(encoding="utf-8"))
    dev_stream_paths = [manifest["streams"][sid]["path"] for sid in manifest["dev_streams"]]
    data_paths = ("data/golden/dev.jsonl", "data/streams/manifest.json", *dev_stream_paths,
                  "eval/runs/evasion-v1-dev.json", "eval/runs/evasion-v2-dev.json",
                  "eval/runs/evasion-v3-dev.json", "eval/runs/evasion-v4-dev.json",
                  "eval/runs/evasion-v4-clean-dev.json",
                  "config/authorized_sources.json")
    if include_phase1_inputs:
        data_paths += ("data/golden/test.jsonl", "data/streams/stream_04.jsonl", "data/streams/stream_05.jsonl",
                       "data/annotations/second_annotator_filled.jsonl", "data/annotations/second_annotator_key.json",
                       "data/VERSION", "sim/scenarios.json")
    try:
        code_commit = subprocess.run(["git", "rev-parse", "HEAD"], cwd=ROOT, capture_output=True,
                                     text=True, timeout=3, check=True).stdout.strip()
        tracked_worktree_clean = subprocess.run(["git", "diff", "--quiet", "HEAD", "--"], cwd=ROOT,
                                                timeout=3).returncode == 0
    except (OSError, subprocess.SubprocessError):
        code_commit = None
        tracked_worktree_clean = None
    normalizer_settings = {
        "url_decode_passes_max": 3,
        "html_entity_decode": True,
        "unicode_escape_decode": True,
        "sql_comment_stripping": True,
        "whitespace_collapse": True,
    }
    allowlist_hash = _sha256(ROOT / "config/authorized_sources.json")
    return {
        "code_commit_sha": code_commit,
        "tracked_worktree_clean": tracked_worktree_clean,
        "prompt_hash_sha256": hashlib.sha256(prompt_material.encode()).hexdigest(),
        "prompt_format_version": PROMPT_FORMAT_VERSION,
        "pattern_check_version": PATTERN_CHECK_VERSION,
        "model": model_name,
        "model_digest_sha256": model_digest,
        "model_digest_status": "available" if model_digest else ("unavailable" if model_name else "not_applicable_to_rules_bedrock_pipeline"),
        "thresholds": {
            "brute_force_same_source": "one source and one account; >=5 failures in rolling 60s; no matching success in window",
            "brute_force_distributed": "one username; failures from >=3 source IPs in trailing 60m; no success for that username in that interval",
            "credential_stuffing": "auth endpoint, rolling 60m: >=4 distinct failed usernames, >=2 distinct source IPs, >=4 failed attempts, success ratio <=0.25",
            "sensitive_path_scan": ">=3 sensitive-path probes from one source",
            "generic_scan": ">=75% 4xx and >=5 distinct paths from one source",
            "priv_esc_proxy": ">=5 distinct profile IDs from one source",
            "payload_signatures": "SQLi/XSS/traversal signatures after up to 3 URL decodes",
            "normalization": "up to 3 repeated URL decodes, HTML entities, Unicode escapes, SQL comment stripping, whitespace collapse",
            "authorized_sources": "config/authorized_sources.json source + scope + unexpired grant",
            "window_size_events": 20,
            "cross_ip_brute_force_window_seconds": 3600,
        },
        "seeds": {"evaluation_seed": seed},
        "allowlist_sha256": allowlist_hash,
        "normalizer_settings": normalizer_settings,
        "data_hashes_sha256": {path: _sha256(ROOT / path) for path in data_paths},
    }
