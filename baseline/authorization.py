"""Config-backed, expiry-aware allowlist for explicitly scoped sources."""
from __future__ import annotations

import json
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

CONFIG_PATH = Path(__file__).resolve().parents[1] / "config" / "authorized_sources.json"


@lru_cache(maxsize=1)
def _load_grants() -> tuple[dict, ...]:
    try:
        grants = json.loads(CONFIG_PATH.read_text(encoding="utf-8")).get("sources", [])
        return tuple(grants)
    except (OSError, json.JSONDecodeError, AttributeError):
        return ()


def authorized_source(source: str, scope: str, *, now: datetime | None = None) -> bool:
    grants = _load_grants()
    current = now or datetime.now(timezone.utc)
    for grant in grants:
        if str(grant.get("source")) != source or scope not in grant.get("scopes", []):
            continue
        try:
            expires = datetime.fromisoformat(str(grant["expires_at"]).replace("Z", "+00:00"))
            if expires.tzinfo is None:
                expires = expires.replace(tzinfo=timezone.utc)
        except (KeyError, ValueError):
            continue
        if current < expires:
            return True
    return False
