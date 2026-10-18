#!/usr/bin/env python3
"""Deterministic synthetic web and authentication event generation."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
import random
from urllib.parse import quote


ATTACK_KINDS = (
    "brute_force",
    "credential_stuffing",
    "sqli",
    "xss",
    "path_traversal",
    "priv_esc",
    "scanner_recon",
)
NORMAL_PATHS = ("/", "/products", "/search", "/cart", "/account", "/healthz")
SCANNER_PATHS = (
    "/.env",
    "/wp-admin/",
    "/phpmyadmin/",
    "/backup.zip",
    "/server-status",
    "/robots.txt",
)
USER_AGENTS = (
    "Mozilla/5.0 Chrome/128.0",
    "Mozilla/5.0 Firefox/129.0",
    "Decider-Sec-Healthcheck/1.0",
    "LoadTestClient/1.0",
)


def event_time(start: datetime, event_index: int, events_per_second: int = 5) -> str:
    timestamp = start + timedelta(seconds=event_index / events_per_second)
    return timestamp.astimezone(timezone.utc).isoformat().replace("+00:00", "Z")


def web_event(
    event_id: int,
    session_id: str,
    timestamp: str,
    rng: random.Random,
    *,
    src_ip: str | None = None,
    method: str = "GET",
    path: str = "/",
    query: str = "",
    status: int = 200,
    user_agent: str | None = None,
    referer: str | None = None,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "event_type": "web",
        "src_ip": src_ip or f"198.51.100.{rng.randint(10, 220)}",
        "method": method,
        "path": path,
        "query": query,
        "status": status,
        "bytes": rng.choice((0, 512, 1024, 2048)),
        "user_agent": user_agent or rng.choice(USER_AGENTS[:2]),
        "referer": referer,
    }


def auth_event(
    event_id: int,
    session_id: str,
    timestamp: str,
    rng: random.Random,
    *,
    src_ip: str,
    username: str,
    result: str,
    endpoint: str = "/auth/login",
    mfa: bool = False,
) -> dict[str, object]:
    return {
        "event_id": event_id,
        "session_id": session_id,
        "timestamp": timestamp,
        "event_type": "auth",
        "src_ip": src_ip,
        "method": "POST",
        "path": endpoint,
        "query": "",
        "status": 200 if result == "success" else 401,
        "bytes": 0,
        "user_agent": "Mozilla/5.0 Chrome/128.0",
        "referer": None,
        "username": username,
        "result": result,
        "mfa": mfa,
        "endpoint": endpoint,
    }


def normal_event(
    event_id: int,
    session_id: str,
    timestamp: str,
    rng: random.Random,
) -> dict[str, object]:
    if rng.random() < 0.2:
        return auth_event(
            event_id,
            session_id,
            timestamp,
            rng,
            src_ip=f"198.51.100.{rng.randint(10, 220)}",
            username=f"user{rng.randint(1, 80)}",
            result="success" if rng.random() > 0.08 else "fail",
            mfa=rng.random() < 0.7,
        )
    path = rng.choice(NORMAL_PATHS)
    query = "q=select+union" if path == "/search" and rng.random() < 0.08 else ""
    return web_event(
        event_id,
        session_id,
        timestamp,
        rng,
        method="POST" if path in ("/cart", "/account") and rng.random() < 0.3 else "GET",
        path=path,
        query=query,
        status=rng.choices((200, 302, 404), weights=(92, 6, 2))[0],
    )


def attack_event(
    kind: str,
    event_id: int,
    session_id: str,
    timestamp: str,
    rng: random.Random,
    offset: int,
    *,
    variant: str = "standard",
    src_ip: str = "203.0.113.200",
) -> dict[str, object]:
    if kind == "brute_force":
        return auth_event(event_id, session_id, timestamp, rng, src_ip=src_ip, username="alice", result="fail")
    if kind == "credential_stuffing":
        username = f"candidate{offset + 1}" if variant == "low_slow" else f"account{offset % 20}"
        return auth_event(event_id, session_id, timestamp, rng, src_ip=src_ip, username=username, result="fail")
    if kind == "sqli":
        payload = "1' OR '1'='1" if variant != "encoded" else quote("1' OR '1'='1", safe="")
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/search", query=f"q={payload}")
    if kind == "xss":
        payload = "<script>alert(1)</script>" if variant != "encoded" else quote("<script>alert(1)</script>", safe="")
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/search", query=f"q={payload}")
    if kind == "path_traversal":
        payload = "..%2F..%2Fetc%2Fpasswd" if variant == "encoded" else "../../etc/passwd"
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/download", query=f"file={payload}")
    if kind == "priv_esc":
        target_user = (offset % 20) + 100
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path=f"/api/users/{target_user}/profile", status=200)
    if kind == "scanner_recon":
        path = SCANNER_PATHS[offset % len(SCANNER_PATHS)]
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path=path, status=404, user_agent="Nmap Scripting Engine")
    raise ValueError(f"Unsupported attack kind: {kind}")


def hard_benign_event(
    variant: str,
    event_id: int,
    session_id: str,
    timestamp: str,
    rng: random.Random,
    offset: int,
) -> dict[str, object]:
    src_ip = "198.51.100.42"
    if variant == "typo_then_success":
        result = "success" if offset == 19 else "fail"
        return auth_event(event_id, session_id, timestamp, rng, src_ip=src_ip, username="alice", result=result)
    if variant == "load_test":
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/products", user_agent="LoadTestClient/1.0")
    if variant == "health_check":
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/healthz", user_agent="Decider-Sec-Healthcheck/1.0")
    if variant == "search_terms":
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path="/search", query="q=select+union+jack")
    if variant == "authorized_scanner":
        return web_event(event_id, session_id, timestamp, rng, src_ip=src_ip, path=SCANNER_PATHS[offset % len(SCANNER_PATHS)], status=404, user_agent="Approved-Internal-Scanner/2.0")
    raise ValueError(f"Unsupported hard-benign variant: {variant}")


def generate_window(
    *,
    kind: str,
    session_id: str,
    start_event_id: int,
    start: datetime,
    seed: int,
    events_per_second: int = 5,
    variant: str = "standard",
) -> list[dict[str, object]]:
    """Generate one labeled 20-event scenario window; labels stay outside events."""
    rng = random.Random(seed)
    events = []
    for offset in range(20):
        event_id = start_event_id + offset
        timestamp = event_time(start, offset, events_per_second)
        if kind == "none":
            event = normal_event(event_id, session_id, timestamp, rng)
        elif kind == "hard_benign":
            event = hard_benign_event(variant, event_id, session_id, timestamp, rng, offset)
        elif kind == "ambiguous":
            event = web_event(event_id, session_id, timestamp, rng, path=SCANNER_PATHS[offset % len(SCANNER_PATHS)], status=404, user_agent="Mozilla/5.0 Chrome/128.0") if offset < 10 else normal_event(event_id, session_id, timestamp, rng)
        else:
            event_variant = variant
            if kind == "credential_stuffing" and variant == "low_slow" and offset % 4:
                event = normal_event(event_id, session_id, timestamp, rng)
            else:
                event = attack_event(kind, event_id, session_id, timestamp, rng, offset, variant=event_variant)
        events.append(event)
    return events


def generate_stream_episode(
    *,
    kind: str,
    session_id: str,
    start_event_id: int,
    start: datetime,
    seed: int,
    events_per_second: int = 5,
    variant: str = "standard",
) -> list[dict[str, object]]:
    """Generate a replay episode. Low-slow stuffing is interleaved over 40 events."""
    rng = random.Random(seed)
    length = 40 if kind == "credential_stuffing" and variant == "low_slow" else 20
    events = []
    for offset in range(length):
        event_id = start_event_id + offset
        timestamp = event_time(start, event_id, events_per_second)
        if kind == "credential_stuffing" and variant == "low_slow" and offset % 4:
            event = normal_event(event_id, session_id, timestamp, rng)
        else:
            event = attack_event(kind, event_id, session_id, timestamp, rng, offset // 4 if variant == "low_slow" else offset, variant=variant)
        events.append(event)
    return events
