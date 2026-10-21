#!/usr/bin/env python3
"""Build 20-event model windows and code-computed count headers."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from typing import Any
from baseline.rules import (PROFILE_PATH, SENSITIVE_PATH, SQLI, TRAVERSAL, XSS,
                            distributed_credential_stuffing_candidates)
from baseline.authorization import authorized_source
from baseline.normalization import normalize_request

WINDOW_SIZE = 20
PATTERN_CHECK_VERSION = 5
def _event_seconds(event: dict[str, Any], fallback: int) -> float:
    try:
        timestamp = datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00"))
        if timestamp.tzinfo is None:
            timestamp = timestamp.replace(tzinfo=timezone.utc)
        return timestamp.timestamp()
    except ValueError:
        return float(fallback)


def _max_rolling_counts(attempts: list[tuple[float, str, int]]) -> tuple[int, int, bool]:
    """Return max events, max distinct names, and whether any 60s span meets both thresholds."""
    attempts = sorted(attempts)
    left = 0
    max_events = max_names = 0
    confirmed = False
    for right, (now, _, _) in enumerate(attempts):
        while now - attempts[left][0] > 60:
            left += 1
        span = attempts[left:right + 1]
        event_count = len(span)
        distinct_names = len({name for _, name, _ in span if name})
        max_events = max(max_events, event_count)
        max_names = max(max_names, distinct_names)
        confirmed |= event_count >= 4 and distinct_names >= 4
    return max_events, max_names, confirmed


def compute_pattern_checks(events: list[dict[str, Any]]) -> dict[str, Any]:
    failures_by_account: dict[tuple[str, str], list[tuple[float, str, int]]] = defaultdict(list)
    failures_by_source: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
    successful_accounts: set[tuple[str, str]] = set()
    distributed_failures: dict[str, list[tuple[float, str, int]]] = defaultdict(list)
    distributed_successes: dict[str, list[float]] = defaultdict(list)
    profiles_by_source: dict[str, set[str]] = defaultdict(set)
    profile_event_ids_by_source: dict[str, list[int]] = defaultdict(list)
    paths_by_source: dict[str, set[str]] = defaultdict(set)
    sensitive_by_source: Counter[str] = Counter()
    four_xx_by_source: Counter[str] = Counter()
    request_by_source: Counter[str] = Counter()
    signature_ids: dict[str, list[int]] = {"sqli": [], "xss": [], "path_traversal": []}
    distributed_stuffing = distributed_credential_stuffing_candidates(events)

    for index, event in enumerate(events):
        source = str(event.get("src_ip", "unknown"))
        username = str(event.get("username", ""))
        event_id = int(event.get("event_id", -1))
        second = _event_seconds(event, index)
        status = int(event.get("status", 0) or 0)
        is_auth = event.get("event_type") == "auth" or event.get("result") in ("success", "fail")
        is_failure = event.get("result") == "fail" or (event.get("event_type") == "auth" and status == 401)
        if is_auth and is_failure:
            failures_by_account[(source, username)].append((second, username, event_id))
            failures_by_source[source].append((second, username, event_id))
            if username:
                distributed_failures[username].append((second, source, event_id))
        elif is_auth and event.get("result") == "success":
            successful_accounts.add((source, username))
            if username:
                distributed_successes[username].append(second)

        path = str(event.get("path", ""))
        paths_by_source[source].add(path)
        request_by_source[source] += 1
        if 400 <= status < 500:
            four_xx_by_source[source] += 1
        if SENSITIVE_PATH.search(path):
            sensitive_by_source[source] += 1
        profile = PROFILE_PATH.search(path)
        if profile:
            profiles_by_source[source].add(profile.group(1))
            profile_event_ids_by_source[source].append(event_id)

        request_text = normalize_request(event)
        if SQLI.search(request_text):
            signature_ids["sqli"].append(event_id)
        if XSS.search(request_text):
            signature_ids["xss"].append(event_id)
        if TRAVERSAL.search(request_text):
            signature_ids["path_traversal"].append(event_id)

    brute_candidates = []
    for (source, username), attempts in sorted(failures_by_account.items()):
        max_failures, _, _ = _max_rolling_counts(attempts)
        matching_success = (source, username) in successful_accounts
        brute_candidates.append({
            "src_ip": source,
            "authorized_source": authorized_source(source, "authentication"),
            "username": username,
            "max_failures_60s": max_failures,
            "matching_success_in_window": matching_success,
            "confirmed": bool(username) and max_failures >= 5 and not matching_success,
            "evidence_event_ids": [event_id for _, _, event_id in attempts],
        })

    latest_time = max((_event_seconds(event, index) for index, event in enumerate(events)), default=float("-inf"))
    cutoff_60m = latest_time - 3600
    distributed_candidates = []
    for username, attempts in sorted(distributed_failures.items()):
        recent = sorted((second, source, event_id) for second, source, event_id in attempts if second >= cutoff_60m)
        sources = sorted({source for _, source, _ in recent})
        matching_success = any(second >= cutoff_60m for second in distributed_successes.get(username, []))
        distributed_candidates.append({
            "username": username,
            "source_ips": sources,
            "authorized_source": bool(sources) and all(authorized_source(source, "authentication") for source in sources),
            "max_failures_60m": len(recent),
            "matching_success_in_window": matching_success,
            "confirmed": len(sources) >= 3 and not matching_success,
            "evidence_event_ids": [event_id for _, _, event_id in recent],
        })

    credential_candidates = []
    for source, attempts in sorted(failures_by_source.items()):
        max_failures, max_usernames, confirmed = _max_rolling_counts(attempts)
        credential_candidates.append({
            "src_ip": source,
            "authorized_source": authorized_source(source, "authentication"),
            "max_failures_60s": max_failures,
            "max_distinct_usernames_60s": max_usernames,
            "confirmed": confirmed,
            "evidence_event_ids": [event_id for _, _, event_id in attempts],
        })

    profile_candidates = [
        {
            "src_ip": source,
            "authorized_source": authorized_source(source, "profile_scan"),
            "distinct_profile_ids": len(ids),
            "confirmed": len(ids) >= 5,
            "evidence_event_ids": profile_event_ids_by_source[source],
        }
        for source, ids in sorted(profiles_by_source.items())
    ]
    scan_candidates = []
    for source in sorted(request_by_source):
        event_count = request_by_source[source]
        four_xx_count = four_xx_by_source[source]
        path_count = len(paths_by_source[source])
        sensitive_count = sensitive_by_source[source]
        rate = four_xx_count / event_count
        if sensitive_count or four_xx_count:
            scan_candidates.append({
                "src_ip": source,
                "authorized_source": authorized_source(source, "scanner_recon"),
                "sensitive_path_probes": sensitive_count,
                "four_xx_count": four_xx_count,
                "request_count": event_count,
                "four_xx_rate": rate,
                "distinct_paths": path_count,
                "confirmed": sensitive_count >= 3 or (rate >= 0.75 and path_count >= 5),
                "evidence_event_ids": [
                    int(event.get("event_id", -1))
                    for event in events
                    if str(event.get("src_ip", "unknown")) == source
                    and (SENSITIVE_PATH.search(str(event.get("path", ""))) or 400 <= int(event.get("status", 0) or 0) < 500)
                ],
            })

    return {
        "brute_force_candidates": brute_candidates,
        "distributed_brute_force_candidates": distributed_candidates,
        "credential_stuffing_candidates": credential_candidates,
        "distributed_credential_stuffing_candidates": distributed_stuffing,
        "priv_esc_candidates": profile_candidates,
        "scanner_recon_candidates": scan_candidates,
        "payload_signature_event_ids": signature_ids,
    }


def compute_header(events: list[dict[str, Any]]) -> dict[str, Any]:
    failed_by_ip: Counter[str] = Counter()
    usernames_by_ip: dict[str, set[str]] = defaultdict(set)
    four_xx = 0
    failed_usernames_60m: Counter[str] = Counter()
    timed_failures: list[tuple[float, str]] = []
    latest_time = max((_event_seconds(event, index) for index, event in enumerate(events)), default=float("-inf"))
    for event in events:
        ip = str(event.get("src_ip", "unknown"))
        status = int(event.get("status", 0) or 0)
        if event.get("result") == "fail" or (event.get("event_type") == "auth" and status == 401):
            failed_by_ip[ip] += 1
            username = str(event.get("username", ""))
            if username:
                usernames_by_ip[ip].add(username)
                timed_failures.append((_event_seconds(event, len(timed_failures)), username))
        if 400 <= status < 500:
            four_xx += 1
    cutoff = latest_time - 3600
    for event_time, username in timed_failures:
        if event_time >= cutoff:
            failed_usernames_60m[username] += 1
    return {
        "event_count": len(events),
        "failed_logins_per_ip": dict(failed_by_ip),
        "distinct_usernames_per_ip": {ip: len(users) for ip, users in usernames_by_ip.items()},
        "four_xx_rate": four_xx / max(1, len(events)),
        "failed_logins_per_username_60m": dict(failed_usernames_60m),
        "pattern_checks": compute_pattern_checks(events),
    }


def make_window(events: list[dict[str, Any]], *, require_full: bool = True) -> dict[str, Any]:
    if require_full and len(events) != WINDOW_SIZE:
        raise ValueError(f"expected {WINDOW_SIZE} events, got {len(events)}")
    if len(events) > WINDOW_SIZE:
        raise ValueError(f"window exceeds {WINDOW_SIZE} events")
    return {"header": compute_header(events), "events": events}


def chunk_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [make_window(events[start:start + WINDOW_SIZE], require_full=False) for start in range(0, len(events), WINDOW_SIZE)]
