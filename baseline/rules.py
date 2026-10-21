#!/usr/bin/env python3
"""Small, inspectable web/auth rules baseline for Decider-Sec."""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
from urllib.parse import unquote
import re
from typing import Any
from baseline.authorization import authorized_source

ATTACK_KINDS = (
    "brute_force",
    "credential_stuffing",
    "sqli",
    "xss",
    "path_traversal",
    "priv_esc",
    "scanner_recon",
)

# Include numeric tautologies such as `AND 1=1` found in encoded ModSecurity
# probes. The request is decoded before this signature is evaluated.
SQLI = re.compile(
    r"(?:union\s+(?:all\s+)?select|(?:'|%27)\s*or\s+['\"%]?[0-9]+['\"%]?\s*=|"
    r"select\s+.+\s+from|\b(?:or|and)\s*\(?\s*['\"%]*[0-9]+['\"%]*\s*=\s*['\"%]*[0-9]+)",
    re.I,
)
XSS = re.compile(r"<\s*script\b|javascript\s*:|onerror\s*=|onload\s*=", re.I)
TRAVERSAL = re.compile(r"(?:\.\.[/\\]|%2e%2e(?:%2f|%5c)|\.\.%2f|\.\.%5c)", re.I)
SENSITIVE_PATH = re.compile(
    r"(?:^|/)(?:\.env(?:\.|/|$)|\.git(?:/|$)|\.aws(?:/|$)|\.ssh(?:/|$)|"
    r"wp-config\.php|phpmyadmin|backup(?:\.zip|\.sql)?|dump\.sql|server-status|"
    r"\.kube|terraform\.tfstate|/etc/passwd)",
    re.I,
)
PROFILE_PATH = re.compile(r"/api/users/(\d+)/profile(?:/|$)", re.I)


def _auth_counts_per_60s(events: list[dict[str, Any]]) -> tuple[Counter[str], dict[str, set[str]]]:
    by_ip: dict[str, list[tuple[float, str]]] = defaultdict(list)
    for index, event in enumerate(events):
        if not (event.get("event_type") == "auth" or event.get("result") in ("success", "fail")):
            continue
        if event.get("result") != "fail" and int(event.get("status", 0) or 0) != 401:
            continue
        timestamp = str(event.get("timestamp", ""))
        try:
            parsed = datetime.fromisoformat(timestamp.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
            seconds = parsed.timestamp()
        except ValueError:
            seconds = float(index)
        by_ip[str(event.get("src_ip", "unknown"))].append((seconds, str(event.get("username", ""))))
    max_failures: Counter[str] = Counter()
    max_usernames: dict[str, set[str]] = {}
    for ip, attempts in by_ip.items():
        attempts.sort()
        left = 0
        for right, (current_time, _) in enumerate(attempts):
            while current_time - attempts[left][0] > 60:
                left += 1
            window = attempts[left:right + 1]
            if len(window) > max_failures[ip]:
                max_failures[ip] = len(window)
                max_usernames[ip] = {username for _, username in window if username}
    return max_failures, max_usernames


def decoded_request(event: dict[str, Any]) -> str:
    value = f"{event.get('path', '')}?{event.get('query', '')}"
    for _ in range(3):
        decoded = unquote(value)
        if decoded == value:
            break
        value = decoded
    return value


def inspect_window(events: list[dict[str, Any]]) -> dict[str, Any]:
    """Return rule decisions and compact features for one window."""
    failed_by_ip: Counter[str] = Counter()
    usernames_by_ip: dict[str, set[str]] = defaultdict(set)
    failed_usernames: dict[str, Counter[str]] = defaultdict(Counter)
    failures_by_account_60s: dict[tuple[str, str], list[tuple[float, int]]] = defaultdict(list)
    succeeded_accounts: set[tuple[str, str]] = set()
    four_xx_by_ip: Counter[str] = Counter()
    request_by_ip: Counter[str] = Counter()
    paths_by_ip: dict[str, set[str]] = defaultdict(set)
    signature_hits: dict[str, list[int]] = defaultdict(list)
    sensitive_by_ip: Counter[str] = Counter()
    profile_ids: dict[str, set[str]] = defaultdict(set)
    scanners_by_ip: Counter[str] = Counter()

    latest_time = float("-inf")
    for index, event in enumerate(events):
        try:
            parsed_time = datetime.fromisoformat(str(event.get("timestamp", "")).replace("Z", "+00:00"))
            if parsed_time.tzinfo is None:
                parsed_time = parsed_time.replace(tzinfo=timezone.utc)
            event_time = parsed_time.timestamp()
        except ValueError:
            event_time = float(index)
        latest_time = max(latest_time, event_time)
        ip = str(event.get("src_ip", "unknown"))
        event_id = int(event.get("event_id", -1))
        request_by_ip[ip] += 1
        paths_by_ip[ip].add(str(event.get("path", "")))
        status = int(event.get("status", 0) or 0)
        if 400 <= status < 500:
            four_xx_by_ip[ip] += 1
        is_auth = event.get("event_type") == "auth" or event.get("result") in ("success", "fail")
        if is_auth:
            username = str(event.get("username", ""))
            if event.get("result") == "fail" or (event.get("event_type") == "auth" and status == 401):
                failed_by_ip[ip] += 1
                if username:
                    usernames_by_ip[ip].add(username)
                    failed_usernames[ip][username] += 1
                    failures_by_account_60s[(ip, username)].append((event_time, event_id))
            elif event.get("result") == "success" and username:
                succeeded_accounts.add((ip, username))

        request = decoded_request(event)
        if SQLI.search(request):
            signature_hits["sqli"].append(event_id)
        if XSS.search(request):
            signature_hits["xss"].append(event_id)
        if TRAVERSAL.search(request):
            signature_hits["path_traversal"].append(event_id)
        if SENSITIVE_PATH.search(str(event.get("path", ""))):
            sensitive_by_ip[ip] += 1
        profile = PROFILE_PATH.search(str(event.get("path", "")))
        if profile:
            profile_ids[ip].add(profile.group(1))
        agent = str(event.get("user_agent", ""))
        if re.search(r"nmap|nikto|masscan|sqlmap|gobuster|dirbuster", agent, re.I):
            scanners_by_ip[ip] += 1

    scores: dict[str, tuple[int, list[int], str]] = {}
    for kind, ids in signature_hits.items():
        if ids:
            scores[kind] = (100, ids[:8], "request payload matches an attack signature")

    failures_60s, usernames_60s = _auth_counts_per_60s(events)
    for (ip, username), attempts in failures_by_account_60s.items():
        attempts.sort()
        left = 0
        for right, (now, _) in enumerate(attempts):
            while now - attempts[left][0] > 60:
                left += 1
            span = attempts[left:right + 1]
            if len(span) >= 5 and username and (ip, username) not in succeeded_accounts:
                scores["brute_force"] = (
                    80 + min(len(span), 20),
                    [event_id for _, event_id in span[:8]],
                    f"{len(span)} failed logins for one account from one source within 60 seconds, with no matching success",
                )
    for ip, failures in failures_60s.items():
        unique_users = len(usernames_60s.get(ip, set()))
        if unique_users >= 4 and failures >= 4:
            scores["credential_stuffing"] = (
                80 + min(failures, 20),
                [int(e["event_id"]) for e in events if str(e.get("src_ip")) == ip and e.get("event_type") == "auth" and (e.get("result") == "fail" or e.get("status") == 401)][:8],
                f"{failures} failed logins across {unique_users} usernames from one source",
            )

    for ip, ids in profile_ids.items():
        if len(ids) >= 5:
            scores["priv_esc"] = (
                55 + len(ids),
                [int(e["event_id"]) for e in events if str(e.get("src_ip")) == ip and PROFILE_PATH.search(str(e.get("path", "")))][:8],
                f"one source accessed {len(ids)} distinct user profiles",
            )

    for ip in request_by_ip:
        four_xx_rate = four_xx_by_ip[ip] / request_by_ip[ip]
        if (sensitive_by_ip[ip] >= 3 or scanners_by_ip[ip] >= 1 or (four_xx_rate >= 0.75 and len(paths_by_ip[ip]) >= 5)) and not authorized_source(ip, "scanner_recon"):
            ids = [
                int(e["event_id"])
                for e in events
                if str(e.get("src_ip")) == ip
                and (SENSITIVE_PATH.search(str(e.get("path", ""))) or re.search(r"nmap|nikto|masscan|sqlmap|gobuster|dirbuster", str(e.get("user_agent", "")), re.I) or (int(e.get("status", 0) or 0) >= 400 and four_xx_rate >= 0.75))
            ][:8]
            scores["scanner_recon"] = (60 + len(ids), ids, "automated probes target sensitive or unrelated endpoints")

    if not scores:
        return {"speak": False, "kind": "none", "evidence_ids": [], "confidence": 0.0, "reason": "no rule crossed its threshold", "features": _features(events, failed_by_ip, usernames_by_ip, four_xx_by_ip, request_by_ip)}

    kind, (score, evidence_ids, reason) = max(scores.items(), key=lambda item: (item[1][0], item[0]))
    return {
        "speak": True,
        "kind": kind,
        "evidence_ids": evidence_ids,
        "confidence": min(0.99, score / 110),
        "reason": reason,
        "features": _features(events, failed_by_ip, usernames_by_ip, four_xx_by_ip, request_by_ip),
    }


def _features(
    events: list[dict[str, Any]],
    failed_by_ip: Counter[str],
    usernames_by_ip: dict[str, set[str]],
    four_xx_by_ip: Counter[str],
    request_by_ip: Counter[str],
    failures_by_username_10m: Counter[str] | None = None,
) -> dict[str, Any]:
    return {
        "failed_logins_per_ip": dict(failed_by_ip),
        "distinct_usernames_per_ip": {ip: len(names) for ip, names in usernames_by_ip.items()},
        "four_xx_rate": sum(four_xx_by_ip.values()) / max(1, len(events)),
        "events": len(events),
        "failed_logins_per_username_10m": {},
    }


def predict(events: list[dict[str, Any]]) -> dict[str, Any]:
    return inspect_window(events)
