#!/usr/bin/env python3
"""Cheap event-level prefilter that preserves attack-relevant evidence."""

from __future__ import annotations

import re
from typing import Any

from baseline.rules import SENSITIVE_PATH, SQLI, TRAVERSAL, XSS, decoded_request

SCANNER_AGENT = re.compile(r"nmap|nikto|masscan|sqlmap|gobuster|dirbuster", re.I)
PROFILE = re.compile(r"/api/users/\d+/profile", re.I)


def keep_event(event: dict[str, Any]) -> bool:
    """Keep events with authentication outcomes or suspicious request evidence."""
    if event.get("event_type") == "auth" or event.get("result") in ("fail", "success"):
        return event.get("result") == "fail" or int(event.get("status", 0) or 0) == 401
    path = str(event.get("path", ""))
    agent = str(event.get("user_agent", ""))
    request = decoded_request(event)
    if SQLI.search(request) or XSS.search(request) or TRAVERSAL.search(request):
        return True
    if SENSITIVE_PATH.search(path) or SCANNER_AGENT.search(agent) or PROFILE.search(path):
        return True
    if int(event.get("status", 0) or 0) >= 500:
        return True
    return False


def filter_events(events: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [event for event in events if keep_event(event)]
