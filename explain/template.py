"""Deterministic explanation that only uses entities from cited window events."""
from __future__ import annotations
from typing import Any

KIND_LABELS = {"brute_force":"repeated login failures", "credential_stuffing":"login attempts across accounts",
               "sqli":"SQL injection-like request", "xss":"cross-site scripting-like request",
               "path_traversal":"path traversal-like request", "priv_esc":"profile enumeration / possible authorization issue",
               "scanner_recon":"reconnaissance or sensitive-path probing"}

def suggested_action(kind: str, ips: list[str], names: list[str], paths: list[str]) -> str:
    source = ", ".join(ips) if ips else "the cited source"
    accounts = ", ".join(names[:5]) if names else "the affected accounts"
    targets = ", ".join(paths[:3]) if paths else "the cited endpoints"
    actions = {
        "brute_force": f"Review sign-in and MFA records for {accounts}; check for a later successful login from {source}. If unauthorized, apply your rate-limit or source-blocking policy.",
        "credential_stuffing": f"Check for successful logins across {accounts} and compare with credential-reuse signals. If unauthorized, require step-up authentication and rate-limit {source} under your response policy.",
        "sqli": f"For {source}, check application and database logs to determine whether the injected query against {targets} executed or exposed data; a 200 response alone does not confirm impact.",
        "xss": f"For {source}, check whether the payload sent to {targets} was reflected or stored in rendered output, and review input handling and output encoding.",
        "path_traversal": f"For {source}, check the response and file-access logs for {targets} to determine whether a sensitive file was served; review path normalization and access controls.",
        "priv_esc": f"For {source}, verify the requesting principal and authorization checks for {targets}; determine whether the profile access was permitted before treating it as privilege escalation.",
        "scanner_recon": f"Verify whether a scan involving {source} was authorized. If not, preserve the request evidence and apply your rate-limit or blocking policy.",
    }
    return actions.get(kind, "Review the cited events and confirm whether the activity was authorized.")

def explain(decision: dict[str, Any], events: list[dict[str, Any]]) -> dict[str, Any]:
    ids = set(decision.get("evidence_ids", []))
    cited = [e for e in events if int(e.get("event_id", -1)) in ids]
    if not cited:
        raise ValueError("an alert explanation requires cited evidence in the window")
    kind = str(decision["kind"])
    ips = sorted({str(e["src_ip"]) for e in cited if e.get("src_ip")})
    names = sorted({str(e["username"]) for e in cited if e.get("username")})
    paths = sorted({str(e["path"]) for e in cited if e.get("path")})
    details = []
    if ips: details.append("source " + ", ".join(ips))
    if names: details.append("account(s) " + ", ".join(names[:5]))
    if paths: details.append("path(s) " + ", ".join(paths[:5]))
    return {"summary": f"Observed {KIND_LABELS.get(kind, kind)} involving " + "; ".join(details) + ".",
            "evidence_ids": sorted(ids), "suggested_action": suggested_action(kind,ips,names,paths),
            "source": "template"}

def validate_explanation(value: dict[str, Any], events: list[dict[str, Any]]) -> bool:
    valid_ids = {int(e["event_id"]) for e in events if "event_id" in e}
    ids = value.get("evidence_ids", [])
    if not isinstance(ids, list) or not set(ids) <= valid_ids: return False
    text = " ".join(str(value.get(k, "")) for k in ("summary", "suggested_action"))
    cited = [e for e in events if int(e.get("event_id", -1)) in set(ids)]
    entities = {str(e.get(k)) for e in cited for k in ("src_ip", "username", "path") if e.get(k)}
    all_window_entities = {str(e.get(k)) for e in events for k in ("src_ip", "username", "path") if e.get(k)}
    mentioned = {entity for entity in all_window_entities if entity in text}
    return bool(ids) and mentioned <= entities
