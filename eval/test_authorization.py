"""Focused allowlist boundary tests: expiry, scope, and config membership."""
from __future__ import annotations

import json
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path
from unittest.mock import patch

from baseline import authorization
from baseline.rules import predict


def scanner_events(source: str) -> list[dict]:
    paths = ("/.env", "/phpmyadmin/", "/backup.zip")
    stamp = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
    return [{"event_id": index + 1, "event_type": "web", "src_ip": source, "path": path,
             "status": 404, "timestamp": (stamp + timedelta(seconds=index)).isoformat().replace("+00:00", "Z")}
            for index, path in enumerate(paths)]


def auth_events(sources: list[str], *, success: bool = False, spacing_seconds: int = 20) -> list[dict]:
    stamp = datetime(2026, 10, 21, 12, 0, tzinfo=timezone.utc)
    events = [{"event_id": index + 1, "event_type": "auth", "src_ip": source, "path": "/auth/login",
               "status": 401, "result": "fail", "username": "shared-user",
               "timestamp": (stamp + timedelta(seconds=index * spacing_seconds)).isoformat().replace("+00:00", "Z")}
              for index, source in enumerate(sources)]
    if success:
        events.append({"event_id": len(events) + 1, "event_type": "auth", "src_ip": "203.0.113.99",
                       "path": "/auth/login", "status": 200, "result": "success", "username": "shared-user",
                       "timestamp": (stamp + timedelta(seconds=len(events) * spacing_seconds)).isoformat().replace("+00:00", "Z")})
    return events


class AuthorizationBoundaryTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.config = Path(self.tmp.name) / "authorized_sources.json"
        self.path_patch = patch.object(authorization, "CONFIG_PATH", self.config)
        self.path_patch.start()
        authorization._load_grants.cache_clear()

    def tearDown(self):
        authorization._load_grants.cache_clear()
        self.path_patch.stop()
        self.tmp.cleanup()

    def write_grants(self, sources: list[dict]) -> None:
        self.config.write_text(json.dumps({"schema_version": 1, "sources": sources}), encoding="utf-8")
        authorization._load_grants.cache_clear()

    def assert_scanner_alert(self, source: str) -> None:
        decision = predict(scanner_events(source))
        self.assertTrue(decision["speak"])
        self.assertEqual(decision["kind"], "scanner_recon")

    def test_expired_entry_does_not_suppress_alert(self):
        self.write_grants([{"source": "198.51.100.42", "scopes": ["scanner_recon"], "expires_at": "2026-01-01T00:00:00Z"}])
        self.assert_scanner_alert("198.51.100.42")

    def test_out_of_scope_entry_does_not_suppress_alert(self):
        self.write_grants([{"source": "198.51.100.42", "scopes": ["authentication"], "expires_at": "2027-01-01T00:00:00Z"}])
        self.assert_scanner_alert("198.51.100.42")

    def test_source_missing_from_config_does_not_suppress_alert(self):
        self.write_grants([])
        self.assert_scanner_alert("198.51.100.77")

    def test_active_matching_scope_suppresses_scanner_alert(self):
        self.write_grants([{"source": "198.51.100.42", "scopes": ["scanner_recon"], "expires_at": "2027-01-01T00:00:00Z"}])
        self.assertFalse(predict(scanner_events("198.51.100.42"))["speak"])

    def test_distributed_username_failures_from_three_sources_alert(self):
        decision = predict(auth_events(["203.0.113.1", "203.0.113.2", "203.0.113.3"]))
        self.assertTrue(decision["speak"])
        self.assertEqual(decision["kind"], "brute_force")

    def test_distributed_failures_with_success_are_silent(self):
        decision = predict(auth_events(["203.0.113.1", "203.0.113.2", "203.0.113.3"], success=True))
        self.assertFalse(decision["speak"])

    def test_same_source_rule_remains_five_failures_in_sixty_seconds(self):
        decision = predict(auth_events(["203.0.113.1"] * 5, spacing_seconds=10))
        self.assertTrue(decision["speak"])
        self.assertEqual(decision["kind"], "brute_force")


if __name__ == "__main__":
    unittest.main()
