"""Stateful cooldown, deduplication, confidence, and rolling-budget gate."""
from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class AlertGate:
    cooldown_seconds: float = 30.0
    budget_alerts: int = 6
    budget_seconds: float = 600.0
    confidence_threshold: float = 0.0
    _last_by_key: dict[tuple[str, str], float] = field(default_factory=dict)
    _recent: deque[float] = field(default_factory=deque)
    _seen: set[str] = field(default_factory=set)

    def evaluate(self, decision: dict[str, Any], events: list[dict[str, Any]], *, now: float,
                 alert_fingerprint: str | None = None) -> dict[str, Any]:
        if not decision.get("speak"):
            return {"emit": False, "reason": "decision_silent", "budget_count": len(self._recent)}
        confidence = decision.get("confidence")
        if confidence is not None and float(confidence) < self.confidence_threshold:
            return {"emit": False, "reason": "below_confidence_threshold", "budget_count": len(self._recent)}
        kind = str(decision.get("kind", "none"))
        source = next((str(e.get("src_ip")) for e in events if e.get("src_ip")), "unknown")
        key = (source, kind)
        if alert_fingerprint and alert_fingerprint in self._seen:
            return {"emit": False, "reason": "duplicate", "budget_count": len(self._recent)}
        previous = self._last_by_key.get(key)
        if previous is not None and now - previous < self.cooldown_seconds:
            return {"emit": False, "reason": "cooldown", "budget_count": len(self._recent)}
        while self._recent and now - self._recent[0] >= self.budget_seconds:
            self._recent.popleft()
        if len(self._recent) >= self.budget_alerts:
            return {"emit": False, "reason": "interrupt_budget", "budget_count": len(self._recent)}
        self._recent.append(now)
        self._last_by_key[key] = now
        if alert_fingerprint:
            self._seen.add(alert_fingerprint)
        return {"emit": True, "reason": "emitted", "budget_count": len(self._recent)}
