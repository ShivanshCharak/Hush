"""Temporal Attack-Chain Correlation Engine for Decider-Sec (Hush).

Tracks entities (IP, user, session) across sliding temporal windows, correlates
multi-stage event sequences into dynamic attack graphs, maps them to MITRE ATT&CK
tactics/techniques, and computes accumulated risk scores while suppressing
constant/repetitive attacks from being misclassified as attack chains.
"""
from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
import json
from typing import Any, Dict, List, Optional, Set, Tuple

# MITRE ATT&CK Matrix mapping for Decider-Sec detected attack types & indicators
ATTACK_STAGE_MAPPING: dict[str, dict[str, Any]] = {
    "scanner_recon": {
        "tactic": "Reconnaissance",
        "tactic_id": "TA0043",
        "technique": "Active Scanning",
        "technique_id": "T1595",
        "stage_rank": 1,
        "base_score": 15.0,
    },
    "path_traversal": {
        "tactic": "Discovery",
        "tactic_id": "TA0007",
        "technique": "File and Directory Discovery",
        "technique_id": "T1083",
        "stage_rank": 2,
        "base_score": 30.0,
    },
    "brute_force": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force: Password Guessing",
        "technique_id": "T1110.001",
        "stage_rank": 2,
        "base_score": 35.0,
    },
    "credential_stuffing": {
        "tactic": "Credential Access",
        "tactic_id": "TA0006",
        "technique": "Brute Force: Credential Stuffing",
        "technique_id": "T1110.004",
        "stage_rank": 2,
        "base_score": 40.0,
    },
    "sqli": {
        "tactic": "Initial Access / Exploitation",
        "tactic_id": "TA0001",
        "technique": "Exploit Public-Facing Application",
        "technique_id": "T1190",
        "stage_rank": 3,
        "base_score": 45.0,
    },
    "xss": {
        "tactic": "Execution",
        "tactic_id": "TA0002",
        "technique": "User Execution: Malicious Link/Content",
        "technique_id": "T1204",
        "stage_rank": 3,
        "base_score": 35.0,
    },
    "priv_esc": {
        "tactic": "Privilege Escalation",
        "tactic_id": "TA0004",
        "technique": "Exploitation for Privilege Escalation",
        "technique_id": "T1068",
        "stage_rank": 4,
        "base_score": 50.0,
    },
    "data_exfil": {
        "tactic": "Exfiltration",
        "tactic_id": "TA0010",
        "technique": "Exfiltration Over Web Service",
        "technique_id": "T1567",
        "stage_rank": 5,
        "base_score": 55.0,
    },
}

# Compound chain progressions that represent confirmed multi-stage campaigns
CAMPAIGN_PATTERNS = [
    # Recon -> Credential Access
    (["scanner_recon", "brute_force"], "Reconnaissance leading to Brute Force", 25.0),
    # Recon -> Exploitation
    (["scanner_recon", "sqli"], "Targeted Vulnerability Scan followed by SQL Injection", 35.0),
    (["scanner_recon", "path_traversal"], "Directory Probe followed by Path Traversal", 30.0),
    # Credential Access -> Privilege Escalation
    (["brute_force", "priv_esc"], "Account Compromise escalated to Admin Privileges", 45.0),
    (["credential_stuffing", "priv_esc"], "Stuffed Credential compromise followed by Privilege Escalation", 50.0),
    # Exploitation -> PrivEsc
    (["sqli", "priv_esc"], "Application Breach leading to Privilege Escalation", 50.0),
    # Complete Multi-Stage Attack Chain (Recon -> Access -> PrivEsc)
    (["scanner_recon", "brute_force", "priv_esc"], "Full Kill-Chain: Recon -> Brute Force -> Privilege Escalation", 60.0),
    (["scanner_recon", "sqli", "priv_esc"], "Full Kill-Chain: Recon -> Web Exploitation -> Privilege Escalation", 65.0),
]


def parse_timestamp(ts: Any, fallback: float = 0.0) -> float:
    if isinstance(ts, (int, float)):
        return float(ts)
    if not ts:
        return fallback
    try:
        dt = datetime.fromisoformat(str(ts).replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, TypeError):
        return fallback


@dataclass
class StageEvent:
    event_id: Any
    timestamp: float
    kind: str
    tactic: str
    tactic_id: str
    technique: str
    technique_id: str
    stage_rank: int
    src_ip: str
    username: str
    path: str
    status: int
    raw_details: Dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "event_id": self.event_id,
            "timestamp": self.timestamp,
            "iso_time": datetime.fromtimestamp(self.timestamp, tz=timezone.utc).isoformat(),
            "kind": self.kind,
            "tactic": self.tactic,
            "tactic_id": self.tactic_id,
            "technique": self.technique,
            "technique_id": self.technique_id,
            "stage_rank": self.stage_rank,
            "src_ip": self.src_ip,
            "username": self.username,
            "path": self.path,
            "status": self.status,
        }


@dataclass
class AttackChain:
    chain_id: str
    entity_type: str  # "ip", "user", "session"
    entity_value: str
    start_time: float
    last_seen: float
    stages: List[StageEvent] = field(default_factory=list)
    detected_campaigns: List[str] = field(default_factory=list)
    risk_score: float = 0.0
    status: str = "active"  # "active", "escalated", "constant_attacks", "dormant"
    is_constant_attacker: bool = False

    def to_dict(self) -> dict[str, Any]:
        unique_kinds = list(dict.fromkeys(s.kind for s in self.stages))
        unique_tactics = list(dict.fromkeys(f"{s.tactic} ({s.tactic_id})" for s in self.stages))
        return {
            "chain_id": self.chain_id,
            "entity_type": self.entity_type,
            "entity_value": self.entity_value,
            "duration_seconds": round(max(0.0, self.last_seen - self.start_time), 2),
            "start_time": datetime.fromtimestamp(self.start_time, tz=timezone.utc).isoformat(),
            "last_seen": datetime.fromtimestamp(self.last_seen, tz=timezone.utc).isoformat(),
            "stage_count": len(self.stages),
            "unique_attack_types": unique_kinds,
            "mitre_tactics": unique_tactics,
            "detected_campaigns": self.detected_campaigns,
            "risk_score": round(self.risk_score, 1),
            "status": self.status,
            "is_constant_attacker": self.is_constant_attacker,
            "timeline": [s.to_dict() for s in self.stages],
        }


class TemporalCorrelationEngine:
    """Stateful stream processor tracking entity progression across sliding temporal windows."""

    def __init__(
        self,
        window_ttl_seconds: float = 3600.0,  # 1 hour correlation TTL
        min_chain_score_alert: float = 40.0,
        max_stage_gap_seconds: float = 300.0,  # 5 minutes max gap between consecutive chain stages
        max_chain_duration_seconds: float = 600.0,  # 10 minutes max duration for a kill-chain
        max_chain_stages: int = 5,  # Exceeding 5 stages indicates a continuous/constant attacker
        include_simulation_chain: bool = False,
        simulation_start_time: Optional[float] = None,
    ) -> None:
        self.window_ttl_seconds = window_ttl_seconds
        self.min_chain_score_alert = min_chain_score_alert
        self.max_stage_gap_seconds = max_stage_gap_seconds
        self.max_chain_duration_seconds = max_chain_duration_seconds
        self.max_chain_stages = max_chain_stages
        # Key: entity (e.g., "ip:192.168.1.50") -> AttackChain
        self.active_chains: Dict[str, AttackChain] = {}
        # Entity resolution cross-mappings (IP <-> username, session <-> IP)
        self.ip_to_users: Dict[str, Set[str]] = defaultdict(set)
        self.user_to_ips: Dict[str, Set[str]] = defaultdict(set)
        self.session_to_ip: Dict[str, str] = {}
        # Emitted alert records
        self.completed_alerts: List[Dict[str, Any]] = []

        if include_simulation_chain:
            self.inject_synthetic_simulation_chain(simulation_start_time or 0.0)

    def inject_synthetic_simulation_chain(self, start_timestamp: float = 0.0) -> Dict[str, Any]:
        """Inject a clean, synthetic multi-stage attack chain at the start of the simulation.

        This demonstrates a textbook kill-chain: Recon -> Credential Access -> Privilege Escalation
        from a dedicated simulated attacker IP (198.51.100.99) within 65 seconds.
        """
        ip = "198.51.100.99"
        ts = start_timestamp if start_timestamp > 0 else 1756713600.0  # default 2025-09-01T08:00:00Z
        events = [
            {
                "event_id": "sim_01",
                "timestamp": ts + 15.0,
                "src_ip": ip,
                "username": "",
                "method": "GET",
                "path": "/.env",
                "status": 404,
                "kind": "scanner_recon",
                "confidence": 0.95,
            },
            {
                "event_id": "sim_02",
                "timestamp": ts + 45.0,
                "src_ip": ip,
                "username": "root",
                "method": "POST",
                "path": "/api/login",
                "status": 401,
                "kind": "brute_force",
                "confidence": 0.90,
            },
            {
                "event_id": "sim_03",
                "timestamp": ts + 75.0,
                "src_ip": ip,
                "username": "root",
                "method": "PUT",
                "path": "/api/users/1/profile",
                "status": 200,
                "kind": "priv_esc",
                "confidence": 0.92,
            },
        ]
        last_alert = None
        for ev in events:
            last_alert = self.process_detection(
                ev,
                kind=ev["kind"],
                confidence=ev["confidence"],
                event_time=ev["timestamp"],
            )
        return last_alert or {}

    def _prune_expired(self, current_time: float) -> None:
        """Prune or transition dormant chains past TTL."""
        expired = []
        for key, chain in self.active_chains.items():
            if current_time - chain.last_seen > self.window_ttl_seconds:
                chain.status = "dormant"
                expired.append(key)

    def _check_constant_attacker(self, chain: AttackChain) -> bool:
        """Determine if an entity is conducting constant/repetitive attacks rather than a chain attack."""
        if len(chain.stages) <= 1:
            return False

        duration = chain.last_seen - chain.start_time
        kind_counts = Counter(s.kind for s in chain.stages)
        unique_kinds = len(kind_counts)

        # 1. Repeated attacks of the same type (constant brute force or constant scanning)
        if unique_kinds == 1 and len(chain.stages) >= 2:
            return True

        # 2. Heavy repetition of one attack kind without progression balance
        if max(kind_counts.values()) >= 3 and unique_kinds < 3:
            return True

        # 3. Attacks spanning excessive duration (e.g. constant attacks over 10+ minutes)
        if duration > self.max_chain_duration_seconds:
            return True

        # 4. Exceeding max allowable stages for a focused kill chain (indicates bot or persistent probing)
        if len(chain.stages) > self.max_chain_stages:
            return True

        # 5. Large temporal gap between consecutive stages (broken chain)
        for i in range(len(chain.stages) - 1):
            gap = chain.stages[i + 1].timestamp - chain.stages[i].timestamp
            if gap > self.max_stage_gap_seconds:
                return True

        return False

    def _match_campaigns(self, stages: List[StageEvent]) -> Tuple[List[str], float]:
        """Check if sequence of events matches known progressive attack patterns."""
        if len(stages) < 2:
            return [], 0.0

        kinds_in_order = [s.kind for s in stages]
        campaigns = []
        bonus_score = 0.0

        for pattern, description, bonus in CAMPAIGN_PATTERNS:
            # Check subsequence match in order
            p_idx = 0
            for k in kinds_in_order:
                if k == pattern[p_idx]:
                    p_idx += 1
                    if p_idx == len(pattern):
                        campaigns.append(description)
                        bonus_score += bonus
                        break
        return campaigns, bonus_score

    def _calculate_chain_score(self, chain: AttackChain) -> float:
        """Calculate dynamic multi-factor risk score."""
        if not chain.stages:
            return 0.0

        if chain.is_constant_attacker:
            return 10.0

        # 1. Base scores from distinct MITRE stages
        kinds = set()
        base_total = 0.0
        for s in chain.stages:
            if s.kind not in kinds:
                kinds.add(s.kind)
                meta = ATTACK_STAGE_MAPPING.get(s.kind, {})
                base_total += meta.get("base_score", 10.0)

        # 2. Stage diversity multiplier (Recon + Access + PrivEsc > multiple Recon events)
        diversity_factor = 1.0 + (len(kinds) - 1) * 0.35

        # 3. Campaign progression bonus
        campaigns, campaign_bonus = self._match_campaigns(chain.stages)
        chain.detected_campaigns = campaigns

        # 4. Temporal proximity weight (attacks completed quickly get higher urgency)
        duration = max(1.0, chain.last_seen - chain.start_time)
        velocity_multiplier = 1.15 if duration <= 300 else 1.0  # within 5 mins

        raw_score = ((base_total * diversity_factor) + campaign_bonus) * velocity_multiplier
        return min(100.0, raw_score)

    def process_detection(
        self,
        event: Dict[str, Any],
        kind: str,
        confidence: Optional[float] = None,
        event_time: Optional[float] = None,
    ) -> Optional[Dict[str, Any]]:
        """Feed a detected event into the temporal correlation engine.

        Returns an attack chain compound alert if threshold/stage criteria met.
        Suppresses alerts if the entity exhibits constant/repetitive attack behavior.
        """
        if not kind or kind == "none":
            return None

        event_id = event.get("event_id")
        ts = event_time if event_time is not None else parse_timestamp(event.get("timestamp"))
        self._prune_expired(ts)

        ip = str(event.get("src_ip") or "unknown")
        user = str(event.get("username") or "")
        session = str(event.get("session_id") or "")
        path = str(event.get("path") or "")
        status = int(event.get("status") or 0)

        # Entity resolution links
        if ip != "unknown" and user:
            self.ip_to_users[ip].add(user)
            self.user_to_ips[user].add(ip)
        if session and ip != "unknown":
            self.session_to_ip[session] = ip

        # Retrieve attack mapping metadata
        meta = ATTACK_STAGE_MAPPING.get(
            kind,
            {
                "tactic": "Generic Attack",
                "tactic_id": "TA0000",
                "technique": "Suspicious Activity",
                "technique_id": "T0000",
                "stage_rank": 1,
                "base_score": 10.0,
            },
        )

        stage_ev = StageEvent(
            event_id=event_id,
            timestamp=ts,
            kind=kind,
            tactic=meta["tactic"],
            tactic_id=meta["tactic_id"],
            technique=meta["technique"],
            technique_id=meta["technique_id"],
            stage_rank=meta["stage_rank"],
            src_ip=ip,
            username=user,
            path=path,
            status=status,
            raw_details={"method": event.get("method"), "confidence": confidence},
        )

        # Primary correlation key: IP; secondary fallback: username or session
        entity_type = "ip"
        entity_val = ip
        if entity_val == "unknown" and user:
            entity_type = "user"
            entity_val = user
        elif entity_val == "unknown" and session:
            entity_type = "session"
            entity_val = session

        chain_key = f"{entity_type}:{entity_val}"

        # Initialize or append to entity's chain
        if chain_key not in self.active_chains:
            self.active_chains[chain_key] = AttackChain(
                chain_id=f"chain_{entity_type}_{abs(hash(chain_key)) % 1000000}",
                entity_type=entity_type,
                entity_value=entity_val,
                start_time=ts,
                last_seen=ts,
                stages=[stage_ev],
            )
        else:
            chain = self.active_chains[chain_key]
            chain.last_seen = ts
            # Avoid duplicate spam of exact same event ID
            if not any(s.event_id == event_id for s in chain.stages):
                chain.stages.append(stage_ev)

        current_chain = self.active_chains[chain_key]

        # Check if this entity is exhibiting constant/repetitive attacks
        if self._check_constant_attacker(current_chain):
            current_chain.is_constant_attacker = True
            current_chain.status = "constant_attacks"
            current_chain.risk_score = 10.0
            return None

        current_chain.risk_score = self._calculate_chain_score(current_chain)

        # Evaluate if compound alert conditions are satisfied
        unique_stages = len({s.stage_rank for s in current_chain.stages})
        if (
            not current_chain.is_constant_attacker
            and current_chain.risk_score >= self.min_chain_score_alert
            and unique_stages >= 2
            and bool(current_chain.detected_campaigns)
        ):
            current_chain.status = "escalated"
            alert = {
                "alert_type": "TEMPORAL_ATTACK_CHAIN",
                "chain_id": current_chain.chain_id,
                "entity": f"{current_chain.entity_type}={current_chain.entity_value}",
                "risk_score": current_chain.risk_score,
                "stages_count": len(current_chain.stages),
                "distinct_tactics": len({s.tactic for s in current_chain.stages}),
                "campaigns": current_chain.detected_campaigns,
                "summary": (
                    f"Multi-stage attack chain detected for {current_chain.entity_value}: "
                    f"{' -> '.join(dict.fromkeys(s.kind for s in current_chain.stages))} "
                    f"(Score: {current_chain.risk_score:.1f}/100)"
                ),
                "chain": current_chain.to_dict(),
            }
            return alert

        return None

    def get_all_chains(self, only_escalated: bool = False) -> List[Dict[str, Any]]:
        """Return tracked entity chains. If only_escalated is True, returns only verified escalated attack chains."""
        chains = self.active_chains.values()
        if only_escalated:
            chains = [
                c for c in chains
                if c.status == "escalated" and not c.is_constant_attacker and c.detected_campaigns
            ]
        return [c.to_dict() for c in chains]

    def get_chain(self, chain_id: str) -> Optional[Dict[str, Any]]:
        """Look up a specific attack chain by chain_id."""
        for chain in self.active_chains.values():
            if chain.chain_id == chain_id:
                return chain.to_dict()
        return None

    def export_graph_data(self) -> Dict[str, Any]:
        """Export nodes and directed edges suitable for visualization (Mermaid/D3/Cytoscape)."""
        nodes: List[Dict[str, Any]] = []
        edges: List[Dict[str, Any]] = []
        seen_nodes: Set[str] = set()

        # Only export graphs for verified escalated attack chains
        for chain in self.active_chains.values():
            if chain.status != "escalated" or chain.is_constant_attacker or not chain.detected_campaigns:
                continue

            entity_node_id = f"entity_{chain.entity_value}"
            if entity_node_id not in seen_nodes:
                nodes.append({
                    "id": entity_node_id,
                    "label": f"{chain.entity_type.upper()}: {chain.entity_value}",
                    "type": "entity",
                    "risk_score": chain.risk_score,
                })
                seen_nodes.add(entity_node_id)

            prev_stage_node = None
            for idx, stage in enumerate(chain.stages):
                stage_node_id = f"ev_{chain.chain_id}_{stage.event_id}_{idx}"
                if stage_node_id not in seen_nodes:
                    nodes.append({
                        "id": stage_node_id,
                        "label": f"{stage.kind}\n({stage.tactic})",
                        "type": "stage",
                        "tactic": stage.tactic,
                        "timestamp": stage.timestamp,
                        "path": stage.path,
                        "status": stage.status,
                    })
                    seen_nodes.add(stage_node_id)

                # Connect entity to first event
                if idx == 0:
                    edges.append({
                        "source": entity_node_id,
                        "target": stage_node_id,
                        "relation": "originates_from",
                    })

                # Connect temporal progression between consecutive events
                if prev_stage_node:
                    delta_s = round(stage.timestamp - prev_stage_node[1], 1)
                    edges.append({
                        "source": prev_stage_node[0],
                        "target": stage_node_id,
                        "relation": f"+{delta_s}s",
                    })
                prev_stage_node = (stage_node_id, stage.timestamp)

        return {"nodes": nodes, "edges": edges}
