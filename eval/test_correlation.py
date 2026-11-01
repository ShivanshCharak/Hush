"""Unit and integration tests for the Temporal Attack-Chain Correlation Engine."""
import unittest
from decider.correlation import TemporalCorrelationEngine, ATTACK_STAGE_MAPPING

class TemporalCorrelationTests(unittest.TestCase):
    def test_single_event_correlation(self):
        engine = TemporalCorrelationEngine()
        ev = {
            "event_id": 1,
            "timestamp": "2025-09-01T10:00:00Z",
            "src_ip": "198.51.100.42",
            "username": "admin",
            "session_id": "sess_1",
            "path": "/admin/config",
            "status": 404,
            "method": "GET"
        }
        alert = engine.process_detection(ev, kind="scanner_recon")
        # Single event should be tracked but not trigger a multi-stage compound alert
        self.assertIsNone(alert)
        chains = engine.get_all_chains()
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["entity_value"], "198.51.100.42")
        self.assertEqual(chains[0]["stage_count"], 1)
        self.assertGreater(chains[0]["risk_score"], 0)

    def test_multi_stage_attack_chain_escalation(self):
        engine = TemporalCorrelationEngine(min_chain_score_alert=40.0)
        ip = "203.0.113.99"
        
        # 1. Reconnaissance event at 10:00:00
        ev1 = {
            "event_id": 101,
            "timestamp": "2025-09-01T10:00:00Z",
            "src_ip": ip,
            "path": "/.env",
            "status": 404,
            "method": "GET"
        }
        alert1 = engine.process_detection(ev1, kind="scanner_recon")
        self.assertIsNone(alert1)

        # 2. Brute-force attempt at 10:02:00 (2 mins later)
        ev2 = {
            "event_id": 102,
            "timestamp": "2025-09-01T10:02:00Z",
            "src_ip": ip,
            "username": "root",
            "path": "/api/login",
            "status": 401,
            "method": "POST"
        }
        alert2 = engine.process_detection(ev2, kind="brute_force")
        self.assertIsNotNone(alert2)
        self.assertEqual(alert2["alert_type"], "TEMPORAL_ATTACK_CHAIN")
        self.assertEqual(alert2["distinct_tactics"], 2)
        self.assertIn("Reconnaissance leading to Brute Force", alert2["campaigns"])
        self.assertGreaterEqual(alert2["risk_score"], 40.0)

        # 3. Privilege escalation attempt at 10:04:00 (2 mins later)
        ev3 = {
            "event_id": 103,
            "timestamp": "2025-09-01T10:04:00Z",
            "src_ip": ip,
            "username": "root",
            "path": "/api/users/1/profile",
            "status": 200,
            "method": "PUT"
        }
        alert3 = engine.process_detection(ev3, kind="priv_esc")
        self.assertIsNotNone(alert3)
        self.assertTrue(any("Full Kill-Chain" in c for c in alert3["campaigns"]))
        self.assertGreaterEqual(alert3["risk_score"], 70.0)

        # Check graph export structure
        graph = engine.export_graph_data()
        self.assertGreaterEqual(len(graph["nodes"]), 4) # 1 entity + 3 stages
        self.assertGreaterEqual(len(graph["edges"]), 3)

    def test_ttl_window_separation(self):
        engine = TemporalCorrelationEngine(window_ttl_seconds=3600.0)
        ev1 = {
            "event_id": 201,
            "timestamp": "2025-09-01T08:00:00Z",
            "src_ip": "192.0.2.1",
            "path": "/etc/passwd",
            "status": 404
        }
        engine.process_detection(ev1, kind="path_traversal")
        chain = engine.active_chains["ip:192.0.2.1"]
        self.assertEqual(chain.status, "active")

    def test_constant_attacks_from_one_ip_not_considered_chain(self):
        """Constant/repetitive attacks from an IP should not be classified as a multi-stage chain."""
        engine = TemporalCorrelationEngine()
        ip = "192.0.2.55"

        # Repeated brute-force attacks across consecutive windows
        for idx in range(4):
            ev = {
                "event_id": 300 + idx,
                "timestamp": 1756713600.0 + (idx * 60.0),
                "src_ip": ip,
                "username": "admin",
                "path": "/api/login",
                "status": 401,
            }
            alert = engine.process_detection(ev, kind="brute_force")
            # Must not trigger an escalated attack chain alert
            self.assertIsNone(alert)

        chain = engine.active_chains[f"ip:{ip}"]
        self.assertTrue(chain.is_constant_attacker)
        self.assertEqual(chain.status, "constant_attacks")
        # Must not be returned in escalated chains
        escalated = engine.get_all_chains(only_escalated=True)
        self.assertEqual(len(escalated), 0)

    def test_synthetic_simulation_chain_at_start(self):
        """Verify that simulation mode provides exactly one clean multi-stage chain at the start."""
        engine = TemporalCorrelationEngine(include_simulation_chain=True, simulation_start_time=1756713600.0)
        chains = engine.get_all_chains(only_escalated=True)
        self.assertEqual(len(chains), 1)
        self.assertEqual(chains[0]["entity_value"], "198.51.100.99")
        self.assertEqual(chains[0]["status"], "escalated")
        self.assertIn("Full Kill-Chain: Recon -> Brute Force -> Privilege Escalation", chains[0]["detected_campaigns"])
        graph = engine.export_graph_data()
        self.assertEqual(len(graph["nodes"]), 4)  # 1 entity + 3 stages
        self.assertEqual(len(graph["edges"]), 3)


if __name__ == "__main__":
    unittest.main()
