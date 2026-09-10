"""
Unit Tests for SentinelAI Compliance Manifest & Heartbeat Watchdog Ledger
"""

import os
import sys
import unittest
import tempfile
import json

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.compliance_manifest import ComplianceManifest, COMPLIANCE_MANIFEST
from core.heartbeat_watchdog import HeartbeatWatchdog

class TestHeartbeatAndManifest(unittest.TestCase):

    def test_compliance_manifest_structure(self):
        # 1. SLAs check
        critical_sla = ComplianceManifest.get_sla("CRITICAL")
        self.assertEqual(critical_sla["hours"], 48)
        self.assertEqual(critical_sla["resolution_window"], "48 Hours")

        high_sla = ComplianceManifest.get_sla("HIGH")
        self.assertEqual(high_sla["hours"], 168)

        # 2. Control check
        cc81 = ComplianceManifest.get_control("CC8.1")
        self.assertEqual(cc81["weight"], 30)
        self.assertEqual(cc81["policy_id"], "POL-CM-04")

        # 3. Grading scale
        status_pass, tag_pass = ComplianceManifest.determine_status(95)
        self.assertEqual(status_pass, "SOC 2 Type 2 Audit Ready")
        self.assertEqual(tag_pass, "tag-pass")

        status_fail, tag_fail = ComplianceManifest.determine_status(55)
        self.assertEqual(status_fail, "Critical Audit Risk (Action Required)")
        self.assertEqual(tag_fail, "tag-fail")

    def test_heartbeat_cryptographic_chain(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            watchdog = HeartbeatWatchdog(ledger_path=tmp_path, daemon_id="test-worker")
            
            # Record 3 sequential blocks
            b0 = watchdog.record_heartbeat("org/repo-a", checks_executed=5)
            self.assertEqual(b0["block_index"], 0)
            self.assertEqual(b0["prev_hash"], HeartbeatWatchdog.GENESIS_HASH)

            b1 = watchdog.record_heartbeat("org/repo-a", checks_executed=5)
            self.assertEqual(b1["block_index"], 1)
            self.assertEqual(b1["prev_hash"], b0["block_hash"])

            b2 = watchdog.record_heartbeat("org/repo-a", checks_executed=5)
            self.assertEqual(b2["block_index"], 2)
            self.assertEqual(b2["prev_hash"], b1["block_hash"])

            # Verify ledger integrity
            integrity = watchdog.verify_ledger_integrity()
            self.assertTrue(integrity["valid"])
            self.assertEqual(integrity["total_blocks"], 3)
            self.assertEqual(integrity["root_hash"], b2["block_hash"])

            # Calculate continuity index
            continuity = watchdog.calculate_continuity_index()
            self.assertTrue(continuity["valid"])
            self.assertEqual(continuity["total_pings_verified"], 3)
            self.assertEqual(continuity["continuity_index"], "99.98%")

            # Test Tamper Detection
            with open(tmp_path, "r", encoding="utf-8") as f:
                lines = f.readlines()
            
            # Modify block 1
            tampered_block = json.loads(lines[1])
            tampered_block["checks_executed"] = 999  # Tamper with count
            lines[1] = json.dumps(tampered_block) + "\n"

            with open(tmp_path, "w", encoding="utf-8") as f:
                f.writelines(lines)

            tamper_check = watchdog.verify_ledger_integrity()
            self.assertFalse(tamper_check["valid"])
            self.assertEqual(tamper_check["broken_index"], 1)

        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
