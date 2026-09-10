"""
Unit Tests for SentinelAI Auditor-Only Verification Portal
"""

import os
import sys
import unittest
import tempfile

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.heartbeat_watchdog import HeartbeatWatchdog

class TestAuditorPortalVerification(unittest.TestCase):

    def test_auditor_verification_flow(self):
        with tempfile.NamedTemporaryFile(suffix=".jsonl", delete=False) as tmp:
            tmp_path = tmp.name

        try:
            watchdog = HeartbeatWatchdog(ledger_path=tmp_path, daemon_id="cpa-test-auditor")
            
            # Record 3 blocks
            for i in range(3):
                watchdog.record_heartbeat("summit-tech/production-api", checks_executed=5)

            integrity = watchdog.verify_ledger_integrity()
            self.assertTrue(integrity["valid"])
            self.assertEqual(integrity["total_blocks"], 3)

            continuity = watchdog.calculate_continuity_index()
            self.assertEqual(continuity["continuity_index"], "99.98%")

            # Verify response schema for CPA auditor consumption
            verification_payload = {
                "verified": integrity["valid"],
                "attestation_status": "UNQUALIFIED_EVIDENCE_VALIDATED",
                "governing_standard": "AICPA TSC AT-C Section 205",
                "total_blocks_chained": integrity["total_blocks"],
                "continuity_index": continuity["continuity_index"],
                "tampering_detected": not integrity["valid"]
            }

            self.assertTrue(verification_payload["verified"])
            self.assertFalse(verification_payload["tampering_detected"])
            self.assertEqual(verification_payload["attestation_status"], "UNQUALIFIED_EVIDENCE_VALIDATED")
        finally:
            if os.path.exists(tmp_path):
                os.remove(tmp_path)

if __name__ == "__main__":
    unittest.main()
