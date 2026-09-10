"""
Unit Tests for SentinelAI DriftSentinel
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.drift_sentinel import DriftSentinel

class TestDriftSentinel(unittest.TestCase):

    def setUp(self):
        self.baseline_eval = {
            "score": 95,
            "target": "enterprise-org/core-api",
            "checks": [
                {"code": "CC8.1", "name": "Branch Protection", "desc": "Active", "status": "PASS"},
                {"code": "CC6.1", "name": "Security Policy", "desc": "Active", "status": "PASS"},
                {"code": "CC7.1", "name": "Vulnerability Management", "desc": "Active", "status": "PASS"}
            ],
            "remediations": []
        }

        self.degraded_eval = {
            "score": 65,
            "target": "enterprise-org/core-api",
            "checks": [
                {"code": "CC8.1", "name": "Branch Protection", "desc": "Branch protection removed", "status": "FAIL"},
                {"code": "CC6.1", "name": "Security Policy", "desc": "Active", "status": "PASS"},
                {"code": "CC7.1", "name": "Vulnerability Management", "desc": "3 new high CVEs detected", "status": "WARN"}
            ],
            "remediations": ["Enable branch protection on main", "Fix dependency CVEs"]
        }

    def test_detect_drift_regression(self):
        report = DriftSentinel.detect_drift(self.baseline_eval, self.degraded_eval)
        self.assertTrue(report["has_drift"])
        self.assertEqual(report["severity"], "CRITICAL")
        self.assertEqual(report["score_delta"], -30)
        self.assertEqual(len(report["regressions"]), 2)
        
        # Branch protection regression should be CRITICAL
        bp_reg = next(r for r in report["regressions"] if r["code"] == "CC8.1")
        self.assertEqual(bp_reg["severity"], "CRITICAL")
        self.assertEqual(bp_reg["from_status"], "PASS")
        self.assertEqual(bp_reg["to_status"], "FAIL")

    def test_detect_drift_resolution(self):
        resolved_eval = dict(self.baseline_eval)
        resolved_eval["score"] = 100
        report = DriftSentinel.detect_drift(self.degraded_eval, resolved_eval)
        self.assertTrue(report["has_drift"])
        self.assertEqual(report["severity"], "RESOLVED")
        self.assertEqual(report["score_delta"], 35)
        self.assertEqual(len(report["resolutions"]), 2)

    def test_slack_payload_format(self):
        report = DriftSentinel.detect_drift(self.baseline_eval, self.degraded_eval)
        payload = DriftSentinel.build_slack_payload(report)
        self.assertIn("blocks", payload)
        self.assertTrue(len(payload["blocks"]) >= 4)
        
        # Check that header contains CRITICAL alert emoji
        header_text = payload["blocks"][0]["text"]["text"]
        self.assertIn("🚨", header_text)
        self.assertIn("enterprise-org/core-api", header_text)

    def test_discord_payload_format(self):
        report = DriftSentinel.detect_drift(self.baseline_eval, self.degraded_eval)
        payload = DriftSentinel.build_discord_payload(report)
        self.assertIn("embeds", payload)
        embed = payload["embeds"][0]
        self.assertEqual(embed["color"], 0xef4444)  # Red for critical

    def test_remediation_script_generation(self):
        report = DriftSentinel.detect_drift(self.baseline_eval, self.degraded_eval)
        script = DriftSentinel.generate_remediation_script(report)
        self.assertIn("#!/usr/bin/env bash", script)
        self.assertIn("gh api --method PUT", script)
        self.assertIn("repos/$REPO/branches/$BRANCH/protection", script)

if __name__ == "__main__":
    unittest.main()
