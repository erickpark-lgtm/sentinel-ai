"""
Unit tests for SentinelAI Outbound Prospecting & Lead-Gen Sentinel.
"""

import unittest
import os
import json
from engine.core.outbound_lead_sentinel import OutboundLeadSentinel

class TestOutboundLeadSentinel(unittest.TestCase):

    def setUp(self):
        self.sentinel = OutboundLeadSentinel()

    def test_search_candidates_returns_list(self):
        candidates = self.sentinel.search_candidates(query="topic:saas", limit=2)
        self.assertIsInstance(candidates, list)
        self.assertGreaterEqual(len(candidates), 1)
        self.assertTrue(all("/" in c for c in candidates))

    def test_audit_and_qualify_generates_remediation_package(self):
        lead = self.sentinel.audit_and_qualify("enterprise-cloud/core-backend")
        self.assertIn("score", lead)
        self.assertIn("lead_tier", lead)
        self.assertIn("urgency", lead)
        self.assertIn("outreach_package", lead)

        pkg = lead["outreach_package"]
        self.assertIn("subject", pkg)
        self.assertIn("remediation_cli", pkg)
        self.assertIn("landing_url", pkg)
        self.assertIn("email_body_markdown", pkg)
        self.assertIn("gh api", pkg["remediation_cli"])

    def test_export_pipeline_to_json(self):
        leads = [self.sentinel.audit_and_qualify("test-org/test-repo")]
        test_file = "temp_prospects_test.json"
        exported = self.sentinel.export_pipeline_to_json(leads, test_file)
        self.assertTrue(os.path.exists(exported))

        with open(exported, "r", encoding="utf-8") as f:
            data = json.load(f)
            self.assertEqual(data["total_leads"], 1)

        if os.path.exists(test_file):
            os.remove(test_file)

if __name__ == "__main__":
    unittest.main()
