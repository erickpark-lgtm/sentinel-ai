"""
Unit Tests for SentinelAI Policy-as-Code Generator
"""

import os
import sys
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.policy_generator import PolicyGenerator

class TestPolicyGenerator(unittest.TestCase):

    def test_generate_all_policies(self):
        policies = PolicyGenerator.generate_all_policies(
            org_name="HyperScale Systems Inc.",
            ciso_name="Alex Mercer, vCISO"
        )
        self.assertEqual(len(policies), 5)
        
        codes = [p["code"] for p in policies]
        self.assertIn("POL-WISP-01", codes)
        self.assertIn("POL-AC-02", codes)
        self.assertIn("POL-VM-03", codes)
        self.assertIn("POL-CM-04", codes)
        self.assertIn("POL-VR-05", codes)

        for p in policies:
            self.assertIn("HyperScale Systems Inc.", p["markdown"])
            self.assertIn("Alex Mercer, vCISO", p["markdown"])
            self.assertTrue(len(p["markdown"]) > 200)

    def test_compile_policy_pack_html(self):
        policies = PolicyGenerator.generate_all_policies(org_name="Acme Tech")
        html_doc = PolicyGenerator.compile_policy_pack_html(policies, org_name="Acme Tech")
        
        self.assertIn("INSTITUTIONAL INFORMATION SECURITY POLICY PACK", html_doc)
        self.assertIn("Acme Tech", html_doc)
        self.assertIn("POL-WISP-01", html_doc)
        self.assertIn("POL-VR-05", html_doc)
        self.assertIn("CRYPTOGRAPHIC AUDIT SEAL", html_doc)

if __name__ == "__main__":
    unittest.main()
