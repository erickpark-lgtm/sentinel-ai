"""
Unit Tests for SentinelAI Compliance Audit Engine
"""

import os
import sys
import unittest

# Ensure engine package directory is on sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler

class TestSentinelAuditEngine(unittest.TestCase):

    def test_passing_audit_evaluation(self):
        sample_pass_data = {
            "success": True,
            "target": "acme/enterprise-app",
            "default_branch": "main",
            "is_private": False,
            "has_license": True,
            "branch_protection": {
                "active": True,
                "pr_reviews_required": True,
                "approving_review_count": 2,
                "require_signed_commits": True
            },
            "security_governance": {
                "has_security_policy": True,
                "has_ci_workflows": True,
                "dependabot_active": True,
                "critical_cve_count": 0
            }
        }
        result = ScoreCalculator.evaluate(sample_pass_data)
        self.assertEqual(result["score"], 100)
        self.assertEqual(result["status"], "SOC 2 Type 2 Audit Ready")
        self.assertEqual(result["status_class"], "tag-pass")
        self.assertEqual(len(result["checks"]), 5)

    def test_failing_audit_evaluation(self):
        sample_fail_data = {
            "success": True,
            "target": "acme/vulnerable-app",
            "default_branch": "main",
            "is_private": False,
            "has_license": False,
            "branch_protection": {
                "active": False,
                "pr_reviews_required": False
            },
            "security_governance": {
                "has_security_policy": False,
                "has_ci_workflows": False,
                "dependabot_active": False,
                "critical_cve_count": 3
            }
        }
        result = ScoreCalculator.evaluate(sample_fail_data)
        self.assertLess(result["score"], 50)
        self.assertEqual(result["status_class"], "tag-fail")
        self.assertTrue(len(result["remediations"]) >= 2)

    def test_dossier_compilation(self):
        sample_eval = {
            "score": 95,
            "status": "SOC 2 Type 2 Audit Ready",
            "target": "test-org/test-repo",
            "checks": [
                {"code": "CC8.1", "name": "Branch Protection", "desc": "Passing", "status": "PASS"},
                {"code": "CC6.1", "name": "Security Policy", "desc": "Passing", "status": "PASS"}
            ],
            "remediations": []
        }
        html = DossierCompiler.compile_dossier_html(sample_eval, company_name="Test Corp")
        self.assertIn("INDEPENDENT SERVICE AUDITOR'S EVIDENCE REGISTER", html)
        self.assertIn("Test Corp", html)
        self.assertIn("SHA-256", html)

if __name__ == "__main__":
    unittest.main()
