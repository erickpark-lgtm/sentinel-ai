"""
SentinelAI Compliance Manifest (SSoT: Single Source of Truth)
Centralizes AICPA Trust Services Criteria (CC1 to CC9), binding SLAs, scoring weights, and governance thresholds.
Synchronizes policy generation, audit scoring, and continuous drift monitoring.
"""

from typing import Dict, Any

COMPLIANCE_MANIFEST: Dict[str, Any] = {
    "standard": "AICPA SOC 2 Type 2 / Trust Services Criteria (2017 with 2022 Revisions)",
    "version": "2026.3-ENTERPRISE",
    
    # -------------------------------------------------------------
    # Binding Remediation SLAs (Service Level Agreements)
    # -------------------------------------------------------------
    "remediation_slas": {
        "CRITICAL": {
            "cvss_range": "9.0 - 10.0",
            "resolution_window": "48 Hours",
            "hours": 48,
            "escalation": "Immediate vCISO & CTO Notification",
            "severity_label": "Critical"
        },
        "HIGH": {
            "cvss_range": "7.0 - 8.9",
            "resolution_window": "7 Calendar Days",
            "hours": 168,
            "escalation": "Engineering Lead & SecOps Review",
            "severity_label": "High"
        },
        "MEDIUM": {
            "cvss_range": "4.0 - 6.9",
            "resolution_window": "30 Calendar Days",
            "hours": 720,
            "escalation": "Standard Sprint Cycle Backlog",
            "severity_label": "Medium"
        },
        "LOW": {
            "cvss_range": "0.1 - 3.9",
            "resolution_window": "90 Calendar Days",
            "hours": 2160,
            "escalation": "Quarterly Maintenance Cycle",
            "severity_label": "Low"
        }
    },

    # -------------------------------------------------------------
    # Trust Services Criteria Controls, Weights & Requirements
    # -------------------------------------------------------------
    "controls": {
        "CC8.1": {
            "name": "Branch Protection & Peer Reviews",
            "category": "Change Management & Secure SDLC",
            "weight": 30,
            "required_approvals": 1,
            "dismiss_stale_reviews": True,
            "enforce_admins": True,
            "policy_id": "POL-CM-04"
        },
        "CC7.1": {
            "name": "Vulnerability Management & CI/CD Security",
            "category": "System Operations & Defect Detection",
            "weight": 25,
            "ci_workflows_required": True,
            "allow_critical_cves": 0,
            "policy_id": "POL-VM-03"
        },
        "CC6.1": {
            "name": "Security Policy & Governance Disclosure",
            "category": "Logical & Physical Access Controls",
            "weight": 20,
            "required_file": "SECURITY.md",
            "mfa_mandate": "Hardware FIDO2 / TOTP",
            "policy_id": "POL-AC-02"
        },
        "CC6.6": {
            "name": "Code Provenance & Cryptographic Signatures",
            "category": "Boundary Protection & Data In-Transit",
            "weight": 15,
            "signed_commits_recommended": True,
            "policy_id": "POL-WISP-01"
        },
        "CC9.2": {
            "name": "Third-Party Vendor Risk & CUEC Mapping",
            "category": "Supply Chain & Risk Mitigation",
            "weight": 10,
            "annual_review_cadence": "Annual / Triggered",
            "policy_id": "POL-VR-05"
        }
    },

    # -------------------------------------------------------------
    # Audit Readiness Grading Scale
    # -------------------------------------------------------------
    "grading_scale": {
        "PASS": {
            "min_score": 90,
            "status": "SOC 2 Type 2 Audit Ready",
            "css_class": "tag-pass"
        },
        "WARN": {
            "min_score": 70,
            "status": "Moderate Audit Gap Detected",
            "css_class": "tag-warn"
        },
        "FAIL": {
            "min_score": 0,
            "status": "Critical Audit Risk (Action Required)",
            "css_class": "tag-fail"
        }
    }
}

class ComplianceManifest:
    """Helper methods for querying the compliance manifest."""

    @classmethod
    def get_sla(cls, severity: str) -> Dict[str, Any]:
        return COMPLIANCE_MANIFEST["remediation_slas"].get(severity.upper(), COMPLIANCE_MANIFEST["remediation_slas"]["MEDIUM"])

    @classmethod
    def get_control(cls, code: str) -> Dict[str, Any]:
        return COMPLIANCE_MANIFEST["controls"].get(code, {})

    @classmethod
    def determine_status(cls, score: int) -> tuple[str, str]:
        scale = COMPLIANCE_MANIFEST["grading_scale"]
        if score >= scale["PASS"]["min_score"]:
            return scale["PASS"]["status"], scale["PASS"]["css_class"]
        elif score >= scale["WARN"]["min_score"]:
            return scale["WARN"]["status"], scale["WARN"]["css_class"]
        return scale["FAIL"]["status"], scale["FAIL"]["css_class"]
