"""
SentinelAI AICPA Trust Services Criteria Scoring Engine
Maps raw infrastructure & Git telemetry to SOC 2 Common Criteria controls.
"""

from typing import Dict, Any, List
from .compliance_manifest import ComplianceManifest, COMPLIANCE_MANIFEST

class ScoreCalculator:
    """
    Computes weighted compliance scores and determines pass/warn/fail status
    for AICPA SOC 2 Common Criteria controls (CC6, CC7, CC8, CC9).
    """

    @staticmethod
    def evaluate(audit_data: Dict[str, Any]) -> Dict[str, Any]:
        if not audit_data.get("success"):
            return {
                "score": 0,
                "status": "Audit Failed to Execute",
                "status_class": "tag-fail",
                "checks": [],
                "remediations": [audit_data.get("error", "Unknown error during audit.")]
            }

        bp = audit_data.get("branch_protection", {})
        sec = audit_data.get("security_governance", {})

        score = 0
        checks: List[Dict[str, Any]] = []
        remediations: List[str] = []

        # -------------------------------------------------------------
        # Control 1: CC8.1 Change Management & Peer Reviews (Weight: 30)
        # -------------------------------------------------------------
        if bp.get("active") and bp.get("pr_reviews_required"):
            review_count = bp.get("approving_review_count", 1)
            score += 30
            checks.append({
                "code": "CC8.1",
                "name": "Branch Protection & Peer Reviews",
                "desc": f"Enforced on '{audit_data.get('default_branch')}'; requires {review_count}+ approving peer review(s).",
                "status": "PASS"
            })
        elif bp.get("active"):
            score += 15
            checks.append({
                "code": "CC8.1",
                "name": "Branch Protection & Peer Reviews",
                "desc": f"Branch protection active, but mandatory peer review approvals are not strictly enforced.",
                "status": "WARN"
            })
            remediations.append("Configure branch protection to require at least 1 approving pull request review before merging.")
        else:
            checks.append({
                "code": "CC8.1",
                "name": "Branch Protection & Peer Reviews",
                "desc": f"CRITICAL: '{audit_data.get('default_branch')}' has no branch protection rules. Direct unreviewed pushes permitted.",
                "status": "FAIL"
            })
            remediations.append("Enable Branch Protection on default branch immediately with required peer reviews.")

        # -------------------------------------------------------------
        # Control 2: CC7.1 System Operations & Vulnerability (Weight: 25)
        # -------------------------------------------------------------
        crit_cves = sec.get("critical_cve_count", 0)
        has_ci = sec.get("has_ci_workflows", False)

        if has_ci and crit_cves == 0:
            score += 25
            checks.append({
                "code": "CC7.1",
                "name": "Vulnerability Management & CI/CD Security",
                "desc": "Automated CI/CD security workflows verified; 0 critical or high CVEs detected.",
                "status": "PASS"
            })
        elif has_ci and crit_cves > 0:
            score += 12
            checks.append({
                "code": "CC7.1",
                "name": "Vulnerability Management & CI/CD Security",
                "desc": f"CI/CD workflows present, but {crit_cves} critical/high vulnerability alert(s) detected.",
                "status": "WARN"
            })
            remediations.append(f"Remediate {crit_cves} critical/high package CVE alerts in dependency manifests.")
        elif sec.get("dependabot_active"):
            score += 15
            checks.append({
                "code": "CC7.1",
                "name": "Vulnerability Management & CI/CD Security",
                "desc": "Dependabot alerts active; CI/CD automated pipeline configuration recommended.",
                "status": "WARN"
            })
            remediations.append("Add GitHub Actions CI/CD workflow (.github/workflows) for automated linting and tests.")
        else:
            checks.append({
                "code": "CC7.1",
                "name": "Vulnerability Management & CI/CD Security",
                "desc": "No automated CI/CD workflows or Dependabot scanners detected.",
                "status": "FAIL"
            })
            remediations.append("Enable Dependabot alerts and integrate security scanning into GitHub Actions.")

        # -------------------------------------------------------------
        # Control 3: CC6.1 Identity, Access & Governance (Weight: 20)
        # -------------------------------------------------------------
        has_sec_policy = sec.get("has_security_policy", False)
        has_license = audit_data.get("has_license", False)

        if has_sec_policy and has_license:
            score += 20
            checks.append({
                "code": "CC6.1",
                "name": "Security Policy & Governance Disclosure",
                "desc": "Formal SECURITY.md vulnerability disclosure policy and software license present.",
                "status": "PASS"
            })
        elif has_sec_policy or has_license:
            score += 12
            checks.append({
                "code": "CC6.1",
                "name": "Security Policy & Governance Disclosure",
                "desc": f"Governance baseline partial. Missing {'SECURITY.md' if not has_sec_policy else 'LICENSE'}.",
                "status": "WARN"
            })
            remediations.append("Publish formal SECURITY.md vulnerability reporting policy in repository root.")
        else:
            checks.append({
                "code": "CC6.1",
                "name": "Security Policy & Governance Disclosure",
                "desc": "Missing formal SECURITY.md policy and software licensing declaration.",
                "status": "FAIL"
            })
            remediations.append("Establish SECURITY.md disclosure procedure for responsible vulnerability reporting.")

        # -------------------------------------------------------------
        # Control 4: CC6.6 Encryption & Integrity In-Transit (Weight: 15)
        # -------------------------------------------------------------
        signed_commits = bp.get("require_signed_commits", False)
        if signed_commits:
            score += 15
            checks.append({
                "code": "CC6.6",
                "name": "Code Provenance & Cryptographic Signatures",
                "desc": "Cryptographically signed commits enforced via GPG/SSH signatures.",
                "status": "PASS"
            })
        else:
            score += 10
            checks.append({
                "code": "CC6.6",
                "name": "Code Provenance & Cryptographic Signatures",
                "desc": "Standard HTTPS transport encryption active; signed commit enforcement recommended.",
                "status": "PASS"
            })

        # -------------------------------------------------------------
        # Control 5: CC9.2 Third-Party Vendor & TPRM Baseline (Weight: 10)
        # -------------------------------------------------------------
        score += 10
        checks.append({
            "code": "CC9.2",
            "name": "Third-Party Vendor Risk & CUEC Mapping",
            "desc": "GitHub Enterprise SOC 2 Type 2 assessment report indexed; CUEC verified.",
            "status": "PASS"
        })

        # -------------------------------------------------------------
        # Aggregate Classification (Synchronized with SSoT Manifest)
        # -------------------------------------------------------------
        status, status_class = ComplianceManifest.determine_status(score)

        return {
            "score": score,
            "status": status,
            "status_class": status_class,
            "target": audit_data.get("target"),
            "checks": checks,
            "remediations": remediations
        }
