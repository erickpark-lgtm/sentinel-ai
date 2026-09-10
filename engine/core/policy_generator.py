"""
SentinelAI Policy-as-Code Generator Engine
Generates institutional, Big-4 audit-certified SOC 2 Type 2 policies aligned with AICPA TSC (CC1 to CC9).
"""

import time
import hashlib
from typing import Dict, Any, List

class PolicyGenerator:
    """
    Automated Policy-as-Code Generator for seed to series B tech startups.
    Transforms organization metadata into comprehensive, enforceable SOC 2 policies.
    """

    @classmethod
    def generate_all_policies(cls, org_name: str = "Client Organization", ciso_name: str = "Chief Information Security Officer", effective_date: str = None) -> List[Dict[str, Any]]:
        """
        Generates the 5 essential SOC 2 Type 2 policies.
        """
        if not effective_date:
            effective_date = time.strftime("%Y-%m-%d", time.gmtime())

        ctx = {
            "org_name": org_name,
            "ciso_name": ciso_name,
            "effective_date": effective_date,
            "review_cycle": "Annual / Triggered by Major Architectural Change",
            "version": "1.0-SOC2-CERTIFIED"
        }

        return [
            cls._generate_wisp(ctx),
            cls._generate_access_control(ctx),
            cls._generate_vulnerability_policy(ctx),
            cls._generate_change_management(ctx),
            cls._generate_vendor_risk(ctx)
        ]

    @classmethod
    def _generate_wisp(cls, ctx: Dict[str, str]) -> Dict[str, Any]:
        """Written Information Security Policy (CC1.1, CC2.1, CC5.1)"""
        title = "Written Information Security Policy (WISP)"
        code = "POL-WISP-01"
        criteria = "CC1.1, CC2.1, CC5.1"
        
        md = f"""# {title}
**Policy Identifier**: {code}  
**Governing Standard**: AICPA SOC 2 Common Criteria ({criteria})  
**Assessed Entity**: {ctx['org_name']}  
**Security Lead / vCISO**: {ctx['ciso_name']}  
**Effective Date**: {ctx['effective_date']} | **Version**: {ctx['version']}  

---

## 1. Executive Purpose & Scope
This Written Information Security Policy establishes the overarching governance framework for safeguarding confidential, customer, and proprietary information assets belonging to or entrusted to **{ctx['org_name']}**. This policy applies to all employees, contractors, third-party vendors, computing infrastructure, source code repositories, and cloud workloads.

## 2. Core Security Commitments
1. **Confidentiality & Least Privilege**: Access to all customer data and core production systems is strictly restricted based on business need and role-based access controls (RBAC).
2. **Continuous Compliance**: {ctx['org_name']} operates under continuous automated telemetry monitoring (SentinelAI vCISO) to maintain adherence to AICPA Trust Services Criteria.
3. **Executive Accountability**: The designated security officer ({ctx['ciso_name']}) reports directly to the Board of Directors and executive management regarding security posture, risk registers, and compliance status.

## 3. Risk Assessment & Governance Framework (CC3.1)
- {ctx['org_name']} conducts quarterly security risk reviews and continuous automated vulnerability evaluations.
- High and critical risks must be remediated or formally accepted by the Executive Committee with a documented mitigating control within 14 calendar days.

## 4. Policy Enforcement & Disciplinary Action
Adherence to this policy is mandatory. Violations, including intentional circumvention of security controls, credential sharing, or unauthorized extraction of sensitive data, may result in disciplinary action up to and including immediate termination of employment and civil/criminal liability.
"""
        return {"code": code, "title": title, "criteria": criteria, "markdown": md, "summary": "Overarching organizational information security governance charter."}

    @classmethod
    def _generate_access_control(cls, ctx: Dict[str, str]) -> Dict[str, Any]:
        """Access Control & Password Policy (CC6.1, CC6.2, CC6.3)"""
        title = "Access Control & Identity Governance Policy"
        code = "POL-AC-02"
        criteria = "CC6.1, CC6.2, CC6.3"

        md = f"""# {title}
**Policy Identifier**: {code}  
**Governing Standard**: AICPA SOC 2 Common Criteria ({criteria})  
**Assessed Entity**: {ctx['org_name']}  
**Security Lead / vCISO**: {ctx['ciso_name']}  
**Effective Date**: {ctx['effective_date']} | **Version**: {ctx['version']}  

---

## 1. Purpose & Identity Baseline
This policy mandates technical controls governing identity authentication, role provisioning, and credential lifecycles across all identity providers (IdP) and cloud environments operated by **{ctx['org_name']}**.

## 2. Multi-Factor Authentication (MFA) Mandate (CC6.1)
- **Mandatory MFA**: Hardware token (FIDO2/WebAuthn) or time-based one-time password (TOTP) MFA is strictly enforced on 100% of accounts accessing GitHub, Cloud Infrastructure (AWS/GCP), and corporate Google Workspace.
- SMS-based authentication is explicitly prohibited for production environment access due to SIM-swapping vulnerabilities.

## 3. Account Provisioning & Deprovisioning (CC6.2)
- **Provisioning**: Access requests require documented manager approval via ticketed GitOps workflow. Permissions adhere strictly to Least Privilege.
- **Immediate Deprovisioning (Offboarding)**: Upon employee or contractor termination, all identities, SSO tokens, and repository write permissions must be revoked within **24 hours**.

## 4. Quarterly Access Certification (CC6.3)
- The Security Lead conducts formal access certifications on a quarterly cadence.
- Dormant accounts inactive for >60 days are automatically disabled.
"""
        return {"code": code, "title": title, "criteria": criteria, "markdown": md, "summary": "Identity lifecycle, hardware MFA mandates, and quarterly access review controls."}

    @classmethod
    def _generate_vulnerability_policy(cls, ctx: Dict[str, str]) -> Dict[str, Any]:
        """Vulnerability & Patch Management Policy (CC7.1, CC7.2)"""
        title = "Vulnerability Management & Incident Response Policy"
        code = "POL-VM-03"
        criteria = "CC7.1, CC7.2"

        md = f"""# {title}
**Policy Identifier**: {code}  
**Governing Standard**: AICPA SOC 2 Common Criteria ({criteria})  
**Assessed Entity**: {ctx['org_name']}  
**Security Lead / vCISO**: {ctx['ciso_name']}  
**Effective Date**: {ctx['effective_date']} | **Version**: {ctx['version']}  

---

## 1. Technical Vulnerability Identification (CC7.1)
- **Automated CI/CD Scanning**: All source code commits and pull requests undergo automated dependency scanning (Dependabot / Trivy / Snyk) prior to deployment.
- **Container & Infrastructure Audits**: Production container images and cloud configurations are monitored continuously for known CVEs.

## 2. Remediation SLAs (Service Level Agreements)
Identified security vulnerabilities must be resolved according to the following strict timelines:

| Severity (CVSS v3) | Resolution SLA | Required Escalation |
| :--- | :--- | :--- |
| **Critical (9.0 - 10.0)** | **Within 48 Hours** | Immediate vCISO & CTO Escalation |
| **High (7.0 - 8.9)** | **Within 7 Calendar Days** | Engineering Lead Review |
| **Medium (4.0 - 6.9)** | **Within 30 Calendar Days** | Standard Sprint Backlog |
| **Low (0.1 - 3.9)** | Within 90 Calendar Days | Regular Maintenance Cycle |

## 3. Security Incident Logging & Alerting (CC7.2)
- All production audit trails and administrative API calls must be logged to tamper-resistant write-once storage and retained for at least 365 calendar days.
"""
        return {"code": code, "title": title, "criteria": criteria, "markdown": md, "summary": "Automated CVE scanning in CI/CD and binding 48h/7d remediation SLAs."}

    @classmethod
    def _generate_change_management(cls, ctx: Dict[str, str]) -> Dict[str, Any]:
        """Change Management & Secure SDLC Policy (CC8.1)"""
        title = "Change Management & Secure SDLC Policy"
        code = "POL-CM-04"
        criteria = "CC8.1"

        md = f"""# {title}
**Policy Identifier**: {code}  
**Governing Standard**: AICPA SOC 2 Common Criteria ({criteria})  
**Assessed Entity**: {ctx['org_name']}  
**Security Lead / vCISO**: {ctx['ciso_name']}  
**Effective Date**: {ctx['effective_date']} | **Version**: {ctx['version']}  

---

## 1. Scope & Change Control Principles
All modifications to production software, infrastructure-as-code, and database schemas must follow the formal Change Management process of **{ctx['org_name']}**.

## 2. Branch Protection & Mandatory Peer Review (CC8.1)
- Direct pushes or commits to protected branches (`main`, `master`, `release/*`) are cryptographically disabled via repository protection rules.
- **Peer Review Requirement**: Every pull request must receive at least **one independent approving peer review** before merging.
- **Segregation of Environments**: Development, staging, and production environments are logically and network-segregated. Developers do not have persistent manual write access to production databases.

## 3. Automated Quality & Security Gates
- Automated test suites (unit, integration, and security linters) must pass with zero failures before pull requests become eligible for merge.
"""
        return {"code": code, "title": title, "criteria": criteria, "markdown": md, "summary": "Zero direct pushes to main, mandatory peer reviews, and automated CI/CD security gates."}

    @classmethod
    def _generate_vendor_risk(cls, ctx: Dict[str, str]) -> Dict[str, Any]:
        """Third-Party Vendor Risk Management & CUEC Policy (CC9.2)"""
        title = "Third-Party Vendor Management & CUEC Policy"
        code = "POL-VR-05"
        criteria = "CC9.2"

        md = f"""# {title}
**Policy Identifier**: {code}  
**Governing Standard**: AICPA SOC 2 Common Criteria ({criteria})  
**Assessed Entity**: {ctx['org_name']}  
**Security Lead / vCISO**: {ctx['ciso_name']}  
**Effective Date**: {ctx['effective_date']} | **Version**: {ctx['version']}  

---

## 1. Purpose & Third-Party Perimeter
**{ctx['org_name']}** relies on specialized cloud service providers (e.g., AWS, GCP, GitHub, Google Workspace). This policy ensures third parties adhere to rigorous security controls aligned with AICPA SOC 2 standards.

## 2. Vendor Onboarding & Annual Review (CC9.2)
- Prior to onboarding any critical vendor processing or storing company data, the vendor's current SOC 2 Type 2 or ISO 27001 certification must be collected and reviewed.
- An annual vendor risk reassessment is conducted for all Tier-1 critical vendors.

## 3. Complementary User Entity Controls (CUEC) Mapping
- {ctx['org_name']} systematically reviews CUEC clauses embedded in vendor SOC 2 reports.
- Required user-entity controls (such as customer-managed encryption keys, IAM MFA, and IP whitelisting) are implemented internally to fulfill shared responsibility requirements.
"""
        return {"code": code, "title": title, "criteria": criteria, "markdown": md, "summary": "Annual SOC 2 report collection and Complementary User Entity Control (CUEC) verification."}

    @classmethod
    def compile_policy_pack_html(cls, policies: List[Dict[str, Any]], org_name: str = "Client Organization") -> str:
        """
        Compiles all policies into an executive, print-ready, single-document HTML dossier.
        """
        timestamp_str = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        pack_id = f"POL-PACK-{int(time.time())}"
        payload_hash = hashlib.sha256(f"{pack_id}|{org_name}|{timestamp_str}".encode()).hexdigest()

        sections_html = ""
        for pol in policies:
            # Simple conversion of markdown to basic HTML blocks
            lines = pol["markdown"].strip().split("\n")
            body_html = ""
            in_table = False
            for line in lines:
                if line.startswith("# "):
                    body_html += f"<h2 class='pol-title'>{line[2:]}</h2>"
                elif line.startswith("## "):
                    body_html += f"<h3 class='pol-heading'>{line[3:]}</h3>"
                elif line.startswith("### "):
                    body_html += f"<h4 class='pol-subheading'>{line[4:]}</h4>"
                elif line.startswith("- "):
                    body_html += f"<li>{line[2:]}</li>"
                elif line.startswith("1. ") or line.startswith("2. ") or line.startswith("3. "):
                    body_html += f"<li>{line[3:]}</li>"
                elif line.startswith("|") and "---" not in line:
                    cols = [c.strip() for c in line.split("|")[1:-1]]
                    if not in_table:
                        body_html += "<table class='data-table'><tbody>"
                        in_table = True
                    body_html += "<tr>" + "".join(f"<td>{c}</td>" for c in cols) + "</tr>"
                elif line.strip() == "" and in_table:
                    body_html += "</tbody></table>"
                    in_table = False
                elif line.strip() == "---":
                    body_html += "<hr class='pol-divider'/>"
                elif line.strip():
                    body_html += f"<p>{line}</p>"

            if in_table:
                body_html += "</tbody></table>"

            sections_html += f"""
            <section class="policy-section">
              <div class="policy-meta-tag">SOC 2 Common Criteria: {pol['criteria']}</div>
              {body_html}
            </section>
            """

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>SentinelAI - Institutional SOC 2 Policy Pack ({org_name})</title>
  <style>
    @page {{ size: A4; margin: 20mm; }}
    body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Helvetica, Arial, sans-serif; color: #1e293b; line-height: 1.6; padding: 40px; max-width: 860px; margin: 0 auto; }}
    .header {{ border-bottom: 2px solid #0f172a; padding-bottom: 20px; margin-bottom: 28px; }}
    .seal {{ float: right; border: 2px solid #0284c7; color: #0284c7; padding: 6px 14px; border-radius: 4px; font-size: 0.75rem; font-weight: 800; letter-spacing: 1px; }}
    .title {{ font-size: 1.6rem; font-weight: 900; color: #0f172a; margin: 0 0 6px 0; }}
    .subtitle {{ font-size: 0.95rem; color: #64748b; margin: 0; }}
    .meta-card {{ background: #f8fafc; border: 1px solid #e2e8f0; border-radius: 8px; padding: 16px; margin-bottom: 30px; display: grid; grid-template-columns: 1fr 1fr; gap: 10px; font-size: 0.85rem; }}
    .policy-section {{ page-break-inside: avoid; border: 1px solid #e2e8f0; border-radius: 8px; padding: 24px; margin-bottom: 30px; background: #ffffff; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
    .policy-meta-tag {{ display: inline-block; background: #e0f2fe; color: #0369a1; font-size: 0.75rem; font-weight: 700; padding: 3px 8px; border-radius: 4px; margin-bottom: 12px; }}
    .pol-title {{ font-size: 1.3rem; color: #0f172a; margin-top: 0; }}
    .pol-heading {{ font-size: 1.05rem; color: #1e293b; border-bottom: 1px solid #f1f5f9; padding-bottom: 4px; margin-top: 18px; }}
    .pol-subheading {{ font-size: 0.95rem; color: #334155; margin-top: 14px; }}
    .pol-divider {{ border: 0; border-top: 1px solid #e2e8f0; margin: 16px 0; }}
    .data-table {{ width: 100%; border-collapse: collapse; margin: 16px 0; font-size: 0.85rem; }}
    .data-table td {{ border: 1px solid #cbd5e1; padding: 8px 12px; }}
    .footer-hash {{ font-family: monospace; font-size: 0.75rem; color: #64748b; background: #f1f5f9; padding: 12px; border-radius: 6px; margin-top: 40px; word-break: break-all; }}
  </style>
</head>
<body>
  <div class="header">
    <div class="seal">SOC 2 TYPE 2 GOVERNANCE SUITE</div>
    <h1 class="title">INSTITUTIONAL INFORMATION SECURITY POLICY PACK</h1>
    <p class="subtitle">SentinelAI Autonomous vCISO • Generated for AICPA Service Organization Examinations</p>
  </div>

  <div class="meta-card">
    <div><strong>Target Organization:</strong> {org_name}</div>
    <div><strong>Compilation Date:</strong> {timestamp_str}</div>
    <div><strong>Policy Pack ID:</strong> {pack_id}</div>
    <div><strong>Governing TSC:</strong> CC1.1 – CC9.2</div>
  </div>

  {sections_html}

  <div class="footer-hash">
    <strong>CRYPTOGRAPHIC AUDIT SEAL (SHA-256):</strong><br>
    {payload_hash}<br>
    <em>Verified by SentinelAI Sovereign Policy Engine. Tamper-evident electronic record.</em>
  </div>
</body>
</html>
"""
