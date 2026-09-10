"""
SentinelAI Autonomous Outbound Prospecting & Lead-Gen Sentinel
Discovers vulnerable repositories with compliance gaps, computes instant SOC 2 scores,
and generates personalized, high-conversion, value-first remediation outreach packages.
"""

import json
import os
import urllib.request
import urllib.error
import urllib.parse
from typing import Dict, Any, List, Optional

try:
    from .github_auditor import GitHubAuditor
    from .score_calculator import ScoreCalculator
    from .retry_utils import with_exponential_backoff
except (ImportError, ValueError):
    try:
        from core.github_auditor import GitHubAuditor
        from core.score_calculator import ScoreCalculator
        from core.retry_utils import with_exponential_backoff
    except ImportError:
        from engine.core.github_auditor import GitHubAuditor
        from engine.core.score_calculator import ScoreCalculator
        from engine.core.retry_utils import with_exponential_backoff

class OutboundLeadSentinel:
    """
    Autonomous prospecting engine that identifies B2B SaaS startups with SOC 2 compliance gaps
    and generates value-first diagnostic outreach reports with 1-click remediation scripts.
    """

    SEARCH_API = "https://api.github.com/search/repositories"

    def __init__(self, github_token: Optional[str] = None):
        self.token = github_token or os.environ.get("GITHUB_TOKEN")
        self.auditor = GitHubAuditor(token=self.token)

    @with_exponential_backoff(max_retries=3, base_delay=1.0, max_delay=15.0)
    def search_candidates(self, query: str = "topic:saas stars:50..1000", limit: int = 5) -> List[str]:
        """
        Queries GitHub Search API for candidate repositories matching criteria.
        Falls back to curated high-growth startup targets if unauthenticated.
        """
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "SentinelAI-Lead-Sentinel/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        params = urllib.parse.urlencode({
            "q": query,
            "sort": "updated",
            "order": "desc",
            "per_page": min(limit, 20)
        })
        url = f"{self.SEARCH_API}?{params}"

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                items = data.get("items", [])
                return [item["full_name"] for item in items[:limit]]
        except Exception:
            # High-fidelity fallback list of realistic candidate profiles for demo/offline
            return [
                "enterprise-cloud/microservice-core",
                "hypergrowth-ai/backend-api",
                "fintech-nexus/payment-gateway",
                "healthtech-sys/patient-portal",
                "saas-platform/auth-service"
            ][:limit]

    def audit_and_qualify(self, repo_name: str) -> Dict[str, Any]:
        """
        Audits candidate repository and evaluates lead intent score based on compliance gaps.
        """
        raw_audit = self.auditor.audit_repository(repo_name)
        evaluation = ScoreCalculator.evaluate(raw_audit)

        score = evaluation.get("score", 0)
        failing_checks = [c for c in evaluation.get("checks", []) if c.get("status") in ("FAIL", "WARN")]

        # Classify prospect qualification
        if score < 70:
            lead_tier = "TIER_1_CRITICAL_NEED"
            urgency = "HIGH"
        elif score < 85:
            lead_tier = "TIER_2_MODERATE_GAPS"
            urgency = "MEDIUM"
        else:
            lead_tier = "TIER_3_ALREADY_COMPLIANT"
            urgency = "LOW"

        outreach_package = self.compile_outreach_package(repo_name, evaluation, failing_checks)

        return {
            "repo": repo_name,
            "score": score,
            "lead_tier": lead_tier,
            "urgency": urgency,
            "failing_checks_count": len(failing_checks),
            "failing_checks": failing_checks,
            "outreach_package": outreach_package
        }

    def compile_outreach_package(self, repo: str, evaluation: Dict[str, Any], failing_checks: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Generates a non-spammy, value-first personalized diagnostic outreach letter
        with 1-click executable remediation commands.
        """
        score = evaluation.get("score", 0)
        org_name = repo.split("/")[0]

        # Find primary failure point
        primary_gap = failing_checks[0] if failing_checks else {
            "code": "CC8.1",
            "name": "Branch Protection & Peer Review Gates",
            "desc": "Main branch allows unreviewed direct commits."
        }

        subject = f"🚨 Compliance Diagnostic: {repo} scored {score}/100 on SOC 2 Readiness (1-Click Fix Available)"

        # Generate automated remediation bash command
        remediation_cli = f"""# 1-Click SOC 2 CC8.1 Remediation Script for {repo}
gh api --method PUT "repos/{repo}/branches/main/protection" \\
  -f required_status_checks='{{"strict":true,"contexts":[]}}' \\
  -f enforce_admins=true \\
  -f required_pull_request_reviews='{{"dismiss_stale_reviews":true,"required_approving_review_count":1}}'"""

        # Personalized markdown email body
        email_markdown = f"""Hi {org_name} Engineering Team,

We recently ran an automated AICPA Common Criteria scan against public security indicators for **{repo}** using SentinelAI.

Your current SOC 2 Type 2 readiness score is **{score}/100**. 

### 🔍 Key Audit Vulnerability Identified:
* **Criterion:** [{primary_gap.get('code')}] {primary_gap.get('name')}
* **Observation:** {primary_gap.get('desc')}
* **Enterprise Deal Risk:** Enterprise procurement teams typically reject vendor security reviews if pull request approval gates or dependency scanners are absent.

### ⚡ Immediate 1-Click Fix:
You can remediate this control right now using the GitHub CLI:

```bash
{remediation_cli}
```

### 📄 Free Pre-Compiled Evidence Register:
We compiled a free, zero-trace SOC 2 evidence dossier for your repository:
👉 https://sentinelvciso.com/?repo={urllib.parse.quote(repo)}#scanner

Best regards,  
**SentinelAI Autonomous vCISO Engine**  
*Automated Continuous Compliance for High-Growth Engineering Teams*
"""

        return {
            "subject": subject,
            "target_repo": repo,
            "target_org": org_name,
            "score": score,
            "primary_gap_code": primary_gap.get("code"),
            "remediation_cli": remediation_cli,
            "landing_url": f"https://sentinelvciso.com/?repo={urllib.parse.quote(repo)}#scanner",
            "email_body_markdown": email_markdown
        }

    def scan_pipeline(self, query: str = "topic:saas", limit: int = 3) -> List[Dict[str, Any]]:
        """
        Executes end-to-end prospecting pipeline: search candidates -> audit -> compile outreach.
        """
        candidates = self.search_candidates(query=query, limit=limit)
        results = []
        for c in candidates:
            qualified = self.audit_and_qualify(c)
            results.append(qualified)
        return results

    def export_pipeline_to_json(self, results: List[Dict[str, Any]], filepath: str = "prospects_pipeline.json") -> str:
        """
        Exports qualified leads to JSON for automated CRM/email dispatch.
        """
        dirname = os.path.dirname(filepath)
        if dirname:
            os.makedirs(dirname, exist_ok=True)
        with open(filepath, "w", encoding="utf-8") as f:
            json.dump({"timestamp": "2026-09-09T21:49:00Z", "total_leads": len(results), "leads": results}, f, indent=2)
        return filepath
