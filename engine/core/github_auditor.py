"""
SentinelAI GitHub Security & Compliance Auditor (CC6 / CC7 / CC8)
Audits GitHub repository controls against AICPA Trust Services Criteria.
"""

import json
import os
import urllib.request
import urllib.error
from typing import Dict, Any, Optional

class GitHubAuditor:
    """
    Automated telemetry scanner for GitHub repositories.
    Evaluates branch protection, security files, and dependency scanning.
    """
    BASE_URL = "https://api.github.com"

    def __init__(self, token: Optional[str] = None):
        self.token = token or os.environ.get("GITHUB_TOKEN")

    def _make_request(self, endpoint: str) -> tuple[int, Dict[str, Any]]:
        url = f"{self.BASE_URL}/{endpoint.lstrip('/')}"
        headers = {
            "Accept": "application/vnd.github+json",
            "User-Agent": "SentinelAI-vCISO-Auditor/1.0"
        }
        if self.token:
            headers["Authorization"] = f"Bearer {self.token}"

        req = urllib.request.Request(url, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                status = resp.status
                data = json.loads(resp.read().decode("utf-8"))
                return status, data
        except urllib.error.HTTPError as e:
            try:
                err_body = json.loads(e.read().decode("utf-8"))
            except Exception:
                err_body = {"message": str(e)}
            return e.code, err_body
        except Exception as ex:
            return 500, {"error": str(ex)}

    def audit_repository(self, owner_repo: str) -> Dict[str, Any]:
        """
        Executes comprehensive SOC 2 CC6, CC7, CC8 compliance audit.
        Format: 'owner/repo' or full GitHub URL.
        """
        clean_repo = owner_repo.strip()
        if "github.com/" in clean_repo:
            clean_repo = clean_repo.split("github.com/")[-1].strip("/")
        if clean_repo.endswith(".git"):
            clean_repo = clean_repo[:-4]

        parts = clean_repo.split("/")
        if len(parts) != 2:
            return {
                "success": False,
                "error": f"Invalid repository format: '{owner_repo}'. Expected 'owner/repo'."
            }

        owner, repo = parts

        # 1. Base Repo Telemetry
        status, repo_data = self._make_request(f"/repos/{owner}/{repo}")
        if status == 404:
            return {
                "success": False,
                "error": f"Repository '{owner}/{repo}' not found or private without authentication."
            }
        if status != 200:
            return {
                "success": False,
                "error": f"GitHub API error ({status}): {repo_data.get('message', 'Unknown error')}"
            }

        default_branch = repo_data.get("default_branch", "main")
        is_private = repo_data.get("private", False)
        license_info = repo_data.get("license")

        # 2. Branch Protection Telemetry (CC8.1 Change Management)
        bp_status, bp_data = self._make_request(f"/repos/{owner}/{repo}/branches/{default_branch}/protection")
        branch_protection_active = (bp_status == 200)
        
        pr_reviews_required = False
        approving_review_count = 0
        dismiss_stale_reviews = False
        enforce_admins = False
        require_signed_commits = False

        if branch_protection_active:
            req_reviews = bp_data.get("required_pull_request_reviews", {})
            if req_reviews:
                pr_reviews_required = True
                approving_review_count = req_reviews.get("required_approving_review_count", 1)
                dismiss_stale_reviews = req_reviews.get("dismiss_stale_reviews", False)
            enforce_admins = bp_data.get("enforce_admins", {}).get("enabled", False)
            require_signed_commits = bp_data.get("required_signatures", {}).get("enabled", False)

        # 3. Security Policy & Community Health Files (CC6.1 / CC7.1)
        sec_status, _ = self._make_request(f"/repos/{owner}/{repo}/contents/SECURITY.md")
        has_security_policy = (sec_status == 200)

        actions_status, _ = self._make_request(f"/repos/{owner}/{repo}/contents/.github/workflows")
        has_ci_workflows = (actions_status == 200)

        # 4. Dependency Vulnerability (CC7.1)
        dep_status, dep_data = self._make_request(f"/repos/{owner}/{repo}/dependabot/alerts")
        dependabot_enabled = (dep_status != 404 and dep_status != 403)
        open_cve_count = 0
        critical_cve_count = 0
        if dep_status == 200 and isinstance(dep_data, list):
            open_alerts = [a for a in dep_data if a.get("state") == "open"]
            open_cve_count = len(open_alerts)
            critical_cve_count = sum(1 for a in open_alerts if a.get("security_advisory", {}).get("severity") in ("critical", "high"))

        return {
            "success": True,
            "target": f"{owner}/{repo}",
            "default_branch": default_branch,
            "is_private": is_private,
            "has_license": license_info is not None,
            "license_name": license_info.get("spdx_id", "Custom") if license_info else "None",
            "branch_protection": {
                "active": branch_protection_active,
                "pr_reviews_required": pr_reviews_required,
                "approving_review_count": approving_review_count,
                "dismiss_stale_reviews": dismiss_stale_reviews,
                "enforce_admins": enforce_admins,
                "require_signed_commits": require_signed_commits
            },
            "security_governance": {
                "has_security_policy": has_security_policy,
                "has_ci_workflows": has_ci_workflows,
                "dependabot_active": dependabot_enabled,
                "open_cve_count": open_cve_count,
                "critical_cve_count": critical_cve_count
            }
        }
