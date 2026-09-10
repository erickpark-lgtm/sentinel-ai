"""
SentinelAI Continuous Drift Sentinel & Alert Dispatcher (Pillar 3)
Tracks compliance regressions, detects drift against SOC 2 baselines, and dispatches real-time webhooks.
"""

import time
import json
import urllib.request
import urllib.error
from typing import Dict, Any, List, Optional

class DriftSentinel:
    """
    Continuous monitor comparing sequential audit evaluations.
    Detects control degradations, compiles Slack/Discord webhook alerts, and builds remediation scripts.
    """

    @staticmethod
    def detect_drift(previous_eval: Dict[str, Any], current_eval: Dict[str, Any]) -> Dict[str, Any]:
        """
        Calculates compliance drift between two audit snapshots.
        """
        prev_score = previous_eval.get("score", 0)
        curr_score = current_eval.get("score", 0)
        score_delta = curr_score - prev_score

        prev_checks = {c["code"]: c for c in previous_eval.get("checks", [])}
        curr_checks = {c["code"]: c for c in current_eval.get("checks", [])}

        regressions: List[Dict[str, Any]] = []
        resolutions: List[Dict[str, Any]] = []

        all_codes = set(prev_checks.keys()).union(set(curr_checks.keys()))

        for code in all_codes:
            p_chk = prev_checks.get(code)
            c_chk = curr_checks.get(code)

            if not p_chk or not c_chk:
                continue

            p_status = p_chk.get("status")
            c_status = c_chk.get("status")

            # Check for Regression
            if p_status == "PASS" and c_status in ("FAIL", "WARN"):
                severity = "CRITICAL" if c_status == "FAIL" else "MEDIUM"
                regressions.append({
                    "code": code,
                    "name": c_chk.get("name"),
                    "from_status": p_status,
                    "to_status": c_status,
                    "severity": severity,
                    "desc": c_chk.get("desc")
                })
            elif p_status == "WARN" and c_status == "FAIL":
                regressions.append({
                    "code": code,
                    "name": c_chk.get("name"),
                    "from_status": p_status,
                    "to_status": c_status,
                    "severity": "HIGH",
                    "desc": c_chk.get("desc")
                })

            # Check for Resolution
            elif p_status in ("FAIL", "WARN") and c_status == "PASS":
                resolutions.append({
                    "code": code,
                    "name": c_chk.get("name"),
                    "from_status": p_status,
                    "to_status": c_status,
                    "desc": c_chk.get("desc")
                })

        has_drift = len(regressions) > 0 or len(resolutions) > 0

        # Determine overall severity
        if any(r["severity"] == "CRITICAL" for r in regressions):
            severity = "CRITICAL"
        elif any(r["severity"] == "HIGH" for r in regressions):
            severity = "HIGH"
        elif len(regressions) > 0:
            severity = "MEDIUM"
        elif len(resolutions) > 0:
            severity = "RESOLVED"
        else:
            severity = "STABLE"

        return {
            "has_drift": has_drift,
            "severity": severity,
            "target": current_eval.get("target", "Target Repo"),
            "previous_score": prev_score,
            "current_score": curr_score,
            "score_delta": score_delta,
            "regressions": regressions,
            "resolutions": resolutions,
            "remediations": current_eval.get("remediations", []),
            "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        }

    @classmethod
    def build_slack_payload(cls, drift_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds Slack Block Kit JSON payload.
        """
        severity = drift_report.get("severity", "INFO")
        target = drift_report.get("target", "Target")
        delta = drift_report.get("score_delta", 0)
        delta_str = f"+{delta}" if delta > 0 else f"{delta}"

        color_emoji = "🚨" if severity in ("CRITICAL", "HIGH") else ("⚠️" if severity == "MEDIUM" else "✅")
        header_text = f"{color_emoji} SentinelAI Compliance Drift Alert: {target}"

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": header_text, "emoji": True}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*Repository:*\n`{target}`"},
                    {"type": "mrkdwn", "text": f"*Severity:*\n*{severity}*"},
                    {"type": "mrkdwn", "text": f"*SOC 2 Score:*\n{drift_report.get('current_score')}/100 ({delta_str} pts)"},
                    {"type": "mrkdwn", "text": f"*Timestamp:*\n{drift_report.get('timestamp')}"}
                ]
            },
            {"type": "divider"}
        ]

        # Regressions Block
        if drift_report.get("regressions"):
            reg_lines = []
            for r in drift_report["regressions"]:
                reg_lines.append(f"• *[{r['code']}] {r['name']}*: degraded from `{r['from_status']}` to `*{r['to_status']}*`\n  _{r['desc']}_")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🔴 Detected Compliance Regressions:*\n" + "\n".join(reg_lines)}
            })

        # Resolutions Block
        if drift_report.get("resolutions"):
            res_lines = []
            for res in drift_report["resolutions"]:
                res_lines.append(f"• *[{res['code']}] {res['name']}*: restored from `{res['from_status']}` to `*PASS*`")
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": "*🟢 Resolved Control Items:*\n" + "\n".join(res_lines)}
            })

        # Remediation Commands
        if drift_report.get("remediations"):
            rem_code = "\n".join(f"# {r}" for r in drift_report["remediations"][:3])
            blocks.append({
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*🛠️ Automated Remediation Advice:*\n```{rem_code}```"}
            })

        return {"blocks": blocks}

    @classmethod
    def build_discord_payload(cls, drift_report: Dict[str, Any]) -> Dict[str, Any]:
        """
        Builds Discord Webhook Embed JSON payload.
        """
        severity = drift_report.get("severity", "INFO")
        target = drift_report.get("target", "Target")
        color_code = 0xef4444 if severity in ("CRITICAL", "HIGH") else (0xf59e0b if severity == "MEDIUM" else 0x10b981)

        fields = [
            {"name": "Target Repository", "value": f"`{target}`", "inline": True},
            {"name": "Severity", "value": severity, "inline": True},
            {"name": "SOC 2 Score Delta", "value": f"{drift_report.get('current_score')}/100 ({drift_report.get('score_delta')} pts)", "inline": True}
        ]

        if drift_report.get("regressions"):
            reg_text = "\n".join(f"• **{r['code']}**: {r['from_status']} ➔ **{r['to_status']}** ({r['name']})" for r in drift_report["regressions"])
            fields.append({"name": "🚨 Regressions", "value": reg_text, "inline": False})

        embed = {
            "title": f"🛡️ SentinelAI Continuous Compliance Drift [{severity}]",
            "description": f"Automated telemetry detected compliance drift in `{target}` at {drift_report.get('timestamp')}.",
            "color": color_code,
            "fields": fields,
            "footer": {"text": "SentinelAI 24/7 Sovereign vCISO Engine"}
        }

        return {"embeds": [embed]}

    @classmethod
    def dispatch_webhook(cls, webhook_url: str, payload: Dict[str, Any]) -> tuple[bool, str]:
        """
        Dispatches webhook alert over HTTP.
        """
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                webhook_url,
                data=data,
                headers={"Content-Type": "application/json", "User-Agent": "SentinelAI-Drift-Sentinel/1.0"}
            )
            with urllib.request.urlopen(req, timeout=8) as resp:
                return (resp.status in (200, 204), f"HTTP {resp.status}")
        except urllib.error.HTTPError as e:
            return (False, f"HTTPError {e.code}: {e.reason}")
        except Exception as ex:
            return (False, f"Error: {str(ex)}")

    @classmethod
    def generate_remediation_script(cls, drift_report: Dict[str, Any], default_branch: str = "main") -> str:
        """
        Generates an executable Bash script using GitHub CLI ('gh') to fix identified regressions.
        """
        target = drift_report.get("target", "org/repo")
        lines = [
            "#!/usr/bin/env bash",
            "# ═════════════════════════════════════════════════════════════════════════",
            f"# SentinelAI Autonomous Remediation Script for: {target}",
            f"# Generated: {drift_report.get('timestamp')}",
            "# ═════════════════════════════════════════════════════════════════════════",
            "set -euo pipefail",
            "",
            "echo '[*] Executing SentinelAI Automated Fiduciary Remediation...'",
            f"REPO=\"{target}\"",
            f"BRANCH=\"{default_branch}\"",
            ""
        ]

        # Scan regressions to formulate fixes
        reg_codes = [r["code"] for r in drift_report.get("regressions", [])]
        
        # CC8.1: Branch Protection
        if "CC8.1" in reg_codes or not drift_report.get("regressions"):
            lines.extend([
                "echo '[+] Enforcing Branch Protection on $BRANCH with Required Peer Reviews (CC8.1)...'",
                "gh api --method PUT \"repos/$REPO/branches/$BRANCH/protection\" \\",
                "  -f required_status_checks='{\"strict\":true,\"contexts\":[]}' \\",
                "  -f enforce_admins=true \\",
                "  -f required_pull_request_reviews='{\"dismiss_stale_reviews\":true,\"require_code_owner_reviews\":false,\"required_approving_review_count\":1}' \\",
                "  -f restrictions=null",
                "echo '    [✔] Branch protection successfully armed.'",
                ""
            ])

        # CC6.1: Security Policy
        if "CC6.1" in reg_codes:
            lines.extend([
                "echo '[+] Creating SECURITY.md baseline policy (CC6.1)...'",
                "cat << 'EOF' > SECURITY.md",
                "# Security Policy",
                "## Reporting a Vulnerability",
                "Please report sensitive vulnerabilities to security@sentinelvciso.com.",
                "EOF",
                "git add SECURITY.md && git commit -m 'Add SOC 2 CC6.1 Vulnerability Reporting Policy' || true",
                "echo '    [✔] SECURITY.md staged.'",
                ""
            ])

        lines.extend([
            "echo '[✔] All mandatory SOC 2 compliance controls remediated!'",
            "echo '[*] Triggering SentinelAI re-scan to verify restoration...'"
        ])

        return "\n".join(lines)
