"""
SentinelAI Core Audit API Server
Lightweight REST API serving real-time compliance telemetry and evidence dossiers.
Runs standalone on Python 3 standard library.
"""

import json
import urllib.parse
from http.server import HTTPServer, BaseHTTPRequestHandler
import sys
import os

# Ensure package directory is in python path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.github_auditor import GitHubAuditor
from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler
from core.policy_generator import PolicyGenerator
from core.drift_sentinel import DriftSentinel
from core.heartbeat_watchdog import HeartbeatWatchdog

class AuditAPIHandler(BaseHTTPRequestHandler):

    def _set_cors_headers(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")

    def do_OPTIONS(self):
        self.send_response(200)
        self._set_cors_headers()
        self.end_headers()

    def do_POST(self):
        parsed_path = urllib.parse.urlparse(self.path)

        if parsed_path.path == "/api/scan":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
            except Exception:
                payload = {}

            repo = payload.get("repo", "").strip()
            if not repo:
                self.send_response(400)
                self._set_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"error": "Missing 'repo' parameter."}).encode("utf-8"))
                return

            auditor = GitHubAuditor()
            raw_data = auditor.audit_repository(repo)
            evaluated = ScoreCalculator.evaluate(raw_data)

            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(evaluated).encode("utf-8"))

        elif parsed_path.path == "/api/dossier":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
            except Exception:
                payload = {}

            repo = payload.get("repo", "sample-org/repo")
            auditor = GitHubAuditor()
            raw_data = auditor.audit_repository(repo)
            evaluated = ScoreCalculator.evaluate(raw_data)

            watchdog = HeartbeatWatchdog()
            watchdog.record_heartbeat(repo, checks_executed=len(evaluated.get("checks", [])))
            continuity_data = watchdog.calculate_continuity_index()

            html_doc = DossierCompiler.compile_dossier_html(
                evaluated, 
                company_name=repo.split("/")[0],
                continuity_data=continuity_data
            )
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="SentinelAI_SOC2_Dossier_{repo.replace("/", "_")}.html"')
            self.end_headers()
            self.wfile.write(html_doc.encode("utf-8"))

        elif parsed_path.path == "/api/policies":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
            except Exception:
                payload = {}

            org_name = payload.get("org_name", "Client Organization").strip() or "Client Organization"
            ciso_name = payload.get("ciso_name", "Chief Information Security Officer").strip() or "Chief Information Security Officer"
            req_format = payload.get("format", "html").lower()

            policies = PolicyGenerator.generate_all_policies(org_name=org_name, ciso_name=ciso_name)

            if req_format == "json":
                self.send_response(200)
                self._set_cors_headers()
                self.send_header("Content-Type", "application/json")
                self.end_headers()
                self.wfile.write(json.dumps({"org_name": org_name, "policies": policies}).encode("utf-8"))
            else:
                html_doc = PolicyGenerator.compile_policy_pack_html(policies, org_name=org_name)
                self.send_response(200)
                self._set_cors_headers()
                self.send_header("Content-Type", "text/html; charset=utf-8")
                safe_name = org_name.replace(" ", "_").replace("/", "_")
                self.send_header("Content-Disposition", f'attachment; filename="SentinelAI_SOC2_PolicyPack_{safe_name}.html"')
                self.end_headers()
                self.wfile.write(html_doc.encode("utf-8"))

        elif parsed_path.path == "/api/drift/simulate":
            content_len = int(self.headers.get("Content-Length", 0))
            post_body = self.rfile.read(content_len).decode("utf-8")
            try:
                payload = json.loads(post_body)
            except Exception:
                payload = {}

            repo = payload.get("repo", "enterprise-org/core-backend")
            webhook_url = payload.get("webhook_url")

            # Create baseline evaluation (passing)
            baseline_eval = {
                "score": 94,
                "target": repo,
                "checks": [
                    {"code": "CC8.1", "name": "Branch Protection & Peer Reviews", "desc": "Protected branch with required reviews", "status": "PASS"},
                    {"code": "CC6.1", "name": "Identity & Access Management (MFA)", "desc": "MFA enforced", "status": "PASS"},
                    {"code": "CC7.1", "name": "Vulnerability Management", "desc": "0 critical CVEs", "status": "PASS"}
                ],
                "remediations": []
            }

            # Simulate sudden drift (branch protection removed, CVE entered)
            drifted_eval = {
                "score": 64,
                "target": repo,
                "checks": [
                    {"code": "CC8.1", "name": "Branch Protection & Peer Reviews", "desc": "CRITICAL: Branch protection disabled; unreviewed merges allowed.", "status": "FAIL"},
                    {"code": "CC6.1", "name": "Identity & Access Management (MFA)", "desc": "MFA enforced", "status": "PASS"},
                    {"code": "CC7.1", "name": "Vulnerability Management", "desc": "WARN: 2 High severity CVEs detected in dependencies.", "status": "WARN"}
                ],
                "remediations": ["gh api --method PUT repos/:owner/:repo/branches/main/protection", "npm audit fix"]
            }

            drift_report = DriftSentinel.detect_drift(baseline_eval, drifted_eval)
            slack_payload = DriftSentinel.build_slack_payload(drift_report)
            discord_payload = DriftSentinel.build_discord_payload(drift_report)
            remediation_script = DriftSentinel.generate_remediation_script(drift_report)

            dispatch_status = None
            if webhook_url:
                success, msg = DriftSentinel.dispatch_webhook(webhook_url, slack_payload)
                dispatch_status = {"dispatched": success, "message": msg}

            response_data = {
                "drift_report": drift_report,
                "slack_payload": slack_payload,
                "discord_payload": discord_payload,
                "remediation_script": remediation_script,
                "dispatch_status": dispatch_status
            }

            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps(response_data).encode("utf-8"))

        else:
            self.send_response(404)
            self.end_headers()

    def do_GET(self):
        parsed_path = urllib.parse.urlparse(self.path)
        if parsed_path.path == "/health":
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(json.dumps({"status": "healthy", "service": "SentinelAI-Audit-Engine"}).encode("utf-8"))
        else:
            self.send_response(404)
            self.end_headers()

def run_server(port=8090):
    server_address = ("", port)
    httpd = HTTPServer(server_address, AuditAPIHandler)
    print(f"[*] SentinelAI Core Audit Engine API running at http://localhost:{port}")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Shutting down server.")
        httpd.server_close()

if __name__ == "__main__":
    port = 8090
    if len(sys.argv) > 1:
        port = int(sys.argv[1])
    run_server(port)
