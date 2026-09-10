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

from core.github_auditor import GitHubAuditor
from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler

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

            html_doc = DossierCompiler.compile_dossier_html(evaluated, company_name=repo.split("/")[0])
            self.send_response(200)
            self._set_cors_headers()
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Disposition", f'attachment; filename="SentinelAI_SOC2_Dossier_{repo.replace("/", "_")}.html"')
            self.end_headers()
            self.wfile.write(html_doc.encode("utf-8"))

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
