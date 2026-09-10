"""
SentinelAI CLI Audit Utility
Usage: python cli.py --repo erickpark-lgtm/sentinel-ai [--out dossier.html]
"""

import argparse
import sys
import os

from core.github_auditor import GitHubAuditor
from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler

def main():
    parser = argparse.ArgumentParser(description="SentinelAI Autonomous vCISO Compliance Scanner")
    parser.add_argument("--repo", required=True, help="GitHub repository (e.g. erickpark-lgtm/sentinel-ai)")
    parser.add_argument("--out", default="evidence_dossier.html", help="Output dossier path")
    parser.add_argument("--token", default=None, help="Optional GitHub Personal Access Token")
    args = parser.parse_args()

    print("\n" + "═" * 70)
    print(" 🛡️  SENTINEL AI : 24/7 AUTONOMOUS COMPLIANCE SENTINEL")
    print("═" * 70)
    print(f"[*] Target Target: {args.repo}")
    print("[*] Initiating Zero-Trace Read-Only Telemetry Scraper...")

    auditor = GitHubAuditor(token=args.token)
    raw_data = auditor.audit_repository(args.repo)

    if not raw_data.get("success"):
        print(f"\n[!] Audit Failed: {raw_data.get('error')}")
        sys.exit(1)

    evaluated = ScoreCalculator.evaluate(raw_data)

    print("\n" + "─" * 70)
    print(f"[*] Overall SOC 2 Readiness Score: {evaluated['score']} / 100")
    print(f"[*] Compliance Status: {evaluated['status']}")
    print("─" * 70)

    for chk in evaluated["checks"]:
        badge = "✔ PASS" if chk['status'] == "PASS" else ("▲ WARN" if chk['status'] == "WARN" else "✖ FAIL")
        print(f"[{badge}] {chk['code']}: {chk['name']}")
        print(f"       -> {chk['desc']}")

    if evaluated["remediations"]:
        print("\n[!] Mandatory Remediation Steps for Audit Defense:")
        for idx, rem in enumerate(evaluated["remediations"], 1):
            print(f"    {idx}. {rem}")

    # Compile Dossier
    html_content = DossierCompiler.compile_dossier_html(evaluated, company_name=args.repo.split("/")[0])
    with open(args.out, "w", encoding="utf-8") as f:
        f.write(html_content)

    print(f"\n[✔] CPA Evidence Dossier successfully generated at: {os.path.abspath(args.out)}")
    print("═" * 70 + "\n")

if __name__ == "__main__":
    main()
