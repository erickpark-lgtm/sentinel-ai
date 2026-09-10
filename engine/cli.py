"""
SentinelAI CLI Audit Utility
Usage: python cli.py --repo erickpark-lgtm/sentinel-ai [--out dossier.html]
"""

import argparse
import sys
import os

# Ensure package directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from core.github_auditor import GitHubAuditor
from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler
from core.policy_generator import PolicyGenerator

def main():
    parser = argparse.ArgumentParser(description="SentinelAI Autonomous vCISO Compliance Scanner")
    parser.add_argument("--repo", default=None, help="GitHub repository (e.g. erickpark-lgtm/sentinel-ai)")
    parser.add_argument("--out", default="evidence_dossier.html", help="Output dossier path")
    parser.add_argument("--token", default=None, help="Optional GitHub Personal Access Token")
    parser.add_argument("--generate-policies", action="store_true", help="Generate 5 institutional SOC 2 policies")
    parser.add_argument("--org-name", default=None, help="Organization name for policies")
    parser.add_argument("--out-dir", default="soc2_policies", help="Directory to save generated policies")
    args = parser.parse_args()

    if not args.repo and not args.generate_policies:
        parser.print_help()
        sys.exit(1)

    org_name = args.org_name
    if not org_name and args.repo:
        org_name = args.repo.split("/")[0].replace("-", " ").title()
    if not org_name:
        org_name = "Enterprise Client Organization"

    print("\n" + "═" * 70)
    print(" 🛡️  SENTINEL AI : 24/7 AUTONOMOUS COMPLIANCE SENTINEL")
    print("═" * 70)

    # 1. Policy Generation Mode
    if args.generate_policies:
        print(f"[*] Compiling Institutional SOC 2 Policy Pack for: {org_name}")
        policies = PolicyGenerator.generate_all_policies(org_name=org_name)
        os.makedirs(args.out_dir, exist_ok=True)

        for p in policies:
            fname = f"{p['code']}_{p['title'].replace(' ', '_')}.md"
            fpath = os.path.join(args.out_dir, fname)
            with open(fpath, "w", encoding="utf-8") as f:
                f.write(p["markdown"])
            print(f"    [✔] Generated Policy: {fname} ({p['criteria']})")

        pack_html = PolicyGenerator.compile_policy_pack_html(policies, org_name=org_name)
        pack_html_path = os.path.join(args.out_dir, "SOC2_Institutional_Policy_Pack.html")
        with open(pack_html_path, "w", encoding="utf-8") as f:
            f.write(pack_html)
        print(f"[✔] Compiled Master Policy Pack HTML: {os.path.abspath(pack_html_path)}")

    # 2. Telemetry Audit Mode
    if args.repo:
        print(f"\n[*] Target Repository: {args.repo}")
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
        html_content = DossierCompiler.compile_dossier_html(evaluated, company_name=org_name)
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"\n[✔] CPA Evidence Dossier successfully generated at: {os.path.abspath(args.out)}")

    print("═" * 70 + "\n")

if __name__ == "__main__":
    main()
