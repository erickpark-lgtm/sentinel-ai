"""
SentinelAI CLI Audit Utility
Usage: python cli.py --repo erickpark-lgtm/sentinel-ai [--out dossier.html]
"""

import argparse
import sys
import os

# Ensure package directory is on sys.path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import time
from core.github_auditor import GitHubAuditor
from core.score_calculator import ScoreCalculator
from core.dossier_compiler import DossierCompiler
from core.policy_generator import PolicyGenerator
from core.drift_sentinel import DriftSentinel
from core.heartbeat_watchdog import HeartbeatWatchdog

def main():
    parser = argparse.ArgumentParser(description="SentinelAI Autonomous vCISO Compliance Scanner")
    parser.add_argument("--repo", default=None, help="GitHub repository (e.g. erickpark-lgtm/sentinel-ai)")
    parser.add_argument("--out", default="evidence_dossier.html", help="Output dossier path")
    parser.add_argument("--token", default=None, help="Optional GitHub Personal Access Token")
    parser.add_argument("--generate-policies", action="store_true", help="Generate 5 institutional SOC 2 policies")
    parser.add_argument("--org-name", default=None, help="Organization name for policies")
    parser.add_argument("--out-dir", default="soc2_policies", help="Directory to save generated policies")
    parser.add_argument("--watch", action="store_true", help="Run continuous monitoring daemon for drift")
    parser.add_argument("--interval", type=int, default=60, help="Watch interval in seconds (default: 60)")
    parser.add_argument("--webhook", default=None, help="Slack or Discord webhook URL for drift alerts")
    parser.add_argument("--fix-script", default=None, help="Generate automated shell remediation script")
    parser.add_argument("--prospect", action="store_true", help="Run autonomous outbound lead qualification and outreach generation")
    parser.add_argument("--prospect-query", default="topic:saas", help="Search query for candidate discovery")
    args = parser.parse_args()

    if not args.repo and not args.generate_policies and not args.prospect:
        parser.print_help()
        sys.exit(1)

    # Autonomous Outbound Lead Generation Mode
    if args.prospect:
        from core.outbound_lead_sentinel import OutboundLeadSentinel
        sentinel = OutboundLeadSentinel(github_token=args.token)
        print("\n" + "═" * 70)
        print(" 🎯  SENTINEL AI : OUTBOUND PROSPECTING LEAD-GEN SENTINEL")
        print("═" * 70)
        if args.repo:
            print(f"[*] Auditing prospect candidate: {args.repo}")
            lead = sentinel.audit_and_qualify(args.repo)
            pkg = lead["outreach_package"]
            print(f"[✔] Prospect Score: {lead['score']}/100 | Tier: {lead['lead_tier']} | Urgency: {lead['urgency']}")
            print(f"[*] Subject: {pkg['subject']}")
            print(f"[*] 1-Click Fix:\n{pkg['remediation_cli']}")
            print(f"\n[*] Outreach Email Draft:\n{pkg['email_body_markdown']}")
        else:
            print(f"[*] Discovering startup candidates matching: '{args.prospect_query}'...")
            leads = sentinel.scan_pipeline(query=args.prospect_query, limit=3)
            sentinel.export_pipeline_to_json(leads, "prospects_pipeline.json")
            print(f"[✔] Discovered {len(leads)} qualified leads. Exported to prospects_pipeline.json\n")
            for idx, l in enumerate(leads, 1):
                print(f"    {idx}. {l['repo']} -> Score: {l['score']}/100 ({l['lead_tier']})")
        print("═" * 70 + "\n")
        return

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

        # Heartbeat Watchdog Ledger
        watchdog = HeartbeatWatchdog()
        watchdog.record_heartbeat(args.repo, checks_executed=len(evaluated.get("checks", [])))
        continuity_data = watchdog.calculate_continuity_index()

        # Compile Dossier with Continuous Observation Proof
        html_content = DossierCompiler.compile_dossier_html(
            evaluated, 
            company_name=org_name,
            continuity_data=continuity_data
        )
        with open(args.out, "w", encoding="utf-8") as f:
            f.write(html_content)

        print(f"\n[✔] CPA Evidence Dossier successfully generated at: {os.path.abspath(args.out)}")
        print(f"    [Heartbeat Proof]: Continuity Index {continuity_data['continuity_index']} | Hash: {continuity_data.get('root_ledger_hash', '')[:20]}...")

        # Remediation Script Generation
        if args.fix_script:
            dummy_baseline = {"score": 100, "target": args.repo, "checks": [{"code": c["code"], "name": c["name"], "status": "PASS", "desc": ""} for c in evaluated["checks"]]}
            drift_rep = DriftSentinel.detect_drift(dummy_baseline, evaluated)
            script_body = DriftSentinel.generate_remediation_script(drift_rep)
            with open(args.fix_script, "w", encoding="utf-8") as f:
                f.write(script_body)
            os.chmod(args.fix_script, 0o755)
            print(f"[✔] Executable Remediation Script saved to: {os.path.abspath(args.fix_script)}")

        # Continuous Watch Daemon
        if args.watch:
            print(f"\n[⚡] SentinelAI Continuous Watch Mode Activated (Interval: {args.interval}s)")
            print("[*] Press Ctrl+C to stop continuous monitoring daemon.")
            baseline_eval = evaluated
            try:
                while True:
                    time.sleep(args.interval)
                    print(f"\n[*] [{time.strftime('%H:%M:%S')}] Polling continuous telemetry for {args.repo}...")
                    curr_raw = auditor.audit_repository(args.repo)
                    if curr_raw.get("success"):
                        curr_eval = ScoreCalculator.evaluate(curr_raw)
                        drift_report = DriftSentinel.detect_drift(baseline_eval, curr_eval)
                        if drift_report["has_drift"]:
                            print(f"[🚨] COMPLIANCE DRIFT DETECTED! Delta: {drift_report['score_delta']} pts | Severity: {drift_report['severity']}")
                            for r in drift_report["regressions"]:
                                print(f"     -> REGRESSION [{r['code']}]: {r['from_status']} -> {r['to_status']} ({r['name']})")
                            
                            if args.webhook:
                                print(f"[*] Dispatching webhook alert to: {args.webhook}")
                                slack_msg = DriftSentinel.build_slack_payload(drift_report)
                                ok, status = DriftSentinel.dispatch_webhook(args.webhook, slack_msg)
                                print(f"    [Webhook Dispatch]: {status}")
                            
                            baseline_eval = curr_eval
                        else:
                            print("[✔] Infrastructure controls stable. Zero compliance drift.")
            except KeyboardInterrupt:
                print("\n[!] Watch daemon terminated by user.")

    print("═" * 70 + "\n")

if __name__ == "__main__":
    main()
