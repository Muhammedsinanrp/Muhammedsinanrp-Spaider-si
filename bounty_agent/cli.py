"""SPAIDER Bounty Agent — direct CLI (no MCP client needed).

Usage:
    python3 -m bounty_agent.cli --scope bounty_agent/scope.example.json --recon
    python3 -m bounty_agent.cli --scope bounty_agent/scope.example.json --audit
    python3 -m bounty_agent.cli --scope bounty_agent/scope.example.json --audit --triage
"""

from __future__ import annotations

import argparse
import asyncio
import json
from pathlib import Path

from .core import Scope, ScopeError, https_audit, recon
from .triage import draft_report_section, triage_findings


def main() -> int:
    parser = argparse.ArgumentParser(description="SPAIDER Bounty Agent (authorized targets only)")
    parser.add_argument("--scope", required=True, help="Path to scope.json")
    parser.add_argument("--recon", action="store_true", help="Passive subdomain recon via CT logs")
    parser.add_argument("--audit", action="store_true", help="Low-impact HTTPS audit")
    parser.add_argument("--triage", action="store_true", help="AI triage via AshnaAI (needs ASHNA_API_KEY)")
    parser.add_argument("--draft", action="store_true", help="Draft report section via AshnaAI")
    parser.add_argument("--out", default="bounty-report.json", help="Output JSON report path")
    args = parser.parse_args()

    try:
        scope = Scope.load(args.scope)
    except (ScopeError, FileNotFoundError, json.JSONDecodeError) as exc:
        print(f"[!] Scope error: {exc}")
        return 2

    print(f"[*] Program: {scope.program} ({scope.policy_url})")
    print(f"[*] Authorized hosts: {', '.join(scope.in_scope_hosts)}")
    if not (args.recon or args.audit):
        print("[*] Nothing to do: pass --recon, --audit, and/or --triage")
        return 0

    report: dict = {"program": scope.program, "scope_hosts": scope.in_scope_hosts}

    if args.recon:
        for domain in scope.in_scope_hosts:
            print(f"[*] Recon: {domain}")
            report.setdefault("recon", []).append(asyncio.run(recon(scope, domain)))

    if args.audit:
        for host in scope.in_scope_hosts:
            print(f"[*] HTTPS audit: {host}")
            result = asyncio.run(https_audit(scope, host))
            report.setdefault("audits", []).append(result)
            if args.triage:
                print(f"[*] AI triage: {host}")
                triage_result = triage_findings(host, result)
                report.setdefault("triages", []).append(triage_result)
                if args.draft:
                    print(f"[*] Drafting report section: {host}")
                    report.setdefault("drafts", []).append(draft_report_section(host, result, triage_result))

    out_path = Path(args.out)
    out_path.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"[+] Report saved to {out_path}")
    print("[i] Review every finding manually. Nothing was submitted to any platform.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
