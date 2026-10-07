"""SPAIDER Bounty Agent — FastMCP server.

Run:
    ASHNA_API_KEY=... python3 -m bounty_agent.mcp_server

Then register in your MCP client (Claude Desktop / Cursor / Roo):
    {
      "mcpServers": {
        "spaider-bounty": {
          "command": "python3",
          "args": ["-m", "bounty_agent.mcp_server"],
          "cwd": "/path/to/repo",
          "env": {"ASHNA_API_KEY": "<your-key>", "SPAIDER_SCOPE_FILE": "bounty_agent/scope.example.json"}
        }
      }
    }

Safety: every tool re-checks the target against scope.json (SPAIDER_SCOPE_FILE).
No exploitation, no auto-submission, no out-of-scope target is ever processed.
"""

from __future__ import annotations

import os
from pathlib import Path

from fastmcp import FastMCP

from .core import ScopeError, https_audit, recon, resolve_public
from .triage import draft_report_section, triage_findings

mcp = FastMCP("spaider-bounty")


def _scope_file() -> Path:
    return Path(os.environ.get("SPAIDER_SCOPE_FILE", "bounty_agent/scope.example.json"))


@mcp.tool()
def scope_gate(target: str) -> str:
    """Check whether a hostname is authorized by the configured scope file. Call before anything else."""
    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        host = scope.check(target)
        return f"AUTHORIZED: {host} is in scope for '{scope.program}'. Passive/low-impact checks permitted."
    except ScopeError as exc:
        return f"BLOCKED: {exc}"


@mcp.tool()
def check_dns(target: str) -> dict:
    """Resolve an in-scope hostname and confirm all IPs are public. Refuses private ranges."""
    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        host = scope.check(target)
        return {"host": host, "public_ips": resolve_public_sync(host)}
    except ScopeError as exc:
        return {"blocked": str(exc)}


def resolve_public_sync(host: str) -> list[str]:
    import asyncio

    return asyncio.run(resolve_public(host))


@mcp.tool()
def recon_subdomains(domain: str) -> dict:
    """Passive subdomain discovery via crt.sh CT logs for an in-scope root domain."""
    import asyncio

    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        return asyncio.run(recon(scope, domain))
    except ScopeError as exc:
        return {"blocked": str(exc)}


@mcp.tool()
def audit_https(target: str) -> dict:
    """Low-impact HTTPS audit (headers/TLS/security.txt) for an in-scope host. Rate-limited, no redirects."""
    import asyncio

    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        return asyncio.run(https_audit(scope, target))
    except ScopeError as exc:
        return {"blocked": str(exc)}


@mcp.tool()
def triage(target: str, audit_result: dict) -> dict:
    """Use AshnaAI to classify audit findings as bounty-eligible or not. Human reviews every result."""
    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        host = scope.check(target)
        return triage_findings(host, audit_result)
    except ScopeError as exc:
        return {"blocked": str(exc)}


@mcp.tool()
def draft_report(target: str, audit_result: dict, triage_result: dict) -> dict:
    """Draft a Markdown report section via AshnaAI for a human to review. Never auto-submits."""
    from .core import Scope

    try:
        scope = Scope.load(_scope_file())
        host = scope.check(target)
        return draft_report_section(host, audit_result, triage_result)
    except ScopeError as exc:
        return {"blocked": str(exc)}


if __name__ == "__main__":
    mcp.run()
