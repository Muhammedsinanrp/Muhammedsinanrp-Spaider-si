"""
SPAIDER HTTP Header Inspector Plugin
HTTPS Security Header Auditor — checks HSTS, CSP, X-Content-Type-Options, and frame restrictions.
"""
import hashlib
import http.client
import ipaddress
import json
import os
import socket
import ssl
import time
import urllib.request
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "httpheader",
    "version": "1.0.0",
    "category": "Web",
    "description": "HTTPS Security Header Inspector — checks HSTS, CSP, X-Content-Type-Options, and framing protection.",
}

CHECKS = {
    "hsts": "No Strict-Transport-Security header observed.",
    "csp": "No enforcing Content-Security-Policy header observed.",
    "nosniff": "X-Content-Type-Options is not nosniff.",
    "framing": "No recognized frame restriction observed.",
}


def normalize_host(value: str) -> str:
    if not isinstance(value, str):
        raise ValueError("Each hostname must be a string.")

    host = value.strip().lower()
    # Strip protocol if accidentally passed
    if host.startswith("https://"):
        host = host[8:]
    elif host.startswith("http://"):
        host = host[7:]
    host = host.split("/")[0].split(":")[0]

    host = host.encode("idna").decode("ascii")
    allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-.")

    if len(host) > 253 or "." not in host:
        raise ValueError("Use exact, fully qualified DNS hostnames.")

    for label in host.split("."):
        label_allowed = set("abcdefghijklmnopqrstuvwxyz0123456789-")
        if (
            not label
            or len(label) > 63
            or label.startswith("-")
            or label.endswith("-")
            or not set(label) <= label_allowed
        ):
            raise ValueError("URLs, ports and wildcards are not allowed.")

    try:
        ipaddress.ip_address(host)
        raise ValueError("IP literals are not allowed.")
    except ValueError as e:
        if "IP literals" in str(e):
            raise
        return host


def resolve_public(host: str) -> str:
    addresses = sorted({
        item[4][0]
        for item in socket.getaddrinfo(
            host, 443, type=socket.SOCK_STREAM
        )
    })
    if not addresses:
        raise ValueError("No DNS addresses returned.")

    for address in addresses:
        ip = ipaddress.ip_address(address)
        if (
            not ip.is_global
            or ip.is_multicast
            or getattr(ip, "ipv4_mapped", None)
        ):
            raise ValueError("Non-public target address rejected.")

    return addresses[0]


class PinnedHTTPS(http.client.HTTPSConnection):
    """Pin the connection IP; preserve TLS hostname verification."""

    def __init__(self, host: str, address: str):
        super().__init__(
            host, timeout=10, context=ssl.create_default_context()
        )
        self.address = address

    def connect(self):
        raw = socket.create_connection(
            (self.address, 443), timeout=self.timeout
        )
        try:
            self.sock = self._context.wrap_socket(
                raw, server_hostname=self.host
            )
        except Exception:
            raw.close()
            raise


def inspect_host(host: str) -> Dict[str, Any]:
    """Inspect a single host's security headers."""
    try:
        address = resolve_public(host)
    except Exception as e:
        return {
            "host": host,
            "status": None,
            "outcome": f"failed: {str(e)}",
            "findings": [],
            "headers_observed": {},
        }

    connection = PinnedHTTPS(host, address)
    try:
        connection.request(
            "GET",
            "/",
            headers={
                "User-Agent": "AuthorizedBountyAssistant/0.1",
                "Accept": "text/html",
                "Connection": "close",
            },
        )
        response = connection.getresponse()
        status = response.status

        headers = {}
        for name, value in response.getheaders():
            headers.setdefault(name.lower(), []).append(value)

        # No redirects, crawling, cookies, or response-body storage.
        is_html = any(
            "text/html" in value.lower()
            for value in headers.get("content-type", [])
        )
        if not (200 <= status < 300 and is_html):
            return {
                "host": host,
                "status": status,
                "outcome": "skipped: non-success or non-HTML",
                "findings": [],
                "headers_observed": {k: v for k, v in headers.items() if k in (
                    "strict-transport-security",
                    "content-security-policy",
                    "x-content-type-options",
                    "x-frame-options",
                )},
            }

        csp = ";".join(
            headers.get("content-security-policy", [])
        ).lower()

        frame_policy = (
            any(
                directive.strip().startswith("frame-ancestors ")
                for directive in csp.split(";")
            )
            or any(
                value.strip().lower() in ("deny", "sameorigin")
                for value in headers.get("x-frame-options", [])
            )
        )

        missing = {
            "hsts": not any(
                value.strip()
                for value in headers.get(
                    "strict-transport-security", []
                )
            ),
            "csp": not csp.strip(),
            "nosniff": not any(
                value.strip().lower() == "nosniff"
                for value in headers.get(
                    "x-content-type-options", []
                )
            ),
            "framing": not frame_policy,
        }

        findings = []
        for check, observed in missing.items():
            if observed:
                finding_id = hashlib.sha256(
                    f"{host}:/:{check}".encode()
                ).hexdigest()[:16]
                findings.append({
                    "id": finding_id,
                    "host": host,
                    "path": "/",
                    "check": check,
                    "severity": "informational",
                    "evidence": CHECKS[check],
                    "validation": "human review required",
                })

        return {
            "host": host,
            "status": status,
            "outcome": "checked",
            "findings": findings,
            "headers_observed": {k: v for k, v in headers.items() if k in (
                "strict-transport-security",
                "content-security-policy",
                "x-content-type-options",
                "x-frame-options",
            )},
        }
    finally:
        connection.close()


def _ai_advice(findings: List[Dict[str, Any]]) -> str:
    # Only fixed check IDs and descriptions leave this process.
    # Target hostnames and HTTP responses are not sent to the AI.
    api_key = os.getenv("OPENAI_API_KEY")
    if not api_key:
        return "AI advisory skipped: OPENAI_API_KEY environment variable not configured."

    model = os.getenv("OPENAI_MODEL", "gpt-4o")
    check_ids = sorted({item["check"] for item in findings})
    payload = {
        "model": model,
        "messages": [
            {
                "role": "system",
                "content": (
                    "You are a defensive security reviewer. Explain "
                    "safe manual validation, limitations, and remediation "
                    "for these HTTP header observations. They are "
                    "informational, not proven vulnerabilities. Do not "
                    "invent impact or recommend exploitation. Return "
                    "a concise Markdown advisory."
                ),
            },
            {
                "role": "user",
                "content": json.dumps({
                    check: CHECKS[check] for check in check_ids
                }),
            },
        ],
    }
    request = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(payload).encode(),
        headers={
            "Content-Type": "application/json",
            "Authorization": f"Bearer {api_key}",
        },
        method="POST",
    )
    with urllib.request.build_opener(urllib.request.ProxyHandler({})).open(request, timeout=30) as response:
        raw = response.read(1_000_001)

    if len(raw) > 1_000_000:
        raise ValueError("AI response exceeds size limit.")

    content = json.loads(raw)["choices"][0]["message"]["content"]
    if not isinstance(content, str):
        raise ValueError("AI did not return text.")
    return content


def scan(
    targets: List[str],
    options: Optional[Dict[str, Any]] = None,
    results_dir: str = "./scan_results",
) -> Dict[str, Any]:
    """Inspect HTTPS security headers for a list of hosts."""
    options = options or {}
    interval = float(options.get("interval", 1.0))
    enable_ai = str(options.get("ai", "no")).lower() in ("yes", "true", "1")

    all_findings = []
    target_results = []
    failed = False

    for index, raw_host in enumerate(targets):
        if index > 0:
            time.sleep(min(max(interval, 0.1), 10.0))

        try:
            host = normalize_host(raw_host)
            res = inspect_host(host)
            target_results.append(res)
            all_findings.extend(res.get("findings", []))
            if "failed" in str(res.get("outcome", "")):
                failed = True
        except Exception as exc:
            failed = True
            target_results.append({
                "host": raw_host,
                "status": None,
                "outcome": "failed",
                "error": str(exc),
                "findings": [],
            })

    ai_advice_text = None
    if enable_ai and all_findings:
        try:
            ai_advice_text = _ai_advice(all_findings)
        except Exception as exc:
            ai_advice_text = f"AI advisory failed: {type(exc).__name__} ({str(exc)})"

    return {
        "targets": target_results,
        "findings": all_findings,
        "total_hosts": len(targets),
        "total_findings": len(all_findings),
        "failed": failed,
        "ai_advice": ai_advice_text,
        "checks_performed": list(CHECKS.keys()),
    }


def analyze(results: Dict[str, Any]) -> Dict[str, Any]:
    findings = results.get("findings", [])
    by_check: Dict[str, int] = {}
    for f in findings:
        c = f.get("check", "unknown")
        by_check[c] = by_check.get(c, 0) + 1

    return {
        "total_hosts_checked": results.get("total_hosts", 0),
        "total_observations": len(findings),
        "by_check": by_check,
        "risk_summary": "Informational observations — require manual validation before remediation.",
        "most_common_observation": max(by_check, key=by_check.get) if by_check else "none",
    }


def normalize(raw: Dict[str, Any]) -> List[Dict[str, Any]]:
    return [
        {
            "type": "HEADER_FINDING",
            "host": f.get("host"),
            "check": f.get("check"),
            "severity": f.get("severity", "informational"),
            "evidence": f.get("evidence"),
            "plugin": "httpheader",
        }
        for f in raw.get("findings", [])
    ]


def report(results: Dict[str, Any]) -> str:
    lines = [
        "════════════════════════════════════════════════════════════",
        "  SPAIDER HTTPS SECURITY HEADER INSPECTION REPORT",
        "════════════════════════════════════════════════════════════",
        f"Hosts Checked : {results.get('total_hosts', 0)}",
        f"Observations  : {results.get('total_findings', 0)}",
        "────────────────────────────────────────────────────────────",
    ]

    for t in results.get("targets", []):
        lines.append(f"\nTarget: {t.get('host')}  [Status: {t.get('status') or 'N/A'}]")
        lines.append(f"Outcome: {t.get('outcome')}")
        obs = t.get("findings", [])
        if obs:
            lines.append("Observations:")
            for f in obs:
                lines.append(f"  • [{f.get('check', '').upper()}] {f.get('evidence')}")
        else:
            lines.append("  • No missing standard security headers flagged.")

    if results.get("ai_advice"):
        lines.append("\n────────────────────────────────────────────────────────────")
        lines.append("AI DEFENSIVE ADVISORY:")
        lines.append("────────────────────────────────────────────────────────────")
        lines.append(results["ai_advice"])

    return "\n".join(lines)
