"""Core engine: scope enforcement, passive recon, DNS resolution, HTTPS audit.

Safety model:
- Only exact hosts listed in scope.json may be touched.
- Resolved IPs must be public; private/loopback/link-local targets are refused.
- Requests are sequential, rate-limited, no redirects, bounded timeouts.
- No exploitation, no fuzzing, no credential use, no report submission.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import socket
import ssl
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

REQUEST_DELAY = 2.0          # seconds between requests to the same host
HTTP_TIMEOUT = 10.0
MAX_SUBDOMAINS = 60
USER_AGENT = "SPAIDER-Bounty-Agent/0.1 (authorized security testing; contact via program policy)"


class ScopeError(Exception):
    """Raised when a target is not authorized by scope.json."""


@dataclass
class Scope:
    program: str = ""
    policy_url: str = ""
    in_scope_hosts: list[str] = field(default_factory=list)
    out_of_scope_hosts: list[str] = field(default_factory=list)
    authorized: bool = False

    @classmethod
    def load(cls, path: str | Path) -> "Scope":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        scope = cls(
            program=data.get("program", ""),
            policy_url=data.get("policy_url", ""),
            in_scope_hosts=[h.lower().strip() for h in data.get("in_scope_hosts", [])],
            out_of_scope_hosts=[h.lower().strip() for h in data.get("out_of_scope_hosts", [])],
            authorized=bool(data.get("authorized", False)),
        )
        if not scope.in_scope_hosts:
            raise ScopeError("scope.json lists no in_scope_hosts.")
        if not scope.authorized:
            raise ScopeError("scope.json does not confirm authorization ('authorized': true required).")
        overlap = set(scope.in_scope_hosts) & set(scope.out_of_scope_hosts)
        if overlap:
            raise ScopeError(f"Hosts both in and out of scope: {sorted(overlap)}")
        return scope

    def check(self, host: str) -> str:
        """Return normalized host if in scope; raise ScopeError otherwise."""
        host = host.lower().strip().rstrip(".")
        if host in self.out_of_scope_hosts:
            raise ScopeError(f"{host} is explicitly out of scope.")
        if host not in self.in_scope_hosts:
            raise ScopeError(
                f"{host} is not listed in scope.json. Add it to in_scope_hosts only if the "
                "program's written policy authorizes you to test it."
            )
        return host


def is_public_ip(ip_text: str) -> bool:
    ip = ipaddress.ip_address(ip_text)
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast
    )


async def resolve_public(host: str) -> list[str]:
    """Resolve hostnames; return only public IPs. Refuse private ranges."""
    loop = asyncio.get_running_loop()
    try:
        infos = await loop.run_in_executor(None, socket.getaddrinfo, host, None, socket.AF_INET)
    except socket.gaierror as exc:
        raise ScopeError(f"DNS resolution failed for {host}: {exc}") from exc
    ips: list[str] = []
    for info in infos:
        ip = info[4][0]
        if not is_public_ip(ip):
            raise ScopeError(f"{host} resolves to non-public address {ip}; refusing.")
        if ip not in ips:
            ips.append(ip)
    return ips


async def fetch_subdomains_from_ct_logs(domain: str) -> list[str]:
    """Passive: pull subdomains from crt.sh certificate transparency logs."""
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers={"User-Agent": USER_AGENT})
        if resp.status_code != 200:
            return []
        names: set[str] = set()
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lstrip("*.").lower()
                if name.endswith(domain) and name not in names:
                    names.add(name)
        return sorted(names)[:MAX_SUBDOMAINS]
    except Exception:
        return []


async def recon(scope: Scope, domain: str) -> dict[str, Any]:
    """Passive subdomain discovery limited to the authorized root domain."""
    domain = scope.check(domain)
    subdomains = await fetch_subdomains_from_ct_logs(domain)
    resolved: dict[str, Any] = {}
    for sub in subdomains:
        try:
            resolved[sub] = await resolve_public(sub)
        except ScopeError:
            resolved[sub] = "skipped (non-public or unresolvable)"
    return {
        "domain": domain,
        "discovered_subdomains": subdomains,
        "resolution": resolved,
        "note": "Passive CT-log enumeration only; subdomains still require explicit scope approval before active checks.",
    }


HEADER_CHECKS = {
    "strict_transport_security": {
        "header": "strict-transport-security",
        "expected": "max-age present",
        "reference": "Missing HSTS may allow protocol downgrade; often informational-only in bounty programs.",
    },
    "content_security_policy": {
        "header": "content-security-policy",
        "expected": "policy present",
        "reference": "Missing CSP widens XSS/HTML-injection impact; check program eligibility.",
    },
    "x_content_type_options": {
        "header": "x-content-type-options",
        "expected": "nosniff",
        "reference": "Missing nosniff can enable MIME confusion in some browsers.",
    },
    "frame_protection": {
        "headers": ("x-frame-options", "content-security-policy"),
        "expected": "frame-ancestors or DENY/SAMEORIGIN",
        "reference": "Absence of frame restrictions is often out of scope.",
    },
}


def _evaluate_headers(headers: httpx.Headers) -> list[dict[str, str]]:
    findings: list[dict[str, str]] = []
    csp = headers.get("content-security-policy", "")
    for key, spec in HEADER_CHECKS.items():
        if key == "frame_protection":
            ok = bool(csp and "frame-ancestors" in csp) or headers.get("x-frame-options", "").upper() in ("DENY", "SAMEORIGIN")
        else:
            value = headers.get(spec["header"], "")
            ok = bool(value) and ("max-age" in value.lower() if key == "strict_transport_security" else True)
        if not ok:
            findings.append({"check": key, "observation": spec["expected"] + " not observed", "reference": spec["reference"]})
    return findings


async def https_audit(scope: Scope, host: str) -> dict[str, Any]:
    """Fetch https://host once, evaluate response headers, TLS certificate and security.txt."""
    host = scope.check(host)
    await resolve_public(host)  # refuse private targets
    result: dict[str, Any] = {"host": host, "findings": []}

    async with httpx.AsyncClient(
        timeout=HTTP_TIMEOUT,
        follow_redirects=False,
        verify=True,
        headers={"User-Agent": USER_AGENT},
    ) as client:
        try:
            resp = await client.get(f"https://{host}/")
            result["status"] = resp.status_code
            result["server"] = resp.headers.get("server", "")
            result["findings"].extend(_evaluate_headers(resp.headers))
        except httpx.HTTPError as exc:
            result["status"] = "unreachable"
            result["findings"].append({"check": "availability", "observation": f"HTTPS request failed: {type(exc).__name__}", "reference": "Host unreachable; nothing to assess."})
            return result
        await asyncio.sleep(REQUEST_DELAY)
        try:
            sec = await client.get(f"https://{host}/.well-known/security.txt")
            if sec.status_code == 200:
                result["security_txt"] = "present"
                result["findings"].append({"check": "security_txt", "observation": "security.txt present — check disclosure policy inside it", "reference": "Follow the policy contact before reporting."})
        except httpx.HTTPError:
            pass

    try:
        cert = await asyncio.get_running_loop().run_in_executor(None, _tls_cert_summary, host)
        result["tls"] = cert
    except Exception as exc:
        result["tls"] = {"error": f"TLS probe failed: {type(exc).__name__}"}
    return result


def _tls_cert_summary(host: str) -> dict[str, Any]:
    ctx = ssl.create_default_context()
    with socket.create_connection((host, 443), timeout=HTTP_TIMEOUT) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            cert = tls.getpeercert()
    not_after = cert.get("notAfter")
    return {
        "tls_version": tls.version(),
        "issuer": dict(x[0] for x in cert.get("issuer", ())),
        "not_after": not_after,
        "san_count": len([v for k, v in cert.get("subjectAltName", ()) for _ in [0] if True]),
    }
