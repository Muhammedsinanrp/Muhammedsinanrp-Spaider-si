"""
SPAIDER Web Security Engine
Integrates Nuclei for template-based web/API vulnerability scanning.

Covers:
  XSS, SQLi, SSRF, IDOR/BOLA, Auth weaknesses, AuthZ flaws, CSRF,
  Security misconfig, Path traversal, File upload, API security,
  JWT, OAuth/OIDC, GraphQL, CORS, Prototype pollution,
  Request smuggling, Injection classes
"""

import subprocess
import json
import os
import uuid
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."

PLUGIN_META = {
    "name": "nuclei",
    "version": "3.2.4",
    "category": "Web/API Security",
    "description": "Template-based web vulnerability scanner. Detects XSS, SQLi, SSRF, IDOR, JWT, CORS, GraphQL issues and 8000+ other checks.",
}

# Nuclei template groups mapped to vulnerability categories
WEB_VULN_CATEGORIES = {
    "injection": {
        "label": "Injection",
        "templates": ["vulnerabilities/generic/sqli", "vulnerabilities/generic/xss"],
        "description": "SQL Injection, XSS, Command Injection, Template Injection",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "ssrf": {
        "label": "SSRF",
        "templates": ["vulnerabilities/generic/ssrf"],
        "description": "Server-Side Request Forgery — internal service exposure",
        "severity": "HIGH",
        "mitre": ["T1190"],
    },
    "auth": {
        "label": "Authentication Weaknesses",
        "templates": ["exposures/configs", "vulnerabilities/generic/default-login"],
        "description": "Default credentials, weak auth, session management issues",
        "severity": "HIGH",
        "mitre": ["T1078"],
    },
    "misconfig": {
        "label": "Security Misconfiguration",
        "templates": ["misconfiguration"],
        "description": "Open redirects, debug endpoints, directory listing, backup files",
        "severity": "MEDIUM",
        "mitre": ["T1190"],
    },
    "cves": {
        "label": "Known CVEs",
        "templates": ["cves"],
        "description": "CVE-identified vulnerabilities in web frameworks and CMS platforms",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
    "jwt": {
        "label": "JWT / OAuth Issues",
        "templates": ["vulnerabilities/generic/jwt"],
        "description": "JWT alg:none, weak signing, OAuth misconfiguration, token leakage",
        "severity": "HIGH",
        "mitre": ["T1078.001"],
    },
    "cors": {
        "label": "CORS Issues",
        "templates": ["misconfiguration/cors"],
        "description": "Overly permissive CORS allowing cross-origin credential theft",
        "severity": "MEDIUM",
        "mitre": ["T1185"],
    },
    "api": {
        "label": "API Security",
        "templates": ["exposures/apis", "misconfiguration/graphql"],
        "description": "Exposed API docs, GraphQL introspection, BOLA/IDOR, mass assignment",
        "severity": "HIGH",
        "mitre": ["T1190"],
    },
    "exposures": {
        "label": "Sensitive Exposures",
        "templates": ["exposures"],
        "description": ".env files, git repos, AWS keys, private keys, debug info",
        "severity": "HIGH",
        "mitre": ["T1552"],
    },
    "takeovers": {
        "label": "Subdomain Takeovers",
        "templates": ["takeovers"],
        "description": "Dangling DNS pointing to unclaimed cloud/SaaS services",
        "severity": "HIGH",
        "mitre": ["T1584"],
    },
    "path_traversal": {
        "label": "Path Traversal",
        "templates": ["vulnerabilities/generic/lfi"],
        "description": "Local file inclusion, directory traversal, file read",
        "severity": "HIGH",
        "mitre": ["T1083"],
    },
    "upload": {
        "label": "File Upload",
        "templates": ["vulnerabilities/generic/file-upload"],
        "description": "Unrestricted file upload, webshell upload, MIME bypass",
        "severity": "CRITICAL",
        "mitre": ["T1190"],
    },
}


def scan_web(targets: List[str], categories: Optional[List[str]] = None,
             output_dir: str = "/app/scan_results") -> Dict[str, Any]:
    """
    Run Nuclei web security scan against targets.

    Args:
        targets: List of URLs to scan (e.g. ["https://example.com"])
        categories: List of category keys to scan (None = all)
        output_dir: Directory to write JSON results

    Returns:
        dict with findings list and summary
    """
    os.makedirs(output_dir, exist_ok=True)
    run_id = str(uuid.uuid4())[:8]
    output_file = os.path.join(output_dir, f"nuclei_web_{run_id}.json")

    # Select templates
    if categories:
        templates = []
        for cat in categories:
            if cat in WEB_VULN_CATEGORIES:
                templates.extend(WEB_VULN_CATEGORIES[cat]["templates"])
    else:
        # Default: all high-value web templates
        templates = ["cves", "vulnerabilities", "misconfiguration", "exposures", "takeovers"]

    cmd = [
        "nuclei",
        "-json-export", output_file,
        "-silent",
        "-severity", "critical,high,medium",
        "-rate-limit", "50",
        "-timeout", "10",
        "-retries", "1",
    ]
    for tpl in templates:
        cmd.extend(["-t", tpl])
    for target in targets:
        cmd.extend(["-u", target])

    logger.info("Starting Nuclei web scan", targets=targets, templates=templates)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=900)
        findings = _parse_nuclei_output(output_file)
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": categories or list(WEB_VULN_CATEGORIES.keys()),
            "total_findings": len(findings),
            "findings": findings,
            "output_file": output_file,
            "authorization_warning": AUTH_WARNING,
        }
    except FileNotFoundError:
        logger.warning("Nuclei not installed — returning demo results")
        return _demo_findings(targets)
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out", "targets": targets, "authorization_warning": AUTH_WARNING}


def _parse_nuclei_output(output_file: str) -> List[Dict]:
    """Parse Nuclei JSONL output into structured findings."""
    findings = []
    if not os.path.exists(output_file):
        return findings

    severity_map = {
        "critical": "CRITICAL", "high": "HIGH",
        "medium": "MEDIUM", "low": "LOW", "info": "INFO",
    }

    with open(output_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
                info = item.get("info", {})
                findings.append({
                    "template_id": item.get("template-id", ""),
                    "title": info.get("name", "Unknown"),
                    "description": info.get("description", ""),
                    "severity": severity_map.get(info.get("severity", "info").lower(), "INFO"),
                    "url": item.get("matched-at", item.get("host", "")),
                    "cve_ids": info.get("classification", {}).get("cve-id", []),
                    "cwe_ids": info.get("classification", {}).get("cwe-id", []),
                    "cvss_score": info.get("classification", {}).get("cvss-score"),
                    "tags": info.get("tags", []),
                    "references": info.get("reference", []),
                    "curl_command": item.get("curl-command", ""),
                    "request": item.get("request", ""),
                    "response": item.get("response", "")[:500] if item.get("response") else "",
                    "matcher_name": item.get("matcher-name", ""),
                    "extracted_results": item.get("extracted-results", []),
                })
            except json.JSONDecodeError:
                continue

    return findings


def _demo_findings(targets: List[str]) -> Dict[str, Any]:
    """Return realistic demo findings when Nuclei is not installed."""
    return {
        "run_id": "demo",
        "targets": targets,
        "demo": True,
        "authorization_warning": AUTH_WARNING,
        "total_findings": 5,
        "findings": [
            {
                "template_id": "CVE-2021-41773",
                "title": "Apache HTTP Server 2.4.49 - Path Traversal (CVE-2021-41773)",
                "description": "A flaw was found in path normalization in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
                "severity": "CRITICAL",
                "url": targets[0] if targets else "https://example.com",
                "cve_ids": ["CVE-2021-41773"],
                "cvss_score": 9.8,
                "tags": ["cve", "apache", "path-traversal"],
                "curl_command": f"curl -s --path-as-is '{targets[0] if targets else 'https://example.com'}/.%2e/.%2e/etc/passwd'",
                "references": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
            },
            {
                "template_id": "cors-misconfiguration",
                "title": "CORS Misconfiguration — Wildcard Origin Allowed",
                "description": "The application reflects the Origin header in Access-Control-Allow-Origin and allows credentials, enabling cross-site requests.",
                "severity": "HIGH",
                "url": targets[0] if targets else "https://example.com",
                "cve_ids": [],
                "cvss_score": 7.5,
                "tags": ["cors", "misconfiguration"],
                "curl_command": f"curl -H 'Origin: https://attacker.com' -I '{targets[0] if targets else 'https://example.com'}/api/'",
                "references": ["https://portswigger.net/web-security/cors"],
            },
            {
                "template_id": "exposed-env-file",
                "title": "Exposed .env File Containing Secrets",
                "description": "An environment configuration file is publicly accessible, potentially exposing database credentials, API keys, and other secrets.",
                "severity": "HIGH",
                "url": f"{targets[0] if targets else 'https://example.com'}/.env",
                "cve_ids": [],
                "cvss_score": 7.5,
                "tags": ["exposure", "config", "secrets"],
                "references": ["https://owasp.org/www-project-top-ten/"],
            },
            {
                "template_id": "graphql-introspection",
                "title": "GraphQL Introspection Enabled",
                "description": "GraphQL introspection is enabled in production, allowing attackers to enumerate the full API schema.",
                "severity": "MEDIUM",
                "url": f"{targets[0] if targets else 'https://example.com'}/graphql",
                "cve_ids": [],
                "cvss_score": 5.3,
                "tags": ["graphql", "api", "exposure"],
                "references": ["https://graphql.org/learn/introspection/"],
            },
            {
                "template_id": "missing-security-headers",
                "title": "Missing HTTP Security Headers",
                "description": "The application is missing security headers: Content-Security-Policy, X-Frame-Options, X-Content-Type-Options.",
                "severity": "MEDIUM",
                "url": targets[0] if targets else "https://example.com",
                "cve_ids": [],
                "cvss_score": 4.3,
                "tags": ["headers", "misconfiguration"],
                "references": ["https://owasp.org/www-project-secure-headers/"],
            },
        ],
    }


def get_categories() -> Dict[str, Any]:
    """Return all available vulnerability categories."""
    return WEB_VULN_CATEGORIES


def scan_with_burp_integration(target: str, proxy_url: str = "http://127.0.0.1:8080") -> Dict:
    """
    Route traffic through Burp Suite proxy for manual + automated testing.
    Requires Burp running with the SPAIDER extension installed.
    """
    return {
        "mode": "burp_proxy",
        "target": target,
        "proxy": proxy_url,
        "instructions": [
            f"1. Start Burp Suite and configure proxy at {proxy_url}",
            "2. Install SPAIDER extension from Plugin Marketplace",
            "3. Browse target through proxy — SPAIDER will analyse traffic",
            "4. Run Active Scan from Burp Dashboard",
            "5. SPAIDER extension will sync findings to this platform",
        ],
    }
