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


def scan_web(
    targets: List[str],
    categories: Optional[List[str]] = None,
    output_dir: str = "/app/scan_results",
    rate_limit: int = 10,
    timeout: int = 10,
    proxy: Optional[str] = None,
) -> Dict[str, Any]:
    """Execute Nuclei and return only findings produced by the real scanner.

    Missing tools, non-zero exits, and timeouts are explicit errors. Demo
    findings are deliberately never substituted for real results.
    """
    import shutil

    os.makedirs(output_dir, exist_ok=True)
    run_id = str(uuid.uuid4())
    output_file = os.path.join(output_dir, f"nuclei_web_{run_id}.json")

    nuclei_path = shutil.which("nuclei")
    if not nuclei_path:
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": categories or [],
            "total_findings": 0,
            "findings": [],
            "error": "Nuclei is not installed or is not on PATH. Install Nuclei and its templates, then retry.",
            "demo": False,
            "authorization_warning": AUTH_WARNING,
        }

    selected = categories or list(WEB_VULN_CATEGORIES.keys())
    unknown = sorted(set(selected) - set(WEB_VULN_CATEGORIES))
    if unknown:
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": selected,
            "total_findings": 0,
            "findings": [],
            "error": f"Unsupported categories: {', '.join(unknown)}",
            "demo": False,
            "authorization_warning": AUTH_WARNING,
        }

    templates = []
    for category in selected:
        templates.extend(WEB_VULN_CATEGORIES[category]["templates"])
    templates = list(dict.fromkeys(templates))

    command = [
        nuclei_path, "-jsonl-export", output_file, "-silent", "-no-color", "-no-interactsh",
        "-severity", "critical,high,medium,low,info",
        "-rate-limit", str(max(1, min(int(rate_limit), 100))),
        "-timeout", str(max(1, min(int(timeout), 60))),
        "-retries", "1",
    ]
    for template in templates:
        command.extend(["-t", template])
    if proxy:
        command.extend(["-proxy", proxy])
    for target in targets:
        command.extend(["-u", target])

    logger.info(
        "Starting real Nuclei web scan",
        targets=targets,
        categories=selected,
        rate_limit=rate_limit,
        timeout=timeout,
        proxy_enabled=bool(proxy),
    )

    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=900, check=False
        )
        findings = _parse_nuclei_output(output_file)
        if completed.returncode != 0:
            error = (completed.stderr or completed.stdout or "Nuclei exited unsuccessfully").strip()
            if not findings:
                return {
                    "run_id": run_id,
                    "targets": targets,
                    "categories_scanned": selected,
                    "total_findings": 0,
                    "findings": [],
                    "error": error[-4000:],
                    "exit_code": completed.returncode,
                    "output_file": output_file,
                    "demo": False,
                    "authorization_warning": AUTH_WARNING,
                }
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": selected,
            "total_findings": len(findings),
            "findings": findings,
            "output_file": output_file,
            "exit_code": completed.returncode,
            "demo": False,
            "authorization_warning": AUTH_WARNING,
        }
    except subprocess.TimeoutExpired:
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": selected,
            "total_findings": 0,
            "findings": [],
            "error": "Nuclei scan timed out after 900 seconds.",
            "demo": False,
            "authorization_warning": AUTH_WARNING,
        }
    except OSError as exc:
        logger.exception("Unable to execute Nuclei")
        return {
            "run_id": run_id,
            "targets": targets,
            "categories_scanned": selected,
            "total_findings": 0,
            "findings": [],
            "error": f"Unable to execute Nuclei: {exc}",
            "demo": False,
            "authorization_warning": AUTH_WARNING,
        }


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
                info = item.get("info") or {}
                classification = info.get("classification") or {}
                def as_list(value):
                    if value is None:
                        return []
                    return value if isinstance(value, list) else [value]
                matched_url = item.get("matched-at") or item.get("url") or item.get("host") or ""
                template_id = item.get("template-id") or item.get("templateID") or "nuclei-unknown"
                findings.append({
                    "id": f"{template_id}::{matched_url}",
                    "template_id": template_id,
                    "title": info.get("name") or template_id,
                    "description": info.get("description") or "",
                    "severity": severity_map.get(str(info.get("severity", "info")).lower(), "INFO"),
                    "url": matched_url,
                    "cve_ids": as_list(classification.get("cve-id")),
                    "cwe_ids": as_list(classification.get("cwe-id")),
                    "cvss_score": classification.get("cvss-score"),
                    "tags": as_list(info.get("tags")),
                    "references": as_list(info.get("reference")),
                    "curl_command": item.get("curl-command", ""),
                    "request": item.get("request", ""),
                    "response": (item.get("response", "") or "")[:500],
                    "matcher_name": item.get("matcher-name", ""),
                    "extracted_results": as_list(item.get("extracted-results")),
                })
            except json.JSONDecodeError:
                continue

    return findings


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
