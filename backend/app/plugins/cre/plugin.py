"""
SPAIDER OpenCRE Plugin — Open Common Requirement Enumeration.
Bridges cybersecurity frameworks, standards, guidelines, and weaknesses:
OWASP Top 10, NIST SP 800-53, ISO/IEC 27001, OWASP ASVS, CWE, and CAPEC.
Official Knowledge Graph: opencre.org
"""

import os
import json
import urllib.request
import urllib.error
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "cre",
    "version": "1.4.0",
    "category": "Governance & Compliance",
    "description": "OWASP OpenCRE — interactive cybersecurity requirements cross-referencing, linking NIST 800-53, ISO 27001, OWASP ASVS, CWE, and CAPEC.",
}

# Embedded knowledge base for instant offline lookup and fast responses
CRE_DATABASE = [
    {
        "cre_id": "074-651",
        "title": "Establish and maintain cryptographic keys",
        "description": "Cryptographic keys must be generated, stored, distributed, rotated, and destroyed securely throughout their lifecycle.",
        "nist": "SC-12, SC-13, IA-5(2)",
        "iso27001": "A.10.1.2 Key management",
        "asvs": "V6 Cryptography Verification Requirements",
        "cwe": ["CWE-320", "CWE-321", "CWE-324"],
        "owasp_top10": "A02:2021-Cryptographic Failures",
    },
    {
        "cre_id": "270-388",
        "title": "Verify user identity / Authentication",
        "description": "Ensure users and automated agents are uniquely and strongly authenticated before granting system or data access.",
        "nist": "IA-2, IA-5, AC-2",
        "iso27001": "A.9.2 User access management, A.9.4 Access control",
        "asvs": "V2 Authentication Verification Requirements",
        "cwe": ["CWE-287", "CWE-306", "CWE-798"],
        "owasp_top10": "A07:2021-Identification and Authentication Failures",
    },
    {
        "cre_id": "314-722",
        "title": "Validate all incoming data / Input sanitization",
        "description": "Enforce strict syntactic and semantic input validation using positive validation allowlists across all inputs.",
        "nist": "SI-10 Information Input Validation",
        "iso27001": "A.14.1.2 Securing application services on public networks",
        "asvs": "V5 Validation, Sanitization and Encoding",
        "cwe": ["CWE-20", "CWE-79", "CWE-89"],
        "owasp_top10": "A03:2021-Injection",
    },
    {
        "cre_id": "495-210",
        "title": "Enforce principle of least privilege / Access control",
        "description": "Users and software services should only be granted the minimum necessary permissions required to execute tasks.",
        "nist": "AC-3, AC-6 Least Privilege",
        "iso27001": "A.9.1.2 Access to networks and network services",
        "asvs": "V4 Access Control Verification Requirements",
        "cwe": ["CWE-269", "CWE-285", "CWE-639", "CWE-862"],
        "owasp_top10": "A01:2021-Broken Access Control",
    },
    {
        "cre_id": "622-489",
        "title": "Log and monitor security-relevant events",
        "description": "Capture tamper-evident audit trails for user activities, exceptions, faults, and access violations.",
        "nist": "AU-2, AU-3, AU-6 Audit Review, Analysis, and Reporting",
        "iso27001": "A.12.4 Logging and monitoring",
        "asvs": "V8 Error Handling and Logging",
        "cwe": ["CWE-778", "CWE-117", "CWE-532"],
        "owasp_top10": "A09:2021-Security Logging and Monitoring Failures",
    },
    {
        "cre_id": "812-390",
        "title": "Secure software supply chain & third-party dependencies",
        "description": "Catalog and continuously audit software dependencies (SBOM) against known CVEs and maintain patched components.",
        "nist": "SR-3, SA-12 Supply Chain Protection",
        "iso27001": "A.15 Supplier relationships",
        "asvs": "V14 Build and Deployment Verification Requirements",
        "cwe": ["CWE-1104", "CWE-1395"],
        "owasp_top10": "A06:2021-Vulnerable and Outdated Components",
    },
]


def query(keyword_or_id: str, framework_filter: Optional[str] = None) -> dict:
    """
    Search OpenCRE knowledge base for requirements matching keyword, CRE ID, CWE, or NIST code.
    Attempts live query to opencre.org API, fallback to rich offline embedded knowledge graph.
    """
    cleaned = keyword_or_id.strip().lower()
    
    # Try opencre.org public API if internet reachable
    if len(cleaned) >= 3 and not framework_filter:
        try:
            url = f"https://www.opencre.org/rest/cre/{cleaned}"
            req = urllib.request.Request(url, headers={"User-Agent": "SPAIDER-OpenCRE/1.4"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    data = json.loads(resp.read().decode("utf-8"))
                    return {
                        "source": "opencre.org (Live API)",
                        "query": keyword_or_id,
                        "matches": [data.get("data", {})],
                    }
        except Exception:
            pass

    # Search local database
    matches = []
    for item in CRE_DATABASE:
        blob = f"{item['cre_id']} {item['title']} {item['description']} {item['nist']} {item['iso27001']} {item['asvs']} {' '.join(item['cwe'])} {item['owasp_top10']}".lower()
        if not cleaned or cleaned in blob:
            matches.append(item)

    return {
        "source": "OpenCRE Local Catalog & Standards Cross-Reference Engine",
        "query": keyword_or_id,
        "total_results": len(matches),
        "matches": matches,
    }


def scan(target: str = "all", **kwargs) -> dict:
    """Wrapper for scan orchestration."""
    return query(target, **kwargs)


def analyze(results: dict) -> dict:
    """Analyze standards alignment and return coverage metrics."""
    matches = results.get("matches", [])
    frameworks_covered = {
        "NIST SP 800-53": sum(1 for m in matches if m.get("nist")),
        "ISO/IEC 27001": sum(1 for m in matches if m.get("iso27001")),
        "OWASP ASVS": sum(1 for m in matches if m.get("asvs")),
        "OWASP Top 10": sum(1 for m in matches if m.get("owasp_top10")),
    }
    return {
        "matched_requirements": len(matches),
        "framework_breakdown": frameworks_covered,
        "compliance_readiness_score": f"{min(100, len(matches) * 18)}%",
    }


def normalize(raw: dict) -> List[Dict[str, Any]]:
    """Convert CRE mappings into standard requirement nodes."""
    return [
        {
            "type": "REQUIREMENT",
            "cre_id": m.get("cre_id"),
            "title": m.get("title"),
            "nist": m.get("nist"),
            "iso27001": m.get("iso27001"),
            "owasp": m.get("owasp_top10"),
        }
        for m in raw.get("matches", [])
    ]


def report(results: dict) -> str:
    """Generate OpenCRE standards mapping summary."""
    lines = [
        "════════════════════════════════════════════════════════════════",
        "  OWASP OPEN CRE — STANDARDS & COMPLIANCE MAPPING",
        "════════════════════════════════════════════════════════════════",
        f"Search Term: '{results.get('query', '')}'",
        f"Total Matching CRE Nodes: {len(results.get('matches', []))}",
        "",
    ]
    for m in results.get("matches", []):
        lines.append(f"CRE [{m.get('cre_id')}]: {m.get('title')}")
        lines.append(f"  • NIST:     {m.get('nist')}")
        lines.append(f"  • ISO27001: {m.get('iso27001')}")
        lines.append(f"  • ASVS:     {m.get('asvs')}")
        lines.append(f"  • CWE:      {', '.join(m.get('cwe', []))}")
        lines.append(f"  • OWASP:    {m.get('owasp_top10')}")
        lines.append("")
    return "\n".join(lines)
