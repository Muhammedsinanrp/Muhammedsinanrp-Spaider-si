"""
SPAIDER AI Analyzer Service
Operates strictly AFTER scanner evidence is established.
Performs:
1. Root-cause explanation
2. Business impact assessment
3. Mathematical risk prioritization (Severity x Exposure x Confidence x Criticality)
4. Concrete technical remediation & patch generation
"""

from typing import Dict, Any, List, Optional


SEVERITY_BASE_SCORES = {
    "CRITICAL": 9.5,
    "HIGH": 8.0,
    "MEDIUM": 5.5,
    "LOW": 2.5,
    "INFO": 1.0,
}


def calculate_prioritized_risk(
    severity: str,
    cvss: Optional[float],
    confidence: float,
    asset: str,
    port: Optional[int],
    is_public: bool = True,
) -> float:
    """
    Mathematical Risk Scoring:
    Risk Score = Base(Severity/CVSS) * Exposure * Confidence * Criticality
    Normalized to a 0.0 - 10.0 scale.
    """
    base = cvss if (cvss and cvss > 0) else SEVERITY_BASE_SCORES.get(severity.upper(), 5.0)

    # Exposure: Web-facing ports (80, 443, 3000, 8080) or public IP
    exposure_mult = 1.25 if (is_public or port in (80, 443, 3000, 8000, 8080, 8443)) else 1.0

    # Confidence factor (capped 0.7 - 1.0)
    conf_factor = max(0.7, min(1.0, confidence))

    # Asset criticality: DBs, APIs, Auth servers higher
    crit_mult = 1.0
    asset_lower = asset.lower()
    if any(k in asset_lower for k in ["api", "auth", "db", "admin", "prod", "gateway"]):
        crit_mult = 1.2

    raw_risk = (base * exposure_mult * conf_factor * crit_mult) / (1.25 * 1.2)
    return round(min(10.0, max(1.0, raw_risk)), 1)


def generate_ai_analysis_for_finding(finding_dict: Dict[str, Any]) -> Dict[str, Any]:
    """
    Generate structured reasoning, explanation, and remediation based on scanner evidence.
    """
    title = finding_dict.get("title", "Security Finding")
    severity = str(finding_dict.get("severity", "MEDIUM")).upper()
    asset = finding_dict.get("asset", "target.local")
    endpoint = finding_dict.get("endpoint", "/")
    evidence = finding_dict.get("evidence", "")
    curl_poc = finding_dict.get("curl_poc", "")
    cvss = finding_dict.get("cvss")
    cwe = finding_dict.get("cwe") or "CWE-Unknown"
    confidence = float(finding_dict.get("confidence", 0.9))
    port = finding_dict.get("port")

    risk_score = calculate_prioritized_risk(
        severity=severity,
        cvss=cvss,
        confidence=confidence,
        asset=asset,
        port=port,
        is_public=True,
    )

    # Generate tailored technical remediation
    title_lower = title.lower()
    if "sql injection" in title_lower or "sqli" in title_lower:
        remediation_text = (
            "1. Replace dynamic SQL string concatenations with parameterized prepared statements.\n"
            "2. Enforce object-relational mapping (ORM) with strict input validation.\n"
            "3. Restrict DB user permissions to least privilege."
        )
        impact_text = "Enables attackers to bypass authentication, exfiltrate sensitive databases, and tamper with records."
    elif "ssrf" in title_lower or "request forgery" in title_lower:
        remediation_text = (
            "1. Validate destination URLs against an explicit strict domain/IP whitelist.\n"
            "2. Disallow connections to private IP spaces (RFC 1918, RFC 3927 cloud metadata 169.254.169.254).\n"
            "3. Enforce network-layer firewall egress filtering."
        )
        impact_text = "Allows attackers to pivot through internal network perimeters and extract cloud instance IAM credentials."
    elif "xss" in title_lower or "cross-site scripting" in title_lower:
        remediation_text = (
            "1. Implement context-aware output encoding before rendering dynamic data in the DOM.\n"
            "2. Deploy a robust Content-Security-Policy (CSP) restricting script-src.\n"
            "3. Set HttpOnly and SameSite=Strict flags on session cookies."
        )
        impact_text = "Facilitates session hijacking, credential theft, and unauthorized browser actions on behalf of victims."
    elif "traversal" in title_lower or "file read" in title_lower:
        remediation_text = (
            "1. Sanitize user input using canonicalized absolute paths and reject '../' sequences.\n"
            "2. Upgrade web server daemon to current patch revision.\n"
            "3. Run web worker under unprivileged chroot/jail containers."
        )
        impact_text = "Permits unauthorized reading of configuration files, password hashes, and environment variables."
    elif "cors" in title_lower:
        remediation_text = (
            "1. Avoid reflecting arbitrary Origin headers.\n"
            "2. Specify explicit trusted origin domains rather than wildcard '*'.\n"
            "3. Restrict Access-Control-Allow-Credentials to strictly necessary origins."
        )
        impact_text = "Enables third-party attacker domains to steal authenticated private user data via cross-origin requests."
    else:
        remediation_text = (
            f"1. Apply latest vendor security updates for software running on {asset}:{port or 80}.\n"
            f"2. Audit access controls and input validation on endpoint {endpoint}.\n"
            f"3. Add defensive WAF / IPS monitoring rules matching this pattern."
        )
        impact_text = f"Compromises application integrity on {asset} and exposes attack surface to unauthorized probing."

    explanation = {
        "what_happened": f"Scanner detected {title} on asset {asset} (endpoint: {endpoint}).",
        "why_it_matters": impact_text,
        "affected_asset": f"{asset}:{port or 80}",
        "evidence_summary": evidence[:300] if evidence else (f"Validated via: {curl_poc[:180]}" if curl_poc else "Detected by scanner engine"),
    }

    return {
        "risk_score": risk_score,
        "prioritization_tier": "CRITICAL_ACTION" if risk_score >= 8.5 else ("HIGH_PRIORITY" if risk_score >= 7.0 else "NORMAL"),
        "explanation": explanation,
        "remediation_plan": remediation_text,
        "confidence_level": f"{int(confidence * 100)}%",
        "correlations": [
            f"Shares affected host with {asset}",
            f"Maps to {cwe}",
        ],
    }
