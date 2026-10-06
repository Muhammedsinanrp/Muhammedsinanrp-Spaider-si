"""
SPAIDER Finding Normalizer & Deduplication Service
Translates disparate scanner outputs (Nmap, Nuclei, HTTP crawler) into a Universal Finding Schema.
Performs intelligent deduplication and tracking.
"""

import hashlib
import json
import urllib.parse
from datetime import datetime
from typing import Dict, Any, Optional, List, Tuple
from sqlalchemy.orm import Session
from sqlalchemy import select

from app.models.models import Finding, Severity


def compute_dedup_hash(asset: str, port: Optional[int], endpoint: Optional[str], cwe_or_title: str) -> str:
    """Deterministic hash for deduplicating findings across repeat scans."""
    clean_asset = (asset or "").strip().lower()
    clean_port = str(port or 0)
    clean_endpoint = (endpoint or "/").strip().lower()
    clean_title = (cwe_or_title or "").strip().lower()
    raw = f"{clean_asset}:{clean_port}:{clean_endpoint}:{clean_title}"
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def map_severity_string(sev_str: Optional[str]) -> Severity:
    """Normalize severity strings into standard Severity Enum."""
    if not sev_str:
        return Severity.INFO
    s = str(sev_str).strip().upper()
    if "CRIT" in s:
        return Severity.CRITICAL
    if "HIGH" in s:
        return Severity.HIGH
    if "MED" in s:
        return Severity.MEDIUM
    if "LOW" in s:
        return Severity.LOW
    return Severity.INFO


class UniversalFinding:
    """Universal Finding Data Structure."""

    def __init__(
        self,
        title: str,
        severity: str,
        asset: str,
        confidence: float = 0.90,
        endpoint: str = "/",
        port: Optional[int] = None,
        protocol: str = "http",
        cve: Optional[str] = None,
        cwe: Optional[str] = None,
        cvss: Optional[float] = None,
        description: str = "",
        evidence: str = "",
        curl_poc: Optional[str] = None,
        request_raw: Optional[str] = None,
        response_raw: Optional[str] = None,
        remediation: str = "",
        scanner: str = "nuclei",
        status: str = "open",
        raw_data: Optional[Dict[str, Any]] = None,
        mitre_techniques: Optional[List[str]] = None,
    ):
        self.title = title
        self.severity = severity
        self.confidence = float(confidence)
        self.asset = asset
        self.endpoint = endpoint
        self.port = port
        self.protocol = protocol
        self.cve = cve
        self.cwe = cwe
        self.cvss = cvss
        self.description = description
        self.evidence = evidence
        self.curl_poc = curl_poc
        self.request_raw = request_raw
        self.response_raw = response_raw
        self.remediation = remediation
        self.scanner = scanner
        self.status = status
        self.raw_data = raw_data or {}
        self.mitre_techniques = mitre_techniques or []
        self.dedup_hash = compute_dedup_hash(
            asset=self.asset,
            port=self.port,
            endpoint=self.endpoint,
            cwe_or_title=self.cwe or self.cve or self.title,
        )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "severity": self.severity.lower(),
            "confidence": round(self.confidence, 2),
            "asset": self.asset,
            "endpoint": self.endpoint,
            "port": self.port,
            "protocol": self.protocol,
            "cve": self.cve,
            "cwe": self.cwe,
            "cvss": self.cvss,
            "description": self.description,
            "evidence": self.evidence,
            "curl_poc": self.curl_poc,
            "remediation": self.remediation,
            "scanner": self.scanner,
            "status": self.status,
            "dedup_hash": self.dedup_hash,
        }


def normalize_nuclei_item(item: Dict[str, Any], default_target: str = "") -> UniversalFinding:
    """Convert raw Nuclei JSON item to UniversalFinding."""
    info = item.get("info", {})
    matched_at = item.get("matched-at") or item.get("host") or default_target

    parsed_url = urllib.parse.urlparse(matched_at) if "://" in matched_at else None
    asset = parsed_url.hostname if parsed_url else matched_at.split(":")[0]
    port = parsed_url.port if parsed_url and parsed_url.port else (443 if matched_at.startswith("https") else 80)
    endpoint = parsed_url.path if parsed_url and parsed_url.path else "/"

    # Classification
    classification = info.get("classification", {})
    cve_list = classification.get("cve-id", [])
    cve = cve_list[0] if cve_list else None
    cwe_list = classification.get("cwe-id", [])
    cwe = cwe_list[0] if cwe_list else None
    cvss = classification.get("cvss-score")
    if cvss is not None:
        try:
            cvss = float(cvss)
        except (ValueError, TypeError):
            cvss = None

    curl_command = item.get("curl-command")
    req_extracted = item.get("request", "")
    res_extracted = item.get("response", "")
    extracted_results = item.get("extracted-results", [])
    evidence = "\n".join(extracted_results) if extracted_results else (res_extracted[:400] if res_extracted else "")

    return UniversalFinding(
        title=info.get("name", item.get("template-id", "Nuclei Vulnerability")),
        severity=info.get("severity", "info").upper(),
        confidence=0.95 if curl_command or evidence else 0.85,
        asset=asset or default_target,
        endpoint=endpoint,
        port=port,
        protocol="https" if "https://" in matched_at else "http",
        cve=cve,
        cwe=cwe,
        cvss=cvss,
        description=info.get("description", ""),
        evidence=evidence,
        curl_poc=curl_command,
        request_raw=req_extracted,
        response_raw=res_extracted,
        remediation=info.get("remediation", ""),
        scanner="nuclei",
        status="open",
        raw_data=item,
        mitre_techniques=info.get("tags", []),
    )


def normalize_nmap_service(host_ip: str, port_info: Dict[str, Any]) -> Optional[UniversalFinding]:
    """Convert suspicious open ports / vulnerable service versions from Nmap into UniversalFinding."""
    svc_name = port_info.get("name", "unknown")
    port = port_info.get("port", 0)
    product = port_info.get("product", "")
    version = port_info.get("version", "")

    # Identify clear security concerns
    is_vuln = False
    title = ""
    severity = "INFO"
    cvss = 0.0

    if port in (21, 23):  # Telnet or FTP cleartext
        is_vuln = True
        title = f"Unencrypted Cleartext Service Exposed ({svc_name.upper()} on Port {port})"
        severity = "MEDIUM"
        cvss = 5.3
    elif port in (445, 139):  # SMB exposed
        is_vuln = True
        title = f"SMB Service Exposed Directly on Port {port}"
        severity = "HIGH"
        cvss = 7.5
    elif port in (3389, 5900):  # RDP / VNC exposed
        is_vuln = True
        title = f"Remote Desktop Protocol Exposed ({svc_name.upper()} on Port {port})"
        severity = "MEDIUM"
        cvss = 6.5
    elif "Apache/2.4.49" in f"{product} {version}":
        is_vuln = True
        title = "Apache 2.4.49 Path Traversal & RCE Vulnerability"
        severity = "CRITICAL"
        cvss = 9.8

    if not is_vuln:
        return None

    return UniversalFinding(
        title=title,
        severity=severity,
        confidence=0.92,
        asset=host_ip,
        endpoint=f":{port}/{svc_name}",
        port=port,
        protocol=port_info.get("protocol", "tcp"),
        cvss=cvss,
        description=f"Service {product} {version} running on port {port} exposes unauthorized surface.",
        evidence=f"Nmap discovered open port {port}/{port_info.get('protocol')} ({product} {version})",
        scanner="nmap",
        status="open",
    )


def save_or_deduplicate_finding(
    db: Session,
    uf: UniversalFinding,
    scan_job_id: Optional[str] = None,
    asset_id: Optional[str] = None,
) -> Tuple[Finding, bool]:
    """
    Persist finding to database with deduplication logic.
    Returns: (finding_record, is_new)
    """
    existing = db.query(Finding).filter(Finding.dedup_hash == uf.dedup_hash).first()

    if existing:
        # Update existing finding
        existing.occurrence_count = (existing.occurrence_count or 1) + 1
        existing.updated_at = datetime.utcnow()
        if uf.curl_poc and not existing.curl_poc:
            existing.curl_poc = uf.curl_poc
        if uf.evidence and not existing.evidence:
            existing.evidence = uf.evidence
        if uf.confidence > (existing.confidence or 0.0):
            existing.confidence = uf.confidence
        return existing, False

    # Create new finding
    sev_enum = map_severity_string(uf.severity)
    finding = Finding(
        title=uf.title,
        description=uf.description,
        severity=sev_enum,
        confidence=uf.confidence,
        asset_value=uf.asset,
        endpoint=uf.endpoint,
        port=uf.port,
        protocol=uf.protocol,
        cve=uf.cve,
        cwe=uf.cwe,
        cvss=uf.cvss,
        cvss_score=uf.cvss,
        scanner=uf.scanner,
        plugin=uf.scanner,
        status=uf.status,
        evidence=uf.evidence,
        curl_poc=uf.curl_poc,
        request_raw=uf.request_raw,
        response_raw=uf.response_raw,
        remediation=uf.remediation,
        dedup_hash=uf.dedup_hash,
        occurrence_count=1,
        raw_data=uf.raw_data,
        cve_ids=[uf.cve] if uf.cve else [],
        cwe_ids=[uf.cwe] if uf.cwe else [],
        mitre_techniques=uf.mitre_techniques,
        scan_job_id=scan_job_id,
        asset_id=asset_id,
        is_verified=True if uf.curl_poc or (uf.confidence >= 0.90) else False,
    )
    db.add(finding)
    return finding, True
