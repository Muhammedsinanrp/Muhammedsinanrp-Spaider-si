"""OSINT Tools endpoints — Shodan, VirusTotal, Truecaller intelligence lookups."""

from typing import Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db

router = APIRouter()

AUTH_WARNING = (
    "⚠️ OSINT queries must be conducted within legal boundaries. "
    "Only investigate targets you are authorised to research."
)


# ── Shodan ────────────────────────────────────────────────────────────────────

class ShodanRequest(BaseModel):
    query: str                          # IP address, hostname, or search query
    query_type: str = "host"            # host | search | dns
    api_key: Optional[str] = None       # override env key


class ShodanResponse(BaseModel):
    query: str
    query_type: str
    result: dict
    risk_analysis: dict
    authorization_warning: str = AUTH_WARNING


@router.post("/shodan", response_model=ShodanResponse)
async def shodan_lookup(payload: ShodanRequest, db: AsyncSession = Depends(get_db)):
    """
    Query Shodan for host intelligence, search results, or DNS data.

    query_type options:
    - **host**   — lookup a specific IP address (e.g. '8.8.8.8')
    - **search** — full-text Shodan search (e.g. 'apache port:8080')
    - **dns**    — resolve hostnames to IPs (comma-separated)
    """
    if not payload.query.strip():
        raise HTTPException(status_code=400, detail="Query cannot be empty")

    from app.plugins.shodan.plugin import lookup, analyze
    result = lookup(payload.query, api_key=payload.api_key, query_type=payload.query_type)
    risk = analyze(result)

    return ShodanResponse(
        query=payload.query,
        query_type=payload.query_type,
        result=result,
        risk_analysis=risk,
    )


@router.get("/shodan/host/{ip}")
async def shodan_host(ip: str):
    """Quick GET endpoint: lookup a specific IP on Shodan."""
    from app.plugins.shodan.plugin import lookup, analyze
    result = lookup(ip, query_type="host")
    return {"ip": ip, "result": result, "risk": analyze(result), "authorization_warning": AUTH_WARNING}


# ── VirusTotal ────────────────────────────────────────────────────────────────

class VirusTotalRequest(BaseModel):
    target: str                          # URL, IP, domain, or file hash
    scan_type: str = "url"               # url | ip | domain | hash
    api_key: Optional[str] = None        # override env key


class VirusTotalResponse(BaseModel):
    target: str
    scan_type: str
    result: dict
    risk_analysis: dict
    authorization_warning: str = AUTH_WARNING


@router.post("/virustotal", response_model=VirusTotalResponse)
async def virustotal_scan(payload: VirusTotalRequest, db: AsyncSession = Depends(get_db)):
    """
    Analyse a target against VirusTotal's 70+ security engines.

    scan_type options:
    - **url**    — scan a URL for phishing/malware
    - **ip**     — check an IP address reputation
    - **domain** — check a domain reputation
    - **hash**   — look up a file hash (MD5/SHA1/SHA256)
    """
    if not payload.target.strip():
        raise HTTPException(status_code=400, detail="Target cannot be empty")

    valid_types = {"url", "ip", "domain", "hash"}
    if payload.scan_type not in valid_types:
        raise HTTPException(status_code=400, detail=f"scan_type must be one of {valid_types}")

    from app.plugins.virustotal.plugin import scan, analyze
    result = scan(payload.target, scan_type=payload.scan_type, api_key=payload.api_key)
    risk = analyze(result)

    return VirusTotalResponse(
        target=payload.target,
        scan_type=payload.scan_type,
        result=result,
        risk_analysis=risk,
    )


@router.get("/virustotal/quick/{scan_type}/{target:path}")
async def virustotal_quick(scan_type: str, target: str):
    """Quick GET endpoint for VT lookups: /virustotal/quick/url/https://example.com"""
    from app.plugins.virustotal.plugin import scan, analyze
    result = scan(target, scan_type=scan_type)
    return {"target": target, "result": result, "risk": analyze(result), "authorization_warning": AUTH_WARNING}


# ── Truecaller ────────────────────────────────────────────────────────────────

class TruecallerRequest(BaseModel):
    phone: str                           # phone number (without country dialling prefix)
    country_code: str = "IN"             # ISO 2-letter country code
    auth_token: Optional[str] = None     # override env token


class TruecallerResponse(BaseModel):
    phone: str
    country_code: str
    result: dict
    risk_analysis: dict
    authorization_warning: str = AUTH_WARNING


@router.post("/truecaller", response_model=TruecallerResponse)
async def truecaller_lookup(payload: TruecallerRequest, db: AsyncSession = Depends(get_db)):
    """
    Look up a phone number via Truecaller for caller identity and spam intelligence.

    Provide the phone number **without** the country dialling code (e.g. '9876543210').
    Set country_code to the 2-letter ISO code of the number's country (default: IN).

    ⚠️ Requires TRUECALLER_AUTH_TOKEN env variable (obtain via truecallerpy login flow).
    """
    if not payload.phone.strip():
        raise HTTPException(status_code=400, detail="Phone number cannot be empty")

    from app.plugins.truecaller.plugin import lookup, analyze
    result = lookup(payload.phone, country_code=payload.country_code, auth_token=payload.auth_token)
    risk = analyze(result)

    return TruecallerResponse(
        phone=payload.phone,
        country_code=payload.country_code,
        result=result,
        risk_analysis=risk,
    )


# ── Combined OSINT Summary ────────────────────────────────────────────────────

@router.get("/summary")
async def osint_summary():
    """Return available OSINT tools and their configuration status."""
    import os
    return {
        "tools": [
            {
                "name": "Shodan",
                "id": "shodan",
                "configured": bool(os.getenv("SHODAN_API_KEY")),
                "requires": "SHODAN_API_KEY",
                "capabilities": ["host_lookup", "internet_search", "dns_resolve", "cve_detection"],
            },
            {
                "name": "VirusTotal",
                "id": "virustotal",
                "configured": bool(os.getenv("VIRUSTOTAL_API_KEY")),
                "requires": "VIRUSTOTAL_API_KEY",
                "capabilities": ["url_scan", "ip_reputation", "domain_check", "file_hash_lookup"],
            },
            {
                "name": "Truecaller",
                "id": "truecaller",
                "configured": bool(os.getenv("TRUECALLER_AUTH_TOKEN")),
                "requires": "TRUECALLER_AUTH_TOKEN",
                "capabilities": ["phone_lookup", "spam_detection", "carrier_info", "social_enrichment"],
            },
        ],
        "authorization_warning": AUTH_WARNING,
    }
