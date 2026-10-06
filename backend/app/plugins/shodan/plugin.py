"""
SPAIDER Shodan Plugin — Internet-wide host intelligence and exposure scanning.
Requires SHODAN_API_KEY in environment / .env
"""

import os
from typing import List, Optional
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = "⚠️ Only query hosts you are authorised to investigate. Shodan data may expose sensitive infrastructure."

PLUGIN_META = {
    "name": "shodan",
    "version": "1.0",
    "category": "OSINT",
    "description": "Internet-wide host intelligence — open ports, banners, CVEs, geolocation, and exposure analysis via Shodan.",
}


def lookup(query: str, api_key: Optional[str] = None, query_type: str = "host") -> dict:
    """Query Shodan for host/search/DNS intelligence."""
    key = api_key or os.getenv("SHODAN_API_KEY", "")
    if not key:
        logger.warning("No Shodan API key — returning mock data")
        return _mock_result(query, query_type)

    try:
        import shodan as shodan_lib  # pip install shodan
        api = shodan_lib.Shodan(key)

        if query_type == "host":
            data = api.host(query)
            return _parse_host(data)
        elif query_type == "search":
            data = api.search(query, limit=10)
            return _parse_search(data)
        elif query_type == "dns":
            data = api.dns.resolve(query.split(","))
            return {"dns": data, "authorization_warning": AUTH_WARNING}
        else:
            return {"error": f"Unknown query type: {query_type}", "authorization_warning": AUTH_WARNING}

    except ImportError:
        logger.warning("shodan library not installed — pip install shodan")
        return _mock_result(query, query_type)
    except Exception as e:
        logger.error("Shodan API error", error=str(e))
        return {"error": str(e), "authorization_warning": AUTH_WARNING}


def _parse_host(data: dict) -> dict:
    return {
        "ip": data.get("ip_str"),
        "org": data.get("org", "N/A"),
        "isp": data.get("isp", "N/A"),
        "country": data.get("country_name", "N/A"),
        "city": data.get("city", "N/A"),
        "os": data.get("os", "Unknown"),
        "hostnames": data.get("hostnames", []),
        "domains": data.get("domains", []),
        "ports": data.get("ports", []),
        "vulns": list(data.get("vulns", {}).keys()),
        "tags": data.get("tags", []),
        "last_update": data.get("last_update"),
        "services": [
            {
                "port": svc.get("port"),
                "transport": svc.get("transport", "tcp"),
                "product": svc.get("product", ""),
                "version": svc.get("version", ""),
                "banner": svc.get("data", "")[:200],
            }
            for svc in data.get("data", [])
        ],
        "authorization_warning": AUTH_WARNING,
    }


def _parse_search(data: dict) -> dict:
    matches = []
    for m in data.get("matches", []):
        matches.append({
            "ip": m.get("ip_str"),
            "port": m.get("port"),
            "org": m.get("org", "N/A"),
            "country": m.get("location", {}).get("country_name", "N/A"),
            "banner": m.get("data", "")[:200],
        })
    return {
        "total": data.get("total", 0),
        "matches": matches,
        "authorization_warning": AUTH_WARNING,
    }


def _mock_result(query: str, query_type: str) -> dict:
    if query_type == "host":
        return {
            "ip": query or "8.8.8.8",
            "org": "Google LLC",
            "isp": "Google",
            "country": "United States",
            "city": "Mountain View",
            "os": "Linux",
            "hostnames": ["dns.google"],
            "domains": ["google.com"],
            "ports": [53, 443],
            "vulns": [],
            "tags": ["cloud"],
            "last_update": "2024-01-15T10:00:00",
            "services": [
                {"port": 53, "transport": "udp", "product": "DNS", "version": "", "banner": ""},
                {"port": 443, "transport": "tcp", "product": "HTTPS", "version": "TLS 1.3", "banner": ""},
            ],
            "mock": True,
            "authorization_warning": AUTH_WARNING,
        }
    return {
        "total": 2,
        "matches": [
            {"ip": "1.2.3.4", "port": 80, "org": "Example ISP", "country": "Germany", "banner": "HTTP/1.1 200 OK"},
            {"ip": "5.6.7.8", "port": 443, "org": "Another ISP", "country": "France", "banner": "HTTP/1.1 301"},
        ],
        "mock": True,
        "authorization_warning": AUTH_WARNING,
    }


def analyze(results: dict) -> dict:
    """Identify high-risk findings from Shodan data."""
    flags = []
    risky_ports = {21: "FTP", 23: "Telnet", 3389: "RDP", 5900: "VNC", 445: "SMB", 1433: "MSSQL"}

    for svc in results.get("services", []):
        if svc.get("port") in risky_ports:
            flags.append({
                "port": svc["port"],
                "service": risky_ports[svc["port"]],
                "risk": "HIGH",
                "note": f"Dangerous service {risky_ports[svc['port']]} exposed to internet",
            })
    for cve in results.get("vulns", []):
        flags.append({"cve": cve, "risk": "CRITICAL", "note": f"Known vulnerability: {cve}"})

    return {"flags": flags, "total_risky": len(flags)}


def report(results: dict) -> str:
    lines = [f"Shodan Intelligence Report — {results.get('ip', 'N/A')}\n"]
    lines.append(f"  Org:     {results.get('org', 'N/A')}")
    lines.append(f"  Country: {results.get('country', 'N/A')}, {results.get('city', 'N/A')}")
    lines.append(f"  OS:      {results.get('os', 'Unknown')}")
    lines.append(f"  Ports:   {', '.join(str(p) for p in results.get('ports', []))}")
    if results.get("vulns"):
        lines.append(f"  CVEs:    {', '.join(results['vulns'])}")
    return "\n".join(lines)
