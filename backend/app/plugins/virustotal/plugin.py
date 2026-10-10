"""
SPAIDER VirusTotal Plugin — Multi-AV file/URL/IP/domain reputation analysis.
Requires VIRUSTOTAL_API_KEY in environment / .env
"""

import os
import hashlib
from typing import Optional
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = "⚠️ Submitted samples and queries are processed by VirusTotal. Avoid submitting confidential files."

PLUGIN_META = {
    "name": "virustotal",
    "version": "3.0",
    "category": "Threat Intel",
    "description": "Multi-engine AV/reputation analysis — scan files, URLs, IPs, and domains against 70+ security engines.",
}


def scan(target: str, scan_type: str = "url", api_key: Optional[str] = None) -> dict:
    """Scan a file hash, URL, IP, or domain via VirusTotal API v3."""
    key = api_key or os.getenv("VIRUSTOTAL_API_KEY", "")
    if not key:
        return {
            "error": "VirusTotal API key is not configured. Set VIRUSTOTAL_API_KEY or provide an API key for this request.",
            "configured": False,
            "authorization_warning": AUTH_WARNING,
        }

    try:
        import vt  # pip install vt-py
        client = vt.Client(key)

        if scan_type == "url":
            url_id = vt.url_id(target)
            obj = client.get_object(f"/urls/{url_id}")
        elif scan_type == "ip":
            obj = client.get_object(f"/ip_addresses/{target}")
        elif scan_type == "domain":
            obj = client.get_object(f"/domains/{target}")
        elif scan_type == "hash":
            obj = client.get_object(f"/files/{target}")
        else:
            client.close()
            return {"error": f"Unknown scan_type: {scan_type}", "authorization_warning": AUTH_WARNING}

        stats = obj.last_analysis_stats if hasattr(obj, "last_analysis_stats") else {}
        result = {
            "target": target,
            "scan_type": scan_type,
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "harmless": stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "reputation": getattr(obj, "reputation", 0),
            "tags": getattr(obj, "tags", []),
            "categories": dict(getattr(obj, "categories", {})),
            "verdicts": _extract_verdicts(obj),
            "authorization_warning": AUTH_WARNING,
        }
        client.close()
        return result

    except ImportError:
        return {
            "error": "The VirusTotal Python client is not installed. Install vt-py in the backend environment.",
            "configured": bool(key),
            "authorization_warning": AUTH_WARNING,
        }
    except Exception as e:
        logger.error("VirusTotal API error", error=str(e))
        return {"error": str(e), "authorization_warning": AUTH_WARNING}


def _extract_verdicts(obj) -> list:
    """Extract top engine verdicts from VT object."""
    results = dict(getattr(obj, "last_analysis_results", {}))
    verdicts = []
    for engine, res in list(results.items())[:20]:
        if res.get("category") in ("malicious", "suspicious"):
            verdicts.append({
                "engine": engine,
                "category": res.get("category"),
                "result": res.get("result", ""),
            })
    return verdicts


def analyze(results: dict) -> dict:
    """Flag high-risk items based on VT results."""
    malicious = results.get("malicious", 0)
    suspicious = results.get("suspicious", 0)
    total = results.get("total_engines", 1)
    ratio = malicious / max(total, 1)

    if malicious >= 10 or ratio > 0.3:
        risk = "CRITICAL"
    elif malicious >= 3 or suspicious >= 5:
        risk = "HIGH"
    elif malicious >= 1 or suspicious >= 1:
        risk = "MEDIUM"
    else:
        risk = "SAFE"

    return {
        "risk": risk,
        "malicious_engines": malicious,
        "detection_ratio": f"{malicious}/{total}",
        "recommendation": (
            "Block immediately — high confidence malware" if risk == "CRITICAL"
            else "Investigate further" if risk in ("HIGH", "MEDIUM")
            else "No known threats detected"
        ),
    }


def report(results: dict) -> str:
    lines = [f"VirusTotal Report — {results.get('target', 'N/A')} ({results.get('scan_type', '').upper()})\n"]
    lines.append(f"  Malicious:  {results.get('malicious', 0)}")
    lines.append(f"  Suspicious: {results.get('suspicious', 0)}")
    lines.append(f"  Harmless:   {results.get('harmless', 0)}")
    lines.append(f"  Total Engines: {results.get('total_engines', 0)}")
    if results.get("verdicts"):
        lines.append("  Detections:")
        for v in results["verdicts"][:5]:
            lines.append(f"    [{v['category'].upper()}] {v['engine']}: {v['result']}")
    return "\n".join(lines)
