"""
SPAIDER Suricata Plugin — IDS/IPS alert collection and rule management.
"""

import subprocess
import os
import json
from typing import List, Dict, Any, Optional
from datetime import datetime
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "suricata",
    "version": "7.0",
    "category": "IDS/IPS",
    "description": "Suricata IDS alert collection, EVE JSON parsing, and signature-based threat detection.",
}

EVE_LOG_DEFAULT = "/var/log/suricata/eve.json"


def discover(log_path: str = EVE_LOG_DEFAULT) -> dict:
    """Check if Suricata is running and return log metadata."""
    running = _is_running()
    log_exists = os.path.exists(log_path)
    size = os.path.getsize(log_path) if log_exists else 0
    return {
        "suricata_running": running,
        "eve_log": log_path,
        "log_exists": log_exists,
        "log_size_bytes": size,
    }


def _is_running() -> bool:
    try:
        result = subprocess.run(["pgrep", "suricata"], capture_output=True)
        return result.returncode == 0
    except Exception:
        return False


def scan(pcap_file: str, rules: Optional[str] = None, output_dir: str = "./suricata_output") -> dict:
    """Run Suricata against a PCAP file in offline mode."""
    os.makedirs(output_dir, exist_ok=True)
    eve_file = os.path.join(output_dir, "eve.json")
    cmd = ["suricata", "-r", pcap_file, "-l", output_dir, "--runmode=autofp"]
    if rules:
        cmd += ["-S", rules]
    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        alerts = _parse_eve_json(eve_file)
        return {"status": "completed", "pcap": pcap_file, "alerts": alerts}
    except FileNotFoundError:
        logger.warning("Suricata not installed — returning mock data")
        return _mock_alerts()
    except subprocess.TimeoutExpired:
        return {"error": "Suricata analysis timed out"}


def collect(log_path: str = EVE_LOG_DEFAULT, limit: int = 500) -> list:
    """Collect recent alerts from the Suricata EVE JSON log."""
    return _parse_eve_json(log_path, limit=limit)


def _parse_eve_json(eve_file: str, limit: int = 500) -> list:
    """Parse Suricata EVE JSON log and return alert events."""
    alerts = []
    if not os.path.exists(eve_file):
        return alerts
    try:
        with open(eve_file) as f:
            for line in f:
                try:
                    event = json.loads(line)
                    if event.get("event_type") == "alert":
                        alerts.append({
                            "timestamp": event.get("timestamp"),
                            "signature": event.get("alert", {}).get("signature"),
                            "severity": event.get("alert", {}).get("severity", 3),
                            "category": event.get("alert", {}).get("category"),
                            "src_ip": event.get("src_ip"),
                            "dest_ip": event.get("dest_ip"),
                            "src_port": event.get("src_port"),
                            "dest_port": event.get("dest_port"),
                            "proto": event.get("proto"),
                            "sid": event.get("alert", {}).get("signature_id"),
                        })
                        if len(alerts) >= limit:
                            break
                except json.JSONDecodeError:
                    continue
    except Exception as e:
        logger.error("Failed to parse Suricata EVE log", error=str(e))
    return alerts


def _mock_alerts() -> dict:
    return {
        "status": "mock",
        "alerts": [
            {
                "timestamp": datetime.utcnow().isoformat(),
                "signature": "ET MALWARE Observed Malicious SSL Cert (C2 Domain)",
                "severity": 1,
                "category": "A Network Trojan was Detected",
                "src_ip": "192.168.1.10",
                "dest_ip": "185.220.101.1",
                "dest_port": 443,
                "proto": "TCP",
                "sid": 2028675,
            },
            {
                "timestamp": datetime.utcnow().isoformat(),
                "signature": "ET SCAN Nmap Scripting Engine User-Agent Detected",
                "severity": 2,
                "category": "Attempted Information Leak",
                "src_ip": "10.0.0.50",
                "dest_ip": "192.168.1.0/24",
                "dest_port": 0,
                "proto": "TCP",
                "sid": 2009582,
            },
        ],
    }


def analyze(results: dict) -> dict:
    """Analyze Suricata alerts for patterns and criticality."""
    alerts = results.get("alerts", [])
    by_category = {}
    by_severity = {1: 0, 2: 0, 3: 0}
    for alert in alerts:
        cat = alert.get("category", "Unknown")
        by_category[cat] = by_category.get(cat, 0) + 1
        sev = alert.get("severity", 3)
        if sev in by_severity:
            by_severity[sev] += 1

    mitre_map = {
        "ET SCAN": "T1046",
        "ET MALWARE": "T1071",
        "ET TROJAN": "T1071",
        "ET C2": "T1071",
        "ET EXPLOIT": "T1190",
        "ET BRUTE": "T1110",
    }
    mitre_hits = set()
    for alert in alerts:
        sig = alert.get("signature", "")
        for prefix, technique in mitre_map.items():
            if sig.startswith(prefix):
                mitre_hits.add(technique)

    return {
        "total_alerts": len(alerts),
        "by_category": by_category,
        "by_severity": by_severity,
        "mitre_techniques": list(mitre_hits),
    }


def normalize(results: dict) -> dict:
    """Normalize Suricata output to SPAIDER schema."""
    analysis = analyze(results)
    return {
        "source": "suricata",
        "alert_count": analysis["total_alerts"],
        "by_severity": analysis["by_severity"],
        "mitre_techniques": analysis["mitre_techniques"],
        "alerts": results.get("alerts", []),
    }


def report(results: dict) -> str:
    """Generate plain-text Suricata report."""
    analysis = analyze(results)
    lines = [
        "Suricata IDS Alert Report",
        "=" * 40,
        f"Total Alerts: {analysis['total_alerts']}",
        f"Critical (Sev 1): {analysis['by_severity'].get(1, 0)}",
        f"High (Sev 2): {analysis['by_severity'].get(2, 0)}",
        f"Medium (Sev 3): {analysis['by_severity'].get(3, 0)}",
        "\nTop Categories:",
    ]
    for cat, count in sorted(analysis["by_category"].items(), key=lambda x: x[1], reverse=True)[:5]:
        lines.append(f"  {count:4d}  {cat}")
    if analysis["mitre_techniques"]:
        lines.append(f"\nMITRE ATT&CK: {', '.join(analysis['mitre_techniques'])}")
    return "\n".join(lines)
