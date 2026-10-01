"""
SPAIDER Zeek Plugin — Network traffic analysis and protocol intelligence.
"""

import subprocess
import os
import json
from typing import List, Dict, Any, Optional
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "zeek",
    "version": "6.0",
    "category": "Network Analysis",
    "description": "Network traffic analysis via Zeek. Extracts connection logs, DNS, HTTP, SSL, and detects anomalies.",
}


def discover(pcap_dir: str = "./pcap_files") -> dict:
    """List PCAP files available for analysis."""
    files = []
    if os.path.isdir(pcap_dir):
        for f in os.listdir(pcap_dir):
            if f.endswith((".pcap", ".pcapng", ".cap")):
                full = os.path.join(pcap_dir, f)
                files.append({"path": full, "name": f, "size": os.path.getsize(full)})
    return {"pcap_files": files, "count": len(files)}


def scan(pcap_file: str, output_dir: str = "./zeek_output") -> dict:
    """Run Zeek against a PCAP file and return structured log data."""
    os.makedirs(output_dir, exist_ok=True)
    try:
        result = subprocess.run(
            ["zeek", "-C", "-r", pcap_file],
            capture_output=True, text=True, timeout=300,
            cwd=output_dir,
        )
        logs = _parse_zeek_logs(output_dir)
        return {"status": "completed", "pcap": pcap_file, "logs": logs}
    except FileNotFoundError:
        logger.warning("Zeek not installed — returning mock data")
        return _mock_zeek_result(pcap_file)
    except subprocess.TimeoutExpired:
        return {"error": "Zeek analysis timed out"}


def _parse_zeek_logs(log_dir: str) -> dict:
    """Parse Zeek TSV log files into structured dicts."""
    logs = {}
    log_types = ["conn", "dns", "http", "ssl", "notice", "files", "weird"]
    for log_type in log_types:
        log_file = os.path.join(log_dir, f"{log_type}.log")
        if os.path.exists(log_file):
            logs[log_type] = _parse_tsv_log(log_file)
    return logs


def _parse_tsv_log(path: str, limit: int = 500) -> list:
    """Parse a Zeek TSV log file."""
    records = []
    fields = []
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("#fields"):
                    fields = line.split("\t")[1:]
                elif line.startswith("#"):
                    continue
                elif fields and len(records) < limit:
                    values = line.split("\t")
                    records.append(dict(zip(fields, values)))
    except Exception as e:
        logger.error("Failed to parse Zeek log", path=path, error=str(e))
    return records


def _mock_zeek_result(pcap_file: str) -> dict:
    return {
        "status": "mock",
        "pcap": pcap_file,
        "logs": {
            "conn": [
                {"id.orig_h": "192.168.1.10", "id.resp_h": "8.8.8.8", "proto": "udp", "id.resp_p": "53", "duration": "0.001"},
                {"id.orig_h": "192.168.1.10", "id.resp_h": "185.220.101.1", "proto": "tcp", "id.resp_p": "443", "duration": "12.5"},
            ],
            "dns": [
                {"query": "c2.evilcorp.ru", "qtype_name": "A", "id.orig_h": "192.168.1.10"},
            ],
        },
    }


def analyze(results: dict) -> dict:
    """Detect anomalies in Zeek log data."""
    alerts = []
    logs = results.get("logs", {})

    # Suspicious DNS
    suspicious_tlds = [".ru", ".cn", ".xyz", ".top", ".tk"]
    for dns_entry in logs.get("dns", []):
        query = dns_entry.get("query", "")
        if any(query.endswith(tld) for tld in suspicious_tlds):
            alerts.append({
                "type": "suspicious_dns",
                "severity": "HIGH",
                "detail": f"Suspicious DNS query: {query}",
                "source_ip": dns_entry.get("id.orig_h"),
                "mitre": ["T1071.004"],
            })

    # Long-duration connections (possible C2 beaconing)
    for conn in logs.get("conn", []):
        try:
            duration = float(conn.get("duration", 0))
            if duration > 3600:
                alerts.append({
                    "type": "long_connection",
                    "severity": "MEDIUM",
                    "detail": f"Long connection ({duration:.0f}s) to {conn.get('id.resp_h')}",
                    "source_ip": conn.get("id.orig_h"),
                    "dest_ip": conn.get("id.resp_h"),
                    "mitre": ["T1071"],
                })
        except (ValueError, TypeError):
            pass

    return {"alerts": alerts, "total_anomalies": len(alerts)}


def collect(results: dict) -> list:
    """Extract network IOCs from Zeek logs."""
    iocs = []
    logs = results.get("logs", {})
    seen = set()
    for dns_entry in logs.get("dns", []):
        query = dns_entry.get("query", "")
        if query and query not in seen:
            iocs.append({"type": "domain", "value": query})
            seen.add(query)
    for conn in logs.get("conn", []):
        ip = conn.get("id.resp_h", "")
        if ip and ip not in seen:
            iocs.append({"type": "ip", "value": ip})
            seen.add(ip)
    return iocs


def normalize(results: dict) -> dict:
    """Normalize Zeek output to SPAIDER schema."""
    analysis = analyze(results)
    return {
        "source": "zeek",
        "alerts": analysis["alerts"],
        "iocs": collect(results),
        "log_summary": {k: len(v) for k, v in results.get("logs", {}).items()},
    }


def report(results: dict) -> str:
    """Generate a plain-text Zeek analysis report."""
    logs = results.get("logs", {})
    lines = ["Zeek Network Analysis Report", "=" * 40]
    for log_type, entries in logs.items():
        lines.append(f"\n{log_type.upper()} log: {len(entries)} entries")
    analysis = analyze(results)
    if analysis["alerts"]:
        lines.append(f"\nAnomalies detected: {analysis['total_anomalies']}")
        for alert in analysis["alerts"]:
            lines.append(f"  [{alert['severity']}] {alert['type']}: {alert['detail']}")
    return "\n".join(lines)
