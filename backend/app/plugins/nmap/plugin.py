"""
SPAIDER Nmap Plugin — Network discovery and asset enumeration.
"""

import subprocess
import uuid
import os
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."


PLUGIN_META = {
    "name": "nmap",
    "version": "7.94",
    "category": "Network Discovery",
    "description": "Network service discovery, OS detection, version scanning, and topology mapping.",
}


def discover(targets: List[str], scan_type: str = "quick") -> dict:
    """Discover hosts and services on the network."""
    return scan(targets, scan_type=scan_type)


def scan(
    targets: List[str],
    scan_type: str = "full",
    ports: Optional[str] = None,
    timing: int = 3,
    results_dir: str = "./scan_results",
) -> dict:
    """Run Nmap scan and return parsed results."""
    from app.core.config import settings

    nmap_path = getattr(settings, "nmap_path", "nmap")
    os.makedirs(results_dir, exist_ok=True)
    result_file = os.path.join(results_dir, f"nmap_{uuid.uuid4()}.xml")

    scan_profiles = {
        "quick":   ["-T4", "-F", "-sV"],
        "full":    ["-T3", "-sV", "-sC", "-O", "--version-intensity", "5"],
        "stealth": ["-T2", "-sS", "-sV"],
        "udp":     ["-sU", "-T3", "--top-ports", "100"],
        "os":      ["-O", "-sV", "-T4"],
        "version": ["-sV", "--version-all", "-T3"],
    }

    args = [nmap_path] + scan_profiles.get(scan_type, scan_profiles["quick"])
    if ports:
        args += ["-p", ports]
    args += ["-oX", result_file] + targets

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"error": result.stderr, "mock": False, "authorization_warning": AUTH_WARNING}
        parsed = _parse_xml(result_file)
        return {"hosts": len(parsed), "result_file": result_file, "parsed": parsed, "authorization_warning": AUTH_WARNING}
    except FileNotFoundError:
        logger.error("Nmap executable not found; no scan was performed")
        return {"error": "Nmap executable not found. Install Nmap and ensure it is on PATH.", "targets": targets, "mock": False, "authorization_warning": AUTH_WARNING}
    except subprocess.TimeoutExpired:
        return {"error": "Scan timed out", "authorization_warning": AUTH_WARNING}


def _parse_xml(xml_file: str) -> list:
    """Parse Nmap XML output into structured host list."""
    try:
        import xmltodict
        with open(xml_file) as f:
            data = xmltodict.parse(f.read())
        hosts = []
        host_data = data.get("nmaprun", {}).get("host", [])
        if isinstance(host_data, dict):
            host_data = [host_data]
        for host in host_data:
            addrs = host.get("address", [])
            if isinstance(addrs, dict):
                addrs = [addrs]
            ip = next((a["@addr"] for a in addrs if a.get("@addrtype") == "ipv4"), None)
            if not ip:
                continue
            port_data = host.get("ports", {}).get("port", [])
            if isinstance(port_data, dict):
                port_data = [port_data]
            ports = []
            for p in port_data:
                if p.get("state", {}).get("@state") == "open":
                    svc = p.get("service", {})
                    ports.append({
                        "port": int(p.get("@portid", 0)),
                        "protocol": p.get("@protocol", "tcp"),
                        "name": svc.get("@name", "unknown"),
                        "product": svc.get("@product", ""),
                        "version": svc.get("@version", ""),
                    })
            os_info = host.get("os", {}).get("osmatch", {})
            if isinstance(os_info, list):
                os_info = os_info[0] if os_info else {}
            hosts.append({
                "ip": ip,
                "hostname": host.get("hostnames", {}).get("hostname", {}).get("@name", ""),
                "os": os_info.get("@name", ""),
                "ports": ports,
                "status": host.get("status", {}).get("@state", "up"),
            })
        return hosts
    except Exception as e:
        logger.error("Failed to parse Nmap XML", error=str(e))
        return []


def analyze(results: dict) -> dict:
    """Analyse scan results for interesting findings."""
    risky_ports = {21: "FTP", 23: "Telnet", 445: "SMB", 3389: "RDP", 5900: "VNC"}
    flags = []
    for host in results.get("parsed", []):
        for port_info in host.get("ports", []):
            port = port_info.get("port")
            if port in risky_ports:
                flags.append({
                    "host": host["ip"],
                    "port": port,
                    "service": risky_ports[port],
                    "risk": "HIGH" if port in (23, 445, 3389) else "MEDIUM",
                    "note": f"Risky service {risky_ports[port]} exposed",
                })
    return {"flags": flags, "total_risky": len(flags)}


def normalize(raw: dict) -> list:
    """Normalize Nmap output to SPAIDER asset schema."""
    assets = []
    for host in raw.get("parsed", []):
        assets.append({
            "type": "HOST",
            "value": host["ip"],
            "name": host.get("hostname") or host["ip"],
            "os": host.get("os"),
            "services": host.get("ports", []),
        })
    return assets


def report(results: dict) -> str:
    """Generate a plain-text summary report."""
    parsed = results.get("parsed", [])
    lines = [f"Nmap Scan Report — {len(parsed)} host(s) found\n"]
    for host in parsed:
        lines.append(f"  Host: {host['ip']} ({host.get('hostname', '')})")
        lines.append(f"  OS:   {host.get('os', 'Unknown')}")
        for p in host.get("ports", []):
            lines.append(f"    {p['port']}/{p.get('protocol','tcp')}  {p.get('name','')}")
        lines.append("")
    return "\n".join(lines)
