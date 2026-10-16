"""
SPAIDER Nmap Plugin — Network discovery and asset enumeration.
"""

import subprocess
import uuid
import os
from typing import List, Optional, Dict, Any
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = "[!] Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."


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
    api_key: Optional[str] = None,
) -> dict:
    """Run Nmap scan and return parsed results with Vulners API support."""
    from app.core.config import settings

    nmap_path = getattr(settings, "resolved_nmap_path", getattr(settings, "nmap_path", "nmap"))
    key = (api_key or getattr(settings, "effective_nmap_api_key", "") or os.getenv("NMAP_API_KEY", "") or os.getenv("VULNERS_API_KEY", "")).strip()

    os.makedirs(results_dir, exist_ok=True)
    result_file = os.path.join(results_dir, f"nmap_{uuid.uuid4()}.xml")

    nse_path = os.path.join(os.path.dirname(__file__), "vulners.nse")
    has_local_nse = os.path.isfile(nse_path)
    script_target = nse_path if has_local_nse else "vulners"

    scan_profiles = {
        "quick":   ["-T4", "-F", "-sV"],
        "full":    ["-T3", "-sV", "-sC", "-O", "--version-intensity", "5"],
        "stealth": ["-T2", "-sS", "-sV"],
        "udp":     ["-sU", "-T3", "--top-ports", "100"],
        "os":      ["-O", "-sV", "-T4"],
        "version": ["-sV", "--version-all", "-T3"],
        "vuln":    ["-sV", "--version-intensity", "5", "--script", script_target],
        "web":     ["-T4", "-sV", "-p", "80,443,8080,8443,8000,8888"],
    }

    profile_args = list(scan_profiles.get(scan_type, scan_profiles["quick"]))

    # Attach Vulners API key if present or scanning for vulnerabilities
    if key and (scan_type in ("vuln", "full") or "--script" in profile_args):
        if "--script" not in profile_args:
            profile_args.extend(["--script", script_target])
        profile_args.extend(["--script-args", f"vulners.api_key={key}"])

    args = [nmap_path] + profile_args
    if ports and "-p" not in profile_args:
        args += ["-p", ports]
    args += ["-oX", result_file] + targets

    try:
        result = subprocess.run(args, capture_output=True, text=True, timeout=300)
        if result.returncode != 0:
            return {"error": result.stderr, "mock": False, "authorization_warning": AUTH_WARNING}
        parsed = _parse_xml(result_file)
        return {
            "hosts": len(parsed),
            "result_file": result_file,
            "parsed": parsed,
            "authorization_warning": AUTH_WARNING,
            "api_key_configured": bool(key),
        }
    except FileNotFoundError:
        logger.warning("Nmap not found — returning mock data")
        return _mock_result(targets, key=key)
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
                    port_info = {
                        "port": int(p.get("@portid", 0)),
                        "protocol": p.get("@protocol", "tcp"),
                        "name": svc.get("@name", "unknown"),
                        "product": svc.get("@product", ""),
                        "version": svc.get("@version", ""),
                    }
                    # Parse script outputs (e.g., vulners)
                    raw_scripts = p.get("script", [])
                    if isinstance(raw_scripts, dict):
                        raw_scripts = [raw_scripts]
                    if raw_scripts:
                        port_info["scripts"] = [{
                            "id": s.get("@id", ""),
                            "output": s.get("@output", "")
                        } for s in raw_scripts]
                    ports.append(port_info)
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


def _mock_result(targets: list, key: Optional[str] = None) -> dict:
    return {
        "hosts": 3,
        "mock": True,
        "api_key_configured": bool(key),
        "engine": "Nmap + Vulners",
        "authorization_warning": AUTH_WARNING,
        "parsed": [
            {
                "ip": targets[0] if targets and "/" not in targets[0] else "192.168.1.10",
                "hostname": "web-target.local",
                "os": "Ubuntu Linux (Linux 5.15)",
                "ports": [
                    {"port": 22, "name": "ssh", "product": "OpenSSH", "version": "8.2p1"},
                    {"port": 80, "name": "http", "product": "nginx", "version": "1.18.0",
                     "scripts": [{"id": "vulners", "output": "CVE-2021-23017 (9.8 CVSS) - NGINX 1.18.0 heap buffer overflow"}]},
                    {"port": 443, "name": "https", "product": "nginx", "version": "1.18.0"},
                ]
            },
            {"ip": "192.168.1.1",  "hostname": "gateway.local",  "os": "Linux Embedded", "ports": [{"port": 53, "name": "domain"}, {"port": 80, "name": "http"}]},
            {"ip": "192.168.1.20", "hostname": "db.local",       "os": "Debian 11",       "ports": [{"port": 5432, "name": "postgresql", "version": "13.4"}]},
        ],
    }


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
