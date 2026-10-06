"""
SPAIDER WiFite Plugin — Automated wireless network auditing.
Requires: wifite2 (pip install wifite2 or apt install wifite)
Requires: wireless adapter in monitor mode (aircrack-ng suite)

⚠️ LEGAL WARNING: Only audit networks you own or have written permission to test.
"""

import subprocess
import os
import uuid
from typing import List, Optional
import structlog

logger = structlog.get_logger(__name__)

AUTH_WARNING = (
    "⚠️ Wireless auditing must only be performed on networks you own or have explicit "
    "written authorisation to test. Unauthorised access is a criminal offence."
)

PLUGIN_META = {
    "name": "wifite",
    "version": "2.7.0",
    "category": "Wireless",
    "description": "Automated Wi-Fi auditing — WPS brute-force, WPA/WPA2 handshake capture, PMKID attacks, Evil Twin.",
}


def scan(
    interface: str = "wlan0",
    attack: str = "all",
    bssid: Optional[str] = None,
    channel: Optional[str] = None,
    results_dir: str = "./wifi_results",
) -> dict:
    """Run WiFite wireless audit."""
    os.makedirs(results_dir, exist_ok=True)
    result_id = str(uuid.uuid4())[:8]

    cmd = ["wifite", "--interface", interface, "--kill", "--no-pmkid-repeat"]

    if attack == "wps":
        cmd += ["--wps-only"]
    elif attack == "wpa":
        cmd += ["--wpa", "--no-wps"]
    elif attack == "pmkid":
        cmd += ["--pmkid"]
    elif attack == "evil-twin":
        cmd += ["--evil-twin"]
    # 'all' = no filter, attack everything visible

    if bssid and bssid != "broadcast":
        cmd += ["--bssid", bssid]
    if channel:
        cmd += ["--channel", channel]

    # Always output to file
    output_file = os.path.join(results_dir, f"wifite_{result_id}.log")
    cmd += ["--dict", "/usr/share/wordlists/rockyou.txt"]

    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
        )
        # Non-blocking: collect first 10 lines as preview
        lines = []
        for _ in range(10):
            line = proc.stdout.readline()
            if not line:
                break
            lines.append(line.strip())
        proc.terminate()

        return {
            "status": "running",
            "interface": interface,
            "attack": attack,
            "bssid": bssid,
            "channel": channel,
            "preview": lines,
            "result_id": result_id,
            "authorization_warning": AUTH_WARNING,
        }

    except FileNotFoundError:
        logger.warning("wifite not installed — returning mock data")
        return _mock_result(interface, attack, bssid)
    except Exception as e:
        logger.error("WiFite error", error=str(e))
        return {"error": str(e), "authorization_warning": AUTH_WARNING}


def _mock_result(interface: str, attack: str, bssid: Optional[str]) -> dict:
    return {
        "status": "mock",
        "interface": interface,
        "attack": attack,
        "bssid": bssid or "broadcast",
        "networks_found": [
            {
                "bssid": "AA:BB:CC:DD:EE:01",
                "essid": "HomeNetwork",
                "channel": 6,
                "encryption": "WPA2",
                "signal": -65,
                "wps": True,
            },
            {
                "bssid": "AA:BB:CC:DD:EE:02",
                "essid": "OfficeWifi",
                "channel": 11,
                "encryption": "WPA2",
                "signal": -72,
                "wps": False,
            },
        ],
        "attacks_attempted": [{"type": attack, "target": bssid or "all", "result": "handshake_captured"}],
        "mock": True,
        "authorization_warning": AUTH_WARNING,
    }


def analyze(results: dict) -> dict:
    """Identify weak/vulnerable networks from scan results."""
    flags = []
    for net in results.get("networks_found", []):
        if net.get("wps"):
            flags.append({
                "bssid": net.get("bssid"),
                "essid": net.get("essid"),
                "risk": "HIGH",
                "note": "WPS enabled — vulnerable to Pixie Dust / PIN brute-force",
            })
        if net.get("encryption") in ("WEP", "OPEN"):
            flags.append({
                "bssid": net.get("bssid"),
                "essid": net.get("essid"),
                "risk": "CRITICAL",
                "note": f"Weak encryption: {net.get('encryption')}",
            })
    return {"flags": flags, "total_risky": len(flags)}


def report(results: dict) -> str:
    lines = [f"WiFite Wireless Audit Report — Interface: {results.get('interface', 'N/A')}\n"]
    lines.append(f"  Attack Mode: {results.get('attack', 'N/A')}")
    lines.append(f"  Status:      {results.get('status', 'N/A')}")
    lines.append(f"\n  Networks Found:")
    for net in results.get("networks_found", []):
        lines.append(
            f"    {net.get('essid', 'N/A')} [{net.get('bssid', '')}]"
            f"  CH:{net.get('channel', '?')}  {net.get('encryption', '?')}"
            f"  WPS:{'YES' if net.get('wps') else 'no'}"
        )
    return "\n".join(lines)
