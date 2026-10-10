"""Runtime plugin inventory.

Registry metadata describes integrations; enabled/availability fields are checked
against the current backend environment instead of hard-coded demo status.
"""

import importlib.util
import os
import shutil
import subprocess
from pathlib import Path
from typing import Optional

from fastapi import APIRouter, HTTPException

router = APIRouter()
PLUGIN_ROOT = Path(__file__).resolve().parents[3] / "plugins"

# Static catalogue metadata is fine; runtime state below is discovered per request.
PLUGINS = [
    {"name": "nmap", "category": "Network Discovery", "icon": "📡", "description": "Nmap port and service discovery", "binary": "nmap", "version_args": ["--version"]},
    {"name": "nuclei", "category": "Web/API Security", "icon": "⚡", "description": "Nuclei template-based vulnerability detection", "binary": "nuclei", "version_args": ["-version"]},
    {"name": "zeek", "category": "Network Detection", "icon": "🕸️", "description": "Network protocol and traffic analysis", "binary": "zeek", "version_args": ["--version"]},
    {"name": "suricata", "category": "IDS/IPS", "icon": "🛡️", "description": "Network IDS/IPS engine", "binary": "suricata", "version_args": ["--build-info"]},
    {"name": "wazuh", "category": "SIEM/EDR", "icon": "🔍", "description": "Wazuh SIEM/XDR connector", "module": "wazuh", "env_required": ["WAZUH_URL", "WAZUH_API_USER"]},
    {"name": "yara", "category": "Malware Detection", "icon": "🦠", "description": "YARA-based malware pattern matching", "python_modules": ["yara"]},
    {"name": "burp", "category": "Web Proxy", "icon": "🔥", "description": "External Burp Suite proxy; findings may be imported through the SPAiDER API", "external": True},
    {"name": "caido", "category": "Web Proxy", "icon": "🌊", "description": "External Caido proxy; findings may be imported through the SPAiDER API", "external": True},
    {"name": "shodan", "category": "OSINT", "icon": "🌐", "description": "Shodan host intelligence API", "module": "shodan", "python_modules": ["shodan"], "env_required": ["SHODAN_API_KEY"], "per_request_config": True},
    {"name": "virustotal", "category": "Threat Intelligence", "icon": "🦠", "description": "VirusTotal reputation and analysis API", "module": "virustotal", "python_modules": ["vt"], "env_required": ["VIRUSTOTAL_API_KEY"], "per_request_config": True},
    {"name": "truecaller", "category": "OSINT", "icon": "📞", "description": "Truecaller lookup connector", "module": "truecaller", "env_required": ["TRUECALLER_AUTH_TOKEN"], "per_request_config": True},
    {"name": "wifite", "category": "Wireless Security", "icon": "📶", "description": "Wireless auditing via Wifite", "binary": "wifite"},
    {"name": "maltego", "category": "OSINT", "icon": "🕵️", "description": "External Maltego desktop integration", "external": True},
    {"name": "godseye", "category": "External Intelligence", "icon": "👁️", "description": "External intelligence website; not executed by SPAiDER", "external": True},
    {"name": "zingela", "category": "Network Discovery", "icon": "🎯", "description": "Zingela packet scanning plugin", "module": "zingela"},
    {"name": "lisdex", "category": "Endpoint Audit", "icon": "🐧", "description": "Local Linux security audit plugin", "module": "lisdex"},
    {"name": "cre", "category": "Governance & Compliance", "icon": "📚", "description": "Cross-framework security control mapping", "module": "cre"},
    {"name": "fwrule", "category": "Defensive Hardening", "icon": "🛡️", "description": "Firewall rule generation", "module": "fwrule"},
    {"name": "httpheader", "category": "Web/API Security", "icon": "🧭", "description": "HTTP response header inspection", "module": "httpheader"},
    {"name": "masscan", "category": "Network Discovery", "icon": "🚀", "description": "Masscan port scanner", "binary": "masscan"},
    {"name": "tshark", "category": "Packet Analysis", "icon": "🦈", "description": "TShark packet inspection", "binary": "tshark", "version_args": ["--version"]},
]


def _detect_version(executable: str, args: list[str]) -> Optional[str]:
    if not args:
        return None
    try:
        result = subprocess.run(
            [executable, *args],
            capture_output=True,
            text=True,
            timeout=2,
            check=False,
        )
        output = (result.stdout or result.stderr or "").strip().splitlines()
        if not output:
            return None
        line = output[0].strip()
        return line[:100] if line else None
    except (OSError, subprocess.TimeoutExpired):
        return None


def _plugin_state(meta: dict) -> dict:
    item = {key: value for key, value in meta.items()
            if key not in {"binary", "module", "python_modules", "env_required", "version_args", "per_request_config", "external"}}
    external = bool(meta.get("external"))
    missing = []

    if external:
        item.update({
            "available": False,
            "enabled": False,
            "status": "external",
            "reason": "External product or website; SPAiDER does not execute it directly.",
            "version": None,
        })
        return item

    module = meta.get("module")
    if module and not (PLUGIN_ROOT / module / "plugin.py").is_file():
        missing.append(f"SPAIDER module '{module}' is not present")
    for module_name in meta.get("python_modules", []):
        if importlib.util.find_spec(module_name) is None:
            missing.append(f"Python dependency '{module_name}' is not installed")

    executable = None
    binary = meta.get("binary")
    if binary:
        executable = shutil.which(binary)
        if not executable:
            missing.append(f"Executable '{binary}' is not installed or not on PATH")

    env_missing = [name for name in meta.get("env_required", []) if not os.getenv(name)]
    if env_missing and not meta.get("per_request_config"):
        missing.append("Missing configuration: " + ", ".join(env_missing))

    available = not missing
    reason = "; ".join(missing) if missing else (
        "Ready for use. API keys may also be supplied with a specific request."
        if meta.get("per_request_config") and env_missing
        else "Dependencies detected."
    )
    item.update({
        "available": available,
        "enabled": available,
        "status": "ready" if available else ("configuration_required" if env_missing else "not_installed"),
        "reason": reason,
        "version": _detect_version(executable, meta.get("version_args", [])) if executable else None,
    })
    return item


@router.get("")
async def list_plugins():
    """Return catalogue metadata enriched with detected local availability."""
    return [_plugin_state(plugin) for plugin in PLUGINS]


@router.get("/{name}")
async def get_plugin(name: str):
    plugin = next((p for p in PLUGINS if p["name"] == name), None)
    if not plugin:
        raise HTTPException(status_code=404, detail="Plugin not found")
    return _plugin_state(plugin)
