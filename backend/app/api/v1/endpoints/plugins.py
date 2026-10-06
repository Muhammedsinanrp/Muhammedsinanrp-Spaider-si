"""Plugins registry endpoint."""

from fastapi import APIRouter

router = APIRouter()

PLUGINS = [
    {"name": "nmap",        "version": "7.94",   "category": "network",     "enabled": True},
    {"name": "nuclei",      "version": "3.2",    "category": "web",         "enabled": True},
    {"name": "zeek",        "version": "6.0",    "category": "network",     "enabled": True},
    {"name": "suricata",    "version": "7.0",    "category": "ids",         "enabled": True},
    {"name": "wazuh",       "version": "4.8",    "category": "siem",        "enabled": False},
    {"name": "yara",        "version": "4.5",    "category": "malware",     "enabled": True},
    {"name": "burp",        "version": "2024.5", "category": "web",         "enabled": False},
    {"name": "caido",       "version": "0.42",   "category": "web",         "enabled": False},
    {"name": "shodan",      "version": "1.0",    "category": "osint",        "enabled": True},
    {"name": "virustotal",  "version": "3.0",    "category": "threat_intel", "enabled": True},
    {"name": "truecaller",  "version": "1.0",    "category": "osint",        "enabled": True},
    {"name": "wifite",      "version": "2.7.0",  "category": "wireless",     "enabled": True},
    {"name": "maltego",     "version": "4.6",    "category": "osint",        "enabled": False},
    {"name": "godseye",     "version": "2024",   "category": "global_intel", "enabled": True},
    {"name": "zingela",     "version": "1.2.0",  "category": "network",      "enabled": True},
    {"name": "lisdex",      "version": "2.1.0",  "category": "endpoint",     "enabled": True},
    {"name": "cre",         "version": "1.4.0",  "category": "compliance",   "enabled": True},
    {"name": "fwrule",      "version": "1.8.0",  "category": "hardening",    "enabled": True},
    {"name": "httpheader",  "version": "1.0.0",  "category": "web",          "enabled": True},
]



@router.get("")
async def list_plugins():
    return PLUGINS


@router.get("/{name}")
async def get_plugin(name: str):
    plugin = next((p for p in PLUGINS if p["name"] == name), None)
    if not plugin:
        from fastapi import HTTPException
        raise HTTPException(status_code=404, detail="Plugin not found")
    return plugin
