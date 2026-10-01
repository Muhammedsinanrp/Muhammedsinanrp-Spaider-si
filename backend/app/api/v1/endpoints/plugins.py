"""Plugins registry endpoint."""

from fastapi import APIRouter

router = APIRouter()

PLUGINS = [
    {"name": "nmap", "version": "7.94", "category": "network", "enabled": True},
    {"name": "nuclei", "version": "3.2", "category": "web", "enabled": True},
    {"name": "zeek", "version": "6.0", "category": "network", "enabled": True},
    {"name": "suricata", "version": "7.0", "category": "ids", "enabled": True},
    {"name": "wazuh", "version": "4.8", "category": "siem", "enabled": False},
    {"name": "yara", "version": "4.5", "category": "malware", "enabled": True},
    {"name": "burp", "version": "2024.5", "category": "web", "enabled": False},
    {"name": "caido", "version": "0.42", "category": "web", "enabled": False},
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
