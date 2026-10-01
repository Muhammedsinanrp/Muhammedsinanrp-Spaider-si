"""
SPAIDER Wazuh Plugin — SIEM integration for host-based detection.
"""

import httpx
import json
from typing import List, Dict, Any, Optional
from datetime import datetime, timedelta
import structlog

logger = structlog.get_logger(__name__)

PLUGIN_META = {
    "name": "wazuh",
    "version": "4.8",
    "category": "SIEM / EDR",
    "description": "Wazuh SIEM integration for host-based alert collection, agent monitoring, and rule management.",
}


class WazuhClient:
    """HTTP client for the Wazuh REST API."""

    def __init__(self, url: str, username: str = "wazuh", password: str = "wazuh"):
        self.base_url = url.rstrip("/")
        self.username = username
        self.password = password
        self._token: Optional[str] = None

    async def _get_token(self) -> str:
        if self._token:
            return self._token
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.post(
                f"{self.base_url}/security/user/authenticate",
                auth=(self.username, self.password),
            )
            r.raise_for_status()
            self._token = r.json()["data"]["token"]
            return self._token

    async def get_alerts(self, limit: int = 100, hours: int = 24) -> list:
        """Fetch recent alerts from Wazuh."""
        token = await self._get_token()
        since = (datetime.utcnow() - timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.base_url}/alerts",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": limit, "q": f"timestamp>{since}"},
            )
            r.raise_for_status()
            return r.json().get("data", {}).get("items", [])

    async def get_agents(self) -> list:
        """List all Wazuh agents."""
        token = await self._get_token()
        async with httpx.AsyncClient(verify=False) as client:
            r = await client.get(
                f"{self.base_url}/agents",
                headers={"Authorization": f"Bearer {token}"},
            )
            r.raise_for_status()
            return r.json().get("data", {}).get("items", [])


def discover(wazuh_url: str = "http://localhost:55000") -> dict:
    """Check Wazuh API availability."""
    try:
        import asyncio
        client = WazuhClient(wazuh_url)
        # Sync wrapper for discovery
        return {"status": "reachable", "url": wazuh_url}
    except Exception as e:
        return {"status": "unreachable", "url": wazuh_url, "error": str(e)}


def collect(alerts_raw: List[dict]) -> List[dict]:
    """Collect and normalise Wazuh alerts to SPAIDER schema."""
    normalized = []
    for alert in alerts_raw:
        rule = alert.get("rule", {})
        agent = alert.get("agent", {})
        sev_level = int(rule.get("level", 5))
        severity = (
            "CRITICAL" if sev_level >= 15 else
            "HIGH" if sev_level >= 12 else
            "MEDIUM" if sev_level >= 8 else
            "LOW"
        )
        normalized.append({
            "title": rule.get("description", "Wazuh Alert"),
            "severity": severity,
            "source": "wazuh",
            "source_ip": agent.get("ip"),
            "event_type": rule.get("groups", ["unknown"])[0] if rule.get("groups") else "unknown",
            "raw_log": json.dumps(alert),
            "mitre_techniques": [
                t.get("id") for t in rule.get("mitre", {}).get("technique", [])
            ],
            "agent_name": agent.get("name"),
            "agent_id": agent.get("id"),
            "rule_id": rule.get("id"),
            "rule_level": sev_level,
            "timestamp": alert.get("timestamp"),
        })
    return normalized


def analyze(alerts: List[dict]) -> dict:
    """Analyze Wazuh alert patterns."""
    by_agent = {}
    by_rule_level = {}
    for alert in alerts:
        agent = alert.get("agent_name", "unknown")
        by_agent[agent] = by_agent.get(agent, 0) + 1
        level = str(alert.get("rule_level", "?"))
        by_rule_level[level] = by_rule_level.get(level, 0) + 1

    return {
        "total": len(alerts),
        "by_agent": by_agent,
        "by_rule_level": by_rule_level,
        "high_severity": len([a for a in alerts if a.get("severity") in ("CRITICAL", "HIGH")]),
    }


def normalize(results: dict) -> dict:
    """Normalize Wazuh data to SPAIDER schema."""
    alerts = results.get("alerts", [])
    return {
        "source": "wazuh",
        "alert_count": len(alerts),
        "alerts": collect(alerts),
    }


def report(results: dict) -> str:
    """Generate a Wazuh summary report."""
    alerts = results.get("alerts", [])
    analysis = analyze(collect(alerts))
    lines = [
        "Wazuh SIEM Report",
        "=" * 40,
        f"Total Alerts: {analysis['total']}",
        f"High/Critical: {analysis['high_severity']}",
        "\nAlerts by Agent:",
    ]
    for agent, count in sorted(analysis["by_agent"].items(), key=lambda x: x[1], reverse=True)[:5]:
        lines.append(f"  {count:4d}  {agent}")
    return "\n".join(lines)
