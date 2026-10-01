"""SIEM — log ingestion, alert correlation, and status endpoints."""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Alert, AlertStatus, Severity
from app.core.websocket_manager import ws_manager

router = APIRouter()


# ─── Schema ───────────────────────────────────────────────────────────────────

class LogEvent(BaseModel):
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"         # CRITICAL | HIGH | MEDIUM | LOW | INFO
    source: str = "custom"           # wazuh | zeek | suricata | custom
    source_ip: Optional[str] = None
    destination_ip: Optional[str] = None
    source_port: Optional[int] = None
    destination_port: Optional[int] = None
    protocol: Optional[str] = None
    event_type: Optional[str] = None
    mitre_techniques: List[str] = []
    raw_log: Optional[str] = None


class AlertOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    status: str
    source: Optional[str]
    source_ip: Optional[str]
    destination_ip: Optional[str]
    event_type: Optional[str]
    mitre_techniques: List[str]
    is_purple_validated: bool
    detection_gap: bool
    count: int
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("/status")
async def siem_status(db: AsyncSession = Depends(get_db)):
    """Return SIEM connection status and alert counts."""
    total = await db.execute(select(func.count(Alert.id)))
    open_count = await db.execute(
        select(func.count(Alert.id)).where(Alert.status == AlertStatus.OPEN)
    )
    critical_count = await db.execute(
        select(func.count(Alert.id)).where(Alert.severity == Severity.CRITICAL)
    )
    return {
        "connected_sources": ["wazuh", "zeek", "suricata"],
        "status": "active",
        "total_alerts": total.scalar(),
        "open_alerts": open_count.scalar(),
        "critical_alerts": critical_count.scalar(),
        "last_check": datetime.utcnow().isoformat(),
    }


@router.post("/ingest", response_model=AlertOut)
async def ingest_log(event: LogEvent, db: AsyncSession = Depends(get_db)):
    """Ingest a normalised log event and create or update an Alert."""
    sev_map = {
        "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO,
    }
    severity = sev_map.get(event.severity.upper(), Severity.MEDIUM)

    # Deduplicate: check for matching open alert from same source + title in last 10 min
    since = datetime.utcnow() - timedelta(minutes=10)
    existing = await db.execute(
        select(Alert).where(
            Alert.title == event.title,
            Alert.source == event.source,
            Alert.status == AlertStatus.OPEN,
            Alert.created_at >= since,
        ).limit(1)
    )
    alert = existing.scalar_one_or_none()

    if alert:
        alert.count = (alert.count or 1) + 1
        alert.last_seen = datetime.utcnow()
        await db.commit()
    else:
        alert = Alert(
            id=str(uuid.uuid4()),
            title=event.title,
            description=event.description,
            severity=severity,
            status=AlertStatus.OPEN,
            source=event.source,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            event_type=event.event_type,
            mitre_techniques=event.mitre_techniques,
            raw_log=event.raw_log,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            count=1,
        )
        db.add(alert)
        await db.commit()
        await db.refresh(alert)

        # Real-time notification
        await ws_manager.emit("new_alert", {
            "alert_id": str(alert.id),
            "title": alert.title,
            "severity": severity.value,
            "source": event.source,
        })

    return AlertOut(
        id=str(alert.id), title=alert.title, description=alert.description,
        severity=alert.severity.value, status=alert.status.value,
        source=alert.source, source_ip=alert.source_ip,
        destination_ip=alert.destination_ip, event_type=alert.event_type,
        mitre_techniques=alert.mitre_techniques or [],
        is_purple_validated=alert.is_purple_validated,
        detection_gap=alert.detection_gap, count=alert.count,
        created_at=alert.created_at,
    )


@router.post("/ingest/batch")
async def ingest_batch(events: List[LogEvent], db: AsyncSession = Depends(get_db)):
    """Batch-ingest log events (e.g., from Wazuh/Zeek log shippers)."""
    created = 0
    for event in events:
        sev_map = {
            "CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW, "INFO": Severity.INFO,
        }
        severity = sev_map.get(event.severity.upper(), Severity.MEDIUM)
        alert = Alert(
            id=str(uuid.uuid4()),
            title=event.title,
            description=event.description,
            severity=severity,
            status=AlertStatus.OPEN,
            source=event.source,
            source_ip=event.source_ip,
            destination_ip=event.destination_ip,
            source_port=event.source_port,
            destination_port=event.destination_port,
            protocol=event.protocol,
            event_type=event.event_type,
            mitre_techniques=event.mitre_techniques,
            raw_log=event.raw_log,
            first_seen=datetime.utcnow(),
            last_seen=datetime.utcnow(),
            count=1,
        )
        db.add(alert)
        created += 1
    await db.commit()
    return {"ingested": created, "status": "ok"}


@router.get("/timeline")
async def alert_timeline(
    hours: int = Query(default=24, le=168),
    db: AsyncSession = Depends(get_db),
):
    """Return alert counts per hour for the last N hours (used by timeline chart)."""
    since = datetime.utcnow() - timedelta(hours=hours)
    # Build a manual hourly bucket (SQLite compatible)
    result = await db.execute(
        select(Alert.created_at, Alert.severity)
        .where(Alert.created_at >= since)
        .order_by(Alert.created_at)
    )
    rows = result.all()

    # Group by hour
    buckets: dict = {}
    for created_at, severity in rows:
        hour = created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        if hour not in buckets:
            buckets[hour] = {"hour": hour, "total": 0, "critical": 0, "high": 0}
        buckets[hour]["total"] += 1
        if severity == Severity.CRITICAL:
            buckets[hour]["critical"] += 1
        elif severity == Severity.HIGH:
            buckets[hour]["high"] += 1

    return sorted(buckets.values(), key=lambda x: x["hour"])


@router.get("/stats")
async def siem_stats(db: AsyncSession = Depends(get_db)):
    """Return alert statistics by source, severity, and status."""
    stats = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count(Alert.id)).where(Alert.severity == sev)
        )
        stats[sev.value] = result.scalar()

    by_source = {}
    result = await db.execute(
        select(Alert.source, func.count(Alert.id)).group_by(Alert.source)
    )
    for source, count in result.all():
        by_source[source or "unknown"] = count

    return {"by_severity": stats, "by_source": by_source}
