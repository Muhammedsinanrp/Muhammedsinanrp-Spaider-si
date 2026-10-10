"""Alerts / SIEM events endpoints."""

import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Alert, AlertStatus, Severity

router = APIRouter()

LEGACY_DEMO_ALERT_IDS = ("alt-001", "alt-002", "alt-003", "alt-004")



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
    created_at: datetime
    model_config = {"from_attributes": True}


@router.get("", response_model=List[AlertOut])
async def list_alerts(
    status: Optional[AlertStatus] = None,
    severity: Optional[Severity] = None,
    source: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Alert).where(Alert.id.notin_(LEGACY_DEMO_ALERT_IDS)).order_by(desc(Alert.created_at)).limit(limit).offset(offset)
    if status:
        stmt = stmt.where(Alert.status == status)
    if severity:
        stmt = stmt.where(Alert.severity == severity)
    if source:
        stmt = stmt.where(Alert.source == source)
    result = await db.execute(stmt)
    alerts = result.scalars().all()
    return [
        AlertOut(
            id=str(a.id), title=a.title, description=a.description,
            severity=a.severity.value, status=a.status.value, source=a.source,
            source_ip=a.source_ip, destination_ip=a.destination_ip,
            event_type=a.event_type, mitre_techniques=a.mitre_techniques or [],
            is_purple_validated=a.is_purple_validated, detection_gap=a.detection_gap,
            created_at=a.created_at,
        ) for a in alerts
    ]


@router.patch("/{alert_id}/status")
async def update_alert_status(
    alert_id: str,
    new_status: AlertStatus,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(select(Alert).where(Alert.id == str(alert_id), Alert.id.notin_(LEGACY_DEMO_ALERT_IDS)))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(status_code=404, detail="Alert not found")
    alert.status = new_status
    if new_status == AlertStatus.RESOLVED:
        alert.resolved_at = datetime.utcnow()
    await db.commit()
    return {"detail": "Alert status updated", "status": new_status.value}


@router.get("/timeline")
async def alert_timeline(
    hours: int = 24,
    db: AsyncSession = Depends(get_db),
):
    """Return alert counts grouped by hour for timeline visualization."""
    from datetime import timedelta
    since = datetime.utcnow() - timedelta(hours=hours)
    result = await db.execute(
        select(Alert.created_at, Alert.severity).where(Alert.id.notin_(LEGACY_DEMO_ALERT_IDS))
        .where(Alert.created_at >= since)
        .order_by(Alert.created_at)
    )
    rows = result.all()

    # Group by hour (Python-side, SQLite compatible)
    buckets: dict = {}
    for created_at, severity in rows:
        hour = created_at.replace(minute=0, second=0, microsecond=0).isoformat()
        if hour not in buckets:
            buckets[hour] = {"hour": hour, "count": 0}
        buckets[hour]["count"] += 1

    return sorted(buckets.values(), key=lambda x: x["hour"])

