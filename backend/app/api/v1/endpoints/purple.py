"""Purple-team telemetry correlation endpoints.

These endpoints correlate existing saved alerts with ATT&CK techniques. They do
not simulate attacks or claim detection failure merely because an alert is absent.
"""

from datetime import datetime, timedelta
from typing import List
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.models.models import Alert, Finding

router = APIRouter()


class PurpleValidationRequest(BaseModel):
    finding_id: str = Field(min_length=1, max_length=64)
    test_technique: str = Field(min_length=3, max_length=32)
    detection_sources: List[str] = Field(default_factory=lambda: ["wazuh", "zeek", "suricata"], max_length=10)
    safe_mode: bool = True
    lookback_hours: int = Field(default=168, ge=1, le=720)


@router.post("/validate")
async def validate_detection(payload: PurpleValidationRequest, db: AsyncSession = Depends(get_db)):
    """Correlate stored alerts for the selected finding/technique and time window."""
    finding_result = await db.execute(select(Finding).where(Finding.id == payload.finding_id))
    finding = finding_result.scalar_one_or_none()
    if finding is None:
        raise HTTPException(
            status_code=404,
            detail="Finding not found. Select a finding saved by SPAIDER before running telemetry correlation.",
        )

    requested_sources = list(dict.fromkeys(str(s).strip().lower() for s in payload.detection_sources if str(s).strip()))
    if not requested_sources:
        raise HTTPException(status_code=400, detail="Select at least one detection source.")

    now = datetime.utcnow()
    since = now - timedelta(hours=payload.lookback_hours)
    alert_result = await db.execute(
        select(Alert)
        .where(Alert.created_at >= since)
        .order_by(Alert.created_at.desc())
        .limit(1000)
    )
    recent_alerts = alert_result.scalars().all()
    matches = []
    seen_sources = set()
    for alert in recent_alerts:
        source = str(alert.source or "").strip().lower()
        techniques = [str(t).upper() for t in (alert.mitre_techniques or [])]
        if source in requested_sources and payload.test_technique.upper() in techniques:
            seen_sources.add(source)
            matches.append({
                "alert_id": str(alert.id),
                "title": alert.title,
                "source": alert.source,
                "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
                "created_at": alert.created_at.isoformat() if alert.created_at else None,
                "mitre_techniques": alert.mitre_techniques or [],
            })

    detected_by = sorted(seen_sources)
    matched = set(detected_by)
    no_matching_alert_observed = [source for source in requested_sources if source not in matched]
    coverage = round((len(matched) / len(requested_sources)) * 100) if requested_sources else 0

    if matches:
        recommendation = (
            "Saved alerts matched this ATT&CK technique. Review their timestamps and raw telemetry, "
            "then run an approved controlled simulation if you need to verify end-to-end sensor coverage."
        )
    else:
        recommendation = (
            "No matching saved alert was found in the selected time window. This alone does not prove a "
            "detection gap: verify that the selected sensors are connected, healthy, and ingesting events, "
            "then use an approved controlled simulation before drawing a conclusion."
        )

    return {
        "status": "historical_correlation",
        "finding_id": str(finding.id),
        "finding_title": finding.title,
        "technique": payload.test_technique.upper(),
        "lookback_hours": payload.lookback_hours,
        "since": since.isoformat(),
        "until": now.isoformat(),
        "requested_sources": requested_sources,
        "detected_by": detected_by,
        "no_matching_alert_observed": no_matching_alert_observed,
        "coverage": coverage,
        "coverage_type": "historical_alert_match_percentage",
        "detection_gap": None,
        "gap": False,
        "recommendation": recommendation,
        "evidence": matches,
        "simulation_executed": False,
        "safe_mode": payload.safe_mode,
        "message": (
            "Historical telemetry correlation only. SPAiDER did not execute ATT&CK behavior; "
            "absence of a stored alert is not a verified detection failure."
        ),
    }


@router.get("/gaps")
async def detection_gaps(db: AsyncSession = Depends(get_db)):
    """List only alerts explicitly marked as detection gaps by a real integration."""
    result = await db.execute(
        select(Alert).where(Alert.detection_gap.is_(True), Alert.id.notin_(("alt-001", "alt-002", "alt-003", "alt-004"))).order_by(Alert.created_at.desc()).limit(500)
    )
    alerts = result.scalars().all()
    return [
        {
            "alert_id": str(alert.id),
            "title": alert.title,
            "severity": alert.severity.value if hasattr(alert.severity, "value") else str(alert.severity),
            "mitre_techniques": alert.mitre_techniques or [],
            "recommendation": "Review sensor health, event ingestion and the alert's supporting evidence.",
            "created_at": alert.created_at.isoformat() if alert.created_at else None,
            "source": alert.source,
        }
        for alert in alerts
    ]
