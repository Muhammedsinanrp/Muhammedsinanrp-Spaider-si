"""Purple team validation endpoints."""

from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from typing import List, Optional

from app.core.database import get_db
from app.workers.celery_app import celery_app

router = APIRouter()


AUTH_WARNING = "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."


class PurpleValidationRequest(BaseModel):
    finding_id: str
    test_technique: str         # ATT&CK technique ID
    detection_sources: List[str] = ["wazuh", "zeek", "suricata"]
    safe_mode: bool = True


@router.post("/validate")
async def validate_detection(payload: PurpleValidationRequest, db: AsyncSession = Depends(get_db)):
    """
    Purple team: validate whether a finding/attack would be detected
    by the configured defensive stack.
    """
    task = celery_app.send_task(
        "app.workers.tasks.purple_validate",
        args=[payload.finding_id, payload.test_technique, payload.detection_sources, payload.safe_mode],
        queue="blue_queue",
    )
    return {
        "task_id": task.id,
        "status": "queued",
        "message": "Purple validation queued. Defensive telemetry will be correlated.",
        "authorization_warning": AUTH_WARNING,
    }


@router.get("/gaps")
async def detection_gaps(db: AsyncSession = Depends(get_db)):
    """List findings/attacks that created a detection gap (not caught by defenses)."""
    from sqlalchemy import select
    from app.models.models import Alert
    result = await db.execute(
        select(Alert).where(Alert.detection_gap == True)
    )
    gaps = result.scalars().all()
    return [
        {
            "alert_id": str(a.id),
            "title": a.title,
            "severity": a.severity.value,
            "mitre_techniques": a.mitre_techniques,
            "recommendation": "Add detection rule for this technique",
        } for a in gaps
    ]
