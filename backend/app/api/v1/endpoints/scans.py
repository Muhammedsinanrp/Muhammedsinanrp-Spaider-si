"""Scans endpoints — launch, monitor, cancel scan jobs."""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import ScanJob, ScanMode, ScanStatus, Scope
from app.workers.celery_app import celery_app
from app.core.websocket_manager import ws_manager

router = APIRouter()


class ScanCreate(BaseModel):
    name: str
    mode: ScanMode
    plugin: str  # nmap | nuclei | zeek | yara
    targets: List[str]
    options: dict = {}
    scope_id: Optional[str] = None


AUTH_WARNING = "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."


class ScanResponse(BaseModel):
    id: str
    name: str
    mode: str
    plugin: str
    status: str
    targets: List[str]
    progress: float
    created_at: datetime
    started_at: Optional[datetime]
    completed_at: Optional[datetime]
    celery_task_id: Optional[str]
    authorization_warning: str = AUTH_WARNING

    model_config = {"from_attributes": True}


@router.post("", response_model=ScanResponse)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    """Launch a new scan job."""
    job = ScanJob(
        id=uuid.uuid4(),
        name=payload.name,
        mode=payload.mode,
        plugin=payload.plugin,
        targets=payload.targets,
        options=payload.options,
        scope_id=uuid.UUID(payload.scope_id) if payload.scope_id else None,
        status=ScanStatus.PENDING,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Dispatch to the appropriate Celery queue
    queue = "red_queue" if payload.mode == ScanMode.RED else "blue_queue"
    task = celery_app.send_task(
        f"app.workers.tasks.run_scan",
        args=[str(job.id), payload.plugin, payload.targets, payload.options],
        queue=queue,
    )
    job.celery_task_id = task.id
    job.status = ScanStatus.RUNNING
    job.started_at = datetime.utcnow()
    await db.commit()

    # Notify WebSocket clients
    await ws_manager.emit("scan_started", {
        "scan_id": str(job.id),
        "name": job.name,
        "mode": payload.mode,
        "plugin": payload.plugin,
    })

    return ScanResponse(
        id=str(job.id),
        name=job.name,
        mode=job.mode.value,
        plugin=job.plugin,
        status=job.status.value,
        targets=job.targets,
        progress=job.progress,
        created_at=job.created_at,
        started_at=job.started_at,
        completed_at=job.completed_at,
        celery_task_id=job.celery_task_id,
    )


@router.get("", response_model=List[ScanResponse])
async def list_scans(
    mode: Optional[ScanMode] = None,
    status: Optional[ScanStatus] = None,
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    """List scan jobs with optional filters."""
    stmt = select(ScanJob).order_by(desc(ScanJob.created_at)).limit(limit).offset(offset)
    if mode:
        stmt = stmt.where(ScanJob.mode == mode)
    if status:
        stmt = stmt.where(ScanJob.status == status)
    result = await db.execute(stmt)
    jobs = result.scalars().all()
    return [
        ScanResponse(
            id=str(j.id), name=j.name, mode=j.mode.value, plugin=j.plugin,
            status=j.status.value, targets=j.targets, progress=j.progress,
            created_at=j.created_at, started_at=j.started_at,
            completed_at=j.completed_at, celery_task_id=j.celery_task_id,
        ) for j in jobs
    ]


@router.get("/{scan_id}", response_model=ScanResponse)
async def get_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Get details of a specific scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanResponse(
        id=str(job.id), name=job.name, mode=job.mode.value, plugin=job.plugin,
        status=job.status.value, targets=job.targets, progress=job.progress,
        created_at=job.created_at, started_at=job.started_at,
        completed_at=job.completed_at, celery_task_id=job.celery_task_id,
    )


@router.delete("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == uuid.UUID(scan_id)))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.celery_task_id:
        celery_app.control.revoke(job.celery_task_id, terminate=True)
    job.status = ScanStatus.CANCELLED
    await db.commit()
    return {"detail": "Scan cancelled", "scan_id": scan_id}
