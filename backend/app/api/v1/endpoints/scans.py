"""Scans endpoints — launch, monitor, cancel scan jobs."""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

import structlog
from app.core.config import settings
from app.core.database import get_db
from app.models.models import ScanJob, ScanMode, ScanStatus, Scope, Target, ScanEvent, Asset, Finding, Service, Endpoint
from app.workers.celery_app import celery_app
from app.core.websocket_manager import ws_manager
from app.services.scope_validator import validate_target_scope

logger = structlog.get_logger(__name__)

router = APIRouter()


class ScanCreate(BaseModel):
    name: str
    mode: ScanMode = ScanMode.RED
    plugin: str = "nuclei"  # nmap | nuclei | web
    targets: List[str]
    options: dict = {}
    scope_id: Optional[str] = None
    target_id: Optional[str] = None
    scan_type: Optional[str] = "web"
    profile: Optional[str] = "safe"


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
    target_id: Optional[str] = None
    authorization_warning: str = AUTH_WARNING

    model_config = {"from_attributes": True}


@router.post("", response_model=ScanResponse)
async def create_scan(payload: ScanCreate, db: AsyncSession = Depends(get_db)):
    """
    Launch a new scan job with strict scope & authorization checks.
    Refuses scanning if any target is not explicitly authorized.
    """
    if not payload.targets:
        raise HTTPException(status_code=400, detail="At least one target is required.")

    # 1. Validate Scope & Authorization for every target
    matched_scope_id = payload.scope_id
    for target in payload.targets:
        is_auth, reason, matched_scope = await validate_target_scope(target, db, payload.scope_id)
        if not is_auth:
            raise HTTPException(
                status_code=403,
                detail=f"AUTHORIZATION ERROR: {reason}"
            )
        if matched_scope and not matched_scope_id:
            matched_scope_id = str(matched_scope.id)

    job_id = str(uuid.uuid4())
    job = ScanJob(
        id=job_id,
        name=payload.name,
        mode=payload.mode,
        plugin=payload.plugin,
        targets=payload.targets,
        options={**payload.options, "profile": payload.profile, "scan_type": payload.scan_type},
        scope_id=matched_scope_id,
        target_id=payload.target_id,
        status=ScanStatus.PENDING,
    )
    db.add(job)
    await db.commit()
    await db.refresh(job)

    # Initial scan event
    event = ScanEvent(
        id=str(uuid.uuid4()),
        scan_job_id=job.id,
        stage="RECON",
        progress=5,
        message=f"Scan initialized for targets: {', '.join(payload.targets)}. Scope validated: AUTHORIZED.",
        data={"targets": payload.targets, "profile": payload.profile},
    )
    db.add(event)
    await db.commit()

    # Dispatch to Celery (or instant background execution if Redis is offline)
    queue = "red_queue" if payload.mode == ScanMode.RED else "blue_queue"
    import socket
    import urllib.parse
    redis_online = False
    try:
        parsed_r = urllib.parse.urlparse(settings.redis_url)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(0.3)
            sock.connect((parsed_r.hostname or "127.0.0.1", parsed_r.port or 6379))
            redis_online = True
    except Exception:
        redis_online = False

    if redis_online:
        try:
            task = celery_app.send_task(
                "app.workers.tasks.run_scan",
                args=[str(job.id), payload.plugin, payload.targets, job.options],
                queue=queue,
            )
            job.celery_task_id = task.id
            job.status = ScanStatus.RUNNING
        except Exception:
            redis_online = False

    if not redis_online:
        logger.info("Redis queue offline; running scan worker in background thread")
        job.celery_task_id = f"local-{uuid.uuid4()}"
        job.status = ScanStatus.RUNNING
        import threading
        from app.workers.tasks import run_scan
        t = threading.Thread(
            target=run_scan,
            args=[str(job.id), payload.plugin, payload.targets, job.options or {}],
            daemon=True,
        )
        t.start()

    job.started_at = datetime.utcnow()
    await db.commit()

    # WebSocket broadcast
    await ws_manager.emit("scan_started", {
        "scan_id": str(job.id),
        "name": job.name,
        "mode": payload.mode.value,
        "plugin": payload.plugin,
        "stage": "RECON",
        "progress": 5,
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
        target_id=job.target_id,
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
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    return ScanResponse(
        id=str(job.id), name=job.name, mode=job.mode.value, plugin=job.plugin,
        status=job.status.value, targets=job.targets, progress=job.progress,
        created_at=job.created_at, started_at=job.started_at,
        completed_at=job.completed_at, celery_task_id=job.celery_task_id,
        target_id=job.target_id,
    )


@router.get("/{scan_id}/events")
async def get_scan_events(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Fetch progressive real-time scan events for the 3D pipeline visualizer."""
    stmt = select(ScanEvent).where(ScanEvent.scan_job_id == scan_id).order_by(ScanEvent.created_at)
    res = await db.execute(stmt)
    events = res.scalars().all()
    return [
        {
            "id": e.id,
            "scan_id": e.scan_job_id,
            "stage": e.stage,
            "progress": e.progress,
            "message": e.message,
            "data": e.data or {},
            "created_at": e.created_at.isoformat(),
        }
        for e in events
    ]


@router.get("/experiment/metrics")
async def get_experiment_metrics(db: AsyncSession = Depends(get_db)):
    """
    Experimental Architecture metrics:
    Tracks targets scanned, assets discovered, endpoints, ports, confirmed findings,
    false positives, duplicates, and severity distributions.
    """
    from sqlalchemy import func

    # Targets & assets
    t_count = (await db.execute(select(func.count(Target.id)))).scalar() or 0
    a_count = (await db.execute(select(func.count(Asset.id)))).scalar() or 0
    e_count = (await db.execute(select(func.count(Endpoint.id)))).scalar() or 0
    s_count = (await db.execute(select(func.count(Service.id)))).scalar() or 0
    scans_total = (await db.execute(select(func.count(ScanJob.id)))).scalar() or 0

    # Findings metrics
    all_findings_res = await db.execute(select(Finding))
    findings = all_findings_res.scalars().all()

    total_findings = len(findings)
    confirmed = len([f for f in findings if f.is_verified or f.status in ("confirmed", "validated")])
    false_positives = len([f for f in findings if f.is_false_positive or f.status == "false_positive"])
    duplicates = sum([max(0, (f.occurrence_count or 1) - 1) for f in findings])

    sev_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        sev_name = f.severity.value if hasattr(f.severity, "value") else str(f.severity)
        sev_counts[sev_name] = sev_counts.get(sev_name, 0) + 1

    return {
        "targets_scanned": max(t_count, 1),
        "scans_executed": scans_total,
        "assets_discovered": a_count,
        "endpoints_discovered": e_count,
        "ports_discovered": s_count,
        "findings": {
            "total": total_findings,
            "confirmed": confirmed,
            "duplicates": duplicates,
            "false_positives": false_positives,
            "critical": sev_counts["CRITICAL"],
            "high": sev_counts["HIGH"],
            "medium": sev_counts["MEDIUM"],
            "low": sev_counts["LOW"],
            "info": sev_counts["INFO"],
        },
        "pipeline_stages": [
            "TARGET AUTHORIZATION",
            "PORT SCAN (Nmap)",
            "ENDPOINT SPIDERING",
            "VULN DETECTION (Nuclei)",
            "FINDING NORMALIZATION",
            "DEDUPLICATION",
            "AI RISK SCORING",
            "REPORT COMPILATION",
        ],
    }


@router.delete("/{scan_id}/cancel")
async def cancel_scan(scan_id: str, db: AsyncSession = Depends(get_db)):
    """Cancel a running scan job."""
    result = await db.execute(select(ScanJob).where(ScanJob.id == scan_id))
    job = result.scalar_one_or_none()
    if not job:
        raise HTTPException(status_code=404, detail="Scan job not found")
    if job.celery_task_id:
        celery_app.control.revoke(job.celery_task_id, terminate=True)
    job.status = ScanStatus.CANCELLED
    await db.commit()
    return {"detail": "Scan cancelled", "scan_id": scan_id}
