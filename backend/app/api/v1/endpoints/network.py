"""Scope-checked network discovery endpoints — Nmap and topology tasks."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.services.scope_validator import validate_target_scope
from app.workers.celery_app import celery_app

router = APIRouter()


class NetworkScanRequest(BaseModel):
    targets: List[str] = Field(min_length=1, max_length=100)
    scan_type: str = "quick"  # quick | full | stealth | udp | os | version
    ports: Optional[str] = None
    timing: int = Field(default=3, ge=0, le=5)


async def _require_authorized_network_scope(
    targets: List[str], db: AsyncSession
) -> None:
    """Require an explicit domain/IP/CIDR scope for any network-level scan."""
    for raw_target in targets:
        target = str(raw_target).strip()
        if not target or "://" in target or any(ch.isspace() for ch in target):
            raise HTTPException(
                status_code=400,
                detail="Network discovery accepts a host, IP, or CIDR (not an HTTP URL).",
            )
        authorized, reason, matched_scope = await validate_target_scope(target, db)
        if not authorized:
            raise HTTPException(status_code=403, detail=f"AUTHORIZATION ERROR: {reason}")
        # The scope validator deliberately won't match an origin URL to a bare
        # host. Require an explicit host/network-style scope for Nmap/topology.
        if matched_scope and "://" in str(matched_scope.value or ""):
            raise HTTPException(
                status_code=403,
                detail="This is an HTTP-origin scope. Add a separate domain/IP/CIDR scope to authorize network port discovery.",
            )


@router.post("/discover")
async def discover_network(payload: NetworkScanRequest, db: AsyncSession = Depends(get_db)):
    """Launch Nmap only after checking all hosts against an authorized network scope."""
    if payload.scan_type not in {"quick", "full", "stealth", "udp", "os", "version"}:
        raise HTTPException(status_code=400, detail="Unsupported Nmap scan type.")
    await _require_authorized_network_scope(payload.targets, db)
    task = celery_app.send_task(
        "app.workers.tasks.run_nmap_scan",
        args=[payload.targets, payload.scan_type, payload.ports, payload.timing],
        queue="red_queue",
    )
    return {
        "task_id": task.id,
        "status": "queued",
        "targets": payload.targets,
        "authorization_warning": "Only targets in an active scope with a recorded authorization document may be scanned.",
    }


@router.post("/topology")
async def discover_topology(targets: List[str], db: AsyncSession = Depends(get_db)):
    """Queue topology discovery only for explicitly scoped network targets."""
    if not targets:
        raise HTTPException(status_code=400, detail="At least one target host or network is required.")
    await _require_authorized_network_scope(targets, db)
    task = celery_app.send_task(
        "app.workers.tasks.discover_topology",
        args=[targets],
        queue="red_queue",
    )
    return {
        "task_id": task.id,
        "status": "queued",
        "authorization_warning": "Only targets in an active scope with a recorded authorization document may be scanned.",
    }


@router.post("/pcap/upload")
async def upload_pcap(filename: str):
    """Queue a PCAP file for Zeek/Suricata analysis."""
    if not filename or ".." in filename or "/" in filename or "\\" in filename:
        raise HTTPException(status_code=400, detail="Provide a basename only for the uploaded PCAP file.")
    task = celery_app.send_task(
        "app.workers.tasks.analyze_pcap",
        args=[filename],
        queue="blue_queue",
    )
    return {"task_id": task.id, "status": "queued"}
