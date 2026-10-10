"""Targets & Scopes endpoints — manage lab targets and their authorized scopes."""

import uuid
from datetime import datetime, timedelta
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc, func
from pydantic import BaseModel, Field

from app.core.database import get_db
from app.models.models import Target, Scope, Asset, ScanJob, Finding, ScanStatus, Severity, User
from app.api.v1.endpoints.auth import get_current_user

router = APIRouter()


class TargetCreate(BaseModel):
    name: str
    hostname: str
    description: Optional[str] = None
    tags: List[str] = []


class ScopeCreate(BaseModel):
    target_id: Optional[str] = None
    name: str = Field(min_length=3, max_length=128)
    scope_type: str = "url"   # url | domain | ip | cidr
    value: str = Field(min_length=3, max_length=512)
    authorized_by: str = Field(min_length=3, max_length=255)
    authorization_document: str = Field(min_length=3, max_length=512)
    authorization_confirmed: bool = False
    active_testing: bool = True
    rate_limit: str = "controlled"
    valid_days: int = Field(default=365, ge=1, le=3650)


class TargetOut(BaseModel):
    id: str
    name: str
    hostname: str
    description: Optional[str]
    status: str
    tags: List[str]
    created_at: datetime
    model_config = {"from_attributes": True}


class ScopeOut(BaseModel):
    id: str
    target_id: Optional[str]
    name: str
    scope_type: str
    value: Optional[str]
    authorization_status: str
    active_testing: bool
    rate_limit: str
    authorized_by: Optional[str]
    authorization_document_present: bool = False
    valid_from: Optional[datetime] = None
    valid_until: Optional[datetime]
    created_at: datetime
    model_config = {"from_attributes": True}


# ─── Target CRUD ─────────────────────────────────────────────────────────────

@router.get("", response_model=List[TargetOut])
async def list_targets(db: AsyncSession = Depends(get_db)):
    """List all registered targets."""
    result = await db.execute(select(Target).order_by(desc(Target.created_at)))
    targets = result.scalars().all()
    return [
        TargetOut(
            id=str(t.id), name=t.name, hostname=t.hostname,
            description=t.description, status=t.status,
            tags=t.tags or [], created_at=t.created_at,
        )
        for t in targets
    ]


@router.post("", response_model=TargetOut, status_code=201)
async def create_target(payload: TargetCreate, db: AsyncSession = Depends(get_db)):
    """Register a new target for bug bounty research."""
    target = Target(
        id=str(uuid.uuid4()),
        name=payload.name,
        hostname=payload.hostname,
        description=payload.description,
        tags=payload.tags,
        status="active",
    )
    db.add(target)
    await db.commit()
    await db.refresh(target)
    return TargetOut(
        id=str(target.id), name=target.name, hostname=target.hostname,
        description=target.description, status=target.status,
        tags=target.tags or [], created_at=target.created_at,
    )


@router.get("/{target_id}/summary")
async def get_target_summary(target_id: str, db: AsyncSession = Depends(get_db)):
    """Full target summary: scope, asset count, findings, and scan history."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")

    # Scopes
    scopes_res = await db.execute(select(Scope).where(Scope.target_id == target_id))
    scopes = scopes_res.scalars().all()

    # Scans
    scans_res = await db.execute(
        select(ScanJob).where(ScanJob.target_id == target_id).order_by(desc(ScanJob.created_at)).limit(10)
    )
    recent_scans = scans_res.scalars().all()

    # Findings
    findings_res = await db.execute(select(Finding))
    all_findings = findings_res.scalars().all()
    sev_counts = {s.value: 0 for s in Severity}
    for f in all_findings:
        sev_counts[f.severity.value] = sev_counts.get(f.severity.value, 0) + 1

    return {
        "id": str(target.id),
        "name": target.name,
        "hostname": target.hostname,
        "description": target.description,
        "status": target.status,
        "tags": target.tags or [],
        "authorization": "AUTHORIZED" if scopes else "PENDING",
        "scopes": [
            {
                "id": str(s.id),
                "name": s.name,
                "value": s.value,
                "scope_type": s.scope_type,
                "authorization_status": s.authorization_status,
                "active_testing": s.active_testing,
                "authorization_document_present": bool(str(s.authorization_document or "").strip()),
                "valid_from": s.valid_from.isoformat() if s.valid_from else None,
                "valid_until": s.valid_until.isoformat() if s.valid_until else None,
            }
            for s in scopes
        ],
        "recent_scans": [
            {
                "id": str(s.id),
                "name": s.name,
                "plugin": s.plugin,
                "status": s.status.value,
                "created_at": s.created_at.isoformat(),
            }
            for s in recent_scans
        ],
        "findings_summary": sev_counts,
        "created_at": target.created_at.isoformat(),
    }


@router.delete("/{target_id}", status_code=204)
async def delete_target(target_id: str, db: AsyncSession = Depends(get_db)):
    """Remove a target (and cascade-delete its scopes)."""
    result = await db.execute(select(Target).where(Target.id == target_id))
    target = result.scalar_one_or_none()
    if not target:
        raise HTTPException(status_code=404, detail="Target not found")
    await db.delete(target)
    await db.commit()


# ─── Scope management ────────────────────────────────────────────────────────

@router.get("/{target_id}/scopes", response_model=List[ScopeOut])
async def list_scopes(target_id: str, db: AsyncSession = Depends(get_db)):
    """List scopes for a target."""
    result = await db.execute(select(Scope).where(Scope.target_id == target_id))
    scopes = result.scalars().all()
    return [
        ScopeOut(
            id=str(s.id), target_id=str(s.target_id) if s.target_id else None,
            name=s.name, scope_type=s.scope_type, value=s.value,
            authorization_status=s.authorization_status,
            active_testing=s.active_testing, rate_limit=s.rate_limit,
            authorized_by=s.authorized_by,
            authorization_document_present=bool(str(s.authorization_document or "").strip()),
            valid_from=s.valid_from, valid_until=s.valid_until,
            created_at=s.created_at,
        )
        for s in scopes
    ]


@router.post("/{target_id}/scopes", response_model=ScopeOut, status_code=201)
async def add_scope(target_id: str, payload: ScopeCreate, db: AsyncSession = Depends(get_db), current_user: User = Depends(get_current_user)):
    """Record scope only after an administrator attests to authorization."""
    if current_user.role != "admin" and not current_user.is_superuser:
        raise HTTPException(status_code=403, detail="Only an administrator can create or activate an authorization scope.")
    target_result = await db.execute(select(Target).where(Target.id == target_id))
    target = target_result.scalar_one_or_none()
    if target is None:
        raise HTTPException(status_code=404, detail="Target not found")

    if payload.target_id and payload.target_id != target_id:
        raise HTTPException(status_code=400, detail="target_id does not match the route target.")
    if not payload.authorization_confirmed:
        raise HTTPException(
            status_code=400,
            detail="Explicit authorization confirmation is required before a scope can be activated.",
        )
    if not payload.authorized_by.strip() or not payload.authorization_document.strip():
        raise HTTPException(
            status_code=400,
            detail="Record the authorizing person and the authorization document reference.",
        )

    now = datetime.utcnow()
    scope = Scope(
        id=str(uuid.uuid4()),
        target_id=target_id,
        name=payload.name.strip(),
        scope_type=payload.scope_type,
        value=payload.value.strip(),
        authorization_status="AUTHORIZED",
        targets=[payload.value.strip()],
        excluded_targets=[],
        active_testing=payload.active_testing,
        rate_limit=payload.rate_limit,
        authorized_by=payload.authorized_by.strip(),
        authorization_document=payload.authorization_document.strip(),
        valid_from=now,
        valid_until=now + timedelta(days=payload.valid_days),
    )
    db.add(scope)
    await db.commit()
    await db.refresh(scope)
    return ScopeOut(
        id=str(scope.id), target_id=str(scope.target_id) if scope.target_id else None,
        name=scope.name, scope_type=scope.scope_type, value=scope.value,
        authorization_status=scope.authorization_status,
        active_testing=scope.active_testing, rate_limit=scope.rate_limit,
        authorized_by=scope.authorized_by,
        authorization_document_present=bool(str(scope.authorization_document or "").strip()),
        valid_from=scope.valid_from, valid_until=scope.valid_until,
        created_at=scope.created_at,
    )
