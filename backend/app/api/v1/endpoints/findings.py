"""Findings endpoints."""

import uuid
from typing import List, Optional
from datetime import datetime
from fastapi import APIRouter, Depends, Query, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Finding, Severity

router = APIRouter()


class FindingOut(BaseModel):
    id: str
    title: str
    description: Optional[str]
    severity: str
    plugin: Optional[str]
    cve_ids: List[str]
    cvss_score: Optional[float]
    cvss_vector: Optional[str] = None
    mitre_techniques: List[str]
    cwe_ids: List[str] = []
    remediation: Optional[str]
    asset_value: Optional[str] = None
    endpoint: Optional[str] = None
    affected_url: Optional[str] = None
    confidence: Optional[float] = None
    evidence: Optional[str] = None
    request_raw: Optional[str] = None
    response_raw: Optional[str] = None
    proof_of_concept: Optional[str] = None
    references: List[str] = []
    tags: List[str] = []
    status: Optional[str] = None
    scan_job_id: Optional[str] = None
    is_verified: bool
    is_false_positive: bool
    created_at: datetime
    model_config = {"from_attributes": True}


@router.get("", response_model=List[FindingOut])
async def list_findings(
    severity: Optional[Severity] = None,
    asset_id: Optional[str] = None,
    limit: int = Query(default=100, le=500),
    offset: int = 0,
    db: AsyncSession = Depends(get_db),
):
    stmt = select(Finding).order_by(desc(Finding.created_at)).limit(limit).offset(offset)
    if severity:
        stmt = stmt.where(Finding.severity == severity)
    if asset_id:
        stmt = stmt.where(Finding.asset_id == uuid.UUID(asset_id))
    result = await db.execute(stmt)
    findings = result.scalars().all()
    return [
        FindingOut(
            id=str(f.id), title=f.title, description=f.description,
            severity=f.severity.value, plugin=f.plugin, cve_ids=f.cve_ids or [],
            cvss_score=f.cvss_score if f.cvss_score is not None else f.cvss,
            cvss_vector=f.cvss_vector,
            mitre_techniques=f.mitre_techniques or [],
            cwe_ids=f.cwe_ids or [],
            remediation=f.remediation,
            asset_value=f.asset_value,
            endpoint=f.endpoint,
            affected_url=f.affected_url,
            confidence=f.confidence,
            evidence=f.evidence,
            request_raw=f.request_raw,
            response_raw=f.response_raw,
            proof_of_concept=f.proof_of_concept or f.curl_poc,
            references=f.references or [],
            tags=f.tags or [],
            status=f.status,
            scan_job_id=f.scan_job_id,
            is_verified=f.is_verified,
            is_false_positive=f.is_false_positive,
            created_at=f.created_at,
        ) for f in findings
    ]


@router.get("/stats")
async def finding_stats(db: AsyncSession = Depends(get_db)):
    from sqlalchemy import func
    counts = {}
    for sev in Severity:
        result = await db.execute(
            select(func.count(Finding.id)).where(Finding.severity == sev)
        )
        counts[sev.value] = result.scalar()
    return counts


@router.get("/{finding_id}")
async def get_finding(finding_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Finding).where(Finding.id == uuid.UUID(finding_id)))
    f = result.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": str(f.id), "title": f.title, "description": f.description,
        "severity": f.severity.value, "plugin": f.plugin, "cve_ids": f.cve_ids or [],
        "cvss_score": f.cvss_score, "cvss_vector": f.cvss_vector,
        "mitre_techniques": f.mitre_techniques or [], "evidence": f.evidence or [],
        "request_raw": f.request_raw, "response_raw": f.response_raw,
        "proof_of_concept": f.proof_of_concept, "remediation": f.remediation,
        "references": f.references or [], "ai_analysis": f.ai_analysis or {},
        "is_verified": f.is_verified, "is_false_positive": f.is_false_positive,
        "created_at": f.created_at,
    }
