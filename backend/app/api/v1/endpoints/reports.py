"""Reports endpoint — generate and retrieve AI-powered security reports."""

import uuid
from datetime import datetime
from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, desc
from pydantic import BaseModel

from app.core.database import get_db
from app.models.models import Report, Finding, Alert, ScanJob, Asset, Severity

router = APIRouter()


# ─── Schemas ──────────────────────────────────────────────────────────────────

class ReportRequest(BaseModel):
    title: str
    report_type: str = "technical"          # executive | technical | soc
    scan_job_ids: List[str] = []
    asset_ids: List[str] = []
    include_findings: bool = True
    include_alerts: bool = True
    include_mitre: bool = True


class ReportOut(BaseModel):
    id: str
    title: str
    report_type: str
    created_at: datetime
    summary: Optional[str] = None
    model_config = {"from_attributes": True}


# ─── Helpers ──────────────────────────────────────────────────────────────────

async def _build_report_content(
    report_type: str,
    db: AsyncSession,
    scan_job_ids: list,
    asset_ids: list,
) -> dict:
    """Aggregate data and build report content dict."""
    # Pull findings
    stmt = select(Finding).order_by(desc(Finding.created_at)).limit(200)
    if scan_job_ids:
        stmt = stmt.where(Finding.scan_job_id.in_(scan_job_ids))
    findings_result = await db.execute(stmt)
    findings = findings_result.scalars().all()

    # Pull alerts
    alerts_result = await db.execute(
        select(Alert).order_by(desc(Alert.created_at)).limit(200)
    )
    alerts = alerts_result.scalars().all()

    # Severity counts
    severity_counts = {s.value: 0 for s in Severity}
    for f in findings:
        severity_counts[f.severity.value] += 1

    # Top CVEs
    cves = []
    for f in findings:
        cves.extend(f.cve_ids or [])
    cve_freq = {}
    for cve in cves:
        cve_freq[cve] = cve_freq.get(cve, 0) + 1
    top_cves = sorted(cve_freq.items(), key=lambda x: x[1], reverse=True)[:10]

    # MITRE techniques
    techniques = []
    for f in findings:
        techniques.extend(f.mitre_techniques or [])
    for a in alerts:
        techniques.extend(a.mitre_techniques or [])
    unique_techniques = list(set(techniques))

    if report_type == "executive":
        content = {
            "report_type": "executive",
            "executive_summary": (
                f"Security assessment identified {len(findings)} findings across the environment. "
                f"{severity_counts.get('CRITICAL', 0)} critical and "
                f"{severity_counts.get('HIGH', 0)} high severity issues require immediate attention."
            ),
            "severity_breakdown": severity_counts,
            "open_alerts": len([a for a in alerts if a.status.value == "OPEN"]),
            "top_risks": [
                f.title for f in findings if f.severity.value in ("CRITICAL", "HIGH")
            ][:5],
            "mitre_coverage": unique_techniques,
            "recommendation": "Prioritise patching of critical and high findings. Strengthen detection rules.",
        }
    elif report_type == "soc":
        content = {
            "report_type": "soc",
            "incident_count": len(alerts),
            "open_incidents": len([a for a in alerts if a.status.value == "OPEN"]),
            "detection_sources": list(set(a.source for a in alerts if a.source)),
            "alert_severity_breakdown": {
                s.value: len([a for a in alerts if a.severity.value == s.value])
                for s in Severity
            },
            "mitre_techniques_observed": unique_techniques,
            "detection_gaps": len([a for a in alerts if a.detection_gap]),
            "recommendations": [
                "Enable Suricata rules for lateral movement detection",
                "Tune Wazuh alerts to reduce false positives",
                "Add DNS monitoring for C2 detection",
            ],
        }
    else:  # technical
        content = {
            "report_type": "technical",
            "findings": [
                {
                    "id": str(f.id),
                    "title": f.title,
                    "severity": f.severity.value,
                    "plugin": f.plugin,
                    "cve_ids": f.cve_ids or [],
                    "cvss_score": f.cvss_score,
                    "mitre_techniques": f.mitre_techniques or [],
                    "remediation": f.remediation,
                    "affected_url": f.affected_url,
                    "is_verified": f.is_verified,
                }
                for f in findings
            ],
            "severity_breakdown": severity_counts,
            "top_cves": [{"cve": c, "count": n} for c, n in top_cves],
            "total_findings": len(findings),
        }

    return content


# ─── Endpoints ────────────────────────────────────────────────────────────────

@router.get("", response_model=List[ReportOut])
async def list_reports(
    limit: int = 50,
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(Report).order_by(desc(Report.created_at)).limit(limit)
    )
    reports = result.scalars().all()
    return [
        ReportOut(
            id=str(r.id), title=r.title, report_type=r.report_type,
            created_at=r.created_at,
            summary=r.content.get("executive_summary") if r.content else None,
        )
        for r in reports
    ]


@router.post("/generate", status_code=201)
async def generate_report(
    payload: ReportRequest,
    background_tasks: BackgroundTasks,
    db: AsyncSession = Depends(get_db),
):
    """Generate an AI-powered security report."""
    content = await _build_report_content(
        payload.report_type, db, payload.scan_job_ids, payload.asset_ids
    )

    report = Report(
        id=str(uuid.uuid4()),
        title=payload.title,
        report_type=payload.report_type,
        content=content,
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)

    return {
        "id": str(report.id),
        "title": report.title,
        "report_type": report.report_type,
        "status": "generated",
        "content": content,
        "created_at": report.created_at,
    }


@router.get("/{report_id}")
async def get_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    return {
        "id": str(report.id),
        "title": report.title,
        "report_type": report.report_type,
        "content": report.content,
        "created_at": report.created_at,
    }


@router.delete("/{report_id}", status_code=204)
async def delete_report(report_id: str, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Report).where(Report.id == report_id))
    report = result.scalar_one_or_none()
    if not report:
        raise HTTPException(status_code=404, detail="Report not found")
    await db.delete(report)
    await db.commit()
