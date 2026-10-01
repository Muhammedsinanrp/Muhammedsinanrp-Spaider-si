"""Web Security scanning endpoints — Nuclei-powered vulnerability detection."""

from typing import List, Optional
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.database import get_db
from app.workers.celery_app import celery_app

router = APIRouter()


class WebScanRequest(BaseModel):
    targets: List[str]
    categories: Optional[List[str]] = None    # None = all categories
    rate_limit: int = 50
    timeout: int = 10
    proxy: Optional[str] = None              # route through Burp/Caido


AUTH_WARNING = "⚠️ Only scan systems you are authorised to test. Ensure a valid scope and authorization document exists."


class WebScanResponse(BaseModel):
    task_id: str
    status: str
    targets: List[str]
    categories_queued: List[str]
    message: str
    authorization_warning: str = AUTH_WARNING


@router.post("/scan", response_model=WebScanResponse)
async def launch_web_scan(payload: WebScanRequest, db: AsyncSession = Depends(get_db)):
    """
    Launch a Nuclei-based web vulnerability scan.

    Categories: cves | injection | ssrf | path_traversal | auth | jwt |
                cors | api | misconfig | exposures | upload | takeovers
    """
    if not payload.targets:
        raise HTTPException(status_code=400, detail="At least one target URL is required")

    categories = payload.categories or [
        "cves", "injection", "ssrf", "path_traversal", "auth",
        "jwt", "cors", "api", "misconfig", "exposures", "upload", "takeovers"
    ]

    task = celery_app.send_task(
        "app.workers.tasks.run_web_security_scan",
        args=[payload.targets, categories, payload.rate_limit, payload.timeout, payload.proxy],
        queue="red_queue",
    )

    return WebScanResponse(
        task_id=task.id,
        status="queued",
        targets=payload.targets,
        categories_queued=categories,
        message=f"Web security scan queued for {len(payload.targets)} target(s) across {len(categories)} vulnerability categories.",
        authorization_warning=AUTH_WARNING,
    )


@router.get("/categories")
async def get_categories():
    """Return all available vulnerability categories with metadata."""
    from app.plugins.nuclei.plugin import get_categories
    return get_categories()


@router.get("/scan/{task_id}/status")
async def scan_status(task_id: str):
    """Check the status of a running web scan."""
    task = celery_app.AsyncResult(task_id)
    return {
        "task_id": task_id,
        "status": task.status,
        "result": task.result if task.ready() else None,
        "authorization_warning": AUTH_WARNING,
    }


@router.post("/burp/sync")
async def burp_sync(findings: list, db: AsyncSession = Depends(get_db)):
    """
    Receive findings from the SPAIDER Burp Extension.
    The extension POSTs findings here when it detects vulnerabilities.
    """
    # Store findings from Burp
    stored = []
    for finding in findings:
        stored.append({
            "source": "burp",
            "title": finding.get("issueName"),
            "severity": finding.get("severity", "MEDIUM").upper(),
            "url": finding.get("url"),
            "description": finding.get("issueDetail"),
            "remediation": finding.get("remediationDetail"),
        })
    return {"synced": len(stored), "status": "ok"}


@router.post("/caido/sync")
async def caido_sync(findings: list, db: AsyncSession = Depends(get_db)):
    """
    Receive findings from Caido Automate integration.
    """
    return {"synced": len(findings), "status": "ok"}
