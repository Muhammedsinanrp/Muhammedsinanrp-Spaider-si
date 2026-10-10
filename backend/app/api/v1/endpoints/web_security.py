"""Scope-checked web scanning endpoints backed by real Nuclei execution."""

import socket
import threading
import uuid
import json
from datetime import datetime
from typing import List, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.models.models import Finding, ScanEvent, ScanJob, ScanMode, ScanStatus
from app.services.scope_validator import validate_target_scope
from app.workers.celery_app import celery_app

router = APIRouter()

AUTH_WARNING = (
    "Only scan systems for which you have explicit authorization. "
    "Targets must match an active, unexpired SPAIDER scope."
)

# Development fallback when Redis is not reachable. Scan records and findings
# are still persisted in the database; this dictionary only supports live polling.
_LOCAL_WEB_SCANS: dict[str, dict] = {}
_LOCAL_WEB_SCANS_LOCK = threading.Lock()


class WebScanRequest(BaseModel):
    targets: List[str] = Field(min_length=1, max_length=20)
    categories: Optional[List[str]] = None
    rate_limit: int = Field(default=10, ge=1, le=100)
    timeout: int = Field(default=10, ge=1, le=60)
    proxy: Optional[str] = None
    scope_id: Optional[str] = None


class WebScanResponse(BaseModel):
    task_id: str
    scan_id: str
    status: str
    targets: List[str]
    categories_queued: List[str]
    message: str
    authorization_warning: str = AUTH_WARNING


def _validate_url(target: str) -> str:
    """Reject malformed/non-HTTP targets before looking up authorization."""
    if not target or target != target.strip() or any(ch.isspace() for ch in target):
        raise HTTPException(status_code=400, detail=f"Invalid target URL: {target!r}")
    parsed = urlsplit(target)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise HTTPException(
            status_code=400,
            detail=f"Target must be a complete http:// or https:// URL: {target}",
        )
    if parsed.username or parsed.password:
        raise HTTPException(status_code=400, detail="Credentials in target URLs are not allowed.")
    try:
        parsed.port
    except ValueError:
        raise HTTPException(status_code=400, detail=f"Invalid target port in URL: {target}")
    if parsed.fragment:
        raise HTTPException(status_code=400, detail="Target URLs must not contain fragments.")
    return target


def _redis_available() -> bool:
    """Check broker TCP connectivity for a local development fallback."""
    import urllib.parse

    parsed = urllib.parse.urlparse(settings.redis_url)
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection((parsed.hostname, parsed.port or 6379), timeout=0.4):
            return True
    except OSError:
        return False


def _run_local_web_scan(
    scan_id: str,
    targets: List[str],
    categories: List[str],
    rate_limit: int,
    timeout: int,
    proxy: Optional[str],
) -> None:
    """Run actual scanner in a development thread if Redis is offline."""
    with _LOCAL_WEB_SCANS_LOCK:
        _LOCAL_WEB_SCANS[scan_id] = {"status": "STARTED", "result": None}
    try:
        from app.workers.tasks import run_web_security_scan

        result = run_web_security_scan(
            targets, categories, rate_limit=rate_limit, timeout=timeout,
            proxy=proxy, scan_id=scan_id,
        )
        status = "FAILURE" if isinstance(result, dict) and result.get("error") else "SUCCESS"
        with _LOCAL_WEB_SCANS_LOCK:
            _LOCAL_WEB_SCANS[scan_id] = {"status": status, "result": result}
    except Exception as exc:
        with _LOCAL_WEB_SCANS_LOCK:
            _LOCAL_WEB_SCANS[scan_id] = {
                "status": "FAILURE", "result": {"error": str(exc), "findings": []}
            }


@router.post("/scan", response_model=WebScanResponse)
async def launch_web_scan(payload: WebScanRequest, db: AsyncSession = Depends(get_db)):
    """Create a persistent scan record and dispatch only after scope validation."""
    normalized_targets = list(dict.fromkeys(_validate_url(t) for t in payload.targets))
    from app.plugins.nuclei.plugin import WEB_VULN_CATEGORIES

    categories = payload.categories if payload.categories is not None else ["cves", "misconfig", "exposures"]
    if not categories:
        raise HTTPException(status_code=400, detail="Select at least one scan category.")
    unknown = sorted(set(categories) - set(WEB_VULN_CATEGORIES))
    if unknown:
        raise HTTPException(status_code=400, detail=f"Unknown scan category: {', '.join(unknown)}")

    if payload.proxy:
        parsed_proxy = urlsplit(payload.proxy)
        if parsed_proxy.scheme not in {"http", "https", "socks5"} or not parsed_proxy.hostname:
            raise HTTPException(
                status_code=400,
                detail="Proxy must be a valid http://, https://, or socks5:// URL.",
            )

    matched_scope_id = payload.scope_id
    for target in normalized_targets:
        authorized, reason, matched_scope = await validate_target_scope(target, db, payload.scope_id)
        if not authorized:
            raise HTTPException(status_code=403, detail=f"AUTHORIZATION ERROR: {reason}")
        if matched_scope and not matched_scope_id:
            matched_scope_id = str(matched_scope.id)

    scan_id = str(uuid.uuid4())
    job = ScanJob(
        id=scan_id,
        name=f"Web Security Scan — {normalized_targets[0][:180]}",
        mode=ScanMode.RED,
        plugin="nuclei",
        targets=normalized_targets,
        options={
            "web_scan": True,
            "web_categories": categories,
            "rate_limit": payload.rate_limit,
            "timeout": payload.timeout,
            "proxy": payload.proxy,
            "profile": "safe",
            "scan_type": "web",
        },
        scope_id=matched_scope_id,
        status=ScanStatus.PENDING,
        progress=0,
    )
    db.add(job)
    db.add(ScanEvent(
        id=str(uuid.uuid4()),
        scan_job_id=scan_id,
        stage="TARGET AUTHORIZATION",
        progress=5,
        message="All targets matched an active authorized scope.",
        data={"targets": normalized_targets, "categories": categories, "scope_id": matched_scope_id},
    ))
    await db.commit()

    task_id = scan_id
    queue_message = "Scan started in local development mode."
    if _redis_available():
        try:
            task = celery_app.send_task(
                "app.workers.tasks.run_web_security_scan",
                args=[
                    normalized_targets, categories, payload.rate_limit,
                    payload.timeout, payload.proxy, scan_id,
                ],
                queue="red_queue",
            )
            task_id = task.id
            job.celery_task_id = task.id
            await db.commit()
            queue_message = "Authorized web scan queued for a Celery worker."
            return WebScanResponse(
                task_id=task_id, scan_id=scan_id, status="queued",
                targets=normalized_targets, categories_queued=categories,
                message=queue_message,
            )
        except Exception as exc:
            queue_message = f"Redis dispatch failed; using local runner ({type(exc).__name__})."

    job.status = ScanStatus.RUNNING
    job.started_at = datetime.utcnow()
    await db.commit()
    thread = threading.Thread(
        target=_run_local_web_scan,
        args=(scan_id, normalized_targets, categories, payload.rate_limit, payload.timeout, payload.proxy),
        daemon=True,
        name=f"spaider-web-{scan_id[:8]}",
    )
    thread.start()
    return WebScanResponse(
        task_id=task_id, scan_id=scan_id, status="queued",
        targets=normalized_targets, categories_queued=categories,
        message=queue_message,
    )


@router.get("/categories")
async def get_categories():
    """Return supported Nuclei scan categories."""
    from app.plugins.nuclei.plugin import get_categories
    return get_categories()


@router.get("/scan/{task_id}/status")
async def scan_status(task_id: str, db: AsyncSession = Depends(get_db)):
    """Poll task state, with database-backed recovery after process/queue restarts."""
    with _LOCAL_WEB_SCANS_LOCK:
        local = _LOCAL_WEB_SCANS.get(task_id)
    if local is not None:
        return {
            "task_id": task_id,
            "status": local["status"],
            "result": local["result"],
            "authorization_warning": AUTH_WARNING,
        }

    # Celery result backends can expire results; the durable scan job remains.
    job_result = await db.execute(select(ScanJob).where(ScanJob.id == task_id))
    job = job_result.scalar_one_or_none()
    if job is None:
        job_result = await db.execute(select(ScanJob).where(ScanJob.celery_task_id == task_id))
        job = job_result.scalar_one_or_none()

    task = celery_app.AsyncResult(task_id)
    result = task.result if task.ready() else None
    if task.failed():
        result = {"error": str(task.result), "findings": []}

    job_status = str(job.status.value if job and hasattr(job.status, "value") else job.status) if job else ""
    if job and (result is None or job_status in {"COMPLETED", "FAILED", "CANCELLED"}):
        try:
            summary = json.loads(job.raw_output or "{}")
            if not isinstance(summary, dict):
                summary = {}
        except (TypeError, ValueError):
            summary = {}

        stored_result = await db.execute(
            select(Finding).where(Finding.scan_job_id == job.id).order_by(Finding.created_at.desc())
        )
        stored_findings = []
        for finding in stored_result.scalars().all():
            raw = finding.raw_data if isinstance(finding.raw_data, dict) else {}
            stored_findings.append({
                **raw,
                "id": str(finding.id),
                "template_id": finding.template_id or raw.get("template_id", ""),
                "title": finding.title,
                "description": finding.description or "",
                "severity": finding.severity.value if hasattr(finding.severity, "value") else str(finding.severity),
                "url": finding.affected_url or finding.endpoint or raw.get("url", ""),
                "cve_ids": finding.cve_ids or [],
                "cvss_score": finding.cvss_score if finding.cvss_score is not None else finding.cvss,
                "tags": finding.tags or [],
                "references": finding.references or [],
                "curl_command": finding.curl_poc or raw.get("curl_command", ""),
                "request": finding.request_raw or raw.get("request", ""),
                "response": finding.response_raw or raw.get("response", ""),
            })
        if job_status in {"COMPLETED", "FAILED", "CANCELLED"}:
            result = {
                **summary,
                "findings": stored_findings,
                "total_findings": int(summary.get("total_findings", len(stored_findings))),
                "demo": False,
            }
            if job_status == "FAILED":
                result["error"] = job.error_msg or summary.get("error") or "Scan job failed."
            return {
                "task_id": task_id,
                "status": "SUCCESS" if job_status == "COMPLETED" else job_status,
                "result": result,
                "scan_id": str(job.id),
                "authorization_warning": AUTH_WARNING,
            }

    return {
        "task_id": task_id,
        "status": job_status if job and task.status == "PENDING" else task.status,
        "result": result,
        "scan_id": str(job.id) if job else None,
        "authorization_warning": AUTH_WARNING,
    }


async def _persist_proxy_findings(db: AsyncSession, source: str, findings: list) -> int:
    """Persist findings imported from Burp or Caido instead of just acknowledging."""
    from app.models.models import Finding, Severity

    severity_map = {
        "CRITICAL": Severity.CRITICAL,
        "HIGH": Severity.HIGH,
        "MEDIUM": Severity.MEDIUM,
        "LOW": Severity.LOW,
        "INFO": Severity.INFO,
        "INFORMATION": Severity.INFO,
    }
    count = 0
    for item in findings:
        if not isinstance(item, dict):
            continue
        title = item.get("title") or item.get("issueName") or "Imported proxy finding"
        severity = severity_map.get(str(item.get("severity", "INFO")).upper(), Severity.INFO)
        url = item.get("url") or item.get("matched_at") or ""
        finding = Finding(
            id=str(uuid.uuid4()),
            title=str(title)[:512],
            description=str(item.get("description") or item.get("issueDetail") or ""),
            severity=severity,
            plugin=source,
            scanner=source,
            template_id=str(item.get("template_id") or item.get("type") or "")[:128] or None,
            asset_value=urlsplit(url).hostname if url else None,
            endpoint=str(url)[:1024] if url else None,
            affected_url=str(url)[:1024] if url else None,
            cve_ids=item.get("cve_ids") or [],
            references=item.get("references") or [],
            remediation=item.get("remediation") or item.get("remediationDetail"),
            request_raw=item.get("request") or item.get("request_raw") or "",
            response_raw=item.get("response") or item.get("response_raw") or "",
            raw_data=item,
            tags=item.get("tags") or [source],
            status="open",
        )
        db.add(finding)
        count += 1
    if count:
        await db.commit()
    return count


@router.post("/burp/sync")
async def burp_sync(findings: list, db: AsyncSession = Depends(get_db)):
    """Persist findings received from the SPAIDER Burp extension."""
    return {"synced": await _persist_proxy_findings(db, "burp", findings), "status": "ok"}


@router.post("/caido/sync")
async def caido_sync(findings: list, db: AsyncSession = Depends(get_db)):
    """Persist findings received from Caido Automate."""
    return {"synced": await _persist_proxy_findings(db, "caido", findings), "status": "ok"}
