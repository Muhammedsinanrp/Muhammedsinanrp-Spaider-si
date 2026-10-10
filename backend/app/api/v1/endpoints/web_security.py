"""Scope-checked web scanning endpoints backed by Nuclei task execution.

A scan only starts when each URL belongs to an active, unexpired authorization
scope. The endpoint supports Celery workers and a local thread fallback for
development setups without Redis; it never returns simulated findings.
"""

import socket
import threading
import uuid
from typing import List, Optional
from urllib.parse import urlsplit

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import settings
from app.core.database import get_db
from app.services.scope_validator import validate_target_scope
from app.workers.celery_app import celery_app

router = APIRouter()

AUTH_WARNING = (
    "Only scan systems for which you have explicit authorization. "
    "Targets must match an active, unexpired SPAIDER scope."
)

# In-process results are used only when the Redis broker is unavailable.
# Production deployments should run the dedicated Celery worker.
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
    status: str
    targets: List[str]
    categories_queued: List[str]
    message: str
    authorization_warning: str = AUTH_WARNING


def _validate_url(target: str) -> str:
    """Return a normalized URL or reject non-HTTP input."""
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
    """Small connection check so local development can work without Redis."""
    import urllib.parse

    parsed = urllib.parse.urlparse(settings.redis_url)
    if not parsed.hostname:
        return False
    try:
        with socket.create_connection(
            (parsed.hostname, parsed.port or 6379), timeout=0.4
        ):
            return True
    except OSError:
        return False


def _run_local_web_scan(
    task_id: str,
    targets: List[str],
    categories: List[str],
    rate_limit: int,
    timeout: int,
    proxy: Optional[str],
) -> None:
    """Execute the Celery task in a background thread for local development."""
    with _LOCAL_WEB_SCANS_LOCK:
        _LOCAL_WEB_SCANS[task_id]["status"] = "STARTED"
    try:
        from app.workers.tasks import run_web_security_scan

        result = run_web_security_scan(
            targets, categories, rate_limit=rate_limit, timeout=timeout, proxy=proxy
        )
        with _LOCAL_WEB_SCANS_LOCK:
            _LOCAL_WEB_SCANS[task_id]["result"] = result
            _LOCAL_WEB_SCANS[task_id]["status"] = (
                "FAILURE" if isinstance(result, dict) and result.get("error") else "SUCCESS"
            )
    except Exception as exc:
        with _LOCAL_WEB_SCANS_LOCK:
            _LOCAL_WEB_SCANS[task_id]["result"] = {"error": str(exc), "findings": []}
            _LOCAL_WEB_SCANS[task_id]["status"] = "FAILURE"


@router.post("/scan", response_model=WebScanResponse)
async def launch_web_scan(payload: WebScanRequest, db: AsyncSession = Depends(get_db)):
    """Queue a real Nuclei scan after validating every target against saved scope."""
    normalized_targets = list(dict.fromkeys(_validate_url(t) for t in payload.targets))
    from app.plugins.nuclei.plugin import WEB_VULN_CATEGORIES

    categories = payload.categories or list(WEB_VULN_CATEGORIES.keys())
    if not categories:
        raise HTTPException(status_code=400, detail="Select at least one scan category.")
    unknown_categories = sorted(set(categories) - set(WEB_VULN_CATEGORIES))
    if unknown_categories:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown scan category: {', '.join(unknown_categories)}",
        )

    if payload.proxy:
        proxy = urlsplit(payload.proxy)
        if proxy.scheme not in {"http", "https", "socks5"} or not proxy.hostname:
            raise HTTPException(
                status_code=400,
                detail="Proxy must be a valid http://, https://, or socks5:// URL.",
            )

    matched_scope_id = payload.scope_id
    for target in normalized_targets:
        authorized, reason, matched_scope = await validate_target_scope(
            target, db, payload.scope_id
        )
        if not authorized:
            raise HTTPException(status_code=403, detail=f"AUTHORIZATION ERROR: {reason}")
        if matched_scope and not matched_scope_id:
            matched_scope_id = str(matched_scope.id)

    task_args = [
        normalized_targets,
        categories,
        payload.rate_limit,
        payload.timeout,
        payload.proxy,
    ]

    if _redis_available():
        try:
            task = celery_app.send_task(
                "app.workers.tasks.run_web_security_scan",
                args=task_args,
                queue="red_queue",
            )
            return WebScanResponse(
                task_id=task.id,
                status="queued",
                targets=normalized_targets,
                categories_queued=categories,
                message=(
                    f"Authorized scan queued for {len(normalized_targets)} target(s) "
                    f"across {len(categories)} categories."
                ),
            )
        except Exception:
            # Fall through to the local runner if the broker is unavailable.
            pass

    task_id = f"local-{uuid.uuid4()}"
    with _LOCAL_WEB_SCANS_LOCK:
        _LOCAL_WEB_SCANS[task_id] = {"status": "PENDING", "result": None}
    thread = threading.Thread(
        target=_run_local_web_scan,
        args=(task_id, *task_args),
        daemon=True,
        name=f"spaider-web-scan-{task_id[-8:]}",
    )
    thread.start()
    return WebScanResponse(
        task_id=task_id,
        status="queued",
        targets=normalized_targets,
        categories_queued=categories,
        message=(
            f"Authorized local scan started for {len(normalized_targets)} target(s) "
            f"across {len(categories)} categories."
        ),
    )


@router.get("/categories")
async def get_categories():
    """Return supported Nuclei scan categories."""
    from app.plugins.nuclei.plugin import get_categories
    return get_categories()


@router.get("/scan/{task_id}/status")
async def scan_status(task_id: str):
    """Return the actual state and result for a queued or locally executed scan."""
    if task_id.startswith("local-"):
        with _LOCAL_WEB_SCANS_LOCK:
            state = _LOCAL_WEB_SCANS.get(task_id)
            if state is None:
                raise HTTPException(status_code=404, detail="Local scan job not found.")
            return {
                "task_id": task_id,
                "status": state["status"],
                "result": state["result"],
                "authorization_warning": AUTH_WARNING,
            }

    task = celery_app.AsyncResult(task_id)
    result = task.result if task.ready() else None
    if task.ready() and task.failed():
        result = {"error": str(task.result), "findings": []}
    return {
        "task_id": task_id,
        "status": task.status,
        "result": result,
        "authorization_warning": AUTH_WARNING,
    }


async def _persist_proxy_findings(db: AsyncSession, source: str, findings: list) -> int:
    """Store Burp/Caido findings so integrations do not merely acknowledge them."""
    import uuid as uuid_module
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
        severity_raw = str(item.get("severity", "INFO")).upper()
        severity = severity_map.get(severity_raw, Severity.INFO)
        url = item.get("url") or item.get("matched_at") or ""
        template_id = item.get("template_id") or item.get("type") or None
        finding = Finding(
            id=str(uuid_module.uuid4()),
            title=str(title)[:512],
            description=str(item.get("description") or item.get("issueDetail") or ""),
            severity=severity,
            plugin=source,
            scanner=source,
            template_id=str(template_id)[:128] if template_id else None,
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
    stored = await _persist_proxy_findings(db, "burp", findings)
    return {"synced": stored, "status": "ok"}


@router.post("/caido/sync")
async def caido_sync(findings: list, db: AsyncSession = Depends(get_db)):
    """Persist findings received from Caido Automate."""
    stored = await _persist_proxy_findings(db, "caido", findings)
    return {"synced": stored, "status": "ok"}
