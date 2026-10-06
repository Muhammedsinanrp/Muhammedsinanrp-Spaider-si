"""API v1 router — aggregates all endpoint routers."""

from fastapi import APIRouter

from app.api.v1.endpoints import (
    auth,
    assets,
    scans,
    findings,
    alerts,
    malware,
    network,
    siem,
    ai_analyst,
    reports,
    websocket,
    plugins,
    purple,
    web_security,
    osint,
    tools,
    targets,
)

api_router = APIRouter()

api_router.include_router(auth.router, prefix="/auth", tags=["Authentication"])
api_router.include_router(targets.router, prefix="/targets", tags=["Targets"])
api_router.include_router(assets.router, prefix="/assets", tags=["Assets"])
api_router.include_router(scans.router, prefix="/scans", tags=["Scans"])
api_router.include_router(findings.router, prefix="/findings", tags=["Findings"])
api_router.include_router(alerts.router, prefix="/alerts", tags=["Alerts"])
api_router.include_router(malware.router, prefix="/malware", tags=["Malware Analysis"])
api_router.include_router(network.router, prefix="/network", tags=["Network Discovery"])
api_router.include_router(siem.router, prefix="/siem", tags=["SIEM"])
api_router.include_router(ai_analyst.router, prefix="/ai", tags=["AI Analyst"])
api_router.include_router(reports.router, prefix="/reports", tags=["Reports"])
api_router.include_router(plugins.router, prefix="/plugins", tags=["Plugins"])
api_router.include_router(purple.router, prefix="/purple", tags=["Purple Team"])
api_router.include_router(web_security.router, prefix="/web", tags=["Web Security"])
api_router.include_router(osint.router, prefix="/osint", tags=["OSINT"])
api_router.include_router(tools.router, prefix="/tools", tags=["Tools"])
api_router.include_router(websocket.router, prefix="/ws", tags=["WebSocket"])
