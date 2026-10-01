"""
SPAIDER - Security Platform for AI-driven Detection, Investigation,
Exploitation, Analysis, Defense & Response

Main FastAPI application entry point.
"""

from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
import structlog

from app.core.config import settings
from app.core.database import engine, Base
from app.api.v1.router import api_router
from app.core.websocket_manager import ws_manager

logger = structlog.get_logger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Application lifespan: startup and shutdown events."""
    logger.info("SPAIDER starting up...", version="1.0.0")
    # Create all tables (checkfirst skips existing tables/indexes safely)
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))
    logger.info("Database tables initialised")

    # Seed baseline assets, scopes, scans, alerts, and users
    try:
        from app.core.seed import seed_database
        await seed_database(force=False)
    except Exception as e:
        logger.warning(f"Database seeder warning: {e}")

    yield
    logger.info("SPAIDER shutting down...")
    await engine.dispose()


def create_application() -> FastAPI:
    application = FastAPI(
        title="SPAIDER",
        description="AI-Powered Cybersecurity Command Platform — Red | Blue | Purple",
        version="1.0.0",
        docs_url="/api/docs",
        redoc_url="/api/redoc",
        openapi_url="/api/openapi.json",
        lifespan=lifespan,
    )

    # ── Middleware ──────────────────────────────────────────────────────────
    application.add_middleware(
        CORSMiddleware,
        allow_origins=settings.allowed_origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    application.add_middleware(GZipMiddleware, minimum_size=1000)

    # ── Routes ─────────────────────────────────────────────────────────────
    application.include_router(api_router, prefix="/api/v1")

    return application


app = create_application()


@app.get("/health", tags=["health"])
async def health_check():
    return {
        "status": "operational",
        "platform": "SPAIDER",
        "version": "1.0.0",
        "modes": ["RED", "BLUE", "PURPLE"],
    }
