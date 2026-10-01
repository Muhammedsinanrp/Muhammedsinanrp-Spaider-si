"""SQLAlchemy async database engine and session factory.

Supports:
  - SQLite (local dev, default)  — sqlite+aiosqlite:///./spaider_dev.db
  - PostgreSQL (production)       — postgresql+asyncpg://user:pass@host/db
"""

from sqlalchemy.ext.asyncio import AsyncSession, create_async_engine, async_sessionmaker
from sqlalchemy.orm import DeclarativeBase

from app.core.config import settings

# SQLite doesn't support pool_size / max_overflow
_is_sqlite = settings.database_url.startswith("sqlite")

_engine_kwargs = {
    "echo": settings.environment == "development",
}
if not _is_sqlite:
    _engine_kwargs["pool_size"] = 20
    _engine_kwargs["max_overflow"] = 10
    _engine_kwargs["pool_pre_ping"] = True

engine = create_async_engine(settings.database_url, **_engine_kwargs)

AsyncSessionLocal = async_sessionmaker(
    engine,
    class_=AsyncSession,
    expire_on_commit=False,
)


class Base(DeclarativeBase):
    pass


async def get_db() -> AsyncSession:
    async with AsyncSessionLocal() as session:
        try:
            yield session
        finally:
            await session.close()
