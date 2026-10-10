"""SPAIDER application configuration."""

from typing import List
from pydantic_settings import BaseSettings
from pydantic import Field


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────────────
    app_name: str = "SPAIDER"
    environment: str = Field(default="development", env="ENVIRONMENT")
    secret_key: str = Field(default="changeme", env="SECRET_KEY")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24  # 24 hours
    allow_self_registration: bool = Field(default=False, env="ALLOW_SELF_REGISTRATION")
    spaider_admin_password: str = Field(default="", env="SPAIDER_ADMIN_PASSWORD")
    spaider_analyst_password: str = Field(default="", env="SPAIDER_ANALYST_PASSWORD")

    # ── Database ───────────────────────────────────────────────────────────
    # Default: SQLite for local dev. Set DATABASE_URL in .env for PostgreSQL.
    database_url: str = Field(
        default="sqlite+aiosqlite:///./spaider_dev.db",
        env="DATABASE_URL",
    )

    # ── Redis / Celery ─────────────────────────────────────────────────────
    redis_url: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
    )
    celery_broker_url: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
    )
    celery_result_backend: str = Field(
        default="redis://localhost:6379/0",
        env="REDIS_URL",
    )

    # ── OpenSearch ─────────────────────────────────────────────────────────
    opensearch_url: str = Field(
        default="http://localhost:9200",
        env="OPENSEARCH_URL",
    )

    # ── AI / LLM ───────────────────────────────────────────────────────────
    openai_api_key: str = Field(default="", env="OPENAI_API_KEY")
    anthropic_api_key: str = Field(default="", env="ANTHROPIC_API_KEY")
    default_llm_provider: str = Field(default="openai", env="DEFAULT_LLM_PROVIDER")  # openai | anthropic | local
    default_llm_model: str = Field(default="gpt-4o", env="DEFAULT_LLM_MODEL")
    anthropic_model: str = Field(default="claude-sonnet-5", env="ANTHROPIC_MODEL")

    # ── CORS ───────────────────────────────────────────────────────────────
    allowed_origins: List[str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
    )

    # ── Security engine paths ──────────────────────────────────────────────
    nmap_path: str = Field(default="nmap", env="NMAP_PATH")
    nuclei_path: str = Field(default="nuclei", env="NUCLEI_PATH")
    scan_results_dir: str = Field(default="./scan_results", env="SCAN_RESULTS_DIR")
    malware_samples_dir: str = Field(default="./malware_samples", env="MALWARE_SAMPLES_DIR")
    pcap_files_dir: str = Field(default="./pcap_files", env="PCAP_FILES_DIR")

    # ── Safety / Authorization ─────────────────────────────────────────────
    max_scan_targets: int = 1000
    require_scope_authorization: bool = True
    allow_destructive_tests: bool = False

    model_config = {"env_file": ".env", "case_sensitive": False}


settings = Settings()
