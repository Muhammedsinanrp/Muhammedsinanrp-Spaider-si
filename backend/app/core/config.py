"""SPAIDER application configuration."""

import os
import shutil
from typing import List, Any, Union
from pydantic_settings import BaseSettings
from pydantic import Field, field_validator


class Settings(BaseSettings):
    # ── Application ────────────────────────────────────────────────────────
    app_name: str = "SPAIDER"
    environment: str = Field(default="development", env="ENVIRONMENT")
    secret_key: str = Field(default="changeme", env="SECRET_KEY")
    algorithm: str = "HS256"
    access_token_expire_minutes: int = 60 * 24  # 24 hours

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
    default_llm_provider: str = "openai"  # openai | anthropic | local
    default_llm_model: str = "gpt-4o"

    # ── CORS ───────────────────────────────────────────────────────────────
    allowed_origins: Union[List[str], str] = Field(
        default=["http://localhost:3000", "http://localhost:5173"],
    )

    @field_validator("allowed_origins", mode="before")
    @classmethod
    def assemble_cors_origins(cls, v: Any) -> List[str]:
        if isinstance(v, str):
            if v.startswith("[") and v.endswith("]"):
                import json
                try:
                    return json.loads(v)
                except Exception:
                    pass
            return [i.strip() for i in v.split(",") if i.strip()]
        elif isinstance(v, list):
            return v
        return ["http://localhost:3000", "http://localhost:5173"]

    # ── Security engine paths & keys ───────────────────────────────────────
    nmap_path: str = Field(default="nmap", env="NMAP_PATH")
    nmap_api_key: str = Field(default="", env="NMAP_API_KEY")
    vulners_api_key: str = Field(default="", env="VULNERS_API_KEY")
    nuclei_path: str = Field(default="nuclei", env="NUCLEI_PATH")
    scan_results_dir: str = Field(default="./scan_results", env="SCAN_RESULTS_DIR")
    malware_samples_dir: str = Field(default="./malware_samples", env="MALWARE_SAMPLES_DIR")
    pcap_files_dir: str = Field(default="./pcap_files", env="PCAP_FILES_DIR")

    # ── Safety / Authorization ─────────────────────────────────────────────
    max_scan_targets: int = 1000
    require_scope_authorization: bool = True
    allow_destructive_tests: bool = False

    @property
    def resolved_nuclei_path(self) -> str:
        import shutil, os
        if self.nuclei_path != "nuclei" and (shutil.which(self.nuclei_path) or os.path.isfile(self.nuclei_path)):
            return self.nuclei_path
        in_path = shutil.which("nuclei")
        if in_path:
            return in_path
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        for candidate in ["nuclei.exe", "nuclei"]:
            p = os.path.join(root, "bin", candidate)
            if os.path.isfile(p):
                return p
        return self.nuclei_path

    @property
    def effective_nmap_api_key(self) -> str:
        return (self.nmap_api_key or self.vulners_api_key or "").strip()

    @property
    def resolved_nmap_path(self) -> str:
        import shutil, os
        if self.nmap_path != "nmap" and (shutil.which(self.nmap_path) or os.path.isfile(self.nmap_path)):
            return self.nmap_path
        in_path = shutil.which("nmap")
        if in_path:
            return in_path
        root = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".."))
        for candidate in ["nmap.exe", "nmap"]:
            p = os.path.join(root, "bin", candidate)
            if os.path.isfile(p):
                return p
        for default_win in [r"C:\Program Files (x86)\Nmap\nmap.exe", r"C:\Program Files\Nmap\nmap.exe"]:
            if os.path.isfile(default_win):
                return default_win
        return self.nmap_path

    model_config = {
        "env_file": (
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "..", ".env")),
            os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", ".env")),
            ".env",
        ),
        "env_file_encoding": "utf-8",
        "case_sensitive": False,
        "extra": "ignore",
    }


settings = Settings()
