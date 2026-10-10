"""SPAIDER seeder for development accounts, controlled lab scopes, and ATT&CK reference data."""

import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select, delete
import structlog

from app.core.database import engine, Base, AsyncSessionLocal
from app.core.config import settings
from app.models.models import (
    User, Scope, Target, Asset, Service, ScanJob, Finding, Alert,
    MalwareSample, IOC, MitreTechnique, Report,
    ScanMode, ScanStatus, Severity, AssetType, AlertStatus
)
from app.api.v1.endpoints.auth import hash_password

logger = structlog.get_logger(__name__)


async def seed_database(force: bool = False):
    """Seed the database with default admin user and cyber security data."""
    async with engine.begin() as conn:
        if force:
            await conn.run_sync(Base.metadata.drop_all)
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        res = await db.execute(select(Target))
        existing_targets = res.scalars().all()
        if existing_targets and not force:
            logger.info("Database already seeded with targets, skipping.")
            return

        logger.info("Seeding SPAIDER cyber intelligence platform data...")

        # 1. Users
        is_development = settings.environment.lower() in {"development", "dev", "test"}
        admin_password = settings.spaider_admin_password
        analyst_password = settings.spaider_analyst_password
        if not admin_password:
            if not is_development:
                raise RuntimeError(
                    "SPAIDER_ADMIN_PASSWORD must be set before seeding a non-development environment."
                )
            admin_password = "admin123"
            logger.warning(
                "Development administrator password is using the built-in local default. "
                "Set SPAIDER_ADMIN_PASSWORD before exposing this environment."
            )
        if not analyst_password and is_development:
            analyst_password = "analyst123"
            logger.warning("Development analyst password is using the built-in local default.")

        admin_user = User(
            id="usr-admin-001",
            username="admin",
            email="admin@spaider.internal",
            hashed_password=hash_password(admin_password),
            full_name="SPAIDER Administrator",
            role="admin",
            is_active=True,
            is_superuser=True,
        )
        db.add(admin_user)
        if analyst_password:
            db.add(User(
                id="usr-analyst-002",
                username="analyst",
                email="analyst@spaider.internal",
                hashed_password=hash_password(analyst_password),
                full_name="SPAIDER Analyst",
                role="analyst",
                is_active=True,
                is_superuser=False,
            ))
        await db.flush()

        # ─── 2. Lab Targets (controlled test environment) ────────────────────
        target_js = Target(
            id="tgt-juice-001",
            name="OWASP Juice Shop",
            hostname="juice-shop",
            description="Deliberately insecure Node.js web application for security training and bug bounty research. AUTHORIZED LAB TARGET.",
            status="active",
            tags=["lab", "owasp", "nodejs", "authorized"],
        )
        target_dvwa = Target(
            id="tgt-dvwa-002",
            name="Damn Vulnerable Web App (DVWA)",
            hostname="dvwa",
            description="PHP/MySQL vulnerable web application for security research. AUTHORIZED LAB TARGET.",
            status="active",
            tags=["lab", "php", "dvwa", "authorized"],
        )
        target_webgoat = Target(
            id="tgt-webgoat-003",
            name="WebGoat",
            hostname="webgoat",
            description="OWASP WebGoat deliberately insecure Java application. AUTHORIZED LAB TARGET.",
            status="active",
            tags=["lab", "java", "owasp", "authorized"],
        )
        db.add_all([target_js, target_dvwa, target_webgoat])
        await db.flush()

        # 3. Scopes — map each lab target to an AUTHORIZED scope
        scope_js = Scope(
            id="scp-juice-001",
            target_id="tgt-juice-001",
            name="Juice Shop Lab Scope",
            description="Full authorized scope for OWASP Juice Shop lab environment",
            scope_type="url",
            value="http://juice-shop:3000",
            authorization_status="AUTHORIZED",
            targets=["http://juice-shop:3000", "http://localhost:3001"],
            excluded_targets=[],
            active_testing=True,
            destructive_testing=False,
            rate_limit="controlled",
            authorized_by="Lab Administrator",
            authorization_document="LOCAL_DEV_LAB_ATTESTATION: controlled OWASP Juice Shop container",
            valid_from=datetime.utcnow() - timedelta(days=30),
            valid_until=datetime.utcnow() + timedelta(days=365),
        )
        scope_dvwa = Scope(
            id="scp-dvwa-002",
            target_id="tgt-dvwa-002",
            name="DVWA Lab Scope",
            description="Authorized scope for DVWA lab research environment",
            scope_type="url",
            value="http://dvwa:80",
            authorization_status="AUTHORIZED",
            targets=["http://dvwa:80", "http://localhost:8082"],
            excluded_targets=[],
            active_testing=True,
            destructive_testing=False,
            rate_limit="controlled",
            authorized_by="Lab Administrator",
            authorization_document="LOCAL_DEV_LAB_ATTESTATION: controlled DVWA container",
            valid_from=datetime.utcnow() - timedelta(days=30),
            valid_until=datetime.utcnow() + timedelta(days=365),
        )
        scope_webgoat = Scope(
            id="scp-webgoat-003",
            target_id="tgt-webgoat-003",
            name="WebGoat Lab Scope",
            description="Authorized scope for WebGoat lab environment",
            scope_type="url",
            value="http://webgoat:8080",
            authorization_status="AUTHORIZED",
            targets=["http://webgoat:8080", "http://localhost:8083"],
            excluded_targets=[],
            active_testing=True,
            destructive_testing=False,
            rate_limit="controlled",
            authorized_by="Lab Administrator",
            authorization_document="LOCAL_DEV_LAB_ATTESTATION: controlled WebGoat container",
            valid_from=datetime.utcnow() - timedelta(days=30),
            valid_until=datetime.utcnow() + timedelta(days=365),
        )
        db.add_all([scope_js, scope_dvwa, scope_webgoat])
        await db.flush()

        # Operational inventory, scans, findings, and alerts are not seeded.
        # These dashboards must reflect records produced by actual integrations.

        # 7. MITRE Techniques
        t1 = MitreTechnique(
            id="T1059.001",
            name="PowerShell",
            tactic="Execution",
            description="Adversaries may abuse PowerShell commands and scripts for execution.",
            url="https://attack.mitre.org/techniques/T1059/001/",
            platforms=["Windows"],
            data_sources=["Process: Process Creation", "Script: Script Execution"],
            detection="Monitor PowerShell execution arguments, script block logging (Event ID 4104).",
            mitigation="Enable ConstrainedLanguageMode, AppLocker, and PowerShell Script Block Logging.",
        )
        t2 = MitreTechnique(
            id="T1190",
            name="Exploit Public-Facing Application",
            tactic="Initial Access",
            description="Adversaries may attempt to exploit vulnerabilities in Internet-facing software.",
            url="https://attack.mitre.org/techniques/T1190/",
            platforms=["Linux", "Windows", "Containers"],
            data_sources=["Application Log: Application Log Content", "Network Traffic: Network Traffic Content"],
            detection="Inspect HTTP request headers and payload contents with WAF and reverse proxy telemetry.",
            mitigation="Perform regular patch management and segment public-facing systems in DMZs.",
        )
        t3 = MitreTechnique(
            id="T1003.001",
            name="LSASS Memory",
            tactic="Credential Access",
            description="Adversaries may attempt to access credential material stored in the process memory of the Local Security Authority Subsystem Service (LSASS).",
            url="https://attack.mitre.org/techniques/T1003/001/",
            platforms=["Windows"],
            data_sources=["Process: Process Access"],
            detection="Monitor OpenProcess calls targeting lsass.exe (Sysmon Event ID 10).",
            mitigation="Enable LSA Protection (RunAsPPL) and Credential Guard.",
        )
        db.add_all([t1, t2, t3])
        await db.flush()

        # No fabricated threat indicators or pre-generated reports are inserted.

        await db.commit()
        logger.info("Database seeding successfully completed!")


if __name__ == "__main__":
    asyncio.run(seed_database())
