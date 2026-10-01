"""SPAIDER Database Seeder — Populates rich initial demonstration & security data."""

import asyncio
from datetime import datetime, timedelta
from sqlalchemy import select
import structlog

from app.core.database import engine, Base, AsyncSessionLocal
from app.models.models import (
    User, Scope, Asset, Service, ScanJob, Finding, Alert,
    MalwareSample, IOC, MitreTechnique, Report,
    ScanMode, ScanStatus, Severity, AssetType, AlertStatus
)
from app.api.v1.endpoints.auth import hash_password

logger = structlog.get_logger(__name__)


async def seed_database(force: bool = False):
    """Seed the database with default admin user and cyber security data."""
    async with engine.begin() as conn:
        await conn.run_sync(lambda c: Base.metadata.create_all(c, checkfirst=True))

    async with AsyncSessionLocal() as db:
        # Check if already seeded
        res = await db.execute(select(User))
        existing_users = res.scalars().all()
        if existing_users and not force:
            logger.info("Database already seeded, skipping.")
            return

        logger.info("Seeding SPAIDER cyber intelligence platform data...")

        # 1. Users
        admin_user = User(
            id="usr-admin-001",
            username="admin",
            email="admin@spaider.internal",
            hashed_password=hash_password("admin123"),
            full_name="Chief Information Security Officer",
            role="admin",
            is_active=True,
            is_superuser=True,
        )
        analyst_user = User(
            id="usr-analyst-002",
            username="analyst",
            email="analyst@spaider.internal",
            hashed_password=hash_password("analyst123"),
            full_name="Lead SOC Analyst",
            role="analyst",
            is_active=True,
            is_superuser=False,
        )
        db.add_all([admin_user, analyst_user])
        await db.flush()

        # 2. Scopes
        scope1 = Scope(
            id="scp-corp-001",
            name="Primary Infrastructure Scope",
            description="Core corporate network and DMZ perimeter systems",
            targets=["192.168.1.0/24", "10.0.0.0/16", "api.spaider-security.io"],
            excluded_targets=["192.168.1.254"],
            active_testing=True,
            destructive_testing=False,
            rate_limit="controlled",
            authorized_by="Security Operations Committee",
            valid_from=datetime.utcnow() - timedelta(days=30),
            valid_until=datetime.utcnow() + timedelta(days=365),
        )
        scope2 = Scope(
            id="scp-web-002",
            name="External Web Applications Scope",
            description="Production web portals and public API endpoints",
            targets=["https://app.spaider-security.io", "https://auth.spaider-security.io"],
            excluded_targets=[],
            active_testing=True,
            destructive_testing=False,
            rate_limit="stealth",
            authorized_by="VP of Engineering",
            valid_from=datetime.utcnow() - timedelta(days=15),
            valid_until=datetime.utcnow() + timedelta(days=180),
        )
        db.add_all([scope1, scope2])
        await db.flush()

        # 3. Assets
        asset1 = Asset(
            id="ast-dmz-001",
            name="DMZ Perimeter Gateway",
            asset_type=AssetType.HOST,
            value="192.168.1.1",
            description="Main ingress edge firewall and reverse proxy router",
            os="Linux",
            os_version="Ubuntu 22.04 LTS",
            criticality=Severity.CRITICAL,
            tags=["dmz", "perimeter", "ingress", "edge"],
            extra_data={"datacenter": "us-east-1", "managed_by": "secops"},
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        asset2 = Asset(
            id="ast-db-002",
            name="Core Database Cluster",
            asset_type=AssetType.HOST,
            value="192.168.1.10",
            description="Primary encrypted transactional database repository",
            os="Linux",
            os_version="Debian 12 Bookworm",
            criticality=Severity.HIGH,
            tags=["database", "internal", "pii-store"],
            extra_data={"engine": "PostgreSQL 16", "encryption": "AES-256"},
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        asset3 = Asset(
            id="ast-dc-003",
            name="Primary Domain Controller",
            asset_type=AssetType.HOST,
            value="192.168.1.5",
            description="Active Directory domain controller and Kerberos KDC",
            os="Windows Server",
            os_version="Windows Server 2022",
            criticality=Severity.CRITICAL,
            tags=["ad", "identity", "tier-0", "kdc"],
            extra_data={"domain": "SPAIDER.LOCAL", "forest_level": "2016"},
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        asset4 = Asset(
            id="ast-web-004",
            name="Public Web Application Portal",
            asset_type=AssetType.URL,
            value="https://app.spaider-security.io",
            description="Customer facing single-page portal and dashboard",
            os="Linux",
            os_version="Alpine 3.19",
            criticality=Severity.HIGH,
            tags=["frontend", "spa", "cloud", "customer-facing"],
            extra_data={"runtime": "Node 20 / Nginx", "cdn": "Cloudflare"},
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        db.add_all([asset1, asset2, asset3, asset4])
        await db.flush()

        # Services
        srv1 = Service(id="srv-001", asset_id=asset1.id, port=80, protocol="tcp", name="http", product="nginx", version="1.24.0", state="open")
        srv2 = Service(id="srv-002", asset_id=asset1.id, port=443, protocol="tcp", name="https", product="nginx", version="1.24.0", state="open", tls=True)
        srv3 = Service(id="srv-003", asset_id=asset1.id, port=22, protocol="tcp", name="ssh", product="OpenSSH", version="8.9p1", state="open")
        srv4 = Service(id="srv-004", asset_id=asset2.id, port=5432, protocol="tcp", name="postgresql", product="PostgreSQL", version="16.2", state="open")
        srv5 = Service(id="srv-005", asset_id=asset3.id, port=88, protocol="tcp", name="kerberos", product="Microsoft Kerberos", version="10.0", state="open")
        srv6 = Service(id="srv-006", asset_id=asset3.id, port=445, protocol="tcp", name="microsoft-ds", product="SMBv3", version="10.0", state="open")
        db.add_all([srv1, srv2, srv3, srv4, srv5, srv6])
        await db.flush()

        # 4. Scan Jobs
        job1 = ScanJob(
            id="job-nmap-001",
            name="Perimeter Infrastructure Comprehensive Port Scan",
            mode=ScanMode.RED,
            status=ScanStatus.COMPLETED,
            plugin="nmap",
            targets=["192.168.1.1", "192.168.1.5", "192.168.1.10"],
            options={"timing": "-T4", "scripts": "default,vuln", "service_detection": True},
            progress=100,
            started_at=datetime.utcnow() - timedelta(hours=4),
            completed_at=datetime.utcnow() - timedelta(hours=3, minutes=45),
            scope_id=scope1.id,
            created_by=admin_user.id,
        )
        job2 = ScanJob(
            id="job-nuclei-002",
            name="Automated Web Application Vulnerability Assessment",
            mode=ScanMode.RED,
            status=ScanStatus.COMPLETED,
            plugin="nuclei",
            targets=["https://app.spaider-security.io"],
            options={"severity": "critical,high,medium", "templates": "cves,vulnerabilities"},
            progress=100,
            started_at=datetime.utcnow() - timedelta(hours=2),
            completed_at=datetime.utcnow() - timedelta(hours=1, minutes=40),
            scope_id=scope2.id,
            created_by=admin_user.id,
        )
        job3 = ScanJob(
            id="job-wazuh-003",
            name="Continuous Host-Based Detection & Threat Hunting",
            mode=ScanMode.BLUE,
            status=ScanStatus.RUNNING,
            plugin="wazuh",
            targets=["192.168.1.0/24"],
            options={"rule_level": 8, "time_range": "24h"},
            progress=74,
            started_at=datetime.utcnow() - timedelta(minutes=45),
            scope_id=scope1.id,
            created_by=analyst_user.id,
        )
        job4 = ScanJob(
            id="job-purple-004",
            name="Purple Team ATT&CK Matrix Coverage Validation",
            mode=ScanMode.PURPLE,
            status=ScanStatus.COMPLETED,
            plugin="purple",
            targets=["192.168.1.5"],
            options={"matrix": "enterprise", "tactic": "credential-access"},
            progress=100,
            started_at=datetime.utcnow() - timedelta(hours=6),
            completed_at=datetime.utcnow() - timedelta(hours=5),
            scope_id=scope1.id,
            created_by=admin_user.id,
        )
        db.add_all([job1, job2, job3, job4])
        await db.flush()

        # 5. Findings
        f1 = Finding(
            id="fnd-001",
            title="Remote Code Execution via Apache Struts OGNL (CVE-2023-50164)",
            description="Critical path traversal and parameter manipulation flaw leading to remote code execution.",
            severity=Severity.CRITICAL,
            plugin="nuclei",
            template_id="cve-2023-50164",
            cve_ids=["CVE-2023-50164"],
            cvss_score=9.8,
            cvss_vector="CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
            cwe_ids=["CWE-22", "CWE-94"],
            mitre_techniques=["T1190"],
            affected_url="https://app.spaider-security.io/upload",
            evidence="Successfully confirmed parameter manipulation without authentication.",
            remediation="Upgrade Apache Struts to 2.5.33 or 6.3.0.2 immediately.",
            tags=["rce", "cve", "critical"],
            asset_id=asset4.id,
            scan_job_id=job2.id,
            is_verified=True,
            ai_analysis={"risk_summary": "Extremely critical. Immediate internet-facing compromise vector.", "confidence": 0.98},
        )
        f2 = Finding(
            id="fnd-002",
            title="SQL Injection in Authentication Backend Endpoint",
            description="Unsanitized user input in authentication API allows arbitrary database query injection.",
            severity=Severity.HIGH,
            plugin="caido",
            template_id="sqli-blind-boolean",
            cve_ids=[],
            cvss_score=8.6,
            cwe_ids=["CWE-89"],
            mitre_techniques=["T1190"],
            affected_url="https://app.spaider-security.io/api/v1/auth/verify",
            evidence="Response latency varied proportionally with injected SLEEP(5) payloads.",
            remediation="Use parameterized queries and ORM object binding strictly.",
            tags=["sqli", "owasp-top-10"],
            asset_id=asset4.id,
            scan_job_id=job2.id,
            is_verified=True,
            ai_analysis={"risk_summary": "High risk of total database compromise and data exfiltration.", "confidence": 0.95},
        )
        f3 = Finding(
            id="fnd-003",
            title="Exposed Docker Daemon REST API on TCP 2375",
            description="Unauthenticated Docker API endpoint exposed to internal network allows container breakout.",
            severity=Severity.HIGH,
            plugin="nmap",
            template_id="docker-api-exposed",
            cve_ids=[],
            cvss_score=8.1,
            cwe_ids=["CWE-306"],
            mitre_techniques=["T1610"],
            affected_url="http://192.168.1.1:2375/version",
            evidence="Docker Engine v24.0.7 responded with full system information without TLS certificates.",
            remediation="Enable TLS mutual authentication or bind Docker socket exclusively to local unix socket.",
            tags=["docker", "misconfiguration", "privilege-escalation"],
            asset_id=asset1.id,
            scan_job_id=job1.id,
            is_verified=True,
        )
        f4 = Finding(
            id="fnd-004",
            title="Weak SSH Cipher Suites Enabled (CBC Modes)",
            description="SSH daemon supports legacy CBC ciphers vulnerable to plaintext recovery attacks.",
            severity=Severity.LOW,
            plugin="nmap",
            template_id="ssh2-enum-algos",
            cve_ids=["CVE-2008-5161"],
            cvss_score=3.7,
            cwe_ids=["CWE-327"],
            mitre_techniques=[],
            affected_url="ssh://192.168.1.1:22",
            evidence="Offered ciphers included: 3des-cbc, aes128-cbc, aes256-cbc",
            remediation="Update sshd_config to use modern CTR or ChaCha20 cipher suites.",
            tags=["ssh", "cryptography"],
            asset_id=asset1.id,
            scan_job_id=job1.id,
            is_verified=False,
        )
        db.add_all([f1, f2, f3, f4])
        await db.flush()

        # 6. SIEM Alerts
        a1 = Alert(
            id="alt-001",
            title="Multiple Failed SSH Logins (Potential Brute Force)",
            description="Host received 142 failed SSH authentication attempts from external IP 203.0.113.88 in 3 minutes.",
            severity=Severity.HIGH,
            status=AlertStatus.INVESTIGATING,
            source="wazuh",
            source_ip="203.0.113.88",
            destination_ip="192.168.1.1",
            destination_port=22,
            protocol="tcp",
            event_type="authentication_failure",
            mitre_techniques=["T1110.001"],
            count=142,
            asset_id=asset1.id,
            assigned_to=analyst_user.id,
        )
        a2 = Alert(
            id="alt-002",
            title="Suspicious Base64 Encoded PowerShell Process Spawned",
            description="powershell.exe executed with -EncodedCommand parameter spawning from Office document process.",
            severity=Severity.CRITICAL,
            status=AlertStatus.OPEN,
            source="wazuh",
            source_ip="192.168.1.105",
            destination_ip="198.51.100.42",
            destination_port=443,
            protocol="tcp",
            event_type="process_creation",
            mitre_techniques=["T1059.001", "T1027"],
            count=3,
            is_purple_validated=True,
            detection_gap=False,
        )
        a3 = Alert(
            id="alt-003",
            title="DNS Exfiltration Pattern / High Entropy Subdomain Queries",
            description="Continuous sequence of high-entropy DNS TXT and A record queries indicative of iodine/dnscat2.",
            severity=Severity.HIGH,
            status=AlertStatus.OPEN,
            source="zeek",
            source_ip="192.168.1.5",
            destination_ip="8.8.8.8",
            destination_port=53,
            protocol="udp",
            event_type="dns_anomaly",
            mitre_techniques=["T1071.004", "T1048"],
            count=89,
            asset_id=asset3.id,
        )
        a4 = Alert(
            id="alt-004",
            title="Detection Gap: Kerberoasting Attack (T1558.003) Unflagged",
            description="Purple team test performed Kerberoast ticket request SPN queries without SIEM alert triggering.",
            severity=Severity.MEDIUM,
            status=AlertStatus.OPEN,
            source="purple",
            source_ip="192.168.1.105",
            destination_ip="192.168.1.5",
            destination_port=88,
            protocol="tcp",
            event_type="purple_validation_failure",
            mitre_techniques=["T1558.003"],
            count=1,
            is_purple_validated=True,
            detection_gap=True,
            asset_id=asset3.id,
        )
        db.add_all([a1, a2, a3, a4])
        await db.flush()

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

        # 8. IOCs
        ioc1 = IOC(
            id="ioc-001",
            type="ip",
            value="198.51.100.42",
            threat_type="c2_server",
            confidence=0.95,
            source="ThreatIntel Feeds / SPAIDER Honeypot",
            tags=["cobalt-strike", "c2", "active-threat"],
            first_seen=datetime.utcnow() - timedelta(days=7),
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        ioc2 = IOC(
            id="ioc-002",
            type="domain",
            value="update-windows-telemetry.biz",
            threat_type="c2_domain",
            confidence=0.90,
            source="Zeek Network Detection",
            tags=["dns-beacon", "adversary-infra"],
            first_seen=datetime.utcnow() - timedelta(days=3),
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        ioc3 = IOC(
            id="ioc-003",
            type="hash",
            value="e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            threat_type="stager_payload",
            confidence=0.99,
            source="YARA Malware Engine",
            tags=["trojan", "dropper"],
            first_seen=datetime.utcnow() - timedelta(days=1),
            last_seen=datetime.utcnow(),
            is_active=True,
        )
        db.add_all([ioc1, ioc2, ioc3])
        await db.flush()

        # 9. Reports
        rep1 = Report(
            id="rep-exec-001",
            title="Q3 Comprehensive Cyber Threat Landscape & Exposure Summary",
            report_type="executive",
            content={
                "executive_summary": "Overall enterprise risk profile is currently evaluated at ELEVATED due to 1 critical perimeter vulnerability and ongoing credential access attempts.",
                "total_assets_scanned": 4,
                "critical_findings": 1,
                "high_findings": 2,
                "mean_time_to_detect": "14 minutes",
                "recommended_actions": [
                    "Immediate patching of Struts CVE-2023-50164 on public web portal.",
                    "Close or secure Docker daemon port 2375 on perimeter gateway.",
                    "Deploy updated detection rule for T1558.003 Kerberoasting on Active Directory."
                ],
            },
            created_by=admin_user.id,
        )
        rep2 = Report(
            id="rep-tech-002",
            title="Technical Vulnerability Assessment & Proof of Concepts",
            report_type="technical",
            content={
                "scope_evaluated": "Primary Infrastructure & Web Applications",
                "vulnerabilities": [
                    {"id": "CVE-2023-50164", "severity": "CRITICAL", "target": "https://app.spaider-security.io"},
                    {"id": "SQLi-AUTH-01", "severity": "HIGH", "target": "https://app.spaider-security.io/api/v1/auth/verify"},
                    {"id": "DOCKER-2375", "severity": "HIGH", "target": "192.168.1.1:2375"}
                ],
            },
            created_by=admin_user.id,
        )
        db.add_all([rep1, rep2])

        await db.commit()
        logger.info("Database seeding successfully completed!")


if __name__ == "__main__":
    asyncio.run(seed_database())
