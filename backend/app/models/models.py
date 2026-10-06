"""SPAIDER SQLAlchemy models — core security entities.

Compatible with both SQLite (dev) and PostgreSQL (production).
Uses String(36) for UUIDs and JSON for arrays instead of PostgreSQL-specific types.
"""

import uuid
from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, Boolean, DateTime,
    Text, JSON, ForeignKey, Enum as SAEnum, Index, UniqueConstraint,
)
from sqlalchemy.orm import relationship
import enum

from app.core.database import Base


# ─────────────────────────────────────────────────────────────────────────────
#  Enumerations
# ─────────────────────────────────────────────────────────────────────────────

class ScanMode(str, enum.Enum):
    RED    = "RED"
    BLUE   = "BLUE"
    PURPLE = "PURPLE"


class ScanStatus(str, enum.Enum):
    PENDING   = "PENDING"
    RUNNING   = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED    = "FAILED"
    CANCELLED = "CANCELLED"


class Severity(str, enum.Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class AssetType(str, enum.Enum):
    HOST         = "HOST"
    DOMAIN       = "DOMAIN"
    IP_RANGE     = "IP_RANGE"
    URL          = "URL"
    API_ENDPOINT = "API_ENDPOINT"
    SERVICE      = "SERVICE"


class AlertStatus(str, enum.Enum):
    OPEN            = "OPEN"
    INVESTIGATING   = "INVESTIGATING"
    RESOLVED        = "RESOLVED"
    FALSE_POSITIVE  = "FALSE_POSITIVE"


# ─────────────────────────────────────────────────────────────────────────────
#  Timestamp Mixin
# ─────────────────────────────────────────────────────────────────────────────

class TimestampMixin:
    created_at = Column(DateTime, default=datetime.utcnow, nullable=False)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False)


def new_id() -> str:
    return str(uuid.uuid4())


# ─────────────────────────────────────────────────────────────────────────────
#  Users
# ─────────────────────────────────────────────────────────────────────────────

class User(Base, TimestampMixin):
    __tablename__ = "users"

    id             = Column(String(36), primary_key=True, default=new_id)
    username       = Column(String(64), unique=True, nullable=False, index=True)
    email          = Column(String(255), unique=True, nullable=False, index=True)
    hashed_password= Column(String(255), nullable=False)
    full_name      = Column(String(128))
    is_active      = Column(Boolean, default=True)
    is_superuser   = Column(Boolean, default=False)
    role           = Column(String(32), default="analyst")  # admin | analyst | readonly

    scan_jobs = relationship("ScanJob", back_populates="created_by_user")
    alerts    = relationship("Alert",   back_populates="assigned_to_user")


# ─────────────────────────────────────────────────────────────────────────────
#  Targets & Scopes
# ─────────────────────────────────────────────────────────────────────────────

class Target(Base, TimestampMixin):
    __tablename__ = "targets"

    id          = Column(String(36), primary_key=True, default=new_id)
    name        = Column(String(128), nullable=False)
    hostname    = Column(String(255), nullable=False, index=True)
    description = Column(Text)
    status      = Column(String(32), default="active")  # active | paused | archived
    tags        = Column(JSON, default=list)

    scopes    = relationship("Scope", back_populates="target", cascade="all, delete-orphan")
    scan_jobs = relationship("ScanJob", back_populates="target")


class Scope(Base, TimestampMixin):
    __tablename__ = "scopes"

    id                     = Column(String(36), primary_key=True, default=new_id)
    target_id              = Column(String(36), ForeignKey("targets.id"), nullable=True)
    name                   = Column(String(128), nullable=False)
    description            = Column(Text)
    scope_type             = Column(String(32), default="url")  # url | domain | ip_range | cidr | host
    value                  = Column(String(512), nullable=True)
    authorization_status   = Column(String(32), default="AUTHORIZED")  # AUTHORIZED | PENDING | REVOKED
    targets                = Column(JSON, default=list)
    excluded_targets       = Column(JSON, default=list)
    active_testing         = Column(Boolean, default=True)
    destructive_testing    = Column(Boolean, default=False)
    rate_limit             = Column(String(32), default="controlled")
    authorized_by          = Column(String(255))
    authorization_document = Column(String(512))
    valid_from             = Column(DateTime)
    valid_until            = Column(DateTime)
    expires_at             = Column(DateTime, nullable=True)

    target    = relationship("Target", back_populates="scopes")
    scan_jobs = relationship("ScanJob", back_populates="scope")


# ─────────────────────────────────────────────────────────────────────────────
#  Assets
# ─────────────────────────────────────────────────────────────────────────────

class Asset(Base, TimestampMixin):
    __tablename__ = "assets"

    id          = Column(String(36), primary_key=True, default=new_id)
    name        = Column(String(255), nullable=False)
    asset_type  = Column(SAEnum(AssetType), nullable=False)
    value       = Column(String(512), nullable=False, index=True)
    description = Column(Text)
    os          = Column(String(128))
    os_version  = Column(String(64))
    criticality = Column(SAEnum(Severity), default=Severity.MEDIUM)
    tags        = Column(JSON, default=list)
    extra_data  = Column(JSON, default=dict)   # renamed from 'metadata' (reserved by SQLAlchemy)
    last_seen   = Column(DateTime)
    is_active   = Column(Boolean, default=True)

    parent_id = Column(String(36), ForeignKey("assets.id"), nullable=True)
    parent    = relationship("Asset", remote_side=[id], backref="children")

    services = relationship("Service", back_populates="asset", cascade="all, delete-orphan")
    findings = relationship("Finding", back_populates="asset")
    alerts   = relationship("Alert",   back_populates="asset")

    __table_args__ = (
        Index("ix_assets_value_type", "value", "asset_type"),
    )


class Service(Base, TimestampMixin):
    __tablename__ = "services"

    id         = Column(String(36), primary_key=True, default=new_id)
    asset_id   = Column(String(36), ForeignKey("assets.id"), nullable=False)
    port       = Column(Integer, nullable=False)
    protocol   = Column(String(16), default="tcp")
    name       = Column(String(128))
    product    = Column(String(128))
    version    = Column(String(64))
    extra_info = Column(Text)
    state      = Column(String(16), default="open")
    banner     = Column(Text)
    tls        = Column(Boolean, default=False)
    tls_info   = Column(JSON, default=dict)

    asset = relationship("Asset", back_populates="services")

    __table_args__ = (
        UniqueConstraint("asset_id", "port", "protocol", name="uq_service_port"),
    )


# ─────────────────────────────────────────────────────────────────────────────
#  Scan Jobs
# ─────────────────────────────────────────────────────────────────────────────

class ScanJob(Base, TimestampMixin):
    __tablename__ = "scan_jobs"

    id             = Column(String(36), primary_key=True, default=new_id)
    name           = Column(String(255), nullable=False)
    mode           = Column(SAEnum(ScanMode), nullable=False)
    status         = Column(SAEnum(ScanStatus), default=ScanStatus.PENDING)
    plugin         = Column(String(64), nullable=False)
    targets        = Column(JSON, default=list)
    options        = Column(JSON, default=dict)
    celery_task_id = Column(String(36))
    progress       = Column(Integer, default=0)
    error_msg      = Column(Text)
    result_file    = Column(String(512))
    raw_output     = Column(Text)
    started_at     = Column(DateTime, nullable=True)
    completed_at   = Column(DateTime, nullable=True)

    scope_id   = Column(String(36), ForeignKey("scopes.id"), nullable=True)
    target_id  = Column(String(36), ForeignKey("targets.id"), nullable=True)
    created_by = Column(String(36), ForeignKey("users.id"), nullable=True)

    scope           = relationship("Scope", back_populates="scan_jobs")
    target          = relationship("Target", back_populates="scan_jobs")
    created_by_user = relationship("User", back_populates="scan_jobs")
    findings        = relationship("Finding", back_populates="scan_job")
    events          = relationship("ScanEvent", back_populates="scan_job", cascade="all, delete-orphan")


# ─────────────────────────────────────────────────────────────────────────────
#  Endpoints & Scan Events
# ─────────────────────────────────────────────────────────────────────────────

class Endpoint(Base, TimestampMixin):
    __tablename__ = "endpoints"

    id          = Column(String(36), primary_key=True, default=new_id)
    asset_id    = Column(String(36), ForeignKey("assets.id"), nullable=True)
    target_id   = Column(String(36), ForeignKey("targets.id"), nullable=True)
    url         = Column(String(1024), nullable=False)
    path        = Column(String(512), nullable=False, index=True)
    method      = Column(String(16), default="GET")
    status_code = Column(Integer, nullable=True)
    content_type= Column(String(128), nullable=True)
    params      = Column(JSON, default=list)
    headers     = Column(JSON, default=dict)
    extra_data  = Column(JSON, default=dict)

    asset = relationship("Asset", backref="endpoints")


class ScanEvent(Base, TimestampMixin):
    __tablename__ = "scan_events"

    id          = Column(String(36), primary_key=True, default=new_id)
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=False, index=True)
    stage       = Column(String(64), nullable=False)  # RECON | PORT_SCAN | DISCOVERY | WEB_SCAN | ANALYSIS | VALIDATION | REPORT
    progress    = Column(Integer, default=0)
    message     = Column(String(512), nullable=False)
    data        = Column(JSON, default=dict)

    scan_job = relationship("ScanJob", back_populates="events")


# ─────────────────────────────────────────────────────────────────────────────
#  Findings (Universal Vulnerability Schema)
# ─────────────────────────────────────────────────────────────────────────────

class Finding(Base, TimestampMixin):
    __tablename__ = "findings"

    id                = Column(String(36), primary_key=True, default=new_id)
    title             = Column(String(512), nullable=False)
    description       = Column(Text)
    severity          = Column(SAEnum(Severity), nullable=False, index=True)
    confidence        = Column(Float, default=0.90)
    risk_score        = Column(Float, default=0.0)
    asset_value       = Column(String(512), nullable=True, index=True)
    endpoint          = Column(String(1024), nullable=True)
    port              = Column(Integer, nullable=True)
    protocol          = Column(String(16), default="http")
    cve               = Column(String(64), nullable=True)
    cwe               = Column(String(128), nullable=True)
    cvss              = Column(Float, nullable=True)
    scanner           = Column(String(64), default="nuclei")
    status            = Column(String(32), default="open")  # open | triaged | validated | confirmed | reported | fixed | false_positive
    curl_poc          = Column(Text, nullable=True)
    dedup_hash        = Column(String(64), nullable=True, index=True)
    occurrence_count  = Column(Integer, default=1)

    plugin            = Column(String(64))
    template_id       = Column(String(128))
    cve_ids           = Column(JSON, default=list)
    cvss_score        = Column(Float)
    cvss_vector       = Column(String(128))
    cwe_ids           = Column(JSON, default=list)
    mitre_techniques  = Column(JSON, default=list)
    affected_url      = Column(String(1024))
    request_raw       = Column(Text)
    response_raw      = Column(Text)
    evidence          = Column(Text)
    remediation       = Column(Text)
    references        = Column(JSON, default=list)
    tags              = Column(JSON, default=list)
    raw_data          = Column(JSON, default=dict)
    is_verified       = Column(Boolean, default=False)
    is_false_positive = Column(Boolean, default=False)
    proof_of_concept  = Column(Text)
    ai_analysis       = Column(JSON, default=dict)  # AI reasoning chain result

    asset_id    = Column(String(36), ForeignKey("assets.id"), nullable=True)
    scan_job_id = Column(String(36), ForeignKey("scan_jobs.id"), nullable=True)

    asset    = relationship("Asset",   back_populates="findings")
    scan_job = relationship("ScanJob", back_populates="findings")


# ─────────────────────────────────────────────────────────────────────────────
#  Alerts (SIEM Events)
# ─────────────────────────────────────────────────────────────────────────────

class Alert(Base, TimestampMixin):
    __tablename__ = "alerts"

    id               = Column(String(36), primary_key=True, default=new_id)
    title            = Column(String(512), nullable=False)
    description      = Column(Text)
    severity         = Column(SAEnum(Severity), nullable=False, index=True)
    status           = Column(SAEnum(AlertStatus), default=AlertStatus.OPEN, index=True)
    source           = Column(String(64))       # wazuh | zeek | suricata | custom
    source_ip        = Column(String(64))
    destination_ip   = Column(String(64))
    source_port      = Column(Integer)
    destination_port = Column(Integer)
    protocol         = Column(String(16))
    event_type       = Column(String(128))
    mitre_techniques = Column(JSON, default=list)
    raw_log          = Column(Text)
    evidence         = Column(JSON, default=list)
    is_purple_validated = Column(Boolean, default=False)
    detection_gap    = Column(Boolean, default=False)
    first_seen       = Column(DateTime, default=datetime.utcnow)
    last_seen        = Column(DateTime, default=datetime.utcnow)
    resolved_at      = Column(DateTime, nullable=True)
    count            = Column(Integer, default=1)

    asset_id       = Column(String(36), ForeignKey("assets.id"),  nullable=True)
    assigned_to    = Column(String(36), ForeignKey("users.id"),   nullable=True)

    asset            = relationship("Asset", back_populates="alerts")
    assigned_to_user = relationship("User",  back_populates="alerts")


# ─────────────────────────────────────────────────────────────────────────────
#  Malware Samples
# ─────────────────────────────────────────────────────────────────────────────

class MalwareSample(Base, TimestampMixin):
    __tablename__ = "malware_samples"

    id               = Column(String(36), primary_key=True, default=new_id)
    filename         = Column(String(512), nullable=False)
    sha256           = Column(String(64), unique=True, index=True)
    md5              = Column(String(32), index=True)
    sha1             = Column(String(40))
    file_size        = Column(Integer)
    file_type        = Column(String(128))
    is_malicious     = Column(Boolean)
    malware_family   = Column(String(128))
    confidence_score = Column(Float)
    yara_matches     = Column(JSON, default=list)
    strings_found    = Column(JSON, default=list)
    imports          = Column(JSON, default=list)
    exports          = Column(JSON, default=list)
    sections         = Column(JSON, default=list)
    entropy          = Column(Float)
    sandbox_status   = Column(String(32), default="pending")
    sandbox_report   = Column(JSON, default=dict)
    iocs             = Column(JSON, default=list)
    file_path        = Column(String(1024))
    raw_analysis     = Column(JSON, default=dict)
    static_analysis  = Column(JSON, default=dict)  # Full static analysis result
    mitre_techniques = Column(JSON, default=list)  # Mapped ATT&CK techniques
    ai_verdict       = Column(JSON, default=dict)  # AI-generated verdict


# ─────────────────────────────────────────────────────────────────────────────
#  IOCs
# ─────────────────────────────────────────────────────────────────────────────

class IOC(Base, TimestampMixin):
    __tablename__ = "iocs"

    id          = Column(String(36), primary_key=True, default=new_id)
    type        = Column(String(32), nullable=False)  # ip | domain | hash | url | email
    value       = Column(String(512), nullable=False, index=True)
    threat_type = Column(String(64))
    confidence  = Column(Float)
    source      = Column(String(128))
    tags        = Column(JSON, default=list)
    first_seen  = Column(DateTime)
    last_seen   = Column(DateTime)
    is_active   = Column(Boolean, default=True)
    extra_data  = Column(JSON, default=dict)


# ─────────────────────────────────────────────────────────────────────────────
#  MITRE ATT&CK Techniques
# ─────────────────────────────────────────────────────────────────────────────

class MitreTechnique(Base):
    __tablename__ = "mitre_techniques"

    id          = Column(String(16), primary_key=True)   # T1059.001
    name        = Column(String(256), nullable=False)
    tactic      = Column(String(128))
    description = Column(Text)
    url         = Column(String(512))
    platforms   = Column(JSON, default=list)
    data_sources= Column(JSON, default=list)
    detection   = Column(Text)
    mitigation  = Column(Text)


# ─────────────────────────────────────────────────────────────────────────────
#  Reports
# ─────────────────────────────────────────────────────────────────────────────

class Report(Base, TimestampMixin):
    __tablename__ = "reports"

    id          = Column(String(36), primary_key=True, default=new_id)
    title       = Column(String(512), nullable=False)
    report_type = Column(String(32))   # executive | technical | soc
    content     = Column(JSON, default=dict)
    file_path   = Column(String(1024))
    created_by  = Column(String(36), ForeignKey("users.id"), nullable=True)
