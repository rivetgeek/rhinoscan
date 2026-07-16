from datetime import datetime
from sqlalchemy import (
    Column, String, Integer, Float, DateTime, Text, Boolean, ForeignKey, JSON
)
from sqlalchemy.orm import relationship, DeclarativeBase


class Base(DeclarativeBase):
    pass


# ── RhinoScan native baseline assessment ──────────────────────────────────────
# These two tables back the PRD's profile-driven boto3 check battery. They are
# independent of the Prowler/TruffleHog scan_jobs tables above (kept as future
# integrations per the PRD).


class Run(Base):
    __tablename__ = "runs"

    id = Column(String, primary_key=True)  # UUID
    profile = Column(String, nullable=False)
    started_at = Column(String, nullable=False)   # iso8601
    completed_at = Column(String, nullable=True)
    finding_count = Column(Integer, nullable=True)
    status = Column(String, default="running")    # running | complete | failed


class Finding(Base):
    __tablename__ = "findings"

    id = Column(String, primary_key=True)  # deterministic hash of profile+source+resource
    profile = Column(String, nullable=False)
    account_id = Column(String, nullable=False)
    timestamp = Column(String, nullable=False)     # iso8601
    category = Column(String, nullable=False)      # Identity | S3 | CloudTrail | ...
    severity = Column(String, nullable=False)      # Critical | High | Medium | Low | Informational
    title = Column(Text, nullable=False)
    resource = Column(Text, nullable=False)
    description = Column(Text, nullable=False)
    remediation = Column(Text, nullable=False)
    source = Column(String, nullable=False)        # check name e.g. s3_account_block_public_access
    origin = Column(String, nullable=False, default="Baseline")  # Baseline | Prowler | GitHub
    api = Column(String, nullable=True)            # AWS API call(s) backing the finding, for manual verification
    raw = Column(JSON, nullable=True)
    run_id = Column(String, nullable=False)


class ScanJob(Base):
    __tablename__ = "scan_jobs"

    id = Column(String, primary_key=True)  # UUID
    status = Column(String, default="pending")  # pending | running | complete | failed
    profile = Column(String, nullable=True)  # ~/.aws/config profile the scan targets
    role_arn = Column(String, nullable=True)  # legacy; superseded by profile
    github_org = Column(String, nullable=True)
    github_installation_id = Column(Integer, nullable=True)
    aws_region = Column(String, default="us-east-1")
    created_at = Column(DateTime, default=datetime.utcnow)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    prowler_status = Column(String, default="pending")   # pending | running | complete | failed | skipped
    prowler_github_status = Column(String, default="pending")  # Prowler GitHub provider
    truffle_status = Column(String, default="pending")
    scorecard_status = Column(String, default="pending")  # OpenSSF Scorecard
    error_message = Column(Text, nullable=True)

    prowler_findings = relationship("ProwlerFinding", back_populates="job", cascade="all, delete-orphan")
    truffle_findings = relationship("TruffleFinding", back_populates="job", cascade="all, delete-orphan")
    correlated_alerts = relationship("CorrelatedAlert", back_populates="job", cascade="all, delete-orphan")
    scorecard_findings = relationship("ScorecardFinding", back_populates="job", cascade="all, delete-orphan")


class ProwlerFinding(Base):
    __tablename__ = "prowler_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    provider = Column(String, nullable=False, default="aws")  # aws | github
    check_id = Column(String, nullable=False)
    check_title = Column(Text, nullable=False)
    severity = Column(String, nullable=False)   # critical | high | medium | low | informational
    status = Column(String, nullable=False)      # FAIL | PASS | MANUAL | MUTED
    service = Column(String, nullable=False)
    region = Column(String, nullable=True)
    resource_arn = Column(Text, nullable=True)
    resource_name = Column(Text, nullable=True)
    status_extended = Column(Text, nullable=True)
    raw = Column(JSON, nullable=True)

    job = relationship("ScanJob", back_populates="prowler_findings")


class TruffleFinding(Base):
    __tablename__ = "truffle_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    repo = Column(String, nullable=False)
    commit = Column(String, nullable=True)
    author = Column(String, nullable=True)
    date = Column(String, nullable=True)
    file_path = Column(Text, nullable=True)
    line = Column(Integer, nullable=True)
    detector_name = Column(String, nullable=True)   # e.g. "AWS"
    key_id = Column(String, nullable=True)           # extracted AKIA...
    verified = Column(Boolean, default=False)
    raw = Column(JSON, nullable=True)

    job = relationship("ScanJob", back_populates="truffle_findings")
    correlated_alert = relationship("CorrelatedAlert", back_populates="truffle_finding", uselist=False)


class IAMLookup(Base):
    __tablename__ = "iam_lookups"

    id = Column(Integer, primary_key=True, autoincrement=True)
    truffle_finding_id = Column(Integer, ForeignKey("truffle_findings.id"), nullable=False, unique=True)
    key_active = Column(Boolean, nullable=True)
    last_used_date = Column(String, nullable=True)
    last_used_service = Column(String, nullable=True)
    last_used_region = Column(String, nullable=True)
    iam_entity_type = Column(String, nullable=True)   # user | role
    iam_entity_name = Column(String, nullable=True)
    iam_entity_arn = Column(String, nullable=True)
    attached_policies = Column(JSON, nullable=True)    # list of policy ARNs
    inline_policy_names = Column(JSON, nullable=True)  # list of inline policy names
    lookup_error = Column(Text, nullable=True)

    truffle_finding = relationship("TruffleFinding")


class CorrelatedAlert(Base):
    __tablename__ = "correlated_alerts"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    truffle_finding_id = Column(Integer, ForeignKey("truffle_findings.id"), nullable=False, unique=True)
    severity = Column(String, default="CRITICAL")
    title = Column(Text, nullable=False)
    narrative = Column(Text, nullable=True)
    key_id = Column(String, nullable=True)
    key_active = Column(Boolean, nullable=True)
    iam_entity_name = Column(String, nullable=True)
    iam_entity_arn = Column(String, nullable=True)
    attached_policies = Column(JSON, nullable=True)
    repo = Column(String, nullable=True)
    commit = Column(String, nullable=True)
    author = Column(String, nullable=True)
    exposed_date = Column(String, nullable=True)
    file_path = Column(Text, nullable=True)
    created_at = Column(DateTime, default=datetime.utcnow)

    job = relationship("ScanJob", back_populates="correlated_alerts")
    truffle_finding = relationship("TruffleFinding", back_populates="correlated_alert")


class ScorecardFinding(Base):
    __tablename__ = "scorecard_findings"

    id = Column(Integer, primary_key=True, autoincrement=True)
    job_id = Column(String, ForeignKey("scan_jobs.id"), nullable=False)
    repo = Column(String, nullable=False)             # github.com/org/repo
    repo_score = Column(Float, nullable=True)          # overall repo score, repeated per row
    check_name = Column(String, nullable=False)        # e.g. Branch-Protection
    check_score = Column(Integer, nullable=True)       # 0-10, or -1 for inconclusive
    reason = Column(Text, nullable=True)
    documentation_url = Column(Text, nullable=True)
    raw = Column(JSON, nullable=True)                  # the per-check object

    job = relationship("ScanJob", back_populates="scorecard_findings")
