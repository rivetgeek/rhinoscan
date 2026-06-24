import logging
import threading
import uuid
from datetime import datetime
from typing import Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from sqlalchemy import func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db, init_db
from app.models.db import (
    CorrelatedAlert,
    ProwlerFinding,
    ScanJob,
    TruffleFinding,
)
from app.services.correlation import run_correlation
from app.services.prowler import run_prowler
from app.services.truffle import run_trufflehog

app = FastAPI(title="Gray Rhino Security Scanner", version="1.0.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
def on_startup():
    init_db()
    if not settings.HOST_DATA_DIR.strip():
        logging.warning(
            "HOST_DATA_DIR is not set — scan containers may fail to write output. "
            "Set it to the absolute host path of ./data in your .env file."
        )


# ── Schemas ──────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    role_arn: str
    aws_region: str = "us-east-1"
    github_org: Optional[str] = None
    github_token: Optional[str] = None  # installation token from OAuth flow


class ScanResponse(BaseModel):
    job_id: str
    status: str
    created_at: datetime


# ── Scan endpoints ────────────────────────────────────────────────────────────


@app.post("/api/scans", response_model=ScanResponse)
def create_scan(req: ScanRequest, db: Session = Depends(get_db)):
    job_id = str(uuid.uuid4())
    job = ScanJob(
        id=job_id,
        status="running",
        role_arn=req.role_arn,
        aws_region=req.aws_region,
        github_org=req.github_org,
        prowler_status="pending",
        truffle_status="pending" if req.github_org else "skipped",
    )
    db.add(job)
    db.commit()

    # Run scans in background thread so we return immediately
    thread = threading.Thread(
        target=_run_scan_pipeline,
        args=(job_id, req.role_arn, req.aws_region, req.github_org, req.github_token),
        daemon=True,
    )
    thread.start()

    return ScanResponse(job_id=job_id, status="running", created_at=job.created_at)


def _run_scan_pipeline(
    job_id: str,
    role_arn: str,
    region: str,
    github_org: Optional[str],
    github_token: Optional[str],
):
    """Runs both scans, then correlation. Each gets its own DB session."""
    from app.core.database import SessionLocal

    db = SessionLocal()
    prowler_ok = False
    truffle_ok = False

    try:
        run_prowler(job_id, role_arn, region, db)
        prowler_ok = True
    except Exception:
        pass

    if github_org and github_token:
        try:
            run_trufflehog(job_id, github_org, github_token, db)
            truffle_ok = True
        except Exception:
            pass

    if truffle_ok:
        try:
            run_correlation(job_id, role_arn, db)
        except Exception:
            pass

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.status = "complete" if (prowler_ok or truffle_ok) else "failed"
    job.updated_at = datetime.utcnow()
    db.commit()
    db.close()


@app.get("/api/scans")
def list_scans(db: Session = Depends(get_db)):
    jobs = db.query(ScanJob).order_by(ScanJob.created_at.desc()).all()
    return [
        {
            "job_id": j.id,
            "status": j.status,
            "role_arn": j.role_arn,
            "github_org": j.github_org,
            "aws_region": j.aws_region,
            "prowler_status": j.prowler_status,
            "truffle_status": j.truffle_status,
            "created_at": j.created_at,
            "updated_at": j.updated_at,
        }
        for j in jobs
    ]


@app.get("/api/scans/{job_id}")
def get_scan(job_id: str, db: Session = Depends(get_db)):
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if not job:
        raise HTTPException(status_code=404, detail="Scan not found")

    prowler_counts = (
        db.query(ProwlerFinding.severity, func.count(ProwlerFinding.id))
        .filter(ProwlerFinding.job_id == job_id)
        .group_by(ProwlerFinding.severity)
        .all()
    )
    truffle_count = (
        db.query(func.count(TruffleFinding.id))
        .filter(TruffleFinding.job_id == job_id)
        .scalar()
    )
    alert_count = (
        db.query(func.count(CorrelatedAlert.id))
        .filter(CorrelatedAlert.job_id == job_id)
        .scalar()
    )

    return {
        "job_id": job.id,
        "status": job.status,
        "role_arn": job.role_arn,
        "github_org": job.github_org,
        "aws_region": job.aws_region,
        "prowler_status": job.prowler_status,
        "truffle_status": job.truffle_status,
        "error_message": job.error_message,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "summary": {
            "prowler_by_severity": dict(prowler_counts),
            "truffle_findings": truffle_count,
            "correlated_alerts": alert_count,
        },
    }


# ── Findings endpoints ────────────────────────────────────────────────────────


@app.get("/api/scans/{job_id}/prowler")
def get_prowler_findings(
    job_id: str,
    severity: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    service: Optional[str] = Query(None),
    search: Optional[str] = Query(None),
    sort_by: str = Query("severity"),
    sort_dir: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(ProwlerFinding).filter(ProwlerFinding.job_id == job_id)

    if severity:
        q = q.filter(ProwlerFinding.severity == severity.lower())
    if status:
        q = q.filter(ProwlerFinding.status == status.upper())
    if service:
        q = q.filter(ProwlerFinding.service == service)
    if search:
        term = f"%{search}%"
        q = q.filter(
            or_(
                ProwlerFinding.check_title.ilike(term),
                ProwlerFinding.resource_name.ilike(term),
                ProwlerFinding.resource_arn.ilike(term),
                ProwlerFinding.status_extended.ilike(term),
            )
        )

    SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "informational": 4}
    total = q.count()

    # Sorting
    sort_col = {
        "severity": ProwlerFinding.severity,
        "service": ProwlerFinding.service,
        "status": ProwlerFinding.status,
        "region": ProwlerFinding.region,
        "check_title": ProwlerFinding.check_title,
    }.get(sort_by, ProwlerFinding.severity)

    if sort_dir == "asc":
        q = q.order_by(sort_col.asc())
    else:
        q = q.order_by(sort_col.desc())

    findings = q.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": [
            {
                "id": f.id,
                "check_id": f.check_id,
                "check_title": f.check_title,
                "severity": f.severity,
                "status": f.status,
                "service": f.service,
                "region": f.region,
                "resource_name": f.resource_name,
                "resource_arn": f.resource_arn,
                "status_extended": f.status_extended,
            }
            for f in findings
        ],
    }


@app.get("/api/scans/{job_id}/truffle")
def get_truffle_findings(
    job_id: str,
    search: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    verified: Optional[bool] = Query(None),
    sort_by: str = Query("date"),
    sort_dir: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(TruffleFinding).filter(TruffleFinding.job_id == job_id)

    if repo:
        q = q.filter(TruffleFinding.repo == repo)
    if verified is not None:
        q = q.filter(TruffleFinding.verified == verified)
    if search:
        term = f"%{search}%"
        q = q.filter(
            or_(
                TruffleFinding.repo.ilike(term),
                TruffleFinding.author.ilike(term),
                TruffleFinding.file_path.ilike(term),
                TruffleFinding.key_id.ilike(term),
            )
        )

    total = q.count()

    sort_col = {
        "date": TruffleFinding.date,
        "repo": TruffleFinding.repo,
        "author": TruffleFinding.author,
    }.get(sort_by, TruffleFinding.date)

    q = q.order_by(sort_col.asc() if sort_dir == "asc" else sort_col.desc())
    findings = q.offset((page - 1) * page_size).limit(page_size).all()

    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": [
            {
                "id": f.id,
                "repo": f.repo,
                "commit": f.commit,
                "author": f.author,
                "date": f.date,
                "file_path": f.file_path,
                "line": f.line,
                "detector_name": f.detector_name,
                "key_id": f.key_id,
                "verified": f.verified,
            }
            for f in findings
        ],
    }


@app.get("/api/scans/{job_id}/alerts")
def get_correlated_alerts(
    job_id: str,
    db: Session = Depends(get_db),
):
    alerts = (
        db.query(CorrelatedAlert)
        .filter(CorrelatedAlert.job_id == job_id)
        .order_by(CorrelatedAlert.created_at.desc())
        .all()
    )
    return [
        {
            "id": a.id,
            "severity": a.severity,
            "title": a.title,
            "narrative": a.narrative,
            "key_id": a.key_id,
            "key_active": a.key_active,
            "iam_entity_name": a.iam_entity_name,
            "iam_entity_arn": a.iam_entity_arn,
            "attached_policies": a.attached_policies,
            "repo": a.repo,
            "commit": a.commit,
            "author": a.author,
            "exposed_date": a.exposed_date,
            "file_path": a.file_path,
            "created_at": a.created_at,
        }
        for a in alerts
    ]


@app.get("/api/scans/{job_id}/findings/raw")
def get_raw_findings(job_id: str, db: Session = Depends(get_db)):
    """Return all raw JSON for export."""
    prowler = db.query(ProwlerFinding).filter(ProwlerFinding.job_id == job_id).all()
    truffle = db.query(TruffleFinding).filter(TruffleFinding.job_id == job_id).all()
    alerts = db.query(CorrelatedAlert).filter(CorrelatedAlert.job_id == job_id).all()

    return {
        "job_id": job_id,
        "prowler": [f.raw for f in prowler],
        "truffle": [f.raw for f in truffle],
        "correlated_alerts": [
            {
                "id": a.id,
                "severity": a.severity,
                "title": a.title,
                "narrative": a.narrative,
                "key_id": a.key_id,
                "key_active": a.key_active,
                "iam_entity_name": a.iam_entity_name,
                "attached_policies": a.attached_policies,
                "repo": a.repo,
                "file_path": a.file_path,
            }
            for a in alerts
        ],
    }


# ── Health ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    return {"status": "ok"}
