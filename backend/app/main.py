import logging
import threading
import uuid
from datetime import datetime
from typing import List, Optional

from fastapi import Depends, FastAPI, HTTPException, Query
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse
from pydantic import BaseModel
from sqlalchemy import case, func, or_
from sqlalchemy.orm import Session

from app.core.config import settings
from app.core.database import get_db, init_db
from app.models.db import (
    CorrelatedAlert,
    Finding,
    ProwlerFinding,
    Run,
    ScanJob,
    ScorecardFinding,
    TruffleFinding,
)
from app.services import scanner
from app.services.aws_profiles import list_profiles
from app.services.checks.base import SEVERITY_ORDER
from app.services.correlation import run_correlation
from app.services.github_auth import resolve_gh_token
from app.services.prowler import run_prowler, run_prowler_github
from app.services.report import generate_report
from app.services.scorecard import run_scorecard
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
    profile: str  # ~/.aws/config profile the scan targets
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
    available = set(list_profiles())
    if req.profile not in available:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown profile: {req.profile}",
        )

    job_id = str(uuid.uuid4())
    gh_pending = "pending" if req.github_org else "skipped"
    job = ScanJob(
        id=job_id,
        status="running",
        profile=req.profile,
        aws_region=req.aws_region,
        github_org=req.github_org,
        prowler_status="pending",
        prowler_github_status=gh_pending,
        truffle_status=gh_pending,
        scorecard_status=gh_pending,
    )
    db.add(job)
    db.commit()

    # Run scans in background thread so we return immediately
    thread = threading.Thread(
        target=_run_scan_pipeline,
        args=(job_id, req.profile, req.aws_region, req.github_org, req.github_token),
        daemon=True,
    )
    thread.start()

    return ScanResponse(job_id=job_id, status="running", created_at=job.created_at)


def _run_scan_pipeline(
    job_id: str,
    profile: str,
    region: str,
    github_org: Optional[str],
    github_token: Optional[str],
):
    """Runs the AWS + GitHub scanners, then correlation. Own DB session.

    The GitHub-side scanners (Prowler GitHub provider, TruffleHog secrets,
    OpenSSF Scorecard) authenticate with the operator's gh-login PAT, resolved
    server-side via ``github_auth``. A per-request token still takes precedence
    if one was supplied. With an org but no resolvable token, the GitHub
    scanners are cleanly skipped.
    """
    from app.core.database import SessionLocal

    db = SessionLocal()
    any_ok = False
    truffle_ok = False

    try:
        run_prowler(job_id, profile, region, db)
        any_ok = True
    except Exception:
        pass

    token = github_token or resolve_gh_token()

    if github_org and token:
        try:
            run_prowler_github(job_id, github_org, token, db)
            any_ok = True
        except Exception:
            pass

        try:
            run_trufflehog(job_id, github_org, token, db)
            truffle_ok = True
            any_ok = True
        except Exception:
            pass

        try:
            run_scorecard(job_id, github_org, token, db)
            any_ok = True
        except Exception:
            pass
    elif github_org and not token:
        # No PAT available — mark the GitHub scanners skipped rather than failed.
        job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
        job.prowler_github_status = "skipped"
        job.truffle_status = "skipped"
        job.scorecard_status = "skipped"
        db.commit()

    if truffle_ok:
        try:
            run_correlation(job_id, profile, db)
        except Exception:
            pass

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.status = "complete" if any_ok else "failed"
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
            "profile": j.profile,
            "role_arn": j.role_arn,
            "github_org": j.github_org,
            "aws_region": j.aws_region,
            "prowler_status": j.prowler_status,
            "prowler_github_status": j.prowler_github_status,
            "truffle_status": j.truffle_status,
            "scorecard_status": j.scorecard_status,
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

    # Severity cards count FAILs only — a passing critical-severity check is
    # not a critical finding. Totals still report every check evaluated.
    prowler_counts = (
        db.query(ProwlerFinding.severity, func.count(ProwlerFinding.id))
        .filter(
            ProwlerFinding.job_id == job_id,
            ProwlerFinding.provider == "aws",
            ProwlerFinding.status == "FAIL",
        )
        .group_by(ProwlerFinding.severity)
        .all()
    )
    prowler_total = (
        db.query(func.count(ProwlerFinding.id))
        .filter(ProwlerFinding.job_id == job_id, ProwlerFinding.provider == "aws")
        .scalar()
    )
    prowler_github_counts = (
        db.query(ProwlerFinding.severity, func.count(ProwlerFinding.id))
        .filter(
            ProwlerFinding.job_id == job_id,
            ProwlerFinding.provider == "github",
            ProwlerFinding.status == "FAIL",
        )
        .group_by(ProwlerFinding.severity)
        .all()
    )
    prowler_github_total = (
        db.query(func.count(ProwlerFinding.id))
        .filter(ProwlerFinding.job_id == job_id, ProwlerFinding.provider == "github")
        .scalar()
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
    # Scorecard: one repo score (repeated across that repo's check rows), so
    # average distinct repo scores for the headline number.
    repo_scores = (
        db.query(ScorecardFinding.repo, func.max(ScorecardFinding.repo_score))
        .filter(ScorecardFinding.job_id == job_id)
        .group_by(ScorecardFinding.repo)
        .all()
    )
    scored = [s for _, s in repo_scores if s is not None]
    scorecard_summary = {
        "repos_scored": len(repo_scores),
        "avg_score": round(sum(scored) / len(scored), 1) if scored else None,
    }

    return {
        "job_id": job.id,
        "status": job.status,
        "profile": job.profile,
        "role_arn": job.role_arn,
        "github_org": job.github_org,
        "aws_region": job.aws_region,
        "prowler_status": job.prowler_status,
        "prowler_github_status": job.prowler_github_status,
        "truffle_status": job.truffle_status,
        "scorecard_status": job.scorecard_status,
        "error_message": job.error_message,
        "created_at": job.created_at,
        "updated_at": job.updated_at,
        "summary": {
            "prowler_by_severity": dict(prowler_counts),
            "prowler_total_checks": prowler_total,
            "prowler_github_by_severity": dict(prowler_github_counts),
            "prowler_github_total_checks": prowler_github_total,
            "truffle_findings": truffle_count,
            "correlated_alerts": alert_count,
            "scorecard": scorecard_summary,
        },
    }


# ── Findings endpoints ────────────────────────────────────────────────────────


@app.get("/api/scans/{job_id}/prowler")
def get_prowler_findings(
    job_id: str,
    provider: str = Query("aws"),
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
    q = db.query(ProwlerFinding).filter(
        ProwlerFinding.job_id == job_id,
        ProwlerFinding.provider == provider,
    )

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

    total = q.count()

    # Sorting. Severity is ranked (critical→informational), not alphabetical, so
    # it needs a CASE rather than ordering the raw string column. For severity,
    # "desc" means most-severe-first (critical on top) = ascending rank.
    if sort_by == "severity":
        sev_rank = case(
            (ProwlerFinding.severity == "critical", 0),
            (ProwlerFinding.severity == "high", 1),
            (ProwlerFinding.severity == "medium", 2),
            (ProwlerFinding.severity == "low", 3),
            (ProwlerFinding.severity == "informational", 4),
            else_=99,
        )
        q = q.order_by(sev_rank.asc() if sort_dir == "desc" else sev_rank.desc())
    else:
        sort_col = {
            "service": ProwlerFinding.service,
            "status": ProwlerFinding.status,
            "region": ProwlerFinding.region,
            "check_title": ProwlerFinding.check_title,
        }.get(sort_by, ProwlerFinding.check_title)
        q = q.order_by(sort_col.asc() if sort_dir == "asc" else sort_col.desc())

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


@app.get("/api/scans/{job_id}/prowler/{finding_id}")
def get_prowler_finding(job_id: str, finding_id: int, db: Session = Depends(get_db)):
    """Return a single Prowler finding including the full raw Prowler/OCSF result."""
    f = (
        db.query(ProwlerFinding)
        .filter(ProwlerFinding.job_id == job_id, ProwlerFinding.id == finding_id)
        .first()
    )
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return {
        "id": f.id,
        "provider": f.provider,
        "check_id": f.check_id,
        "check_title": f.check_title,
        "severity": f.severity,
        "status": f.status,
        "service": f.service,
        "region": f.region,
        "resource_name": f.resource_name,
        "resource_arn": f.resource_arn,
        "status_extended": f.status_extended,
        "raw": f.raw,
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


@app.get("/api/scans/{job_id}/scorecard")
def get_scorecard_findings(job_id: str, db: Session = Depends(get_db)):
    """Return OpenSSF Scorecard results grouped by repo, weakest scores first."""
    rows = (
        db.query(ScorecardFinding)
        .filter(ScorecardFinding.job_id == job_id)
        .all()
    )
    repos: dict[str, dict] = {}
    for r in rows:
        entry = repos.setdefault(
            r.repo, {"repo": r.repo, "repo_score": r.repo_score, "checks": []}
        )
        entry["checks"].append({
            "check_name": r.check_name,
            "check_score": r.check_score,
            "reason": r.reason,
            "documentation_url": r.documentation_url,
        })

    result = list(repos.values())
    # Weakest repos first; repos with no overall score sort last.
    result.sort(key=lambda e: (e["repo_score"] is None, e["repo_score"] if e["repo_score"] is not None else 0))
    return {"total": len(result), "repos": result}


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
    prowler = db.query(ProwlerFinding).filter(
        ProwlerFinding.job_id == job_id, ProwlerFinding.provider == "aws"
    ).all()
    prowler_github = db.query(ProwlerFinding).filter(
        ProwlerFinding.job_id == job_id, ProwlerFinding.provider == "github"
    ).all()
    truffle = db.query(TruffleFinding).filter(TruffleFinding.job_id == job_id).all()
    scorecard = db.query(ScorecardFinding).filter(ScorecardFinding.job_id == job_id).all()
    alerts = db.query(CorrelatedAlert).filter(CorrelatedAlert.job_id == job_id).all()

    return {
        "job_id": job_id,
        "prowler": [f.raw for f in prowler],
        "prowler_github": [f.raw for f in prowler_github],
        "truffle": [f.raw for f in truffle],
        "scorecard": [f.raw for f in scorecard],
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


# ── RhinoScan baseline assessment (profile-driven, native boto3) ──────────────


class BaselineScanRequest(BaseModel):
    profiles: List[str]


@app.get("/profiles")
def get_profiles():
    """List scannable AWS profiles from ~/.aws/config (excludes operator profiles)."""
    try:
        return {"profiles": list_profiles()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read AWS config: {e}")


@app.post("/scan")
def trigger_scan(req: BaselineScanRequest):
    """Trigger a baseline scan against one or more profiles. Returns run ids."""
    if not req.profiles:
        raise HTTPException(status_code=400, detail="At least one profile is required.")

    available = set(list_profiles())
    unknown = [p for p in req.profiles if p not in available]
    if unknown:
        raise HTTPException(
            status_code=400,
            detail=f"Unknown profile(s): {', '.join(unknown)}",
        )

    run_ids = scanner.start_scan(req.profiles)
    return {"run_ids": run_ids, "status": "running"}


@app.get("/scan/{run_id}")
def scan_status(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return {
        "run_id": run.id,
        "profile": run.profile,
        "status": run.status,
        "started_at": run.started_at,
        "completed_at": run.completed_at,
        "finding_count": run.finding_count,
    }


def _finding_dict(f: Finding) -> dict:
    return {
        "id": f.id,
        "profile": f.profile,
        "account_id": f.account_id,
        "timestamp": f.timestamp,
        "category": f.category,
        "severity": f.severity,
        "title": f.title,
        "resource": f.resource,
        "description": f.description,
        "remediation": f.remediation,
        "source": f.source,
        "origin": f.origin,
        "api": f.api,
        "raw": f.raw,
    }


@app.get("/findings")
def query_findings(
    profile: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if profile:
        q = q.filter(Finding.profile == profile)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category == category)
    if run_id:
        q = q.filter(Finding.run_id == run_id)

    findings = q.all()
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    return {"total": len(findings), "findings": [_finding_dict(f) for f in findings]}


@app.get("/findings/summary")
def findings_summary(
    profile: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if profile:
        q = q.filter(Finding.profile == profile)

    by_severity = dict(
        q.with_entities(Finding.severity, func.count(Finding.id))
        .group_by(Finding.severity)
        .all()
    )
    by_category = dict(
        q.with_entities(Finding.category, func.count(Finding.id))
        .group_by(Finding.category)
        .all()
    )

    runs_q = db.query(Run)
    if profile:
        runs_q = runs_q.filter(Run.profile == profile)
    runs = runs_q.all()
    accounts_scanned = len({r.profile for r in runs if r.status == "complete"})
    last_scan = max((r.completed_at or r.started_at for r in runs), default=None)

    return {
        "by_severity": by_severity,
        "by_category": by_category,
        "accounts_scanned": accounts_scanned,
        "last_scan": last_scan,
        "total": sum(by_severity.values()),
    }


@app.get("/report/{run_id}", response_class=PlainTextResponse)
def report(run_id: str, db: Session = Depends(get_db)):
    md = generate_report(db, run_id)
    if md is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return PlainTextResponse(
        md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="rhinoscan-{run_id}.md"'},
    )


# ── Health ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    return {"status": "ok"}
