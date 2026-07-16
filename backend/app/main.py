import logging
from typing import List, Optional

from fastapi import APIRouter, Depends, FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import PlainTextResponse, StreamingResponse
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
    ScorecardFinding,
    TruffleFinding,
)
from app.services import runner
from app.services.adapters import ADAPTERS, engines_for
from app.services.aws_profiles import list_profiles
from app.services.checks.base import SEVERITY_ORDER
from app.services.export import export_ndjson
from app.services.report import generate_report

app = FastAPI(title="RhinoScan — Gray Rhino Security", version="2.0.0")

# The frontend is served same-origin through nginx; CORS only matters for
# direct dev access to :8000.
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:3000", "http://127.0.0.1:3000"],
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
    if not settings.RHINOSCAN_API_TOKEN:
        logging.warning(
            "RHINOSCAN_API_TOKEN is not set — the API is unauthenticated. "
            "Fine for localhost-only use; set a token before exposing it."
        )


def require_token(request: Request):
    """Static bearer auth for /api/v1. Disabled when no token is configured
    (localhost-only development)."""
    token = settings.RHINOSCAN_API_TOKEN
    if not token:
        return
    auth = request.headers.get("Authorization", "")
    if auth != f"Bearer {token}":
        raise HTTPException(status_code=401, detail="Invalid or missing API token")


v1 = APIRouter(prefix="/api/v1", dependencies=[Depends(require_token)])


# ── Schemas ──────────────────────────────────────────────────────────────────


class ScanRequest(BaseModel):
    targets: List[str]                    # AWS profiles and/or "github:<org>"
    engines: Optional[List[str]] = None   # default: all applicable per target


# ── Targets + engines ─────────────────────────────────────────────────────────


@v1.get("/profiles")
def get_profiles():
    """List scannable AWS profiles from ~/.aws/config (excludes operator profiles)."""
    try:
        return {"profiles": list_profiles()}
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Could not read AWS config: {e}")


@v1.get("/engines")
def get_engines():
    """List available scanner adapters."""
    return {
        "engines": [
            {
                "name": a.engine,
                "label": a.label,
                "origin": a.origin,
                "target_type": a.target_type,
            }
            for a in ADAPTERS.values()
        ]
    }


# ── Scans ─────────────────────────────────────────────────────────────────────


@v1.post("/scans")
def create_scans(req: ScanRequest):
    """Trigger scans: one run per target, engines filtered to what applies."""
    if not req.targets:
        raise HTTPException(status_code=400, detail="At least one target is required.")

    available = set(list_profiles())
    for t in req.targets:
        if t.startswith("github:"):
            if not t.removeprefix("github:").strip():
                raise HTTPException(status_code=400, detail=f"Invalid GitHub target: {t}")
        elif t not in available:
            raise HTTPException(status_code=400, detail=f"Unknown profile: {t}")

    if req.engines:
        unknown = [e for e in req.engines if e not in ADAPTERS]
        if unknown:
            raise HTTPException(
                status_code=400, detail=f"Unknown engine(s): {', '.join(unknown)}"
            )
        for t in req.targets:
            if not set(req.engines) & set(engines_for(t)):
                raise HTTPException(
                    status_code=400,
                    detail=f"None of the requested engines apply to target: {t}",
                )

    run_ids = runner.start_scans(req.targets, req.engines)
    return {"run_ids": run_ids, "status": "running"}


def _run_dict(r: Run) -> dict:
    return {
        "run_id": r.id,
        "target": r.target,
        "engines": r.engines or [],
        "engine_status": r.engine_status or {},
        "errors": r.errors,
        "status": r.status,
        "started_at": r.started_at,
        "completed_at": r.completed_at,
        "finding_count": r.finding_count,
    }


@v1.get("/scans")
def list_runs(
    limit: int = Query(50, ge=1, le=500),
    db: Session = Depends(get_db),
):
    runs = db.query(Run).order_by(Run.started_at.desc()).limit(limit).all()
    return {"runs": [_run_dict(r) for r in runs]}


@v1.get("/scans/{run_id}")
def get_run(run_id: str, db: Session = Depends(get_db)):
    run = db.query(Run).filter(Run.id == run_id).first()
    if not run:
        raise HTTPException(status_code=404, detail="Run not found")
    return _run_dict(run)


# ── Engine raw-detail views ───────────────────────────────────────────────────


@v1.get("/scans/{run_id}/prowler")
def get_prowler_findings(
    run_id: str,
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
        ProwlerFinding.run_id == run_id,
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


@v1.get("/scans/{run_id}/prowler/{finding_id}")
def get_prowler_finding(run_id: str, finding_id: int, db: Session = Depends(get_db)):
    """Return a single Prowler finding including the full raw Prowler/OCSF result."""
    f = (
        db.query(ProwlerFinding)
        .filter(ProwlerFinding.run_id == run_id, ProwlerFinding.id == finding_id)
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


@v1.get("/scans/{run_id}/secrets")
def get_truffle_findings(
    run_id: str,
    search: Optional[str] = Query(None),
    repo: Optional[str] = Query(None),
    verified: Optional[bool] = Query(None),
    sort_by: str = Query("date"),
    sort_dir: str = Query("desc"),
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    db: Session = Depends(get_db),
):
    q = db.query(TruffleFinding).filter(TruffleFinding.run_id == run_id)

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


@v1.get("/scans/{run_id}/scorecard")
def get_scorecard_findings(run_id: str, db: Session = Depends(get_db)):
    """Return OpenSSF Scorecard results grouped by repo, weakest scores first."""
    rows = (
        db.query(ScorecardFinding)
        .filter(ScorecardFinding.run_id == run_id)
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


@v1.get("/scans/{run_id}/alerts")
def get_correlated_alerts(run_id: str, db: Session = Depends(get_db)):
    alerts = (
        db.query(CorrelatedAlert)
        .filter(CorrelatedAlert.run_id == run_id)
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


# ── Unified findings ──────────────────────────────────────────────────────────


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


@v1.get("/findings")
def query_findings(
    target: Optional[str] = Query(None),
    severity: Optional[str] = Query(None),
    category: Optional[str] = Query(None),
    origin: Optional[str] = Query(None),
    run_id: Optional[str] = Query(None),
    page: int = Query(1, ge=1),
    page_size: int = Query(100, ge=1, le=500),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if target:
        q = q.filter(Finding.profile == target)
    if severity:
        q = q.filter(Finding.severity == severity)
    if category:
        q = q.filter(Finding.category == category)
    if origin:
        q = q.filter(Finding.origin == origin)
    if run_id:
        q = q.filter(Finding.run_id == run_id)

    total = q.count()

    # Severity is ranked, not alphabetical — CASE order, most severe first.
    sev_rank = case(
        *[(Finding.severity == sev, rank) for sev, rank in SEVERITY_ORDER.items()],
        else_=99,
    )
    findings = (
        q.order_by(sev_rank.asc(), Finding.category, Finding.title)
        .offset((page - 1) * page_size)
        .limit(page_size)
        .all()
    )
    return {
        "total": total,
        "page": page,
        "page_size": page_size,
        "findings": [_finding_dict(f) for f in findings],
    }


@v1.get("/findings/summary")
def findings_summary(
    target: Optional[str] = Query(None),
    db: Session = Depends(get_db),
):
    q = db.query(Finding)
    if target:
        q = q.filter(Finding.profile == target)

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
    by_origin = dict(
        q.with_entities(Finding.origin, func.count(Finding.id))
        .group_by(Finding.origin)
        .all()
    )

    runs_q = db.query(Run)
    if target:
        runs_q = runs_q.filter(Run.target == target)
    runs = runs_q.all()
    targets_scanned = len({
        r.target for r in runs if r.status in ("complete", "partial")
    })
    last_scan = max((r.completed_at or r.started_at for r in runs), default=None)

    return {
        "by_severity": by_severity,
        "by_category": by_category,
        "by_origin": by_origin,
        "accounts_scanned": targets_scanned,
        "last_scan": last_scan,
        "total": sum(by_severity.values()),
    }


@v1.get("/findings/{finding_id}")
def get_finding(finding_id: str, db: Session = Depends(get_db)):
    f = db.query(Finding).filter(Finding.id == finding_id).first()
    if not f:
        raise HTTPException(status_code=404, detail="Finding not found")
    return _finding_dict(f)


# ── Report + export ───────────────────────────────────────────────────────────


@v1.get("/report/{run_id}", response_class=PlainTextResponse)
def report(run_id: str, db: Session = Depends(get_db)):
    md = generate_report(db, run_id)
    if md is None:
        raise HTTPException(status_code=404, detail="Run not found")
    return PlainTextResponse(
        md,
        media_type="text/markdown",
        headers={"Content-Disposition": f'attachment; filename="rhinoscan-{run_id}.md"'},
    )


@v1.get("/export")
def export(
    since: Optional[str] = Query(None, description="iso8601 lower bound"),
    target: Optional[str] = Query(None),
    include_raw: bool = Query(False),
):
    """Hephaestus export: rhinoscan.export.v1 NDJSON (envelope, then findings)."""

    # Own session, not Depends(get_db): FastAPI tears yield-dependencies down
    # before a StreamingResponse finishes streaming.
    def stream():
        from app.core.database import SessionLocal

        db = SessionLocal()
        try:
            yield from export_ndjson(db, since=since, target=target, include_raw=include_raw)
        finally:
            db.close()

    return StreamingResponse(
        stream(),
        media_type="application/x-ndjson",
        headers={"Content-Disposition": 'attachment; filename="rhinoscan-export.ndjson"'},
    )


app.include_router(v1)


# ── Health ────────────────────────────────────────────────────────────────────


@app.get("/health")
def health():
    return {"status": "ok"}
