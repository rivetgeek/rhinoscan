"""Scan orchestration for the RhinoScan baseline assessment.

A scan request targets one or more AWS profiles. Each profile is assessed
independently: a boto3 session is created from ~/.aws/config, every check module
is run, and findings are upserted into SQLite. Findings carry deterministic IDs
so re-runs update existing rows and deltas stay trackable. A ``runs`` row tracks
status so the frontend can poll.
"""

import logging
import threading
import traceback
import uuid
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.db import Finding as FindingRow
from app.models.db import Run
from app.services.aws_profiles import get_account_id, get_session
from app.services.checks import CHECK_MODULES
from app.services.checks.base import INFORMATIONAL, CheckContext, Finding

log = logging.getLogger("rhinoscan.scanner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_scan(profiles: list[str]) -> list[str]:
    """Create a run per profile and kick off background scanning. Returns run ids."""
    created: list[tuple[str, str]] = []  # (run_id, profile)
    db = SessionLocal()
    try:
        for profile in profiles:
            run_id = str(uuid.uuid4())
            db.add(Run(
                id=run_id, profile=profile,
                started_at=_now(), status="running",
            ))
            created.append((run_id, profile))
        db.commit()
    finally:
        db.close()

    for run_id, profile in created:
        threading.Thread(
            target=_scan_profile, args=(run_id, profile), daemon=True,
        ).start()

    return [run_id for run_id, _ in created]


def _scan_profile(run_id: str, profile: str) -> None:
    """Run the full check battery for one profile (executed in a worker thread)."""
    db = SessionLocal()
    region = settings.AWS_DEFAULT_REGION
    try:
        session = get_session(profile, region)
        account_id = get_account_id(session)
        ctx = CheckContext(
            session=session, profile=profile,
            account_id=account_id or "unknown", region=region,
        )

        findings: list[Finding] = []
        for module in CHECK_MODULES:
            findings += _run_module(ctx, module)

        for f in findings:
            _upsert_finding(db, run_id, f)

        # Drop this profile's findings that were not re-observed this run —
        # resolved issues, or stale error-wrappers from a prior failed run — so
        # the dashboard reflects current posture instead of accumulating forever.
        # Scoped to Baseline origin: Prowler/GitHub roll-ups for the same
        # profile have their own lifecycle (see prowler.rollup_to_findings).
        db.query(FindingRow).filter(
            FindingRow.profile == profile,
            FindingRow.origin == "Baseline",
            FindingRow.run_id != run_id,
        ).delete(synchronize_session=False)

        run = db.query(Run).filter(Run.id == run_id).first()
        run.status = "complete"
        run.completed_at = _now()
        run.finding_count = len(findings)
        db.commit()
        log.info("scan %s for %s complete: %d findings", run_id, profile, len(findings))

    except Exception:  # never let a worker thread die silently
        log.error("scan %s for %s failed:\n%s", run_id, profile, traceback.format_exc())
        run = db.query(Run).filter(Run.id == run_id).first()
        if run:
            run.status = "failed"
            run.completed_at = _now()
            db.commit()
    finally:
        db.close()


def _run_module(ctx: CheckContext, module) -> list[Finding]:
    """Run a single check module, capturing failures as Informational findings."""
    try:
        return module.run(ctx)
    except Exception as e:
        category = getattr(module, "CATEGORY", module.__name__.split(".")[-1])
        log.warning("check %s failed for %s: %s", category, ctx.profile, e)
        return [Finding(
            profile=ctx.profile, account_id=ctx.account_id,
            category=category, severity=INFORMATIONAL,
            title=f"{category} checks could not complete",
            resource=f"profile:{ctx.profile}:{category}",
            description=f"The {category} check battery raised an error and was skipped: {e}",
            remediation="Verify the profile has the required read-only permissions for this service.",
            source=f"{category.lower()}_check_error", raw={"error": str(e)},
        )]


def _upsert_finding(db, run_id: str, f: Finding) -> None:
    """Insert or update a finding by deterministic id, tagging the current run."""
    row = db.query(FindingRow).filter(FindingRow.id == f.id).first()
    if row is None:
        row = FindingRow(id=f.id)
        db.add(row)
    row.profile = f.profile
    row.account_id = f.account_id
    row.timestamp = f.timestamp
    row.category = f.category
    row.severity = f.severity
    row.title = f.title
    row.resource = f.resource
    row.description = f.description
    row.remediation = f.remediation
    row.source = f.source
    row.origin = f.origin
    row.api = f.api
    row.raw = f.raw
    row.run_id = run_id
    # autoflush is off on this session, so flush now to make the new row visible
    # to the next lookup — duplicate ids within one batch update in place rather
    # than triggering a UNIQUE-constraint insert collision.
    db.flush()
