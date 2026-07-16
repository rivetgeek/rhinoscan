"""Run orchestration over the scanner adapter registry.

A scan request is a set of targets (AWS profiles and/or ``github:<org>``) and
a set of engines. Each target becomes one run, executed in a worker thread;
engines run sequentially within the run, each behind its adapter, with
per-engine status tracked on the run row. One engine failing never aborts its
siblings — the run ends ``partial`` instead of ``complete``.
"""

import logging
import threading
import traceback
import uuid
from datetime import datetime, timezone

from app.core.config import settings
from app.core.database import SessionLocal
from app.models.db import Run
from app.services.adapters import ADAPTERS, AdapterContext, engines_for
from app.services.github_auth import resolve_gh_token

log = logging.getLogger("rhinoscan.runner")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def start_scans(targets: list[str], engines: list[str] | None = None) -> list[str]:
    """Create one run per target and kick off background scanning.

    ``engines`` filters which adapters run (all applicable to each target when
    omitted). Returns run ids, in target order.
    """
    ctx = AdapterContext(
        region=settings.AWS_DEFAULT_REGION,
        gh_token=resolve_gh_token(),
        aws_profiles=[t for t in targets if not t.startswith("github:")],
    )

    created: list[tuple[str, str, list[str]]] = []  # (run_id, target, engines)
    db = SessionLocal()
    try:
        for target in targets:
            applicable = engines_for(target)
            run_engines = [e for e in (engines or applicable) if e in applicable]
            run_id = str(uuid.uuid4())
            db.add(Run(
                id=run_id, target=target,
                engines=run_engines,
                engine_status={e: "pending" for e in run_engines},
                started_at=_now(), status="running",
            ))
            created.append((run_id, target, run_engines))
        db.commit()
    finally:
        db.close()

    for run_id, target, run_engines in created:
        threading.Thread(
            target=_execute_run, args=(run_id, target, run_engines, ctx),
            daemon=True,
        ).start()

    return [run_id for run_id, _, _ in created]


def _execute_run(run_id: str, target: str, engines: list[str], ctx: AdapterContext):
    """Run every requested engine against one target (worker thread)."""
    db = SessionLocal()
    total_findings = 0
    failed: dict[str, str] = {}
    completed = 0

    try:
        for engine_name in engines:
            adapter = ADAPTERS[engine_name]
            _set_engine_status(db, run_id, engine_name, "running")
            try:
                total_findings += adapter.scan(target, run_id, db, ctx)
                _set_engine_status(db, run_id, engine_name, "complete")
                completed += 1
            except Exception as e:
                db.rollback()
                log.error("engine %s failed for %s (run %s):\n%s",
                          engine_name, target, run_id, traceback.format_exc())
                failed[engine_name] = str(e)[:500]
                _set_engine_status(db, run_id, engine_name, "failed")

        run = db.query(Run).filter(Run.id == run_id).first()
        if not failed:
            run.status = "complete"
        elif completed:
            run.status = "partial"
        else:
            run.status = "failed"
        run.errors = failed or None
        run.completed_at = _now()
        run.finding_count = total_findings
        db.commit()
        log.info("run %s for %s %s: %d findings (%d/%d engines ok)",
                 run_id, target, run.status, total_findings, completed, len(engines))

    except Exception:  # never let a worker thread die silently
        log.error("run %s for %s crashed:\n%s", run_id, target, traceback.format_exc())
        db.rollback()
        run = db.query(Run).filter(Run.id == run_id).first()
        if run:
            run.status = "failed"
            run.completed_at = _now()
            db.commit()
    finally:
        db.close()


def _set_engine_status(db, run_id: str, engine_name: str, status: str) -> None:
    run = db.query(Run).filter(Run.id == run_id).first()
    # JSON columns don't track in-place mutation — assign a fresh dict.
    run.engine_status = {**(run.engine_status or {}), engine_name: status}
    db.commit()
