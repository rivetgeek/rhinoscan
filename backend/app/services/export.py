"""Hephaestus export — rhinoscan.export.v1.

Pull-based, versioned NDJSON: one envelope line carrying run metadata, then
one line per finding. Finding ids are the deterministic hashes, so ingestion
is an idempotent upsert; a finding absent from a later full export for the
same target has been resolved. ``raw`` is excluded unless requested — client
API responses can be large and Hephaestus rarely needs them.
"""

import json
from datetime import datetime, timezone
from typing import Iterator, Optional

from sqlalchemy.orm import Session

from app.models.db import Finding, Run

SCHEMA = "rhinoscan.export.v1"


def export_ndjson(
    db: Session,
    since: Optional[str] = None,
    target: Optional[str] = None,
    include_raw: bool = False,
) -> Iterator[str]:
    """Yield NDJSON lines: envelope first, then findings.

    ``since`` filters findings by observation timestamp (iso8601) and runs by
    start time. ``target`` scopes both to one profile / github:<org>.
    """
    runs_q = db.query(Run)
    findings_q = db.query(Finding)
    if target:
        runs_q = runs_q.filter(Run.target == target)
        findings_q = findings_q.filter(Finding.profile == target)
    if since:
        # iso8601 strings compare lexicographically when zone-normalized —
        # both columns are written as UTC isoformat by the runner/adapters.
        runs_q = runs_q.filter(Run.started_at >= since)
        findings_q = findings_q.filter(Finding.timestamp >= since)

    runs = runs_q.order_by(Run.started_at).all()
    envelope = {
        "schema": SCHEMA,
        "exported_at": datetime.now(timezone.utc).isoformat(),
        "source": "rhinoscan",
        "targets": sorted({r.target for r in runs}),
        "runs": [
            {
                "id": r.id,
                "target": r.target,
                "engines": r.engines or [],
                "started_at": r.started_at,
                "completed_at": r.completed_at,
                "status": r.status,
            }
            for r in runs
        ],
    }
    yield json.dumps(envelope, default=str) + "\n"

    for f in findings_q.order_by(Finding.timestamp).yield_per(500):
        record = {
            "id": f.id,
            "profile": f.profile,
            "account_id": f.account_id,
            "origin": f.origin,
            "category": f.category,
            "severity": f.severity,
            "title": f.title,
            "resource": f.resource,
            "description": f.description,
            "remediation": f.remediation,
            "source": f.source,
            "api": f.api,
            "timestamp": f.timestamp,
            "run_id": f.run_id,
        }
        if include_raw:
            record["raw"] = f.raw
        yield json.dumps(record, default=str) + "\n"
