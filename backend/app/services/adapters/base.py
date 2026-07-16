"""Scanner adapter contract.

Every engine — proprietary baseline battery or open-source scanner — sits
behind one interface: take a target, emit unified ``findings`` rows with
deterministic ids, return how many were observed. Engine-specific raw detail
(OCSF results, secret hits, scorecard checks) lives in the engine tables;
the unified table is the record and the Hephaestus export contract.

Adapters must not manage run bookkeeping (engine_status, run status) — the
runner owns that. An adapter raising marks its engine failed on the run
without aborting sibling engines.
"""

from dataclasses import dataclass, field
from typing import Protocol

from sqlalchemy.orm import Session

from app.models.db import Finding as FindingRow

TARGET_AWS = "aws"
TARGET_GITHUB = "github"

GITHUB_PREFIX = "github:"


def target_type(target: str) -> str:
    return TARGET_GITHUB if target.startswith(GITHUB_PREFIX) else TARGET_AWS


def github_org(target: str) -> str:
    return target.removeprefix(GITHUB_PREFIX)


@dataclass
class AdapterContext:
    """Cross-engine request context the runner hands each adapter."""

    region: str
    gh_token: str | None = None
    # AWS profile targets from the same scan request — lets GitHub-side
    # engines correlate discovered AWS keys against the client's IAM.
    aws_profiles: list[str] = field(default_factory=list)


class ScannerAdapter(Protocol):
    engine: str       # registry key, e.g. "prowler-aws"
    origin: str       # findings.origin value, e.g. "Prowler"
    target_type: str  # TARGET_AWS | TARGET_GITHUB
    label: str        # human-readable engine name for the UI

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        """Scan the target, upsert unified findings tagged run_id, return count."""
        ...


def prune_stale_findings(db: Session, target: str, origin: str, run_id: str) -> None:
    """Drop this origin's findings for the target that were not re-observed by
    the given run — resolved issues, or leftovers from prior failed runs — so
    the dashboard reflects current posture. Each adapter calls this after a
    successful scan; origins never touch each other's rows."""
    db.query(FindingRow).filter(
        FindingRow.profile == target,
        FindingRow.origin == origin,
        FindingRow.run_id != run_id,
    ).delete(synchronize_session=False)


def upsert_finding(db: Session, run_id: str, f) -> None:
    """Insert or update a unified finding by deterministic id.

    ``f`` is a checks.base.Finding (the shared dataclass all adapters build).
    """
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
