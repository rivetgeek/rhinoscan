"""Prowler (AWS provider) adapter."""

from sqlalchemy.orm import Session

from app.services.prowler import run_prowler

from .base import TARGET_AWS, AdapterContext


class ProwlerAwsAdapter:
    engine = "prowler-aws"
    origin = "Prowler"
    target_type = TARGET_AWS
    label = "Prowler (AWS benchmark)"

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        # run_prowler ingests raw OCSF into prowler_findings, rolls FAILs up
        # into the unified findings table, and prunes the previous scan's rows.
        return run_prowler(run_id, target, ctx.region, db)
