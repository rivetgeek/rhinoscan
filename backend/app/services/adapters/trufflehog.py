"""TruffleHog secrets adapter, with IAM exposure correlation."""

import logging

from sqlalchemy.orm import Session

from app.services import truffle
from app.services.correlation import run_correlation

from .base import TARGET_GITHUB, AdapterContext, github_org

log = logging.getLogger("rhinoscan.adapters.trufflehog")


class TrufflehogAdapter:
    engine = "trufflehog"
    origin = "Secrets"
    target_type = TARGET_GITHUB
    label = "TruffleHog (secret scanning)"

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        if not ctx.gh_token:
            raise RuntimeError("No GitHub token available (gh auth login or GH_TOKEN)")

        truffle.run_trufflehog(run_id, github_org(target), ctx.gh_token, db)

        # Correlate discovered AWS keys against the request's AWS profiles.
        # Enrichment only — a correlation failure never fails the secrets scan.
        if ctx.aws_profiles:
            try:
                run_correlation(run_id, ctx.aws_profiles, db)
            except Exception as e:
                log.warning("correlation failed for run %s: %s", run_id, e)
                db.rollback()

        # Roll up after correlation so alert narratives enrich the findings.
        return truffle.rollup_to_findings(run_id, target, db)
