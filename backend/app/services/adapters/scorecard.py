"""OpenSSF Scorecard adapter."""

from sqlalchemy.orm import Session

from app.services import scorecard

from .base import TARGET_GITHUB, AdapterContext, github_org


class ScorecardAdapter:
    engine = "scorecard"
    origin = "Scorecard"
    target_type = TARGET_GITHUB
    label = "OpenSSF Scorecard (supply chain)"

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        if not ctx.gh_token:
            raise RuntimeError("No GitHub token available (gh auth login or GH_TOKEN)")
        scorecard.run_scorecard(run_id, github_org(target), ctx.gh_token, db)
        return scorecard.rollup_to_findings(run_id, target, db)
