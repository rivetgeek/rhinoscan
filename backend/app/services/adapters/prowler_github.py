"""Prowler (GitHub provider) adapter."""

from sqlalchemy.orm import Session

from app.services.prowler import run_prowler_github

from .base import TARGET_GITHUB, AdapterContext, github_org


class ProwlerGithubAdapter:
    engine = "prowler-github"
    origin = "GitHub"
    target_type = TARGET_GITHUB
    label = "Prowler (GitHub benchmark)"

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        if not ctx.gh_token:
            raise RuntimeError("No GitHub token available (gh auth login or GH_TOKEN)")
        return run_prowler_github(run_id, github_org(target), ctx.gh_token, db)
