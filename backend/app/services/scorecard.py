"""OpenSSF Scorecard scanner.

Scorecard scores a single repository at a time, so we first enumerate the
GitHub org's (non-archived) repos via the REST API, then run the
``gcr.io/openssf/scorecard`` container per repo and ingest the per-check scores.

Auth is the operator's gh-login PAT (resolved upstream by ``github_auth``).
Repo enumeration uses stdlib ``urllib`` only, matching ``github_auth``'s
no-extra-dependency posture.
"""

import json
import logging
import os
import subprocess
import urllib.error
import urllib.request

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import ScanJob, ScorecardFinding

log = logging.getLogger("rhinoscan.scorecard")

# Bound on repos scanned per run. Scorecard launches one container per repo, so
# large orgs would otherwise run for a very long time. The pipeline is a
# background thread, but we still cap to keep a single scan tractable.
_MAX_REPOS = 100
_API = "https://api.github.com"


def _list_org_repos(org: str, token: str) -> list[str]:
    """Return up to ``_MAX_REPOS`` non-archived repo names for the org."""
    repos: list[str] = []
    page = 1
    while len(repos) < _MAX_REPOS:
        url = f"{_API}/orgs/{org}/repos?per_page=100&page={page}&type=all"
        req = urllib.request.Request(
            url,
            headers={
                "Authorization": f"Bearer {token}",
                "Accept": "application/vnd.github+json",
                "User-Agent": "rhinoscan",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=30) as resp:
                batch = json.loads(resp.read().decode("utf-8"))
        except urllib.error.HTTPError as e:
            raise RuntimeError(f"GitHub repo listing failed ({e.code}): {e.reason}")
        if not batch:
            break
        for r in batch:
            if not r.get("archived"):
                repos.append(r["name"])
        if len(batch) < 100:
            break
        page += 1
    return repos[:_MAX_REPOS]


def run_scorecard(job_id: str, github_org: str, token: str, db: Session):
    """Run OpenSSF Scorecard across the org's repos and ingest results."""
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.scorecard_status = "running"
    db.commit()

    try:
        repos = _list_org_repos(github_org, token)
        if not repos:
            job.scorecard_status = "complete"
            db.commit()
            return

        any_ok = False
        for repo in repos:
            try:
                _scan_repo(job_id, github_org, repo, token, db)
                any_ok = True
            except Exception as e:  # one bad repo never aborts the batch
                log.warning("scorecard failed for %s/%s: %s", github_org, repo, e)

        job.scorecard_status = "complete" if any_ok else "failed"
        db.commit()

    except Exception as e:
        job.scorecard_status = "failed"
        job.error_message = (job.error_message or "") + f" | Scorecard: {str(e)}"
        db.commit()
        raise


def _scan_repo(job_id: str, org: str, repo: str, token: str, db: Session):
    # Token passed by name only (value via env) so it can't leak through a
    # subprocess error string. See prowler.run_prowler.
    cmd = [
        "docker", "run", "--rm",
        "-e", "GITHUB_AUTH_TOKEN",
        settings.SCORECARD_IMAGE,
        f"--repo=github.com/{org}/{repo}",
        "--format=json",
        "--show-details",
    ]
    result = subprocess.run(
        cmd, capture_output=True, text=True, timeout=900,
        env={**os.environ, "GITHUB_AUTH_TOKEN": token},
    )
    if not result.stdout.strip():
        raise RuntimeError(result.stderr[:500] or "no scorecard output")

    data = json.loads(result.stdout)
    _ingest(job_id, data, db)


def _ingest(job_id: str, data: dict, db: Session):
    repo_name = (data.get("repo") or {}).get("name", "")
    repo_score = data.get("score")
    for check in data.get("checks", []) or []:
        doc = check.get("documentation") or {}
        db.add(ScorecardFinding(
            job_id=job_id,
            repo=repo_name,
            repo_score=repo_score,
            check_name=check.get("name", ""),
            check_score=check.get("score"),
            reason=check.get("reason", ""),
            documentation_url=doc.get("url", ""),
            raw=check,
        ))
    db.commit()
