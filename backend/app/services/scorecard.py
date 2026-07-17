"""OpenSSF Scorecard scanner.

Scorecard scores a single repository at a time, so we first enumerate the
GitHub org's (non-archived) repos via the REST API, then run the
``gcr.io/openssf/scorecard`` container per repo and ingest the per-check scores.

Auth is the operator's gh-login PAT (resolved upstream by ``github_auth``).
Repo enumeration uses stdlib ``urllib`` only, matching ``github_auth``'s
no-extra-dependency posture.
"""

import hashlib
import json
import logging
import os
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timezone

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import Finding as FindingRow
from app.models.db import ScorecardFinding

log = logging.getLogger("rhinoscan.scorecard")

# Bound on repos scanned per run. Scorecard launches one container per repo, so
# large orgs would otherwise run for a very long time. The pipeline is a
# background thread, but we still cap to keep a single scan tractable.
_MAX_REPOS = 100
_API = "https://api.github.com"

# Repo-score thresholds for the unified findings roll-up (PRD V2):
# score < 3 -> High, < 5 -> Medium, otherwise no finding.
_HIGH_BELOW = 3.0
_MEDIUM_BELOW = 5.0


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


def run_scorecard(run_id: str, github_org: str, token: str, db: Session):
    """Run OpenSSF Scorecard across the org's repos and ingest results.
    Raises when every repo fails — the runner owns run/engine status."""
    repos = _list_org_repos(github_org, token)
    if not repos:
        return

    any_ok = False
    for repo in repos:
        try:
            _scan_repo(run_id, github_org, repo, token, db)
            any_ok = True
        except Exception as e:  # one bad repo never aborts the batch
            log.warning("scorecard failed for %s/%s: %s", github_org, repo, e)

    if not any_ok:
        raise RuntimeError(f"Scorecard failed for all {len(repos)} repos")


def rollup_to_findings(run_id: str, target: str, db: Session) -> int:
    """Roll a run's weak Scorecard repo scores up into ``findings``.

    Origin ``Scorecard``. One finding per repo scoring below 5 (High below 3,
    Medium below 5), summarizing that repo's weakest checks. Repos at or above
    5 produce no finding — per-check detail stays in ``scorecard_findings``.
    Returns the number of findings rolled up.
    """
    rows = (
        db.query(ScorecardFinding)
        .filter(ScorecardFinding.run_id == run_id)
        .all()
    )
    repos: dict[str, dict] = {}
    for r in rows:
        entry = repos.setdefault(r.repo, {"score": r.repo_score, "checks": []})
        entry["checks"].append(r)

    now = datetime.now(timezone.utc).isoformat()
    org = target.removeprefix("github:")
    seen: set[str] = set()
    for repo, entry in repos.items():
        score = entry["score"]
        if score is None or score >= _MEDIUM_BELOW:
            continue
        severity = "High" if score < _HIGH_BELOW else "Medium"

        key = f"{target}|scorecard_repo_score|{repo}"
        fid = hashlib.sha256(key.encode()).hexdigest()[:32]
        seen.add(fid)

        # Weakest failing checks (score 0-10; -1 means inconclusive, skip
        # those). Sub-5/10 are what drag the repo down and where the fix
        # effort belongs; cap at 5 so the finding stays readable.
        weakest = sorted(
            (c for c in entry["checks"]
             if c.check_score is not None and 0 <= c.check_score < _MEDIUM_BELOW),
            key=lambda c: c.check_score,
        )[:5]
        # Fall back to the lowest scored checks if none are below the medium
        # bar (repo scored low for another reason, e.g. many inconclusives).
        if not weakest:
            weakest = sorted(
                (c for c in entry["checks"]
                 if c.check_score is not None and c.check_score >= 0),
                key=lambda c: c.check_score,
            )[:3]
        weak_str = "; ".join(
            f"{c.check_name} ({c.check_score}/10): {c.reason or 'no detail'}"
            for c in weakest
        ) or "no per-check detail available"

        # Per-check specifics Scorecard hands us but the summary drops: the
        # documentation URL (exact fix guide) and the `details` lines (which
        # name the concrete problem, e.g. the unprotected branch). These make
        # the finding actionable on its own — and, since the unified findings
        # table is what feeds the Hephaestus export, actionable downstream too.
        weak_detail = [
            {
                "check": c.check_name,
                "score": c.check_score,
                "reason": c.reason or "",
                "doc": c.documentation_url or "",
                "details": (c.raw or {}).get("details") or [],
            }
            for c in weakest
        ]
        remediation = "Fix the weakest checks:\n" + "\n".join(
            f"- {d['check']} ({d['score']}/10): {d['reason']}"
            + (f" — see {d['doc']}" if d["doc"] else "")
            + (f" [{'; '.join(d['details'])}]" if d["details"] else "")
            for d in weak_detail
        )

        row = db.query(FindingRow).filter(FindingRow.id == fid).first()
        if row is None:
            row = FindingRow(id=fid)
            db.add(row)
        row.profile = target
        row.account_id = org
        row.timestamp = now
        row.category = "SupplyChain"
        row.severity = severity
        row.title = f"Weak OpenSSF Scorecard posture: {repo} scores {score}/10"
        row.resource = repo
        row.description = (
            f"OpenSSF Scorecard rates '{repo}' {score}/10 overall. "
            f"Weakest checks — {weak_str}."
        )
        row.remediation = remediation
        row.source = "scorecard_repo_score"
        row.origin = "Scorecard"
        row.api = ""
        row.raw = {"run_id": run_id, "repo_score": score, "weakest_checks": weak_detail}
        row.run_id = run_id

    # Drop this origin's findings from previous scans of the same target.
    db.query(FindingRow).filter(
        FindingRow.profile == target,
        FindingRow.origin == "Scorecard",
        FindingRow.run_id != run_id,
    ).delete(synchronize_session=False)

    db.commit()
    return len(seen)


def _scan_repo(run_id: str, org: str, repo: str, token: str, db: Session):
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
    _ingest(run_id, data, db)


def _ingest(run_id: str, data: dict, db: Session):
    repo_name = (data.get("repo") or {}).get("name", "")
    repo_score = data.get("score")
    for check in data.get("checks", []) or []:
        doc = check.get("documentation") or {}
        db.add(ScorecardFinding(
            run_id=run_id,
            repo=repo_name,
            repo_score=repo_score,
            check_name=check.get("name", ""),
            check_score=check.get("score"),
            reason=check.get("reason", ""),
            documentation_url=doc.get("url", ""),
            raw=check,
        ))
    db.commit()
