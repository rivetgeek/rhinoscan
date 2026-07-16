import hashlib
import json
import os
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import Finding as FindingRow
from app.models.db import ProwlerFinding, ScanJob
from app.services.aws_profiles import get_frozen_credentials, get_session
from app.services.docker_util import host_data_path


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}

# Prowler severities (lowercase) -> unified findings ladder (title case).
ROLLUP_SEVERITY = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# Prowler service names -> the dashboard's category vocabulary where they
# overlap with the baseline battery; anything else falls back to Title case.
ROLLUP_CATEGORY = {
    "iam": "Identity",
    "s3": "S3",
    "cloudtrail": "CloudTrail",
    "ec2": "EC2",
    "lambda": "Lambda",
    "awslambda": "Lambda",
    "guardduty": "GuardDuty",
    "securityhub": "SecurityHub",
    "account": "Account",
}

# Prowler v5 emits OCSF JSON as "<output-filename>.ocsf.json". Plain `json` was
# removed in v4, so we request `json-ocsf` and parse the OCSF Detection Finding
# schema (see _ingest_prowler_findings).
OCSF_SUFFIX = ".ocsf.json"


def run_prowler(job_id: str, profile: str, region: str, db: Session):
    """Run Prowler in a Docker container and parse results into DB.

    The target account comes from a ~/.aws/config profile (no pasted role ARN).
    We resolve that profile's credential chain here and pass the resulting
    temporary credentials into the container as env vars, since the container
    can't see the operator's AWS config.
    """
    scan_dir = Path(settings.DATA_DIR) / "scans" / job_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.prowler_status = "running"
    db.commit()

    try:
        session = get_session(profile, region)
        creds = get_frozen_credentials(session)
        # Pass secrets to the container by NAME only (`-e KEY`), supplying values
        # via the subprocess env so Docker reads them from its own environment.
        # Keeping them out of argv means a subprocess error (TimeoutExpired /
        # CalledProcessError stringifies the command) can never leak credentials.
        docker_env = {**creds, "AWS_DEFAULT_REGION": region}
        cred_args: list[str] = []
        for key in docker_env:
            cred_args.extend(["-e", key])

        cmd = [
            "docker", "run", "--rm",
            "-v", f"{host_data_path(scan_dir)}:/output",
            *cred_args,
            settings.PROWLER_IMAGE,
            "aws",
            "--region", region,
            "--output-formats", "json-ocsf",
            "--output-directory", "/output",
            "--output-filename", "prowler",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=7200,  # 2h — large accounts
            env={**os.environ, **docker_env},
        )

        # Prowler exits 0 (no fails) or 3 (fails found) on success. It can also
        # exit non-zero from a crash in its *compliance* report generator (a
        # known v5 bug, e.g. KeyError 'MANUAL') *after* the OCSF findings file is
        # fully written — so don't discard a complete scan: ingest whenever the
        # output exists, and only treat a missing output as a real failure.
        findings_file = scan_dir / f"prowler{OCSF_SUFFIX}"
        if not findings_file.exists():
            raise RuntimeError(f"Prowler failed: {_err(result)}")

        with open(findings_file) as f:
            raw_findings = json.load(f)

        _ingest_prowler_findings(job_id, raw_findings, db, provider="aws")
        rollup_to_findings(job_id, db, provider="aws")

        job.prowler_status = "complete"
        db.commit()

    except Exception as e:
        job.prowler_status = "failed"
        job.error_message = str(e)
        db.commit()
        raise


def run_prowler_github(job_id: str, github_org: str, token: str, db: Session):
    """Run Prowler's GitHub provider against an org and parse results into DB.

    Mirrors :func:`run_prowler` but targets the ``github`` provider instead of
    ``aws``; the org is scanned with the operator's gh-login PAT. Findings land
    in the same ``prowler_findings`` table tagged ``provider='github'`` so the
    UI can split AWS vs GitHub posture.
    """
    scan_dir = Path(settings.DATA_DIR) / "scans" / job_id
    scan_dir.mkdir(parents=True, exist_ok=True)

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.prowler_github_status = "running"
    db.commit()

    try:
        # Token passed by name only (value via env) so it can't leak through a
        # subprocess error string. See run_prowler.
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{host_data_path(scan_dir)}:/output",
            "-e", "GITHUB_PERSONAL_ACCESS_TOKEN",
            settings.PROWLER_IMAGE,
            "github",
            "--output-formats", "json-ocsf",
            "--output-directory", "/output",
            "--output-filename", "prowler_github",
        ]

        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=7200,  # 2h — large orgs
            env={**os.environ, "GITHUB_PERSONAL_ACCESS_TOKEN": token},
        )

        # See run_prowler: a compliance-phase crash can exit non-zero after the
        # findings file is written, so key success off the output file existing.
        findings_file = scan_dir / f"prowler_github{OCSF_SUFFIX}"
        if not findings_file.exists():
            raise RuntimeError(f"Prowler GitHub failed: {_err(result)}")

        with open(findings_file) as f:
            raw_findings = json.load(f)

        _ingest_prowler_findings(job_id, raw_findings, db, provider="github")
        rollup_to_findings(job_id, db, provider="github")

        job.prowler_github_status = "complete"
        db.commit()

    except Exception as e:
        job.prowler_github_status = "failed"
        job.error_message = (job.error_message or "") + f" | Prowler GitHub: {str(e)}"
        db.commit()
        raise


def _err(result: subprocess.CompletedProcess) -> str:
    """Return the tail of stderr — the actual error lands at the end, after any
    image-pull progress (whose carriage returns would otherwise dominate)."""
    return (result.stderr or "").strip()[-800:]


def rollup_to_findings(job_id: str, db: Session, provider: str = "aws") -> int:
    """Roll a job's Prowler FAILs up into the unified ``findings`` table.

    Only FAIL results become findings — PASS/MANUAL/MUTED stay in
    ``prowler_findings`` for the scan detail view. Rows carry origin
    ``Prowler`` (aws) or ``GitHub`` and deterministic ids
    (profile|check|region|resource), and a re-scan of the same target replaces
    that origin's previous findings, mirroring the baseline scanner. Reads from
    ``prowler_findings`` rather than raw OCSF so it can also backfill
    already-ingested jobs. Returns the number of findings rolled up.
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    if job is None:
        return 0

    if provider == "github":
        origin = "GitHub"
        # GitHub posture has no AWS profile; namespace by org so it is distinct
        # in the dashboard's profile column (visible under the "All" view).
        profile = f"github:{job.github_org or 'unknown'}"
    else:
        origin = "Prowler"
        profile = job.profile or "unknown"

    rows = (
        db.query(ProwlerFinding)
        .filter(
            ProwlerFinding.job_id == job_id,
            ProwlerFinding.provider == provider,
            ProwlerFinding.status == "FAIL",
        )
        .all()
    )

    now = datetime.now(timezone.utc).isoformat()
    seen: set[str] = set()
    for r in rows:
        raw = r.raw or {}
        resource = r.resource_arn or r.resource_name or "unknown-resource"
        key = f"{profile}|{r.check_id}|{r.region or ''}|{resource}"
        fid = hashlib.sha256(key.encode()).hexdigest()[:32]
        if fid in seen:  # duplicate check/resource pair within the job
            continue
        seen.add(fid)

        service = (r.service or "").lower()
        remediation = ""
        rem = raw.get("remediation")
        if isinstance(rem, dict):
            remediation = str(rem.get("desc") or "")
        account_id = str(
            ((raw.get("cloud") or {}).get("account") or {}).get("uid")
            or (job.github_org if provider == "github" else "")
            or "unknown"
        )

        row = db.query(FindingRow).filter(FindingRow.id == fid).first()
        if row is None:
            row = FindingRow(id=fid)
            db.add(row)
        row.profile = profile
        row.account_id = account_id
        row.timestamp = now
        row.category = ROLLUP_CATEGORY.get(service, (r.service or "General").capitalize())
        row.severity = ROLLUP_SEVERITY.get((r.severity or "").lower(), "Informational")
        row.title = r.check_title or r.check_id
        row.resource = resource
        row.description = r.status_extended or r.check_title or ""
        row.remediation = remediation
        row.source = r.check_id
        row.origin = origin
        row.api = ""
        # Slim reference only — the full OCSF result stays in prowler_findings.
        row.raw = {"job_id": job_id, "prowler_finding_id": r.id, "region": r.region}
        row.run_id = job_id

    # Drop this origin's findings from previous scans of the same target.
    db.query(FindingRow).filter(
        FindingRow.profile == profile,
        FindingRow.origin == origin,
        FindingRow.run_id != job_id,
    ).delete(synchronize_session=False)

    db.commit()
    return len(seen)


def _ingest_prowler_findings(job_id: str, raw: list, db: Session, provider: str = "aws"):
    """Parse Prowler v5 OCSF Detection Findings into ProwlerFinding rows.

    OCSF shape (per finding):
      metadata.event_code           -> check_id
      finding_info.title            -> check_title
      severity                      -> severity (Critical/High/...)
      status_code                   -> status (PASS/FAIL/MANUAL/MUTED)
      status_detail                 -> status_extended
      resources[0].{group.name, region, uid, name}  -> service/region/arn/name
    """
    for item in raw:
        meta = item.get("metadata") or {}
        finding_info = item.get("finding_info") or {}
        resources = item.get("resources") or []
        res = resources[0] if resources else {}
        cloud = item.get("cloud") or {}

        finding = ProwlerFinding(
            job_id=job_id,
            provider=provider,
            check_id=meta.get("event_code", ""),
            check_title=finding_info.get("title", ""),
            severity=SEVERITY_MAP.get(
                str(item.get("severity", "")).lower(), "informational"
            ),
            status=item.get("status_code") or item.get("status", "UNKNOWN"),
            service=(res.get("group") or {}).get("name", "") or cloud.get("provider", ""),
            region=res.get("region", "") or cloud.get("region", ""),
            resource_arn=res.get("uid", ""),
            resource_name=res.get("name", ""),
            status_extended=item.get("status_detail", ""),
            raw=item,
        )
        db.add(finding)

    db.commit()
