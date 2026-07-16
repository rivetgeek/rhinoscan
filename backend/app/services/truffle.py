import hashlib
import json
import os
import re
import subprocess
from datetime import datetime, timezone
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import CorrelatedAlert, TruffleFinding
from app.models.db import Finding as FindingRow
from app.services.docker_util import host_data_path

AWS_KEY_RE = re.compile(r"(AKIA[0-9A-Z]{16})")


def run_trufflehog(run_id: str, github_org: str, github_token: str, db: Session):
    """Run TruffleHog against a GitHub org and parse results into DB.
    Raises on failure — the runner owns run/engine status."""
    scan_dir = Path(settings.DATA_DIR) / "scans" / run_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    output_file = scan_dir / "truffle.json"

    # Token passed by name only (value via env, read by TruffleHog as
    # GITHUB_TOKEN) so it never appears in argv — a subprocess error string
    # then can't leak it. See prowler.run_prowler.
    cmd = [
        "docker", "run", "--rm",
        "-v", f"{host_data_path(scan_dir)}:/output",
        "-e", "GITHUB_TOKEN",
        settings.TRUFFLE_IMAGE,
        "github",
        "--org", github_org,
        "--json",
        "--only-verified",  # remove for unverified secrets too; start conservative
        "--detector=AWS",
    ]

    with open(output_file, "w") as out:
        subprocess.run(
            cmd, stdout=out, stderr=subprocess.PIPE, text=True, timeout=3600,
            env={**os.environ, "GITHUB_TOKEN": github_token},
        )

    # TruffleHog exits non-zero when secrets found — that's expected
    _ingest_truffle_findings(run_id, output_file, db)


def rollup_to_findings(run_id: str, target: str, db: Session) -> int:
    """Roll a run's TruffleHog hits up into the unified ``findings`` table.

    Origin ``Secrets``. One finding per secret; verified (live) credentials are
    Critical, unverified High. Where correlation produced an alert for the same
    hit, its IAM narrative is appended to the description — run this after
    correlation. The stable identity is repo + key id (or file path when no key
    id was extracted), so line-number drift across commits doesn't spawn
    duplicates. Returns the number of findings rolled up.
    """
    rows = (
        db.query(TruffleFinding)
        .filter(TruffleFinding.run_id == run_id)
        .all()
    )
    alerts = {
        a.truffle_finding_id: a
        for a in db.query(CorrelatedAlert)
        .filter(CorrelatedAlert.run_id == run_id)
        .all()
    }

    now = datetime.now(timezone.utc).isoformat()
    org = target.removeprefix("github:")
    seen: set[str] = set()
    for r in rows:
        detector = r.detector_name or "secret"
        secret_ref = r.key_id or r.file_path or "unknown"
        key = f"{target}|trufflehog_{detector.lower()}|{r.repo}:{secret_ref}"
        fid = hashlib.sha256(key.encode()).hexdigest()[:32]
        if fid in seen:  # same secret hit in multiple commits/lines
            continue
        seen.add(fid)

        location = r.file_path or "unknown file"
        if r.line:
            location += f":{r.line}"
        description = (
            f"A {detector} credential was detected in '{r.repo}' at {location} "
            f"(commit {r.commit[:8] if r.commit else 'unknown'}, "
            f"authored by {r.author or 'unknown'} on {r.date or 'unknown date'})."
            + (" TruffleHog verified the credential is live." if r.verified else "")
        )
        alert = alerts.get(r.id)
        if alert and alert.narrative:
            description += f" {alert.narrative}"

        row = db.query(FindingRow).filter(FindingRow.id == fid).first()
        if row is None:
            row = FindingRow(id=fid)
            db.add(row)
        row.profile = target
        row.account_id = org
        row.timestamp = now
        row.category = "Secrets"
        row.severity = "Critical" if r.verified else "High"
        row.title = f"Exposed {detector} credential in {r.repo}"
        row.resource = f"{r.repo}/{location}"
        row.description = description
        row.remediation = (
            "Rotate or deactivate the credential immediately, then purge it "
            "from the repository history and add secret scanning to CI."
        )
        row.source = f"trufflehog_{detector.lower()}"
        row.origin = "Secrets"
        row.api = ""
        # Slim reference only — the full hit stays in truffle_findings.
        row.raw = {"run_id": run_id, "truffle_finding_id": r.id,
                   "key_id": r.key_id, "verified": r.verified}
        row.run_id = run_id

    # Drop this origin's findings from previous scans of the same target.
    db.query(FindingRow).filter(
        FindingRow.profile == target,
        FindingRow.origin == "Secrets",
        FindingRow.run_id != run_id,
    ).delete(synchronize_session=False)

    db.commit()
    return len(seen)


def _ingest_truffle_findings(run_id: str, output_file: Path, db: Session):
    """TruffleHog outputs one JSON object per line (NDJSON)."""
    if not output_file.exists():
        return

    with open(output_file) as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue

            # Extract key ID from raw if present
            raw_str = json.dumps(item)
            key_match = AWS_KEY_RE.search(raw_str)
            key_id = key_match.group(1) if key_match else None

            source_meta = item.get("SourceMetadata", {}).get("Data", {}).get("Github", {})

            finding = TruffleFinding(
                run_id=run_id,
                repo=source_meta.get("repository", ""),
                commit=source_meta.get("commit", ""),
                author=source_meta.get("email", ""),
                date=source_meta.get("timestamp", ""),
                file_path=source_meta.get("file", ""),
                line=source_meta.get("line"),
                detector_name=item.get("DetectorName", ""),
                key_id=key_id,
                verified=item.get("Verified", False),
                raw=item,
            )
            db.add(finding)

    db.commit()
