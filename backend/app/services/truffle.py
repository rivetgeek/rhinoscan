import json
import os
import re
import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import ScanJob, TruffleFinding
from app.services.docker_util import host_data_path

AWS_KEY_RE = re.compile(r"(AKIA[0-9A-Z]{16})")


def run_trufflehog(job_id: str, github_org: str, github_token: str, db: Session):
    """Run TruffleHog against a GitHub org and parse results into DB."""
    scan_dir = Path(settings.DATA_DIR) / "scans" / job_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    output_file = scan_dir / "truffle.json"

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.truffle_status = "running"
    db.commit()

    try:
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
            result = subprocess.run(
                cmd, stdout=out, stderr=subprocess.PIPE, text=True, timeout=3600,
                env={**os.environ, "GITHUB_TOKEN": github_token},
            )

        # TruffleHog exits non-zero when secrets found — that's expected
        _ingest_truffle_findings(job_id, output_file, db)

        job.truffle_status = "complete"
        db.commit()

    except Exception as e:
        job.truffle_status = "failed"
        job.error_message = (job.error_message or "") + f" | TruffleHog: {str(e)}"
        db.commit()
        raise


def _ingest_truffle_findings(job_id: str, output_file: Path, db: Session):
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
                job_id=job_id,
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
