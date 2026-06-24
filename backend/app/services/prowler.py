import json
import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from app.core.config import settings
from app.models.db import ProwlerFinding, ScanJob
from app.services.docker_util import docker_aws_args, host_data_path


SEVERITY_MAP = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "informational": "informational",
}


def run_prowler(job_id: str, role_arn: str, region: str, db: Session):
    """Run Prowler in a Docker container and parse results into DB."""
    scan_dir = Path(settings.DATA_DIR) / "scans" / job_id
    scan_dir.mkdir(parents=True, exist_ok=True)
    output_file = scan_dir / "prowler.json"

    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()
    job.prowler_status = "running"
    db.commit()

    try:
        cmd = [
            "docker", "run", "--rm",
            "-v", f"{host_data_path(scan_dir)}:/output",
            *docker_aws_args(),
            settings.PROWLER_IMAGE,
            "aws",
            "--role", role_arn,
            "--region", region,
            "--output-formats", "json",
            "--output-directory", "/output",
            "--output-filename", "prowler",
            "-M", "json",
        ]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=3600)

        if result.returncode not in (0, 3):  # prowler exits 3 when there are failures
            raise RuntimeError(f"Prowler failed: {result.stderr[:500]}")

        # Parse output
        findings_file = scan_dir / "prowler.json"
        if not findings_file.exists():
            raise FileNotFoundError("Prowler output file not found")

        with open(findings_file) as f:
            raw_findings = json.load(f)

        _ingest_prowler_findings(job_id, raw_findings, db)

        job.prowler_status = "complete"
        db.commit()

    except Exception as e:
        job.prowler_status = "failed"
        job.error_message = str(e)
        db.commit()
        raise


def _ingest_prowler_findings(job_id: str, raw: list, db: Session):
    for item in raw:
        # Prowler v3+ JSON schema
        finding = ProwlerFinding(
            job_id=job_id,
            check_id=item.get("CheckID", ""),
            check_title=item.get("CheckTitle", ""),
            severity=SEVERITY_MAP.get(
                item.get("Severity", "").lower(), "informational"
            ),
            status=item.get("Status", "UNKNOWN"),
            service=item.get("ServiceName", ""),
            region=item.get("Region", ""),
            resource_arn=item.get("ResourceArn", ""),
            resource_name=item.get("ResourceName", ""),
            status_extended=item.get("StatusExtended", ""),
            raw=item,
        )
        db.add(finding)

    db.commit()
