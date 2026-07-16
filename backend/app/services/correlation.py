from botocore.exceptions import ClientError
from sqlalchemy.orm import Session

from app.models.db import CorrelatedAlert, IAMLookup, ScanJob, TruffleFinding
from app.services.aws_profiles import get_session


def run_correlation(job_id: str, profile: str, db: Session):
    """
    For every TruffleHog finding with an AWS key ID:
    1. Look up the key in IAM (active status, owner, policies)
    2. Store IAMLookup record
    3. Generate a CorrelatedAlert
    """
    job = db.query(ScanJob).filter(ScanJob.id == job_id).first()

    findings = (
        db.query(TruffleFinding)
        .filter(
            TruffleFinding.job_id == job_id,
            TruffleFinding.key_id.isnot(None),
        )
        .all()
    )

    if not findings:
        return

    # Use the selected profile's credential chain for IAM lookups — boto3
    # resolves SSO/source_profile/role_arn from ~/.aws/config.
    iam = get_session(profile).client("iam")

    for finding in findings:
        lookup = _lookup_key(iam, finding.key_id)

        iam_record = IAMLookup(
            truffle_finding_id=finding.id,
            key_active=lookup.get("active"),
            last_used_date=lookup.get("last_used_date"),
            last_used_service=lookup.get("last_used_service"),
            last_used_region=lookup.get("last_used_region"),
            iam_entity_type=lookup.get("entity_type"),
            iam_entity_name=lookup.get("entity_name"),
            iam_entity_arn=lookup.get("entity_arn"),
            attached_policies=lookup.get("attached_policies", []),
            inline_policy_names=lookup.get("inline_policy_names", []),
            lookup_error=lookup.get("error"),
        )
        db.add(iam_record)
        db.flush()

        alert = _build_alert(job_id, finding, lookup)
        db.add(alert)

    db.commit()


def _lookup_key(iam, key_id: str) -> dict:
    result = {}
    try:
        # Step 1: who owns this key + is it active
        resp = iam.get_access_key_last_used(AccessKeyId=key_id)
        last_used = resp.get("AccessKeyLastUsed", {})
        username = resp.get("UserName", "")

        result["entity_type"] = "user"
        result["entity_name"] = username
        result["last_used_date"] = str(last_used.get("LastUsedDate", ""))
        result["last_used_service"] = last_used.get("ServiceName", "")
        result["last_used_region"] = last_used.get("Region", "")

        # Check active status via list_access_keys
        keys_resp = iam.list_access_keys(UserName=username)
        for k in keys_resp.get("AccessKeyMetadata", []):
            if k["AccessKeyId"] == key_id:
                result["active"] = k["Status"] == "Active"
                break

        # Get user ARN
        user_resp = iam.get_user(UserName=username)
        result["entity_arn"] = user_resp["User"]["Arn"]

        # Attached managed policies
        policies_resp = iam.list_attached_user_policies(UserName=username)
        result["attached_policies"] = [
            p["PolicyArn"] for p in policies_resp.get("AttachedPolicies", [])
        ]

        # Inline policy names
        inline_resp = iam.list_user_policies(UserName=username)
        result["inline_policy_names"] = inline_resp.get("PolicyNames", [])

    except ClientError as e:
        result["error"] = str(e)
        result["active"] = None

    return result


def _build_alert(job_id: str, finding: TruffleFinding, lookup: dict) -> CorrelatedAlert:
    policies = lookup.get("attached_policies", [])
    inline = lookup.get("inline_policy_names", [])
    entity_name = lookup.get("entity_name", "unknown")
    active = lookup.get("active")

    # Build human-readable policy list
    policy_display = []
    for p in policies:
        # Shorten ARN to just policy name
        policy_display.append(p.split("/")[-1])
    for p in inline:
        policy_display.append(f"{p} (inline)")

    policy_str = ", ".join(policy_display) if policy_display else "no policies found"
    active_str = "active" if active else "inactive" if active is False else "unknown status"

    narrative = (
        f"An AWS access key ({finding.key_id}) was found in the repository "
        f"'{finding.repo}' in file '{finding.file_path}' "
        f"(commit {finding.commit[:8] if finding.commit else 'unknown'}, "
        f"authored by {finding.author or 'unknown'} on {finding.date or 'unknown date'}). "
        f"The key belongs to IAM user '{entity_name}' and is currently {active_str}. "
        f"Attached policies: {policy_str}."
    )

    return CorrelatedAlert(
        job_id=job_id,
        truffle_finding_id=finding.id,
        severity="CRITICAL" if active else "HIGH",
        title=f"Exposed AWS credential in {finding.repo}",
        narrative=narrative,
        key_id=finding.key_id,
        key_active=active,
        iam_entity_name=entity_name,
        iam_entity_arn=lookup.get("entity_arn"),
        attached_policies=policies,
        repo=finding.repo,
        commit=finding.commit,
        author=finding.author,
        exposed_date=finding.date,
        file_path=finding.file_path,
    )
