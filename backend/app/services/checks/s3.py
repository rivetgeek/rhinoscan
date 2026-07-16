"""S3 baseline checks."""

from botocore.exceptions import ClientError

from .base import HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "S3"
PUBLIC_URIS = (
    "http://acs.amazonaws.com/groups/global/AllUsers",
    "http://acs.amazonaws.com/groups/global/AuthenticatedUsers",
)


def run(ctx: CheckContext) -> list[Finding]:
    findings: list[Finding] = []
    s3 = ctx.client("s3", region="us-east-1")  # S3 list/control is region-agnostic

    findings += _account_block_public_access(ctx)

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        return findings + [finding(
            ctx, category=CATEGORY, severity="Informational",
            title="Unable to list S3 buckets",
            resource="s3://*", description=str(e),
            remediation="Verify the profile has s3:ListAllMyBuckets.",
            source="s3_list_buckets", raw={"error": str(e)},
        )]

    for b in buckets:
        name = b["Name"]
        findings += _bucket_checks(ctx, s3, name)
    return findings


def _account_block_public_access(ctx) -> list[Finding]:
    ctrl = ctx.client("s3control", region="us-east-1")
    try:
        cfg = ctrl.get_public_access_block(
            AccountId=ctx.account_id
        )["PublicAccessBlockConfiguration"]
    except ClientError:
        cfg = {}
    all_on = all(cfg.get(k) for k in (
        "BlockPublicAcls", "IgnorePublicAcls",
        "BlockPublicPolicy", "RestrictPublicBuckets",
    ))
    if not all_on:
        return [finding(
            ctx, category=CATEGORY, severity=HIGH,
            title="Account-level S3 Block Public Access is not fully enabled",
            resource=f"arn:aws:s3:::account/{ctx.account_id}",
            description="One or more account-level Block Public Access settings are disabled, "
                        "allowing buckets to be made public.",
            remediation="Enable all four account-level Block Public Access settings.",
            source="s3_account_block_public_access", raw=cfg,
        )]
    return []


def _bucket_checks(ctx, s3, name: str) -> list[Finding]:
    out: list[Finding] = []
    arn = f"arn:aws:s3:::{name}"

    # Public ACL.
    try:
        acl = s3.get_bucket_acl(Bucket=name)
        public_grantees = [
            g for g in acl.get("Grants", [])
            if g.get("Grantee", {}).get("URI") in PUBLIC_URIS
        ]
        if public_grantees:
            out.append(finding(
                ctx, category=CATEGORY, severity=HIGH,
                title=f"Bucket '{name}' has a public ACL",
                resource=arn,
                description="The bucket ACL grants access to AllUsers/AuthenticatedUsers.",
                remediation="Remove public grants and enable Block Public Access.",
                source="s3_bucket_public_acl", raw=acl,
            ))
    except ClientError:
        pass

    # Public policy.
    try:
        status = s3.get_bucket_policy_status(Bucket=name)["PolicyStatus"]
        if status.get("IsPublic"):
            out.append(finding(
                ctx, category=CATEGORY, severity=HIGH,
                title=f"Bucket '{name}' has a public bucket policy",
                resource=arn,
                description="The bucket policy evaluates as public.",
                remediation="Scope the bucket policy to specific principals; enable Block Public Access.",
                source="s3_bucket_public_policy", raw=status,
            ))
    except ClientError:
        pass

    # Versioning.
    try:
        ver = s3.get_bucket_versioning(Bucket=name)
        if ver.get("Status") != "Enabled":
            out.append(finding(
                ctx, category=CATEGORY, severity=LOW,
                title=f"Bucket '{name}' does not have versioning enabled",
                resource=arn,
                description="Versioning is not enabled, so overwritten/deleted objects are unrecoverable.",
                remediation="Enable bucket versioning.",
                source="s3_bucket_versioning", raw=ver,
            ))
    except ClientError:
        pass

    # Encryption.
    try:
        s3.get_bucket_encryption(Bucket=name)
    except ClientError as e:
        if e.response["Error"]["Code"] == "ServerSideEncryptionConfigurationNotFoundError":
            out.append(finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title=f"Bucket '{name}' has no default encryption",
                resource=arn,
                description="The bucket has no default server-side encryption configuration.",
                remediation="Enable default encryption (SSE-S3 or SSE-KMS).",
                source="s3_bucket_encryption", raw={},
            ))

    # Logging.
    try:
        log = s3.get_bucket_logging(Bucket=name)
        if "LoggingEnabled" not in log:
            out.append(finding(
                ctx, category=CATEGORY, severity=LOW,
                title=f"Bucket '{name}' has no access logging",
                resource=arn,
                description="Server access logging is disabled for the bucket.",
                remediation="Enable S3 server access logging to an audit bucket.",
                source="s3_bucket_logging", raw=log,
            ))
    except ClientError:
        pass

    return out
