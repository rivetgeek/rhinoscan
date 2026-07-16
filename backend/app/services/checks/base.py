"""Shared primitives for the RhinoScan baseline check battery.

Every check is a plain function that takes a ``CheckContext`` and returns a list
of ``Finding`` objects. Checks are read-only and must never raise — the scanner
wraps each one and converts unexpected errors into Informational findings so a
single failed API call never aborts the whole assessment (PRD implementation
note).
"""

import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone

import boto3

# Severity levels (PRD finding data model).
CRITICAL = "Critical"
HIGH = "High"
MEDIUM = "Medium"
LOW = "Low"
INFORMATIONAL = "Informational"

SEVERITY_ORDER = {
    CRITICAL: 0,
    HIGH: 1,
    MEDIUM: 2,
    LOW: 3,
    INFORMATIONAL: 4,
}

# Engine that produced a finding. Baseline findings all originate here; the
# Prowler/TruffleHog paths set their own origin when they get aggregated in.
ORIGIN_BASELINE = "Baseline"

# Maps each check ``source`` to the read-only AWS API call(s) it derives from,
# so an analyst can manually re-run the exact call to verify a finding. New
# checks MUST add their source here (a missing entry just yields an empty api
# string — verifiable but less convenient). Format: ``service:Operation``.
SOURCE_API = {
    # Account
    "account_alternate_contacts": "account:GetAlternateContact",
    "config_recorder": "config:DescribeConfigurationRecorders, config:DescribeConfigurationRecorderStatus",
    "config_delivery_channel": "config:DescribeDeliveryChannels",
    "access_analyzer": "accessanalyzer:ListAnalyzers",
    "ec2_ebs_default_encryption": "ec2:GetEbsEncryptionByDefault",
    # CloudTrail
    "cloudtrail_exists": "cloudtrail:DescribeTrails",
    "cloudtrail_multiregion": "cloudtrail:DescribeTrails",
    "cloudtrail_log_validation": "cloudtrail:DescribeTrails",
    "cloudtrail_cwl": "cloudtrail:DescribeTrails",
    "cloudtrail_logging_status": "cloudtrail:GetTrailStatus",
    # EC2
    "ec2_sg_open_ipv4": "ec2:DescribeSecurityGroups",
    "ec2_sg_open_ipv6": "ec2:DescribeSecurityGroups",
    "ec2_imdsv2": "ec2:DescribeInstances",
    "ec2_unencrypted_volume": "ec2:DescribeVolumes",
    "ec2_unencrypted_snapshot": "ec2:DescribeSnapshots",
    "ec2_default_vpc": "ec2:DescribeVpcs",
    # GuardDuty
    "guardduty_enabled": "guardduty:ListDetectors",
    "guardduty_findings_summary": "guardduty:ListFindings, guardduty:GetFindings",
    "guardduty_high_severity": "guardduty:GetFindings",
    # Identity / IAM
    "iam_root_mfa": "iam:GetAccountSummary",
    "iam_root_access_keys": "iam:GetCredentialReport",
    "iam_user_two_keys": "iam:GetCredentialReport",
    "iam_key_age_90": "iam:GetCredentialReport",
    "iam_console_no_mfa": "iam:GetCredentialReport",
    "iam_password_policy": "iam:GetAccountPasswordPolicy",
    "iam_human_users": "iam:ListUsers",
    # Lambda
    "lambda_env_secrets": "lambda:ListFunctions",
    "lambda_deprecated_runtime": "lambda:ListFunctions",
    "lambda_public_url": "lambda:ListFunctionUrlConfigs",
    "lambda_role_summary": "lambda:ListFunctions",
    # S3
    "s3_list_buckets": "s3:ListAllMyBuckets",
    "s3_account_block_public_access": "s3control:GetPublicAccessBlock",
    "s3_bucket_public_acl": "s3:GetBucketAcl",
    "s3_bucket_public_policy": "s3:GetBucketPolicyStatus",
    "s3_bucket_versioning": "s3:GetBucketVersioning",
    "s3_bucket_encryption": "s3:GetBucketEncryption",
    "s3_bucket_logging": "s3:GetBucketLogging",
    # Security Hub
    "securityhub_enabled": "securityhub:DescribeHub",
    "securityhub_standards": "securityhub:GetEnabledStandards",
    "securityhub_failed_controls": "securityhub:GetFindings",
}


@dataclass
class CheckContext:
    """Everything a check needs to talk to one account."""

    session: boto3.Session
    profile: str
    account_id: str
    region: str

    def client(self, service: str, region: str | None = None):
        return self.session.client(service, region_name=region or self.region)


@dataclass
class Finding:
    profile: str
    account_id: str
    category: str
    severity: str
    title: str
    resource: str
    description: str
    remediation: str
    source: str
    raw: dict = field(default_factory=dict)
    timestamp: str = ""
    id: str = ""
    origin: str = ORIGIN_BASELINE
    api: str = ""

    def __post_init__(self):
        if not self.timestamp:
            self.timestamp = datetime.now(timezone.utc).isoformat()
        if not self.id:
            # Deterministic across runs so deltas are trackable (PRD note).
            key = f"{self.profile}|{self.source}|{self.resource}"
            self.id = hashlib.sha256(key.encode()).hexdigest()[:32]
        if not self.api:
            # The AWS API call(s) backing this finding, for manual verification.
            self.api = SOURCE_API.get(self.source, "")
        # Ensure raw is JSON-serializable (boto3 returns datetimes etc.).
        self.raw = json.loads(json.dumps(self.raw, default=str))


def finding(ctx: CheckContext, **kwargs) -> Finding:
    """Build a Finding pre-filled with the context's profile + account."""
    return Finding(profile=ctx.profile, account_id=ctx.account_id, **kwargs)
