"""Account-level baseline checks."""

from botocore.exceptions import ClientError

from .base import HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "Account"


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    out += _alternate_contacts(ctx)
    out += _config_recorder(ctx)
    out += _config_delivery(ctx)
    out += _access_analyzer(ctx)
    out += _ebs_default_encryption(ctx)
    return out


def _alternate_contacts(ctx) -> list[Finding]:
    acct = ctx.client("account", region="us-east-1")
    missing = []
    for ctype in ("SECURITY", "BILLING", "OPERATIONS"):
        try:
            acct.get_alternate_contact(AlternateContactType=ctype)
        except acct.exceptions.ResourceNotFoundException:
            missing.append(ctype)
        except ClientError:
            return []  # no Account API access — skip silently
    if missing:
        return [finding(
            ctx, category=CATEGORY, severity=LOW,
            title="Alternate contacts are not fully configured",
            resource=f"arn:aws:account::{ctx.account_id}:account",
            description="Missing alternate contacts: " + ", ".join(missing) + ".",
            remediation="Set Security, Billing and Operations alternate contacts.",
            source="account_alternate_contacts", raw={"missing": missing},
        )]
    return []


def _config_recorder(ctx) -> list[Finding]:
    cfg = ctx.client("config")
    recorders = cfg.describe_configuration_recorders().get("ConfigurationRecorders", [])
    if not recorders:
        return [finding(
            ctx, category=CATEGORY, severity=MEDIUM,
            title=f"AWS Config has no recorder in {ctx.region}",
            resource=f"arn:aws:config:{ctx.region}:{ctx.account_id}:config-recorder/*",
            description="AWS Config is not recording resource configuration changes.",
            remediation="Enable an AWS Config recorder covering all resource types.",
            source="config_recorder", raw={},
        )]
    # Check recorder is actually running.
    statuses = cfg.describe_configuration_recorder_status().get("ConfigurationRecordersStatus", [])
    if not any(s.get("recording") for s in statuses):
        return [finding(
            ctx, category=CATEGORY, severity=MEDIUM,
            title=f"AWS Config recorder is not running in {ctx.region}",
            resource=f"arn:aws:config:{ctx.region}:{ctx.account_id}:config-recorder/*",
            description="A Config recorder exists but is not currently recording.",
            remediation="Start the AWS Config recorder.",
            source="config_recorder", raw={"statuses": statuses},
        )]
    return []


def _config_delivery(ctx) -> list[Finding]:
    cfg = ctx.client("config")
    channels = cfg.describe_delivery_channels().get("DeliveryChannels", [])
    if not channels:
        return [finding(
            ctx, category=CATEGORY, severity=LOW,
            title=f"AWS Config has no delivery channel in {ctx.region}",
            resource=f"arn:aws:config:{ctx.region}:{ctx.account_id}:delivery-channel/*",
            description="AWS Config has no delivery channel, so configuration snapshots are not stored.",
            remediation="Configure an S3 delivery channel for AWS Config.",
            source="config_delivery_channel", raw={},
        )]
    return []


def _access_analyzer(ctx) -> list[Finding]:
    aa = ctx.client("accessanalyzer")
    analyzers = aa.list_analyzers().get("analyzers", [])
    active = [a for a in analyzers if a.get("status") == "ACTIVE"]
    if not active:
        return [finding(
            ctx, category=CATEGORY, severity=MEDIUM,
            title=f"IAM Access Analyzer is not active in {ctx.region}",
            resource=f"arn:aws:access-analyzer:{ctx.region}:{ctx.account_id}:analyzer/*",
            description="No active IAM Access Analyzer; external resource exposure is not monitored.",
            remediation="Create an account or organization-level Access Analyzer.",
            source="access_analyzer", raw={},
        )]
    return []


def _ebs_default_encryption(ctx) -> list[Finding]:
    ec2 = ctx.client("ec2")
    try:
        enabled = ec2.get_ebs_encryption_by_default().get("EbsEncryptionByDefault", False)
    except ClientError:
        return []
    if not enabled:
        return [finding(
            ctx, category=CATEGORY, severity=HIGH,
            title=f"Account-level default EBS encryption is disabled in {ctx.region}",
            resource=f"arn:aws:ec2:{ctx.region}:{ctx.account_id}:ebs-default-encryption",
            description="New EBS volumes are not encrypted by default in this region.",
            remediation="Enable EBS encryption by default for the account/region.",
            source="ec2_ebs_default_encryption", raw={},
        )]
    return []
