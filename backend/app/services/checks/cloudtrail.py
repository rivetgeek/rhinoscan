"""CloudTrail baseline checks."""

from botocore.exceptions import ClientError

from .base import HIGH, LOW, MEDIUM, CheckContext, Finding, finding

CATEGORY = "CloudTrail"


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    ct = ctx.client("cloudtrail")
    trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])

    if not trails:
        return [finding(
            ctx, category=CATEGORY, severity=HIGH,
            title="No CloudTrail trails are configured",
            resource=f"arn:aws:cloudtrail:{ctx.region}:{ctx.account_id}:trail/*",
            description="The account has no CloudTrail trails, so API activity is not recorded.",
            remediation="Create a multi-region trail with log file validation and CloudWatch Logs.",
            source="cloudtrail_exists", raw={},
        )]

    if not any(t.get("IsMultiRegionTrail") for t in trails):
        out.append(finding(
            ctx, category=CATEGORY, severity=MEDIUM,
            title="No multi-region CloudTrail trail exists",
            resource=f"arn:aws:cloudtrail:{ctx.region}:{ctx.account_id}:trail/*",
            description="No trail captures events across all regions.",
            remediation="Enable multi-region logging on at least one trail.",
            source="cloudtrail_multiregion", raw={},
        ))

    for t in trails:
        name = t.get("Name", "")
        arn = t.get("TrailARN", name)

        if not t.get("LogFileValidationEnabled"):
            out.append(finding(
                ctx, category=CATEGORY, severity=LOW,
                title=f"Trail '{name}' does not have log file validation",
                resource=arn,
                description="Log file integrity validation is disabled.",
                remediation="Enable log file validation to detect tampering.",
                source="cloudtrail_log_validation", raw=t,
            ))

        if not t.get("CloudWatchLogsLogGroupArn"):
            out.append(finding(
                ctx, category=CATEGORY, severity=LOW,
                title=f"Trail '{name}' is not integrated with CloudWatch Logs",
                resource=arn,
                description="The trail does not deliver events to CloudWatch Logs for alerting.",
                remediation="Configure CloudWatch Logs integration for metric filters and alarms.",
                source="cloudtrail_cwl", raw=t,
            ))

        # Logging status.
        try:
            status = ct.get_trail_status(Name=arn)
            if not status.get("IsLogging"):
                out.append(finding(
                    ctx, category=CATEGORY, severity=HIGH,
                    title=f"Trail '{name}' is not actively logging",
                    resource=arn,
                    description="The trail exists but logging is currently stopped.",
                    remediation="Start logging on the trail.",
                    source="cloudtrail_logging_status", raw=status,
                ))
        except ClientError:
            pass

    return out
