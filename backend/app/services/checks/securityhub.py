"""Security Hub baseline checks (region-scoped to the default region)."""

from collections import Counter

from botocore.exceptions import ClientError

from .base import HIGH, MEDIUM, CheckContext, Finding, finding

CATEGORY = "SecurityHub"


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    sh = ctx.client("securityhub")

    try:
        sh.describe_hub()
    except ClientError as e:
        code = e.response["Error"]["Code"]
        if code in ("InvalidAccessException", "ResourceNotFoundException"):
            return [finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title=f"Security Hub is not enabled in {ctx.region}",
                resource=f"arn:aws:securityhub:{ctx.region}:{ctx.account_id}:hub/default",
                description="Security Hub is not enabled; standards and aggregated findings are unavailable.",
                remediation="Enable Security Hub and the AWS Foundational Security Best Practices standard.",
                source="securityhub_enabled", raw={"error": code},
            )]
        raise

    # Enabled standards.
    try:
        standards = sh.get_enabled_standards().get("StandardsSubscriptions", [])
        if not standards:
            out.append(finding(
                ctx, category=CATEGORY, severity=MEDIUM,
                title="Security Hub has no enabled standards",
                resource=f"arn:aws:securityhub:{ctx.region}:{ctx.account_id}:hub/default",
                description="Security Hub is enabled but no compliance standards are active.",
                remediation="Enable the AWS Foundational Security Best Practices and CIS standards.",
                source="securityhub_standards", raw={},
            ))
    except ClientError:
        pass

    # Failed controls.
    try:
        failed = []
        paginator = sh.get_paginator("get_findings")
        filters = {
            "ComplianceStatus": [{"Value": "FAILED", "Comparison": "EQUALS"}],
            "RecordState": [{"Value": "ACTIVE", "Comparison": "EQUALS"}],
        }
        for page in paginator.paginate(Filters=filters, MaxResults=100):
            failed.extend(page.get("Findings", []))
            if len(failed) >= 500:  # cap to keep the scan bounded
                break

        if failed:
            sev_counts = Counter(
                (f.get("Severity", {}).get("Label", "UNKNOWN")) for f in failed
            )
            out.append(finding(
                ctx, category=CATEGORY, severity=HIGH if sev_counts.get("CRITICAL") else MEDIUM,
                title=f"Security Hub reports {len(failed)} failed control(s)",
                resource=f"arn:aws:securityhub:{ctx.region}:{ctx.account_id}:hub/default",
                description=f"Failed controls by severity: {dict(sev_counts)}.",
                remediation="Work through failed Security Hub controls starting with Critical/High.",
                source="securityhub_failed_controls", raw={"severity_counts": dict(sev_counts)},
            ))
    except ClientError:
        pass

    return out
