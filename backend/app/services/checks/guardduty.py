"""GuardDuty baseline checks (region-scoped to the default region)."""

from collections import Counter

from botocore.exceptions import ClientError

from .base import HIGH, MEDIUM, CheckContext, Finding, finding

CATEGORY = "GuardDuty"


def run(ctx: CheckContext) -> list[Finding]:
    out: list[Finding] = []
    gd = ctx.client("guardduty")

    detectors = gd.list_detectors().get("DetectorIds", [])
    if not detectors:
        return [finding(
            ctx, category=CATEGORY, severity=HIGH,
            title=f"GuardDuty is not enabled in {ctx.region}",
            resource=f"arn:aws:guardduty:{ctx.region}:{ctx.account_id}:detector/*",
            description="No GuardDuty detector exists in the region; threat detection is off.",
            remediation="Enable GuardDuty in all active regions.",
            source="guardduty_enabled", raw={},
        )]

    for detector_id in detectors:
        out += _detector_findings(ctx, gd, detector_id)
    return out


def _detector_findings(ctx, gd, detector_id: str) -> list[Finding]:
    out: list[Finding] = []
    arn = f"arn:aws:guardduty:{ctx.region}:{ctx.account_id}:detector/{detector_id}"

    try:
        finding_ids = []
        paginator = gd.get_paginator("list_findings")
        for page in paginator.paginate(DetectorId=detector_id):
            finding_ids.extend(page.get("FindingIds", []))
    except ClientError:
        return out

    if not finding_ids:
        return out

    # Fetch details in batches of 50 (GetFindings limit).
    details = []
    for i in range(0, len(finding_ids), 50):
        batch = gd.get_findings(DetectorId=detector_id, FindingIds=finding_ids[i:i + 50])
        details.extend(batch.get("Findings", []))

    severity_counts = Counter()
    type_counts = Counter()
    high_sev = []
    for f in details:
        sev = f.get("Severity", 0)
        bucket = "high" if sev >= 7 else "medium" if sev >= 4 else "low"
        severity_counts[bucket] += 1
        type_counts[f.get("Type", "Unknown")] += 1
        if sev >= 7:
            high_sev.append(f)

    out.append(finding(
        ctx, category=CATEGORY, severity=MEDIUM,
        title=f"GuardDuty has {len(details)} active finding(s)",
        resource=arn,
        description=(
            f"Findings by severity: {dict(severity_counts)}. "
            f"Top types: {dict(type_counts.most_common(5))}."
        ),
        remediation="Triage and remediate GuardDuty findings; archive false positives.",
        source="guardduty_findings_summary",
        raw={"severity_counts": dict(severity_counts), "type_counts": dict(type_counts)},
    ))

    for f in high_sev:
        out.append(finding(
            ctx, category=CATEGORY, severity=HIGH,
            title=f"GuardDuty high-severity finding: {f.get('Type', 'Unknown')}",
            resource=f.get("Arn", arn),
            description=f.get("Description", "")[:1000] or "High-severity GuardDuty finding.",
            remediation="Investigate immediately; this indicates likely active compromise.",
            source="guardduty_high_severity", raw=f,
        ))
    return out
