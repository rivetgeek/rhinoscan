"""RhinoScan baseline check battery.

Each entry is a check module exposing ``run(ctx: CheckContext) -> list[Finding]``.
The scanner iterates this registry, runs each module in isolation, and converts
any unexpected error into an Informational finding so one failure never aborts
the assessment.
"""

from . import account, cloudtrail, ec2, guardduty, identity, lambda_, s3, securityhub

# Ordered roughly by category importance for readability in reports.
CHECK_MODULES = [
    identity,
    s3,
    cloudtrail,
    guardduty,
    securityhub,
    ec2,
    lambda_,
    account,
]
