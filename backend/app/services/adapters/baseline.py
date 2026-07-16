"""Baseline adapter — RhinoScan's proprietary boto3 check battery."""

import logging

from sqlalchemy.orm import Session

from app.services.aws_profiles import get_account_id, get_session
from app.services.checks import CHECK_MODULES
from app.services.checks.base import INFORMATIONAL, CheckContext, Finding

from .base import TARGET_AWS, AdapterContext, prune_stale_findings, upsert_finding

log = logging.getLogger("rhinoscan.adapters.baseline")


class BaselineAdapter:
    engine = "baseline"
    origin = "Baseline"
    target_type = TARGET_AWS
    label = "Baseline (RhinoScan checks)"

    def scan(self, target: str, run_id: str, db: Session, ctx: AdapterContext) -> int:
        session = get_session(target, ctx.region)
        account_id = get_account_id(session)
        check_ctx = CheckContext(
            session=session, profile=target,
            account_id=account_id or "unknown", region=ctx.region,
        )

        findings: list[Finding] = []
        for module in CHECK_MODULES:
            findings += _run_module(check_ctx, module)

        for f in findings:
            upsert_finding(db, run_id, f)
        prune_stale_findings(db, target, self.origin, run_id)
        db.commit()
        return len(findings)


def _run_module(ctx: CheckContext, module) -> list[Finding]:
    """Run a single check module, capturing failures as Informational findings."""
    try:
        return module.run(ctx)
    except Exception as e:
        category = getattr(module, "CATEGORY", module.__name__.split(".")[-1])
        log.warning("check %s failed for %s: %s", category, ctx.profile, e)
        return [Finding(
            profile=ctx.profile, account_id=ctx.account_id,
            category=category, severity=INFORMATIONAL,
            title=f"{category} checks could not complete",
            resource=f"profile:{ctx.profile}:{category}",
            description=f"The {category} check battery raised an error and was skipped: {e}",
            remediation="Verify the profile has the required read-only permissions for this service.",
            source=f"{category.lower()}_check_error", raw={"error": str(e)},
        )]
