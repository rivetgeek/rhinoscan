"""Scanner adapter registry.

One findings model, many engines. Each adapter wraps one scanner —
proprietary or open source — behind the ``ScannerAdapter`` contract
(see ``base``). Adding a new engine means adding one adapter here;
no new tables, endpoints, or UI pages.
"""

from .base import (  # noqa: F401
    TARGET_AWS,
    TARGET_GITHUB,
    AdapterContext,
    ScannerAdapter,
    github_org,
    target_type,
)
from .baseline import BaselineAdapter
from .prowler_aws import ProwlerAwsAdapter
from .prowler_github import ProwlerGithubAdapter
from .scorecard import ScorecardAdapter
from .trufflehog import TrufflehogAdapter

ADAPTERS: dict[str, ScannerAdapter] = {
    a.engine: a
    for a in (
        BaselineAdapter(),
        ProwlerAwsAdapter(),
        ProwlerGithubAdapter(),
        TrufflehogAdapter(),
        ScorecardAdapter(),
    )
}


def engines_for(target: str) -> list[str]:
    """Engine names applicable to a target, in registry order."""
    t = target_type(target)
    return [name for name, a in ADAPTERS.items() if a.target_type == t]
