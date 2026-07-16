"""AWS profile discovery and session creation.

This replaces the v1 model where the operator pasted a client IAM role ARN into
the UI. RhinoScan instead reads the configured profile chain from ``~/.aws/config``
and resolves credentials exactly as the operator's AWS CLI would.

Credential resolution is delegated to the AWS CLI v2 via
``aws configure export-credentials`` rather than boto3's own chain. This is
deliberate: boto3/botocore ships no ``login`` provider for the CLI v2 web
sign-in flow (``aws login``), so a containerised boto3 cannot resolve a profile
whose chain bottoms out at a ``login_session``. The CLI can — and it reuses the
operator's existing session cached under ~/.aws (mounted into the container) —
so we let it mint short-lived keys and hand those to boto3. When no CLI / login
session is available we fall back to boto3's native resolution (env vars,
shared credentials file, SSO, source_profile), preserving the prior behaviour.
"""

import json
import logging
import os
import shutil
import subprocess

import boto3
from botocore.exceptions import BotoCoreError, ClientError

from app.core.config import settings

log = logging.getLogger("rhinoscan.aws_profiles")


def _config_path() -> str:
    return os.path.expanduser(settings.AWS_CONFIG_FILE)


def _export_credentials(profile: str) -> dict | None:
    """Resolve a profile to temporary keys via the AWS CLI v2.

    Runs ``aws configure export-credentials``, which walks the full chain
    (login web sign-in → source_profile role assumption, with external_id/MFA)
    just like the CLI does, and returns plain keys. Returns ``None`` when the
    CLI is absent or resolution fails, so callers can fall back to boto3.
    """
    aws = shutil.which("aws")
    if not aws:
        return None
    env = {**os.environ, "AWS_CONFIG_FILE": _config_path()}
    try:
        proc = subprocess.run(
            [aws, "configure", "export-credentials",
             "--profile", profile, "--format", "process"],
            capture_output=True, text=True, timeout=60, env=env,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        log.warning("export-credentials failed for %s: %s", profile, exc)
        return None
    if proc.returncode != 0:
        log.warning("export-credentials non-zero for %s: %s",
                    profile, proc.stderr.strip())
        return None
    try:
        data = json.loads(proc.stdout)
        return {
            "aws_access_key_id": data["AccessKeyId"],
            "aws_secret_access_key": data["SecretAccessKey"],
            "aws_session_token": data.get("SessionToken"),
        }
    except (json.JSONDecodeError, KeyError) as exc:
        log.warning("export-credentials bad output for %s: %s", profile, exc)
        return None


def list_profiles() -> list[str]:
    """Return scannable profiles from ~/.aws/config, excluding operator profiles.

    Uses botocore's own parser so SSO sessions, ``[profile name]`` sections and
    the bare ``[default]`` section are all resolved the same way the CLI sees
    them. Order is preserved as written in the config file.
    """
    # Point botocore at the configured file, then read every available profile.
    os.environ["AWS_CONFIG_FILE"] = _config_path()
    session = boto3.Session()
    excluded = settings.excluded_profiles
    return [p for p in session.available_profiles if p not in excluded]


def get_session(profile: str, region: str | None = None) -> boto3.Session:
    """Create a boto3 session for a named profile.

    Prefers credentials minted by the AWS CLI (so the operator's ``aws login``
    session is reused); falls back to boto3's own profile resolution when the
    CLI can't help (env vars, shared credentials, SSO, source_profile).
    """
    os.environ["AWS_CONFIG_FILE"] = _config_path()
    region = region or settings.AWS_DEFAULT_REGION
    creds = _export_credentials(profile)
    if creds:
        return boto3.Session(region_name=region, **creds)
    return boto3.Session(profile_name=profile, region_name=region)


def get_account_id(session: boto3.Session) -> str:
    """Resolve the account id for a session via STS. Returns "" on failure."""
    try:
        return session.client("sts").get_caller_identity()["Account"]
    except (ClientError, BotoCoreError):
        return ""


def get_frozen_credentials(session: boto3.Session) -> dict[str, str]:
    """Resolve a profile's credential chain to static keys.

    boto3 walks the chain (SSO, source_profile, role_arn, MFA) and hands back
    concrete temporary credentials. These can be passed as env vars into the
    Prowler/TruffleHog sibling containers, which have no access to ~/.aws — so
    the profile dropdown drives the legacy path without any pasted role ARN.
    """
    creds = session.get_credentials()
    if creds is None:
        raise RuntimeError("Profile has no resolvable credentials")
    frozen = creds.get_frozen_credentials()
    env = {
        "AWS_ACCESS_KEY_ID": frozen.access_key,
        "AWS_SECRET_ACCESS_KEY": frozen.secret_key,
    }
    if frozen.token:
        env["AWS_SESSION_TOKEN"] = frozen.token
    return env
