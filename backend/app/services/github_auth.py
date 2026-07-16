"""
github_auth.py
--------------

Utility to obtain a GitHub API token for RhinoScan / RhinoEye.

Resolution order:
    1. Environment variable `GH_TOKEN`      (matches gh's own precedence)
    2. Environment variable `GITHUB_TOKEN`
    3. Token stored by the GitHub CLI in ~/.config/gh/hosts.yml
       (uses PyYAML if available; falls back to a minimal, indent-aware parser)

If no token is found, raises RuntimeError. The result -- success or failure --
is cached after the first call.

Standard-library only, except for an *optional* dependency on PyYAML.
"""

from __future__ import annotations

import logging
import os
import pathlib
import sys
import threading
from typing import Final, Optional

__all__ = ["get_gh_token", "resolve_gh_token"]

# --------------------------------------------------------------------------- #
# Logging. We attach a NullHandler so this module is silent until the host
# application configures real logging -- effectively /dev/null for now. The
# "no token found" case is logged at WARNING so it surfaces the moment a real
# handler is wired up (that's the "needs attention" severity).
logger = logging.getLogger(__name__)
logger.addHandler(logging.NullHandler())

# --------------------------------------------------------------------------- #
_HOSTS_PATH: Final[pathlib.Path] = pathlib.Path.home() / ".config" / "gh" / "hosts.yml"

# Checked in order; first non-empty value wins. Mirrors gh's own precedence.
_ENV_VARS: Final[tuple[str, ...]] = ("GH_TOKEN", "GITHUB_TOKEN")

# Defensive bound on the config read. gh's hosts.yml is normally well under a
# kilobyte; anything past this is implausible and we refuse to read/parse it
# rather than pull an arbitrarily large file into memory.
_MAX_HOSTS_BYTES: Final[int] = 1 << 20  # 1 MiB

_NO_TOKEN_MSG: Final[str] = (
    "No GitHub token found. Set GH_TOKEN or GITHUB_TOKEN, "
    "or authenticate via `gh auth login`."
)

# --------------------------------------------------------------------------- #
# Cache state:
#   _UNSET -> not yet resolved
#   None   -> resolved, no token found (failure is cached / sticky)
#   str    -> resolved token
# Guarded by a threading.Lock: get_gh_token() is synchronous and, under
# FastAPI, runs in the sync worker threadpool -- so a threading primitive is
# the correct one (asyncio.Lock would only guard coroutines on one event loop).
_UNSET: Final = object()
_cache_lock: Final = threading.Lock()
_cached_result: object = _UNSET


def _mask(token: str) -> str:
    """Return a masked representation of the token (first 4 ... last 4)."""
    if len(token) <= 8:
        return "*" * len(token)
    return f"{token[:4]}…{token[-4:]}"


def _read_hosts_yml() -> Optional[str]:
    """
    Parse ~/.config/gh/hosts.yml and return the host-level oauth_token for
    github.com.

    Tries PyYAML if present; otherwise falls back to a minimal, indent-aware
    parser. Returns None if the file is missing, too large, or has no token.
    """
    if not _HOSTS_PATH.exists():
        return None

    try:
        size = _HOSTS_PATH.stat().st_size
        if size > _MAX_HOSTS_BYTES:
            logger.warning(
                "%s is unexpectedly large (%d bytes); refusing to parse.",
                _HOSTS_PATH, size,
            )
            return None
        content = _HOSTS_PATH.read_text(encoding="utf-8")
    except OSError:
        return None

    try:
        import yaml  # type: ignore
    except ModuleNotFoundError:
        yaml = None  # type: ignore

    if yaml is not None:
        try:
            data = yaml.safe_load(content) or {}
            host_entry = data.get("github.com", {})
            if isinstance(host_entry, dict):
                token = host_entry.get("oauth_token")
                return str(token) if token else None
        except Exception:
            # Malformed YAML -- degrade to the manual parser below.
            pass

    return _parse_hosts_yml_manually(content)


def _parse_hosts_yml_manually(content: str) -> Optional[str]:
    """
    Indent-aware fallback parser.

    gh's hosts.yml stores a per-user copy of oauth_token under `users:` in
    addition to the canonical host-level key:

        github.com:
            users:
                you:
                    oauth_token: gho_aaa   # per-user copy -- NOT this one
            oauth_token: gho_bbb           # host-level    -- THIS one

    A naive "first oauth_token wins" scan can return the wrong one depending on
    key ordering. We therefore accept oauth_token only at github.com's *direct
    child* indentation level, which is the host-level key gh treats as active.
    """
    inside_host = False
    child_indent: Optional[int] = None

    for raw in content.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        indent = len(raw) - len(raw.lstrip())

        if not inside_host:
            if indent == 0 and stripped.startswith("github.com:"):
                inside_host = True
            continue

        # Inside the github.com block.
        if indent == 0:
            break  # dedented to the next top-level host -- stop

        if child_indent is None:
            child_indent = indent  # first child establishes the canonical level

        if indent == child_indent:
            key, sep, value = stripped.partition(":")
            if sep and key.strip() == "oauth_token":
                token = value.strip().strip("'\"")
                return token or None

    return None


def _resolve_token() -> Optional[str]:
    """Run the resolution order exactly once. Returns a token or None."""
    for var in _ENV_VARS:
        value = os.environ.get(var)
        if value and value.strip():
            return value.strip()

    cli_token = _read_hosts_yml()
    if cli_token:
        return cli_token.strip()

    logger.warning(
        "No GitHub token resolved from env (%s) or %s.",
        ", ".join(_ENV_VARS), _HOSTS_PATH,
    )
    return None


def get_gh_token() -> str:
    """
    Return a GitHub API token according to the resolution order.

    Successful tokens are cached; on miss, the lookup re-runs on the next call,
    so newly-set tokens are picked up immediately without restart.

    Raises
    ------
    RuntimeError
        If no token can be found.
    """
    global _cached_result

    result = _cached_result
    if result is not _UNSET:
        return result

    with _cache_lock:
        if _cached_result is _UNSET:  # double-checked under the lock
            token = _resolve_token()
            if token is not None:
                _cached_result = token
            else:
                raise RuntimeError(_NO_TOKEN_MSG)
        return _cached_result


def resolve_gh_token() -> Optional[str]:
    """Non-raising variant of :func:`get_gh_token`.

    Returns the resolved token, or ``None`` when no token is configured. Use
    this in the scan pipeline where a missing token should cleanly *skip* the
    GitHub-side scanners rather than abort the run.
    """
    try:
        return get_gh_token()
    except RuntimeError:
        return None


if __name__ == "__main__":
    try:
        print(f"Token found: {_mask(get_gh_token())}")
        sys.exit(0)
    except RuntimeError as exc:
        print(exc)
        sys.exit(1)
