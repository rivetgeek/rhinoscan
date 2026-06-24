import os
from pathlib import Path

from app.core.config import settings

_AWS_ENV_KEYS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_SECRET_ACCESS_KEY",
    "AWS_SESSION_TOKEN",
    "AWS_DEFAULT_REGION",
    "AWS_REGION",
)


def host_data_path(container_path: Path) -> str:
    """
    Map a path inside the backend container to the host path Docker expects
    when launching sibling containers via the mounted docker.sock.
    """
    host_data = settings.HOST_DATA_DIR.strip()
    if not host_data:
        return str(container_path)

    rel = container_path.relative_to(settings.DATA_DIR)
    return str(Path(host_data) / rel)


def docker_aws_args() -> list[str]:
    """Pass through AWS credentials from the backend container to scan containers."""
    args: list[str] = []
    for key in _AWS_ENV_KEYS:
        value = os.environ.get(key)
        if value:
            args.extend(["-e", f"{key}={value}"])
    return args
