from pathlib import Path

from app.core.config import settings


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
