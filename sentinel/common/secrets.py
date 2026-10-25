"""Secret loading that works with Docker secrets and plain env vars."""
from __future__ import annotations

import os
from pathlib import Path


def get_secret(name: str, default: str | None = None) -> str | None:
    """Return a secret by name.

    If NAME_FILE is set, the secret is read from that file (the Docker secrets
    convention, e.g. /run/secrets/token). Otherwise NAME is read from the
    environment. The file form is preferred so the value never appears in
    `docker inspect` output or in the process environment.
    """
    file_path = os.environ.get(f"{name}_FILE")
    if file_path:
        return Path(file_path).read_text(encoding="utf-8").strip()
    return os.environ.get(name, default)
