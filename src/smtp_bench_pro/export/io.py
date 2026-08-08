"""Shared file-system helpers for SMTP Bench Pro exporters."""

from __future__ import annotations

import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
from collections.abc import Callable


def atomic_write(path: Path, payload: dict[str, object], writer: Callable[[Path, dict[str, object]], None]) -> None:
    """Write an export file atomically using the provided writer."""
    temp_path = None
    with NamedTemporaryFile("w", encoding="utf-8", delete=False, dir=path.parent, suffix=path.suffix) as temp_file:
        temp_path = Path(temp_file.name)
    try:
        writer(temp_path, payload)
        os.replace(temp_path, path)
    except Exception:
        if temp_path is not None and temp_path.exists():
            temp_path.unlink(missing_ok=True)
        raise


def safe_filename_part(value: str) -> str:
    """Return a Windows-safe filename component."""
    safe = re.sub(r"[^A-Za-z0-9._-]+", "-", value).strip(".-")
    return safe[:80] or "smtp"

