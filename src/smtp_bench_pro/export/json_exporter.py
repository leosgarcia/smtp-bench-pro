"""JSON exporter for persisted historical SMTP runs."""

from __future__ import annotations

import json
from pathlib import Path


def render_json(payload: dict[str, object]) -> str:
    """Render canonical export payload as readable UTF-8 JSON text."""
    return json.dumps(payload, ensure_ascii=False, indent=2) + "\n"


def write_json(path: Path, payload: dict[str, object]) -> None:
    path.write_text(render_json(payload), encoding="utf-8")
