"""Application paths for SMTP Bench Pro."""

from __future__ import annotations

import os
from pathlib import Path

VENDOR_NAME = "WL Tech"
APP_NAME = "SMTP Bench Pro"
APP_WEBSITE = "https://wltech.com.br"
APP_REPOSITORY = "https://github.com/leosgarcia/smtp-bench-pro"
APP_TAGLINE = "Benchmark, diagnóstico e auditoria profissional de servidores SMTP."


def app_data_dir() -> Path:
    """Return the product-owned application data directory for SMTP Bench Pro."""
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    path = base / VENDOR_NAME / APP_NAME
    path.mkdir(parents=True, exist_ok=True)
    return path


def logs_dir() -> Path:
    path = app_data_dir() / "logs"
    path.mkdir(parents=True, exist_ok=True)
    return path


def database_path() -> Path:
    return app_data_dir() / "smtp-bench-pro.db"
