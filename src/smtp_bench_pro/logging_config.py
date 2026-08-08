"""Logging setup for SMTP Bench Pro."""

import logging
from logging.handlers import RotatingFileHandler
import re
import sys

from smtp_bench_pro.paths import logs_dir

_SECRET_PATTERN = re.compile(r"(?i)(password|passwd|token|secret|api[_-]?key)=([^\s;]+)")
_PATH_PATTERN = re.compile(r"[A-Za-z]:\\[^\s]+|(?<!\w)/(?:[^\s/]+/)+[^\s]+")


def sanitize_log_message(message: object, max_length: int = 300) -> str:
    text = str(message) if message else "Unknown error"
    text = _SECRET_PATTERN.sub(r"\1=<redacted>", text)
    text = _PATH_PATTERN.sub("<path>", text)
    text = " ".join(text.split())
    if len(text) > max_length:
        return text[: max_length - 1].rstrip() + "…"
    return text


def configure_logging() -> None:
    root = logging.getLogger()
    if root.handlers:
        return

    root.setLevel(logging.INFO)
    formatter = logging.Formatter(
        "[%(asctime)s] [%(levelname)s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    console_handler = logging.StreamHandler(sys.stderr)
    console_handler.setFormatter(formatter)
    root.addHandler(console_handler)

    try:
        file_handler = RotatingFileHandler(
            logs_dir() / "smtp-bench-pro.log",
            maxBytes=1_000_000,
            backupCount=3,
            encoding="utf-8",
        )
        file_handler.setFormatter(formatter)
        root.addHandler(file_handler)
    except OSError as exc:
        root.warning("File logging unavailable; continuing with console logging: %s", sanitize_log_message(exc))
