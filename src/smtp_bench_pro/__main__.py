"""Entrypoint for SMTP Bench Pro."""

from __future__ import annotations

import argparse
import sys

from PySide6.QtWidgets import QApplication

from smtp_bench_pro.logging_config import configure_logging
from smtp_bench_pro.ui.main_window import SMTPBenchMainWindow
from smtp_bench_pro.ui.styles import APP_STYLESHEET
from smtp_bench_pro.version import __version__


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="SMTP Bench Pro")
    parser.add_argument("--version", action="store_true", help="Show version and exit")
    args = parser.parse_args(argv)
    if args.version:
        print(f"SMTP Bench Pro {__version__}")
        return 0

    configure_logging()
    app = QApplication(sys.argv if argv is None else [sys.argv[0], *argv])
    app.setOrganizationName("WL Tech")
    app.setApplicationName("SMTP Bench Pro")
    app.setStyleSheet(APP_STYLESHEET)
    window = SMTPBenchMainWindow()
    window.show()
    return app.exec()


if __name__ == "__main__":
    raise SystemExit(main())
