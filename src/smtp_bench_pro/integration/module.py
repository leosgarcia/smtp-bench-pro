"""Bench Pro Integration API v1 adapter.

This module intentionally imports nothing from Bench Pro Core. The Core validates
this object through duck typing / a local Protocol.
"""

from __future__ import annotations

from PySide6.QtWidgets import QWidget

from smtp_bench_pro.ui.widgets.smtp_bench_widget import SMTPBenchWidget
from smtp_bench_pro.version import __version__


class SMTPBenchModule:
    module_id = "smtp"
    display_name = "SMTP Bench Pro"
    version = __version__
    integration_api = 1
    vendor = "WL Tech"
    capabilities = frozenset({"benchmark", "diagnostics", "history", "security_audit"})
    description = "Professional SMTP benchmark and diagnostics module."
    icon = None

    def __init__(self) -> None:
        self._widget: SMTPBenchWidget | None = None

    def initialize(self) -> None:
        return None

    def create_widget(self, parent: QWidget | None = None) -> QWidget:
        if self._widget is None:
            self._widget = SMTPBenchWidget(parent=parent, include_about=False)
        return self._widget

    def shutdown(self) -> None:
        if self._widget is not None:
            self._widget.close()
            self._widget.deleteLater()
            self._widget = None
