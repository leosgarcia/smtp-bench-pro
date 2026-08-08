"""Table widget for SMTP probe results."""

from __future__ import annotations

from PySide6.QtWidgets import QHeaderView, QTableWidget, QTableWidgetItem

from smtp_bench_pro.domain.results import SMTPProbeResult


class ResultsTable(QTableWidget):
    HEADERS = [
        "Servidor",
        "IP",
        "Porta",
        "Seguranca",
        "TCP ms",
        "Banner ms",
        "EHLO ms",
        "TLS ms",
        "Total ms",
        "Status",
        "Detalhes",
    ]

    def __init__(self, parent=None):
        super().__init__(0, len(self.HEADERS), parent)
        self.setHorizontalHeaderLabels(self.HEADERS)
        self.setAlternatingRowColors(True)
        self.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.setEditTriggers(QTableWidget.EditTrigger.NoEditTriggers)
        self.horizontalHeader().setStretchLastSection(True)
        self.horizontalHeader().setSectionResizeMode(QHeaderView.ResizeMode.ResizeToContents)
        self._results: list[SMTPProbeResult] = []

    def clear_results(self) -> None:
        self._results.clear()
        self.setRowCount(0)

    def add_result(self, result: SMTPProbeResult) -> None:
        row = self.rowCount()
        self.insertRow(row)
        self._results.append(result)
        values = [
            result.hostname,
            result.resolved_ip or "-",
            str(result.port),
            result.security_mode.value,
            self._fmt(result.tcp_connect_ms),
            self._fmt(result.banner_ms),
            self._fmt(result.ehlo_ms),
            self._fmt(result.tls_handshake_ms),
            self._fmt(result.total_ms),
            result.status.value,
            result.error_message or "OK",
        ]
        for column, value in enumerate(values):
            self.setItem(row, column, QTableWidgetItem(value))

    def result_at(self, row: int) -> SMTPProbeResult | None:
        if 0 <= row < len(self._results):
            return self._results[row]
        return None

    def all_results(self) -> list[SMTPProbeResult]:
        return list(self._results)

    def _fmt(self, value: float | None) -> str:
        return "-" if value is None else f"{value:.2f}"
