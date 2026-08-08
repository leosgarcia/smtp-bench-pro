"""Dialog for historical run comparison results."""

from __future__ import annotations

import logging

from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QDialog,
    QFileDialog,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QPushButton,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
)

from smtp_bench_pro.comparison.models import RunComparison
from smtp_bench_pro.comparison.presentation import (
    change_label,
    delta_text,
    finding_label,
    percent_text,
    trend_label,
    value_text,
)
from smtp_bench_pro.export.comparison_export import ComparisonExportService

logger = logging.getLogger(__name__)


class HistoricalComparisonDialog(QDialog):
    """Read-only comparison view for two persisted SMTP runs."""

    def __init__(self, comparison: RunComparison, parent=None):
        super().__init__(parent)
        self.comparison = comparison
        self.export_service = ComparisonExportService()
        self.setWindowTitle("Comparação de Execuções")
        self.resize(980, 720)
        layout = QVBoxLayout(self)
        header_row = QHBoxLayout()
        header = QLabel(
            f"Execução Base #{value_text(comparison.baseline.run_id)}  vs  "
            f"Execução Comparada #{value_text(comparison.compared.run_id)}"
        )
        header.setWordWrap(True)
        self.export_button = QPushButton("Exportar Comparação")
        self.export_button.setMenu(self._build_export_menu())
        header_row.addWidget(header, 1)
        header_row.addWidget(self.export_button)
        layout.addLayout(header_row)
        self.status_label = QLabel("")
        self.status_label.setWordWrap(True)
        layout.addWidget(self.status_label)
        self.tabs = QTabWidget()
        self.tabs.addTab(self._summary_tab(), "Resumo")
        self.tabs.addTab(self._performance_tab(), "Performance")
        self.tabs.addTab(self._smtp_tab(), "SMTP")
        self.tabs.addTab(self._tls_tab(), "TLS")
        self.tabs.addTab(self._security_tab(), "Segurança")
        layout.addWidget(self.tabs, 1)

    def _build_export_menu(self):
        from PySide6.QtWidgets import QMenu

        menu = QMenu(self)
        json_action = QAction("JSON", self)
        html_action = QAction("HTML", self)
        json_action.triggered.connect(lambda: self._export_comparison("json"))
        html_action.triggered.connect(lambda: self._export_comparison("html"))
        menu.addAction(json_action)
        menu.addAction(html_action)
        return menu

    def _export_comparison(self, export_format: str) -> None:
        suggested = self.export_service.suggested_filename(self.comparison, export_format)
        filter_text = "JSON Files (*.json)" if export_format == "json" else "HTML Files (*.html)"
        destination, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Exportar comparação histórica",
            suggested,
            filter_text,
        )
        if not destination:
            return
        try:
            result = self.export_service.export(self.comparison, destination, export_format)
        except (OSError, ValueError):
            logger.exception("Failed to export historical SMTP comparison")
            QMessageBox.warning(
                self,
                "Falha ao exportar",
                "Não foi possível exportar a comparação. Consulte os logs para detalhes.",
            )
            return
        self.status_label.setText(
            f"Comparação #{value_text(result.baseline_run_id)} vs #{value_text(result.compared_run_id)} "
            f"exportada com sucesso.\n{result.path}"
        )

    def _summary_tab(self) -> QTextEdit:
        view = QTextEdit()
        view.setReadOnly(True)
        lines = [
            "Execução Base",
            f"ID: {value_text(self.comparison.baseline.run_id)}",
            f"Host: {value_text(self.comparison.baseline.hostname)}",
            f"Data: {value_text(self.comparison.baseline.created_at)}",
            f"Perfil: {value_text(self.comparison.baseline.profile)}",
            f"Status: {value_text(self.comparison.baseline.status)}",
            "",
            "Execução Comparada",
            f"ID: {value_text(self.comparison.compared.run_id)}",
            f"Host: {value_text(self.comparison.compared.hostname)}",
            f"Data: {value_text(self.comparison.compared.created_at)}",
            f"Perfil: {value_text(self.comparison.compared.profile)}",
            f"Status: {value_text(self.comparison.compared.status)}",
        ]
        if self.comparison.warnings:
            lines.extend(["", "Avisos", *self.comparison.warnings])
        lines.extend(["", "Principais Mudanças", *self.comparison.summary])
        view.setPlainText("\n".join(lines))
        return view

    def _performance_tab(self) -> QTableWidget:
        table = QTableWidget(0, 6)
        table.setHorizontalHeaderLabels(["Métrica", "Base", "Comparada", "Delta", "Percentual", "Mudança"])
        for change in self.comparison.performance_changes:
            self._add_row(
                table,
                [
                    change.metric,
                    value_text(change.baseline_ms),
                    value_text(change.compared_ms),
                    delta_text(change.delta_ms),
                    percent_text(change.delta_percent),
                    trend_label(change.trend),
                ],
            )
        table.resizeColumnsToContents()
        return table

    def _smtp_tab(self) -> QTextEdit:
        view = QTextEdit()
        view.setReadOnly(True)
        lines = ["Metadata SMTP"]
        for change in self.comparison.smtp_changes:
            lines.append(
                f"{change.name}: {value_text(change.baseline)} -> {value_text(change.compared)} "
                f"({change_label(change.status)})"
            )
        lines.append("")
        lines.append("Capabilities")
        for change in self.comparison.capability_changes:
            lines.append(f"{change.name}")
            lines.append(f"  Adicionadas: {value_text(change.added)}")
            lines.append(f"  Removidas: {value_text(change.removed)}")
            lines.append(f"  Mantidas: {value_text(change.maintained)}")
            for parameter in change.parameter_changes:
                lines.append(
                    f"  Parâmetros {parameter.name}: {value_text(parameter.baseline)} -> "
                    f"{value_text(parameter.compared)}"
                )
        lines.append("")
        lines.append("AUTH")
        for change in self.comparison.auth_changes:
            lines.append(f"{change.name}")
            lines.append(f"  Adicionados: {value_text(change.added)}")
            lines.append(f"  Removidos: {value_text(change.removed)}")
            lines.append(f"  Mantidos: {value_text(change.maintained)}")
        lines.append("")
        lines.append("Command Diagnostics")
        for change in self.comparison.command_changes:
            note = f" - {change.note}" if change.note else ""
            lines.append(
                f"{change.command}: {value_text(change.baseline_status)} -> "
                f"{value_text(change.compared_status)} ({change_label(change.status)}){note}"
            )
        view.setPlainText("\n".join(lines))
        return view

    def _tls_tab(self) -> QTableWidget:
        table = QTableWidget(0, 4)
        table.setHorizontalHeaderLabels(["Campo", "Base", "Comparada", "Mudança"])
        for change in self.comparison.tls_changes:
            self._add_row(
                table,
                [change.name, value_text(change.baseline), value_text(change.compared), change_label(change.status)],
            )
        table.resizeColumnsToContents()
        return table

    def _security_tab(self) -> QTextEdit:
        view = QTextEdit()
        view.setReadOnly(True)
        lines = ["Resumo por severidade"]
        for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
            base = self.comparison.security_summary["baseline"][severity]
            compared = self.comparison.security_summary["compared"][severity]
            delta = self.comparison.security_summary["delta"][severity]
            lines.append(f"{severity}: Base {base} | Comparada {compared} | Delta {delta:+d}")
        lines.append("")
        lines.append("Findings")
        for change in self.comparison.finding_changes:
            lines.append(f"{finding_label(change.lifecycle)}: {change.finding_id}")
            if change.baseline:
                lines.append(f"  Base: {change.baseline.get('severity')} - {change.baseline.get('title')}")
            if change.compared:
                lines.append(f"  Comparada: {change.compared.get('severity')} - {change.compared.get('title')}")
        if not self.comparison.finding_changes:
            lines.append("Nenhum finding registrado nas execuções comparadas.")
        view.setPlainText("\n".join(lines))
        return view

    def _add_row(self, table: QTableWidget, values: list[str]) -> None:
        row = table.rowCount()
        table.insertRow(row)
        for column, value in enumerate(values):
            table.setItem(row, column, QTableWidgetItem(value))
