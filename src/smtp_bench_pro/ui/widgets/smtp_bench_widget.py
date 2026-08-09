"""Root SMTP Bench Pro widget usable standalone or inside Bench Pro Core."""

from __future__ import annotations

import json
import logging
from dataclasses import replace

from PySide6.QtCore import Qt
from PySide6.QtGui import QAction
from PySide6.QtWidgets import (
    QCheckBox,
    QComboBox,
    QDialog,
    QFileDialog,
    QGroupBox,
    QHBoxLayout,
    QLabel,
    QMessageBox,
    QDialogButtonBox,
    QProgressBar,
    QPushButton,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from smtp_bench_pro.application.diagnostics import SMTPDiagnosticsService
from smtp_bench_pro.application.services import BenchmarkRequest, SMTPBenchmarkService
from smtp_bench_pro.ui.historical_mail_dns_widget import HistoricalMailDNSWidget
from smtp_bench_pro.ui.mail_dns_tab import MailDNSTabWidget
from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
    DiagnosticsProfile,
)
from smtp_bench_pro.domain.diagnostics import FindingSeverity, SecurityFinding, SMTPDiagnosticReport
from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.results import BenchmarkRunResult, SMTPProbeResult
from smtp_bench_pro.engine.benchmark_engine import SMTPBenchmarkEngine
from smtp_bench_pro.comparison.comparator import HistoricalRunComparator
from smtp_bench_pro.export.historical_export import HistoricalRunExportService
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository, SMTPRunDetails
from smtp_bench_pro.ui.widgets.comparison_dialog import HistoricalComparisonDialog
from smtp_bench_pro.ui.security_presenter import (
    COMMAND_TOOLTIPS,
    command_finding_for,
    command_presentation,
    profile_description,
    profile_display_name,
    severity_counters_text,
)
from smtp_bench_pro.ui.widgets.connection_panel import ConnectionPanel
from smtp_bench_pro.ui.widgets.results_table import ResultsTable
from smtp_bench_pro.version import __version__

logger = logging.getLogger(__name__)

UNAVAILABLE = "Não disponível nesta execução."


class SMTPBenchWidget(QWidget):
    """Functional SMTP workspace shared by standalone and integrated modes."""

    def __init__(
        self,
        parent: QWidget | None = None,
        *,
        include_about: bool = True,
        engine: SMTPBenchmarkEngine | None = None,
        repository: SMTPBenchmarkRepository | None = None,
    ):
        super().__init__(parent)
        self.service = SMTPBenchmarkService()
        self.diagnostics_service = SMTPDiagnosticsService()
        self.engine = engine or SMTPBenchmarkEngine()
        self.repository = repository or SMTPBenchmarkRepository()
        self.export_service = HistoricalRunExportService()
        self.comparator = HistoricalRunComparator()
        self._active_runs = 0
        self._expected_results = 0
        self._completed_results = 0
        self._pending_results: list[SMTPProbeResult] = []
        self._current_request: BenchmarkRequest | None = None
        self._diagnostics: list[SMTPDiagnosticReport] = []
        self._findings: list[SecurityFinding] = []
        self._command_rows: list[tuple[object, SecurityFinding | None]] = []
        self._history_command_rows: list[tuple[object, SecurityFinding | None]] = []
        self._history_findings: list[SecurityFinding] = []
        self._selected_history_details: SMTPRunDetails | None = None

        self.tab_widget = QTabWidget()
        self.benchmark_tab = QWidget()
        self.diagnostics_tab = QWidget()
        self.security_tab = QWidget()
        self.history_tab = QWidget()

        self.connection_panel = ConnectionPanel()
        self.results_table = ResultsTable()
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 100)
        self.progress_bar.setValue(0)
        self.summary_label = QLabel("Pronto")
        self.profile_combo = QComboBox()
        self.profile_combo.addItem("Seguro (Recomendado)", DiagnosticsProfile.SAFE.value)
        self.profile_combo.addItem("Estendido", DiagnosticsProfile.EXTENDED.value)
        self.profile_combo.addItem("Manual", DiagnosticsProfile.MANUAL.value)
        self.profile_combo.setToolTip(
            "Seguro: verificações conservadoras. Estendido: inclui comandos SMTP opcionais. "
            "Manual: permite selecionar comandos opcionais."
        )
        self.noop_check = QCheckBox("NOOP")
        self.help_check = QCheckBox("HELP")
        self.vrfy_check = QCheckBox("VRFY")
        self.expn_check = QCheckBox("EXPN")
        self.extended_warning = QLabel(
            "Testes estendidos podem gerar eventos nos logs de segurança do servidor SMTP."
        )
        self.extended_warning.setWordWrap(True)
        self.diagnostics_table = QTableWidget(0, 7)
        self.diagnostics_table.setHorizontalHeaderLabels(
            ["Porta", "Role", "STARTTLS", "AUTH antes TLS", "AUTH após TLS", "TLS", "Certificado"]
        )
        self.capabilities_table = QTableWidget(0, 5)
        self.capabilities_table.setHorizontalHeaderLabels(
            ["Porta", "Capability", "Antes TLS", "Após TLS", "Parametros"]
        )
        self.security_summary = QLabel("Nenhum diagnóstico de segurança disponível.")
        self.security_summary.setWordWrap(True)
        self.command_table = QTableWidget(0, 5)
        self.command_table.setHorizontalHeaderLabels(["Comando", "Executado", "Resultado", "Código SMTP", "Observação"])
        self.command_details = QTextEdit()
        self.command_details.setReadOnly(True)
        self.finding_counters = QLabel("Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.findings_table = QTableWidget(0, 5)
        self.findings_table.setHorizontalHeaderLabels(["Severidade", "Categoria", "Achado", "Porta", "Evidencia"])
        self.finding_details = QTextEdit()
        self.finding_details.setReadOnly(True)
        self.compare_history_button = QPushButton("Comparar Execuções")
        self.compare_history_button.setEnabled(False)
        self.export_history_button = QPushButton("Exportar Execução")
        self.export_history_button.setEnabled(False)
        self.compare_history_button.setEnabled(False)
        self.export_history_menu = self._build_history_export_menu()
        self.export_history_button.setMenu(self.export_history_menu)
        self.history_table = QTableWidget(0, 7)
        self.history_table.setHorizontalHeaderLabels(
            ["ID", "Data/Hora", "Servidor", "Portas", "Perfil", "Resultado", "Findings"]
        )
        self.history_header = QLabel("Selecione uma execução para visualizar os detalhes.")
        self.history_header.setWordWrap(True)
        self.history_detail_tabs = QTabWidget()
        self.history_summary_view = QTextEdit()
        self.history_smtp_view = QTextEdit()
        self.history_tls_view = QTextEdit()
        for view in (self.history_summary_view, self.history_smtp_view, self.history_tls_view):
            view.setReadOnly(True)
        self.history_security_summary = QLabel("Nenhum diagnóstico de segurança disponível.")
        self.history_security_summary.setWordWrap(True)
        self.history_finding_counters = QLabel("Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.history_command_table = QTableWidget(0, 5)
        self.history_command_table.setHorizontalHeaderLabels(
            ["Comando", "Executado", "Resultado", "Código SMTP", "Observação"]
        )
        self.history_command_details = QTextEdit()
        self.history_command_details.setReadOnly(True)
        self.history_findings_table = QTableWidget(0, 5)
        self.history_findings_table.setHorizontalHeaderLabels(
            ["Severidade", "Categoria", "Achado", "Porta", "Evidencia"]
        )
        self.history_finding_details = QTextEdit()
        self.history_finding_details.setReadOnly(True)

        self._build_benchmark_tab()
        self._build_diagnostics_tab()
        self._build_security_tab()
        self._build_history_tab()
        self.tab_widget.addTab(self.benchmark_tab, "Benchmark")
        self.tab_widget.addTab(self.diagnostics_tab, "Diagnóstico")
        self.tab_widget.addTab(self.security_tab, "Segurança")
        self.tab_widget.addTab(self.history_tab, "Histórico")
        self.mail_dns_tab = MailDNSTabWidget(repository=self.repository)
        self.tab_widget.addTab(self.mail_dns_tab, "DNS de E-mail")
        if include_about:
            about = QLabel(f"SMTP Bench Pro\nVersion {__version__}\nWL Tech\n(c) 2026 WL Tech")
            about.setAlignment(Qt.AlignmentFlag.AlignCenter)
            self.tab_widget.addTab(about, "Sobre")

        layout = QVBoxLayout(self)
        layout.addWidget(self.tab_widget)

        self.connection_panel.run_requested.connect(self.start_benchmark)
        self.connection_panel.cancel_requested.connect(self.cancel_benchmark)
        self.profile_combo.currentIndexChanged.connect(self._on_profile_changed)
        for check in (self.noop_check, self.help_check, self.vrfy_check, self.expn_check):
            check.stateChanged.connect(self._on_manual_command_changed)
        self.results_table.itemSelectionChanged.connect(self._update_diagnostics_from_selection)
        self.findings_table.itemSelectionChanged.connect(self._update_finding_details_from_selection)
        self.command_table.itemSelectionChanged.connect(self._update_command_details_from_selection)
        self.history_table.itemSelectionChanged.connect(self._on_history_selection_changed)
        self.history_command_table.itemSelectionChanged.connect(self._update_history_command_details_from_selection)
        self.history_findings_table.itemSelectionChanged.connect(self._update_history_finding_details_from_selection)
        self.compare_history_button.clicked.connect(self._compare_selected_history_run)
        self.engine.result_ready.connect(self._on_result_ready)
        self.engine.benchmark_finished.connect(self._on_benchmark_finished)
        self._refresh_history()
        self._on_profile_changed()
        self._render_empty_diagnostics()
        self._render_empty_findings()
        self._render_empty_history_details()

    def start_benchmark(self, request: BenchmarkRequest) -> None:
        request = replace(request, diagnostics_options=self._current_diagnostics_options())
        try:
            targets = self.service.build_targets(request)
        except ValueError as exc:
            QMessageBox.warning(self, "Entrada invalida", str(exc))
            return

        logger.info("Starting SMTP benchmark for %s on %d port(s)", request.hostname, len(targets))
        self._current_request = request
        self._active_runs = len(targets)
        self._expected_results = len(targets) * request.iterations
        self._completed_results = 0
        self._pending_results = []
        self._diagnostics = []
        self._findings = []
        self.results_table.clear_results()
        self.progress_bar.setValue(0)
        self.summary_label.setText("Executando benchmark...")
        self.connection_panel.set_running(True)
        self._render_empty_diagnostics()
        self._render_empty_findings()
        self._render_empty_history_details()

        for target in targets:
            self.engine.run_benchmark(target, request.iterations, diagnostics_options=request.diagnostics_options)

    def cancel_benchmark(self) -> None:
        logger.info("Cancelling SMTP benchmark")
        self.engine.cancel_all()
        self.summary_label.setText("Cancelando...")

    def _current_diagnostics_options(self) -> DiagnosticsOptions:
        profile = DiagnosticsProfile.normalize(self.profile_combo.currentData())
        if profile == DiagnosticsProfile.MANUAL:
            return DiagnosticsOptions(
                profile=profile,
                test_noop=self.noop_check.isChecked(),
                test_help=self.help_check.isChecked(),
                test_vrfy=self.vrfy_check.isChecked(),
                test_expn=self.expn_check.isChecked(),
            )
        return DiagnosticsOptions.from_profile(profile)

    def _on_profile_changed(self) -> None:
        profile = DiagnosticsProfile.normalize(self.profile_combo.currentData())
        options = DiagnosticsOptions.from_profile(profile)
        manual = profile == DiagnosticsProfile.MANUAL
        for check, enabled, checked in (
            (self.noop_check, manual, options.test_noop),
            (self.help_check, manual, options.test_help),
            (self.vrfy_check, manual, options.test_vrfy),
            (self.expn_check, manual, options.test_expn),
        ):
            check.blockSignals(True)
            check.setChecked(checked)
            check.setEnabled(enabled)
            check.blockSignals(False)
        self._update_extended_warning()

    def _on_manual_command_changed(self) -> None:
        self._update_extended_warning()

    def _update_extended_warning(self) -> None:
        options = self._current_diagnostics_options()
        show_warning = options.profile == DiagnosticsProfile.EXTENDED or options.test_vrfy or options.test_expn
        self.extended_warning.setVisible(show_warning)

    def _build_benchmark_tab(self) -> None:
        layout = QVBoxLayout(self.benchmark_tab)
        layout.addWidget(self.connection_panel)
        progress_row = QWidget()
        progress_layout = QHBoxLayout(progress_row)
        progress_layout.setContentsMargins(0, 0, 0, 0)
        progress_layout.addWidget(self.progress_bar, 1)
        progress_layout.addWidget(self.summary_label)
        layout.addWidget(progress_row)
        layout.addWidget(self.results_table, 1)

    def _build_diagnostics_tab(self) -> None:
        layout = QVBoxLayout(self.diagnostics_tab)
        profile_group = QGroupBox("Perfil de Diagnóstico")
        profile_layout = QVBoxLayout(profile_group)
        profile_layout.addWidget(self.profile_combo)
        manual_row = QWidget()
        manual_layout = QHBoxLayout(manual_row)
        manual_layout.setContentsMargins(0, 0, 0, 0)
        for check in (self.noop_check, self.help_check, self.vrfy_check, self.expn_check):
            manual_layout.addWidget(check)
        manual_layout.addStretch(1)
        profile_layout.addWidget(manual_row)
        profile_layout.addWidget(self.extended_warning)
        layout.addWidget(profile_group)
        layout.addWidget(QLabel("Resumo de configuração SMTP/TLS"))
        layout.addWidget(self.diagnostics_table, 1)
        layout.addWidget(QLabel("Capabilities EHLO pré/pós TLS"))
        layout.addWidget(self.capabilities_table, 2)

    def _build_security_tab(self) -> None:
        layout = QVBoxLayout(self.security_tab)
        summary_group = QGroupBox("Resumo do Diagnóstico")
        summary_layout = QVBoxLayout(summary_group)
        summary_layout.addWidget(self.security_summary)
        summary_layout.addWidget(self.finding_counters)
        layout.addWidget(summary_group)
        layout.addWidget(QLabel("Comandos Testados"))
        layout.addWidget(self.command_table, 1)
        layout.addWidget(QLabel("Detalhes do comando"))
        layout.addWidget(self.command_details, 1)
        layout.addWidget(QLabel("Findings"))
        layout.addWidget(self.findings_table, 2)
        layout.addWidget(QLabel("Detalhes do achado"))
        layout.addWidget(self.finding_details, 1)

    def _build_history_tab(self) -> None:
        layout = QVBoxLayout(self.history_tab)
        splitter = QSplitter(Qt.Orientation.Horizontal)
        master = QWidget()
        master_layout = QVBoxLayout(master)
        master_layout.addWidget(self.export_history_button)
        master_layout.addWidget(self.compare_history_button)
        master_layout.addWidget(self.history_table, 1)
        splitter.addWidget(master)

        detail = QWidget()
        detail_layout = QVBoxLayout(detail)
        detail_layout.addWidget(self.history_header)
        detail_layout.addWidget(self.history_detail_tabs, 1)
        self.history_detail_tabs.addTab(self.history_summary_view, "Resumo")
        self.history_detail_tabs.addTab(self.history_smtp_view, "SMTP")
        self.history_detail_tabs.addTab(self.history_tls_view, "TLS")
        self.history_detail_tabs.addTab(self._build_history_security_panel(), "Segurança")
        self.history_mail_dns_widget = HistoricalMailDNSWidget()
        self.history_detail_tabs.addTab(self.history_mail_dns_widget, "DNS de E-mail")
        splitter.addWidget(detail)
        splitter.setSizes([350, 650])
        layout.addWidget(splitter, 1)

    def _build_history_security_panel(self) -> QWidget:
        panel = QWidget()
        layout = QVBoxLayout(panel)
        summary_group = QGroupBox("Resumo do Diagnóstico")
        summary_layout = QVBoxLayout(summary_group)
        summary_layout.addWidget(self.history_security_summary)
        summary_layout.addWidget(self.history_finding_counters)
        layout.addWidget(summary_group)
        layout.addWidget(QLabel("Comandos Testados"))
        layout.addWidget(self.history_command_table, 1)
        layout.addWidget(QLabel("Detalhes do comando"))
        layout.addWidget(self.history_command_details, 1)
        layout.addWidget(QLabel("Findings"))
        layout.addWidget(self.history_findings_table, 2)
        layout.addWidget(QLabel("Detalhes do achado"))
        layout.addWidget(self.history_finding_details, 1)
        return panel
    def _on_result_ready(self, result: SMTPProbeResult) -> None:
        self._completed_results += 1
        self._pending_results.append(result)
        self.results_table.add_result(result)
        if self._expected_results:
            self.progress_bar.setValue(int((self._completed_results / self._expected_results) * 100))

    def _on_benchmark_finished(self, run_result: BenchmarkRunResult) -> None:
        self._active_runs -= 1
        if self._active_runs <= 0:
            self.connection_panel.set_running(False)
            self.progress_bar.setValue(100 if self._pending_results else 0)
            self._diagnostics, self._findings = self.diagnostics_service.analyze_results(self._pending_results)
            self._render_diagnostics(self._diagnostics)
            self._render_security(self._diagnostics, self._findings)
            successes = sum(1 for result in self._pending_results if result.success)
            finding_text = f" | {len(self._findings)} achado(s)"
            self.summary_label.setText(f"Concluido: {successes}/{len(self._pending_results)} sucesso(s){finding_text}")
            if self._current_request is not None and self._pending_results:
                try:
                    self.repository.save_run(
                        hostname=self._current_request.hostname.strip(),
                        iterations=self._current_request.iterations,
                        timeout=self._current_request.timeout,
                        results=self._pending_results,
                        diagnostics_options=self._current_request.diagnostics_options,
                    )
                    self._refresh_history()
                except Exception:
                    logger.exception("Failed to persist SMTP benchmark run")

    def _update_diagnostics_from_selection(self) -> None:
        selected = self.results_table.selectedItems()
        if not selected:
            return
        result = self.results_table.result_at(selected[0].row())
        if result is not None:
            reports, findings = self.diagnostics_service.analyze_results([result])
            self._render_diagnostics(reports)
            self._render_security(reports, findings)

    def _update_finding_details_from_selection(self) -> None:
        selected = self.findings_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if not (0 <= row < len(self._findings)):
            return
        finding = self._findings[row]
        self.finding_details.setPlainText(
            "\n".join(
                [
                    f"ID: {finding.id}",
                    f"Severidade: {finding.severity.value}",
                    f"Categoria: {finding.category}",
                    f"Achado: {finding.title}",
                    "",
                    f"Descrição: {finding.description}",
                    f"Evidência: {finding.evidence}",
                    f"Recomendação: {finding.recommendation}",
                ]
            )
        )

    def _render_empty_diagnostics(self) -> None:
        self.diagnostics_table.setRowCount(0)
        self.capabilities_table.setRowCount(0)

    def _render_empty_findings(self) -> None:
        self._findings = []
        self._command_rows = []
        self.findings_table.setRowCount(0)
        self.command_table.setRowCount(0)
        self.security_summary.setText("Nenhum diagnóstico de segurança disponível.")
        self.finding_counters.setText("Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.command_details.setPlainText("Nenhum diagnóstico de comando disponível.")
        self.finding_details.setPlainText("Nenhum diagnóstico de segurança disponível.")

    def _render_diagnostics(self, reports: list[SMTPDiagnosticReport]) -> None:
        self.diagnostics_table.setRowCount(0)
        self.capabilities_table.setRowCount(0)
        for report in reports:
            self._add_diagnostic_row(report)
            for capability in report.capability_diagnostics:
                row = self.capabilities_table.rowCount()
                self.capabilities_table.insertRow(row)
                params = []
                if capability.parameters_before_tls:
                    params.append("antes: " + " ".join(capability.parameters_before_tls))
                if capability.parameters_after_tls:
                    params.append("após: " + " ".join(capability.parameters_after_tls))
                values = [
                    str(report.port),
                    capability.name,
                    "presente" if capability.present_before_tls else "ausente",
                    "presente" if capability.present_after_tls else "ausente",
                    " | ".join(params) or "-",
                ]
                for column, value in enumerate(values):
                    self.capabilities_table.setItem(row, column, QTableWidgetItem(value))
        self.diagnostics_table.resizeColumnsToContents()
        self.capabilities_table.resizeColumnsToContents()

    def _add_diagnostic_row(self, report: SMTPDiagnosticReport) -> None:
        row = self.diagnostics_table.rowCount()
        self.diagnostics_table.insertRow(row)
        tls = report.tls_information
        cert = report.certificate_diagnostic
        values = [
            str(report.port),
            report.role.value,
            self._bool_text(report.starttls_advertised),
            ", ".join(report.auth_mechanisms_before_tls) or "-",
            ", ".join(report.auth_mechanisms_after_tls) or "-",
            tls.tls_version if tls else "-",
            self._certificate_text(cert),
        ]
        for column, value in enumerate(values):
            self.diagnostics_table.setItem(row, column, QTableWidgetItem(value))

    def _render_security(self, reports: list[SMTPDiagnosticReport], findings: list[SecurityFinding]) -> None:
        self._render_security_summary(reports, findings)
        self._render_command_diagnostics(reports, findings)
        self._render_findings(findings)

    def _render_security_summary(self, reports: list[SMTPDiagnosticReport], findings: list[SecurityFinding]) -> None:
        if not reports:
            self.security_summary.setText("Nenhum diagnóstico de segurança disponível.")
            self.finding_counters.setText("Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
            return
        options = reports[0].diagnostics_options
        partial = any(not report.success for report in reports)
        standard = ["Banner", "EHLO", "STARTTLS", "TLS", "Certificado", "AUTH discovery"]
        if options.test_noop:
            standard.append("NOOP")
        optional_lines = []
        for command, enabled in (
            ("HELP", options.test_help),
            ("VRFY", options.test_vrfy),
            ("EXPN", options.test_expn),
        ):
            if enabled:
                optional_lines.append(f"{command}: habilitado pelo perfil")
            else:
                optional_lines.append(f"{command}: não executado pelo perfil {options.profile.value.upper()}")
        lines = [
            f"Perfil utilizado: {profile_display_name(options.profile)}",
            profile_description(options),
            "Diagnóstico parcial" if partial else "Diagnóstico concluído",
            "Testes padrão: " + ", ".join(standard),
            "Testes opcionais: " + " | ".join(optional_lines),
        ]
        self.security_summary.setText("\n".join(lines))
        self.finding_counters.setText(severity_counters_text(findings))

    def _render_command_diagnostics(
        self, reports: list[SMTPDiagnosticReport], findings: list[SecurityFinding]
    ) -> None:
        self.command_table.setRowCount(0)
        self._command_rows = []
        if not reports:
            self.command_details.setPlainText("Nenhum diagnóstico de comando disponível.")
            return
        for report in reports:
            for result in report.command_diagnostics:
                presentation = command_presentation(result)
                finding = command_finding_for(result.command, findings)
                row = self.command_table.rowCount()
                self.command_table.insertRow(row)
                values = [
                    presentation.command,
                    presentation.executed,
                    presentation.result,
                    presentation.response_code,
                    presentation.note,
                ]
                for column, value in enumerate(values):
                    item = QTableWidgetItem(value)
                    if column == 0 and presentation.command in ("NOOP", "HELP", "VRFY", "EXPN"):
                        item.setToolTip(COMMAND_TOOLTIPS.get(presentation.command, ""))
                    self.command_table.setItem(row, column, item)
                self._command_rows.append((result, finding))
        self.command_table.resizeColumnsToContents()
        if self._command_rows:
            self.command_table.setCurrentCell(0, 0)
            self._update_command_details_from_selection()
        else:
            self.command_details.setPlainText("Nenhum diagnóstico de comando disponível.")

    def _update_command_details_from_selection(self) -> None:
        selected = self.command_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if not (0 <= row < len(self._command_rows)):
            return
        result, finding = self._command_rows[row]
        presentation = command_presentation(result)
        if presentation.command in {"NOOP", "HELP"}:
            command_text = presentation.command
        else:
            command_text = f"{presentation.command} postmaster"
        lines = [
            f"Comando: {command_text}",
            f"Executado: {presentation.executed}",
            f"Resultado: {presentation.result}",
            f"Código SMTP: {presentation.response_code}",
            f"Observação: {presentation.note}",
            "",
            f"Resposta: {presentation.evidence}",
            "",
        ]
        if finding is None:
            lines.append("Nenhum achado de segurança associado.")
        else:
            lines.extend(
                [
                    f"Finding: {finding.id}",
                    f"Severity: {finding.severity.value.title()}",
                    f"Title: {finding.title}",
                    f"Recommendation: {finding.recommendation}",
                ]
            )
        self.command_details.setPlainText("\n".join(lines))

    def _render_findings(self, findings: list[SecurityFinding]) -> None:
        self._findings = findings
        self.findings_table.setRowCount(0)
        if not findings:
            self.finding_details.setPlainText("Nenhum achado de segurança identificado nesta execução.")
            return
        for finding in findings:
            row = self.findings_table.rowCount()
            self.findings_table.insertRow(row)
            values = [
                finding.severity.value,
                finding.category,
                finding.title,
                str(finding.port),
                finding.evidence,
            ]
            for column, value in enumerate(values):
                self.findings_table.setItem(row, column, QTableWidgetItem(value))
        self.findings_table.resizeColumnsToContents()
        self.findings_table.setCurrentCell(0, 0)
        self._update_finding_details_from_selection()

    def _certificate_text(self, cert) -> str:
        if cert is None:
            return "-"
        if cert.expired:
            return "expirado"
        if not cert.hostname_valid:
            return "hostname divergente"
        if not cert.certificate_valid:
            return "não confiável"
        if cert.expires_soon_days is not None:
            return f"válido ({cert.expires_soon_days} dias)"
        return "válido"

    def _bool_text(self, value: bool | None) -> str:
        if value is None:
            return "-"
        return "sim" if value else "não"


    def _compare_selected_history_run(self) -> None:
        if self._selected_history_details is None:
            return
        compared_run_id = self._select_compared_run_id(self._selected_history_details)
        if compared_run_id is None:
            return
        try:
            compared_details = self.repository.get_run_details(compared_run_id)
            if compared_details is None:
                QMessageBox.warning(self, "Comparação indisponível", "Execução comparada não encontrada.")
                return
            comparison = self.comparator.compare(self._selected_history_details, compared_details)
        except ValueError as exc:
            QMessageBox.warning(self, "Comparação inválida", str(exc))
            return
        except Exception:
            logger.exception("Failed to compare historical SMTP runs")
            QMessageBox.warning(
                self,
                "Falha ao comparar",
                "Não foi possível comparar as execuções. Consulte os logs para detalhes.",
            )
            return
        dialog = HistoricalComparisonDialog(comparison, self)
        dialog.exec()

    def _select_compared_run_id(self, baseline: SMTPRunDetails) -> int | None:
        try:
            runs = self.repository.list_run_summaries(limit=100)
        except Exception:
            logger.exception("Failed to list runs for comparison")
            QMessageBox.warning(self, "Comparação indisponível", "Não foi possível listar execuções históricas.")
            return None
        baseline_id = int(baseline.run.get("id")) if baseline.run.get("id") is not None else None
        dialog = QDialog(self)
        dialog.setWindowTitle("Escolher execução comparada")
        layout = QVBoxLayout(dialog)
        layout.addWidget(QLabel("Selecione a execução comparada."))
        table = QTableWidget(0, 5)
        table.setHorizontalHeaderLabels(["ID", "Data/Hora", "Servidor", "Perfil", "Resultado"])
        for run in runs:
            row = table.rowCount()
            table.insertRow(row)
            values = [
                f"#{run['id']}",
                str(run.get("created_at") or "-"),
                str(run.get("hostname") or "-"),
                self._profile_display_from_value(run.get("diagnostics_profile")),
                str(run.get("result_status") or "-"),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, int(run["id"]))
                table.setItem(row, column, item)
        table.resizeColumnsToContents()
        layout.addWidget(table, 1)
        buttons = QDialogButtonBox(QDialogButtonBox.StandardButton.Ok | QDialogButtonBox.StandardButton.Cancel)
        buttons.accepted.connect(dialog.accept)
        buttons.rejected.connect(dialog.reject)
        layout.addWidget(buttons)
        if table.rowCount():
            table.setCurrentCell(0, 0)
        if dialog.exec() != QDialog.DialogCode.Accepted:
            return None
        selected = table.selectedItems()
        if not selected:
            return None
        item = table.item(selected[0].row(), 0)
        if item is None:
            return None
        run_id = int(item.data(Qt.ItemDataRole.UserRole))
        if baseline_id is not None and run_id == baseline_id:
            QMessageBox.warning(self, "Comparação inválida", "Selecione duas execuções diferentes.")
            return None
        return run_id
    def _build_history_export_menu(self):
        menu = self.export_history_button.menu() if hasattr(self, "export_history_button") else None
        if menu is None:
            from PySide6.QtWidgets import QMenu

            menu = QMenu(self)
        json_action = QAction("JSON", self)
        html_action = QAction("HTML", self)
        json_action.triggered.connect(lambda: self._export_selected_history_run("json"))
        html_action.triggered.connect(lambda: self._export_selected_history_run("html"))
        menu.addAction(json_action)
        menu.addAction(html_action)
        return menu

    def _export_selected_history_run(self, export_format: str) -> None:
        if self._selected_history_details is None:
            return
        suggested = self.export_service.suggested_filename(self._selected_history_details, export_format)
        filter_text = "JSON Files (*.json)" if export_format == "json" else "HTML Files (*.html)"
        destination, _selected_filter = QFileDialog.getSaveFileName(
            self,
            "Exportar execução histórica",
            suggested,
            filter_text,
        )
        if not destination:
            return
        try:
            run_id = self._selected_history_details.run.get("id")
            get_snapshot_fn = getattr(self.repository, "get_mail_dns_snapshot", None)
            snapshot = get_snapshot_fn(int(run_id)) if (get_snapshot_fn is not None and run_id is not None) else None
            result = self.export_service.export(
                self._selected_history_details, destination, export_format, mail_dns_snapshot=snapshot
            )
        except (OSError, ValueError):
            logger.exception("Failed to export historical SMTP run")
            QMessageBox.warning(
                self,
                "Falha ao exportar",
                "Não foi possível exportar a execução. Consulte os logs para detalhes.",
            )
            return
        self.history_header.setText(f"Execução #{result.run_id} exportada com sucesso.\n{result.path}")
    def _refresh_history(self) -> None:
        try:
            runs = self.repository.list_run_summaries(limit=100)
        except Exception:
            logger.exception("Failed to load SMTP benchmark history")
            self.history_table.setRowCount(0)
            self.history_header.setText("Histórico indisponível. Consulte os logs para detalhes.")
            self._render_empty_history_details()
            return
        self.history_table.setRowCount(0)
        if not runs:
            self.history_header.setText(
                "Nenhuma execução disponível.\nExecute um benchmark ou diagnóstico para criar histórico."
            )
            self._render_empty_history_details("Nenhuma execução disponível.")
            return
        for run in runs:
            row = self.history_table.rowCount()
            self.history_table.insertRow(row)
            values = [
                f"#{run['id']}",
                str(run.get("created_at") or "-"),
                str(run.get("hostname") or "-"),
                str(run.get("ports") or "-"),
                self._profile_display_from_value(run.get("diagnostics_profile")),
                str(run.get("result_status") or "-"),
                str(run.get("findings_count") or 0),
            ]
            for column, value in enumerate(values):
                item = QTableWidgetItem(value)
                if column == 0:
                    item.setData(Qt.ItemDataRole.UserRole, int(run["id"]))
                self.history_table.setItem(row, column, item)
        self.history_table.resizeColumnsToContents()
        self.history_header.setText("Selecione uma execução para visualizar os detalhes.")
        self._render_empty_history_details()

    def _on_history_selection_changed(self) -> None:
        selected = self.history_table.selectedItems()
        if not selected:
            self._render_empty_history_details()
            return
        run_item = self.history_table.item(selected[0].row(), 0)
        if run_item is None:
            return
        run_id = run_item.data(Qt.ItemDataRole.UserRole)
        try:
            if hasattr(self.repository, "get_security_context_for_run"):
                self.repository.get_security_context_for_run(int(run_id))
            details = self.repository.get_run_details(int(run_id))
        except Exception:
            logger.exception("Failed to load SMTP benchmark run details")
            self.history_header.setText("Falha ao carregar detalhes da execução. Consulte os logs para detalhes.")
            return
        if details is None:
            self._render_empty_history_details("Execução não encontrada.")
            return
        self._render_history_details(details)

    def _render_empty_history_details(
        self, message: str = "Selecione uma execução para visualizar os detalhes."
    ) -> None:
        self._history_findings = []
        self._history_command_rows = []
        self._selected_history_details = None
        self.export_history_button.setEnabled(False)
        self.compare_history_button.setEnabled(False)
        self.history_summary_view.setPlainText(message)
        self.history_smtp_view.setPlainText(message)
        self.history_tls_view.setPlainText(message)
        self.history_security_summary.setText("Nenhum diagnóstico de segurança disponível.")
        self.history_finding_counters.setText("Critical: 0 | High: 0 | Medium: 0 | Low: 0 | Info: 0")
        self.history_command_table.setRowCount(0)
        self.history_findings_table.setRowCount(0)
        self.history_command_details.setPlainText("Nenhum diagnóstico de comando disponível.")
        self.history_finding_details.setPlainText("Nenhum diagnóstico de segurança disponível.")
        if hasattr(self, "history_mail_dns_widget"):
            self.history_mail_dns_widget.set_snapshot(None)

    def _render_history_details(self, details: SMTPRunDetails) -> None:
        self._selected_history_details = details
        self.export_history_button.setEnabled(True)
        self.compare_history_button.setEnabled(True)
        run = details.run
        findings = [self._finding_from_row(row) for row in details.findings]
        command_results = self._historical_command_results(details.results)
        options = self._options_from_run(run)
        status = self._run_status(details.results)
        ports = self._ports_text(details.results)
        self.history_header.setText(
            "\n".join(
                [
                    f"Execução #{run.get('id')}",
                    str(run.get("hostname") or UNAVAILABLE),
                    f"Data: {run.get('created_at') or UNAVAILABLE}",
                    f"Perfil: {profile_display_name(options.profile)}",
                    f"Status: {status}",
                    f"Portas: {ports}",
                    f"Iterações: {run.get('iterations') or UNAVAILABLE}",
                    f"Timeout: {run.get('timeout') or UNAVAILABLE} s",
                ]
            )
        )
        self.history_summary_view.setPlainText(self._history_summary_text(details, findings, options, status, ports))
        self.history_smtp_view.setPlainText(self._history_smtp_text(details.results))
        self.history_tls_view.setPlainText(self._history_tls_text(details.results))
        self._render_history_security(options, command_results, findings, self._has_partial_results(details.results))

        if hasattr(self, "history_mail_dns_widget"):
            run_id = run.get("id")
            get_snapshot_fn = getattr(self.repository, "get_mail_dns_snapshot", None)
            snapshot = get_snapshot_fn(int(run_id)) if (get_snapshot_fn is not None and run_id is not None) else None
            self.history_mail_dns_widget.set_snapshot(snapshot)

    def _history_summary_text(
        self,
        details: SMTPRunDetails,
        findings: list[SecurityFinding],
        options: DiagnosticsOptions,
        status: str,
        ports: str,
    ) -> str:
        results = details.results
        ips = sorted({str(row.get("resolved_ip")) for row in results if row.get("resolved_ip")})
        modes = sorted({str(row.get("security_mode")) for row in results if row.get("security_mode")})
        successes = sum(1 for row in results if int(row.get("success") or 0) == 1)
        failures = len(results) - successes
        total_values = [float(row["total_ms"]) for row in results if row.get("total_ms") is not None]
        total_text = f"{sum(total_values):.2f} ms" if total_values else UNAVAILABLE
        return "\n".join(
            [
                f"Servidor: {details.run.get('hostname') or UNAVAILABLE}",
                f"IPs: {', '.join(ips) if ips else UNAVAILABLE}",
                f"Portas testadas: {ports}",
                f"Modo de segurança: {', '.join(modes) if modes else UNAVAILABLE}",
                f"Perfil de diagnóstico: {profile_display_name(options.profile)}",
                f"Tempo total: {total_text}",
                f"Sucessos/Falhas: {successes}/{failures}",
                f"Status: {status}",
                f"Quantidade de findings: {len(findings)}",
                severity_counters_text(findings),
            ]
        )

    def _history_smtp_text(self, results: list[dict[str, object]]) -> str:
        if not results:
            return UNAVAILABLE
        sections = []
        for row in results:
            lines = [
                f"Porta: {row.get('port') or UNAVAILABLE}",
                f"Modo: {row.get('security_mode') or UNAVAILABLE}",
                f"Banner: {row.get('banner') or UNAVAILABLE}",
                f"EHLO hostname: {row.get('ehlo_hostname') or UNAVAILABLE}",
                "Capabilities pré-TLS: " + self._dict_list_text(row.get("capabilities_before_tls_json")),
                "Capabilities pós-TLS: " + self._dict_list_text(row.get("capabilities_after_tls_json")),
                "AUTH antes TLS: " + self._list_text(row.get("auth_before_tls_json")),
                "AUTH após TLS: " + self._list_text(row.get("auth_after_tls_json")),
                "Command diagnostics:",
            ]
            commands = self._commands_from_result(row)
            if commands:
                lines.extend(self._command_line(command) for command in commands)
            else:
                lines.append(UNAVAILABLE)
            sections.append("\n".join(lines))
        return "\n\n---\n\n".join(sections)

    def _history_tls_text(self, results: list[dict[str, object]]) -> str:
        if not results:
            return UNAVAILABLE
        sections = []
        for row in results:
            tls = row.get("tls_json")
            if not isinstance(tls, dict) or not tls:
                sections.append(f"Porta: {row.get('port') or UNAVAILABLE}\n{UNAVAILABLE}")
                continue
            lines = [
                f"Porta: {row.get('port') or UNAVAILABLE}",
                f"TLS version: {tls.get('tls_version') or UNAVAILABLE}",
                f"Cipher: {tls.get('cipher') or UNAVAILABLE}",
                f"Bits: {tls.get('cipher_bits') or UNAVAILABLE}",
                f"Certificate subject: {tls.get('certificate_subject') or UNAVAILABLE}",
                f"Issuer: {tls.get('certificate_issuer') or UNAVAILABLE}",
                "SAN: " + self._list_text(tls.get("subject_alt_names")),
                f"Expiration: {tls.get('not_after') or UNAVAILABLE}",
                "Days remaining: "
                + str(tls.get("days_remaining") if tls.get("days_remaining") is not None else UNAVAILABLE),
                f"Hostname validation: {self._bool_text(tls.get('hostname_valid'))}",
                f"Certificate validation: {self._bool_text(tls.get('certificate_valid'))}",
            ]
            sections.append("\n".join(lines))
        return "\n\n---\n\n".join(sections)

    def _render_history_security(
        self,
        options: DiagnosticsOptions,
        command_results: list[CommandDiagnosticResult],
        findings: list[SecurityFinding],
        partial: bool,
    ) -> None:
        self._history_findings = findings
        self._history_command_rows = []
        self.history_security_summary.setText(self._security_summary_text(options, findings, partial))
        self.history_finding_counters.setText(severity_counters_text(findings))
        self.history_command_table.setRowCount(0)
        for result in command_results:
            finding = command_finding_for(result.command, findings)
            self._add_command_row(self.history_command_table, result, finding)
            self._history_command_rows.append((result, finding))
        self.history_command_table.resizeColumnsToContents()
        if self._history_command_rows:
            self.history_command_table.setCurrentCell(0, 0)
            self._update_history_command_details_from_selection()
        else:
            self.history_command_details.setPlainText("Nenhum diagnóstico de comando disponível.")
        self.history_findings_table.setRowCount(0)
        if findings:
            for finding in findings:
                self._add_finding_row(self.history_findings_table, finding)
            self.history_findings_table.resizeColumnsToContents()
            self.history_findings_table.setCurrentCell(0, 0)
            self._update_history_finding_details_from_selection()
        else:
            self.history_finding_details.setPlainText("Nenhum achado de segurança identificado nesta execução.")

    def _update_history_command_details_from_selection(self) -> None:
        selected = self.history_command_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if not (0 <= row < len(self._history_command_rows)):
            return
        result, finding = self._history_command_rows[row]
        self._render_command_detail(self.history_command_details, result, finding)

    def _update_history_finding_details_from_selection(self) -> None:
        selected = self.history_findings_table.selectedItems()
        if not selected:
            return
        row = selected[0].row()
        if not (0 <= row < len(self._history_findings)):
            return
        self._render_finding_detail(self.history_finding_details, self._history_findings[row])

    def _security_summary_text(
        self, options: DiagnosticsOptions, findings: list[SecurityFinding], partial: bool
    ) -> str:
        standard = ["Banner", "EHLO", "STARTTLS", "TLS", "Certificado", "AUTH discovery"]
        if options.test_noop:
            standard.append("NOOP")
        optional_lines = []
        for command, enabled in (
            ("HELP", options.test_help),
            ("VRFY", options.test_vrfy),
            ("EXPN", options.test_expn),
        ):
            if enabled:
                optional_lines.append(f"{command}: habilitado pelo perfil")
            else:
                optional_lines.append(f"{command}: não executado pelo perfil {options.profile.value.upper()}")
        return "\n".join(
            [
                f"Perfil utilizado: {profile_display_name(options.profile)}",
                profile_description(options),
                "Diagnóstico parcial" if partial else "Diagnóstico concluído",
                "Testes padrão: " + ", ".join(standard),
                "Testes opcionais: " + " | ".join(optional_lines),
                f"Findings: {len(findings)}",
            ]
        )

    def _add_command_row(
        self,
        table: QTableWidget,
        result: CommandDiagnosticResult,
        finding: SecurityFinding | None,
    ) -> None:
        presentation = command_presentation(result)
        row = table.rowCount()
        table.insertRow(row)
        values = [
            presentation.command,
            presentation.executed,
            presentation.result,
            presentation.response_code,
            presentation.note,
        ]
        for column, value in enumerate(values):
            item = QTableWidgetItem(value)
            if column == 0 and presentation.command in ("NOOP", "HELP", "VRFY", "EXPN"):
                item.setToolTip(COMMAND_TOOLTIPS.get(presentation.command, ""))
            if column == 0 and finding is not None:
                item.setData(Qt.ItemDataRole.UserRole, finding.id)
            table.setItem(row, column, item)

    def _render_command_detail(
        self,
        target: QTextEdit,
        result: CommandDiagnosticResult,
        finding: SecurityFinding | None,
    ) -> None:
        presentation = command_presentation(result)
        if presentation.command in {"NOOP", "HELP"}:
            command_text = presentation.command
        else:
            command_text = f"{presentation.command} postmaster"
        lines = [
            f"Comando: {command_text}",
            f"Executado: {presentation.executed}",
            f"Resultado: {presentation.result}",
            f"Código SMTP: {presentation.response_code}",
            f"Observação: {presentation.note}",
            "",
            f"Resposta: {presentation.evidence}",
            "",
        ]
        if finding is None:
            lines.append("Nenhum achado de segurança associado.")
        else:
            lines.extend(
                [
                    f"Finding: {finding.id}",
                    f"Severity: {finding.severity.value.title()}",
                    f"Title: {finding.title}",
                    f"Recommendation: {finding.recommendation}",
                ]
            )
        target.setPlainText("\n".join(lines))

    def _add_finding_row(self, table: QTableWidget, finding: SecurityFinding) -> None:
        row = table.rowCount()
        table.insertRow(row)
        values = [
            finding.severity.value,
            finding.category,
            finding.title,
            str(finding.port),
            finding.evidence,
        ]
        for column, value in enumerate(values):
            table.setItem(row, column, QTableWidgetItem(value))

    def _render_finding_detail(self, target: QTextEdit, finding: SecurityFinding) -> None:
        target.setPlainText(
            "\n".join(
                [
                    f"ID: {finding.id}",
                    f"Severidade: {finding.severity.value}",
                    f"Categoria: {finding.category}",
                    f"Achado: {finding.title}",
                    "",
                    f"Descrição: {finding.description}",
                    f"Evidência: {finding.evidence}",
                    f"Recomendação: {finding.recommendation}",
                ]
            )
        )

    def _historical_command_results(self, results: list[dict[str, object]]) -> list[CommandDiagnosticResult]:
        commands: list[CommandDiagnosticResult] = []
        for row in results:
            commands.extend(self._commands_from_result(row))
        if commands:
            return commands
        return [
            CommandDiagnosticResult(command=command, executed=False, reason=UNAVAILABLE)
            for command in ("NOOP", "HELP", "VRFY", "EXPN")
        ]

    def _commands_from_result(self, row: dict[str, object]) -> list[CommandDiagnosticResult]:
        raw = row.get("command_diagnostics_json")
        if not isinstance(raw, list):
            return []
        commands = []
        for item in raw:
            if not isinstance(item, dict):
                continue
            commands.append(self._command_from_dict(item))
        return commands

    def _command_from_dict(self, item: dict[str, object]) -> CommandDiagnosticResult:
        try:
            status = CommandDiagnosticStatus(str(item.get("status") or CommandDiagnosticStatus.NOT_TESTED.value))
        except ValueError:
            status = CommandDiagnosticStatus.UNKNOWN
        return CommandDiagnosticResult(
            command=str(item.get("command") or "UNKNOWN"),
            executed=bool(item.get("executed")),
            supported=item.get("supported") if isinstance(item.get("supported"), bool) else None,
            response_code=str(item.get("response_code")) if item.get("response_code") is not None else None,
            response_message=str(item.get("response_message")) if item.get("response_message") is not None else None,
            status=status,
            reason=str(item.get("reason")) if item.get("reason") is not None else None,
        )

    def _finding_from_row(self, row: dict[str, object]) -> SecurityFinding:
        payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
        try:
            severity_value = payload.get("severity") or row.get("severity") or FindingSeverity.INFO.value
            severity = FindingSeverity(str(severity_value))
        except ValueError:
            severity = FindingSeverity.INFO
        security_mode_value = str(payload.get("security_mode") or row.get("security_mode") or SecurityMode.PLAIN.value)
        try:
            security_mode = SecurityMode.from_value(security_mode_value)
        except ValueError:
            security_mode = SecurityMode.PLAIN
        return SecurityFinding(
            id=str(payload.get("id") or row.get("finding_id") or "SMTP-UNKNOWN"),
            title=str(payload.get("title") or row.get("title") or UNAVAILABLE),
            severity=severity,
            category=str(payload.get("category") or row.get("category") or UNAVAILABLE),
            description=str(payload.get("description") or UNAVAILABLE),
            evidence=str(payload.get("evidence") or UNAVAILABLE),
            recommendation=str(payload.get("recommendation") or UNAVAILABLE),
            port=int(payload.get("port") or row.get("port") or 0),
            security_mode=security_mode,
        )

    def _options_from_run(self, run: dict[str, object]) -> DiagnosticsOptions:
        profile = run.get("diagnostics_profile") or DiagnosticsProfile.SAFE.value
        raw_options = run.get("diagnostics_options_json")
        parsed = {}
        if isinstance(raw_options, str) and raw_options:
            try:
                parsed = json.loads(raw_options)
            except json.JSONDecodeError:
                parsed = {}
        elif isinstance(raw_options, dict):
            parsed = raw_options
        try:
            return DiagnosticsOptions(
                profile=parsed.get("profile") or profile,
                test_noop=bool(parsed.get("test_noop", True)),
                test_help=bool(parsed.get("test_help", False)),
                test_vrfy=bool(parsed.get("test_vrfy", False)),
                test_expn=bool(parsed.get("test_expn", False)),
            )
        except ValueError:
            return DiagnosticsOptions()

    def _profile_display_from_value(self, value: object) -> str:
        try:
            return profile_display_name(DiagnosticsProfile.normalize(str(value)))
        except ValueError:
            return UNAVAILABLE

    def _run_status(self, results: list[dict[str, object]]) -> str:
        if not results:
            return "Falhou"
        successes = sum(1 for row in results if int(row.get("success") or 0) == 1)
        if successes == len(results):
            return "Concluído"
        if successes == 0:
            return "Falhou"
        return "Parcial"

    def _has_partial_results(self, results: list[dict[str, object]]) -> bool:
        return not results or any(int(row.get("success") or 0) != 1 for row in results)

    def _ports_text(self, results: list[dict[str, object]]) -> str:
        ports = []
        for row in results:
            try:
                ports.append(int(row.get("port")))
            except (TypeError, ValueError):
                continue
        return ", ".join(str(port) for port in sorted(set(ports))) or UNAVAILABLE

    def _command_line(self, command: CommandDiagnosticResult) -> str:
        presentation = command_presentation(command)
        return (
            f"- {presentation.command}: {presentation.result} | Executado: {presentation.executed} | "
            f"Código: {presentation.response_code} | {presentation.note}"
        )

    def _dict_list_text(self, value: object) -> str:
        if not isinstance(value, dict) or not value:
            return UNAVAILABLE
        parts = []
        for key in sorted(value):
            item = value[key]
            if isinstance(item, list) and item:
                parts.append(f"{key} {' '.join(str(entry) for entry in item)}")
            else:
                parts.append(str(key))
        return ", ".join(parts) if parts else UNAVAILABLE

    def _list_text(self, value: object) -> str:
        if not isinstance(value, list) or not value:
            return UNAVAILABLE
        return ", ".join(str(item) for item in value)








