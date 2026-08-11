"""PySide6 Tab Widget for Mail DNS Diagnostics."""

from __future__ import annotations

import logging
from PySide6.QtCore import Qt, QThreadPool
from PySide6.QtWidgets import (
    QApplication,
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QLineEdit,
    QPlainTextEdit,
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

from smtp_bench_pro.application.mail_dns_coordinator import (
    MailDNSDiagnosticsCoordinator,
    MailDNSDiagnosticsOutcome,
)

from smtp_bench_pro.domain.mail_dns import (
    DMARCStatus,
    MailDNSFinding,
    MXStatus,
    SPFStatus,
)
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository
from smtp_bench_pro.ui.mail_dns_worker import MailDNSDiagnosticsWorker

logger = logging.getLogger("smtp_bench_pro.mail_dns.ui")


class MailDNSTabWidget(QWidget):
    """Main tab widget for Mail DNS Diagnostics (FASE G)."""

    def __init__(
        self,
        coordinator: MailDNSDiagnosticsCoordinator | None = None,
        repository: SMTPBenchmarkRepository | None = None,
        parent: QWidget | None = None,
    ) -> None:
        super().__init__(parent)
        self.repository = repository
        self.coordinator = coordinator or MailDNSDiagnosticsCoordinator(repository=self.repository)

        # Dedicated ThreadPool (never globalInstance)
        self._mail_dns_thread_pool = QThreadPool(self)
        self._mail_dns_thread_pool.setMaxThreadCount(4)

        self._active_worker: MailDNSDiagnosticsWorker | None = None
        self._current_outcome: MailDNSDiagnosticsOutcome | None = None

        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # 1. Top Input & Actions Bar
        input_box = QGroupBox("Diagnóstico de DNS de E-mail")
        input_layout = QHBoxLayout(input_box)

        self.domain_input = QLineEdit()
        self.domain_input.setPlaceholderText("example.com")
        self.domain_input.returnPressed.connect(self._start_diagnostics)

        self.run_button = QPushButton("Executar Diagnóstico")
        self.run_button.setObjectName("primaryButton")
        self.run_button.clicked.connect(self._start_diagnostics)

        self.cancel_button = QPushButton("Cancelar")
        self.cancel_button.setObjectName("secondaryButton")
        self.cancel_button.setEnabled(False)
        self.cancel_button.clicked.connect(self._cancel_diagnostics)

        self.dkim_selectors_input = QLineEdit()
        self.dkim_selectors_input.setPlaceholderText("Selectors DKIM: default, google, selector1")
        self.dkim_selectors_input.setToolTip("Informe selectors DKIM manualmente, separados por vírgula. Opcional.")

        input_layout.addWidget(QLabel("Domínio:"))
        input_layout.addWidget(self.domain_input, 1)
        input_layout.addWidget(QLabel("DKIM:"))
        input_layout.addWidget(self.dkim_selectors_input, 1)
        input_layout.addWidget(self.run_button)
        input_layout.addWidget(self.cancel_button)
        layout.addWidget(input_box)

        # 2. Progress & Status Bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 6)
        self.progress_bar.setValue(0)
        self.progress_bar.setVisible(False)
        layout.addWidget(self.progress_bar)

        self.status_label = QLabel(
            "Nenhum diagnóstico DNS de e-mail executado. Informe um domínio e clique em Executar."
        )
        layout.addWidget(self.status_label)

        # 3. Summary Cards (4 Cards)
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(8)

        self.card_mx = self._create_card("Roteamento MX", "Status: -", "Aguardando diagnóstico...")
        self.card_ptr = self._create_card("PTR / FCRDNS", "Status: -", "Aguardando diagnóstico...")
        self.card_spf = self._create_card("Registro SPF", "Status: -", "Aguardando diagnóstico...")
        self.card_dmarc = self._create_card("Registro DMARC", "Status: -", "Aguardando diagnóstico...")

        cards_layout.addWidget(self.card_mx)
        cards_layout.addWidget(self.card_ptr)
        cards_layout.addWidget(self.card_spf)
        cards_layout.addWidget(self.card_dmarc)
        layout.addLayout(cards_layout)

        # 4. Detail Sub-tabs
        self.detail_tabs = QTabWidget()

        # Tab 1: Routing (MX / A / PTR)
        self.tab_routing = QWidget()
        self._setup_routing_tab(self.tab_routing)
        self.detail_tabs.addTab(self.tab_routing, "Roteamento (MX / PTR)")

        # Tab 2: SPF
        self.tab_spf = QWidget()
        self._setup_spf_tab(self.tab_spf)
        self.detail_tabs.addTab(self.tab_spf, "SPF")

        # Tab 3: DKIM
        self.tab_dkim = QWidget()
        self._setup_dkim_tab(self.tab_dkim)
        self.detail_tabs.addTab(self.tab_dkim, "DKIM")

        # Tab 4: DMARC
        self.tab_dmarc = QWidget()
        self._setup_dmarc_tab(self.tab_dmarc)
        self.detail_tabs.addTab(self.tab_dmarc, "DMARC")

        # Tab 5: Security Findings
        self.tab_findings = QWidget()
        self._setup_findings_tab(self.tab_findings)
        self.detail_tabs.addTab(self.tab_findings, "Achados de Segurança")

        layout.addWidget(self.detail_tabs, 1)

    def _create_card(self, title: str, status: str, details: str) -> QGroupBox:
        box = QGroupBox(title)
        box.setObjectName("mailDnsCard")
        box.setMaximumHeight(92)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(6, 6, 6, 6)
        box_layout.setSpacing(3)
        lbl_status = QLabel(status)
        lbl_status.setObjectName("mailDnsCardStatus")
        lbl_details = QLabel(details)
        lbl_details.setObjectName("mailDnsCardDetails")
        lbl_details.setWordWrap(True)
        box_layout.addWidget(lbl_status)
        box_layout.addWidget(lbl_details)
        box.setProperty("lbl_status", lbl_status)
        box.setProperty("lbl_details", lbl_details)
        return box


    def _create_raw_record_view(self) -> QPlainTextEdit:
        view = QPlainTextEdit()
        view.setReadOnly(True)
        view.setMaximumHeight(74)
        view.setLineWrapMode(QPlainTextEdit.LineWrapMode.WidgetWidth)
        view.setPlainText("-")
        return view

    def _raw_record_row(self, editor: QPlainTextEdit, button: QPushButton) -> QWidget:
        row = QWidget()
        layout = QHBoxLayout(row)
        layout.setContentsMargins(0, 0, 0, 0)
        layout.setSpacing(6)
        layout.addWidget(editor, 1)
        layout.addWidget(button)
        return row

    def _copy_raw_record(self, editor: QPlainTextEdit) -> None:
        QApplication.clipboard().setText(editor.toPlainText())
        self.status_label.setText("Registro copiado para a área de transferência.")

    def _set_table_item(self, table: QTableWidget, row: int, column: int, value: object) -> None:
        text = str(value)
        item = QTableWidgetItem(text)
        if len(text) > 32:
            item.setToolTip(text)
        table.setItem(row, column, item)

    def _card_status(self, state: str, label: str) -> str:
        return f"{state}: {label}"

    def _setup_routing_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        # MX Table
        layout.addWidget(QLabel("Servidores MX de Entrega:"))
        self.table_mx = QTableWidget(0, 5)
        self.table_mx.setHorizontalHeaderLabels(["Prioridade", "Exchange", "IPv4", "IPv6", "CNAME?"])
        self.table_mx.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_mx.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table_mx)

        # PTR Table
        layout.addWidget(QLabel("Validação PTR e FCRDNS por IP:"))
        self.table_ptr = QTableWidget(0, 4)
        self.table_ptr.setHorizontalHeaderLabels(["Endereço IP", "Hostname PTR", "Forward IPs", "FCRDNS Status"])
        self.table_ptr.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_ptr.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table_ptr)

    def _setup_spf_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        form = QFormLayout()

        self.lbl_spf_raw = self._create_raw_record_view()
        self.btn_copy_spf = QPushButton("Copiar")
        self.btn_copy_spf.setObjectName("secondaryButton")
        self.btn_copy_spf.clicked.connect(lambda: self._copy_raw_record(self.lbl_spf_raw))
        self.lbl_spf_status = QLabel("-")
        self.lbl_spf_lookups = QLabel("-")
        self.lbl_spf_all = QLabel("-")
        self.lbl_spf_ptr = QLabel("-")

        form.addRow("Registro Publicado:", self._raw_record_row(self.lbl_spf_raw, self.btn_copy_spf))
        form.addRow("Status Sintático:", self.lbl_spf_status)
        form.addRow("DNS Lookups:", self.lbl_spf_lookups)
        form.addRow("Política all Final:", self.lbl_spf_all)
        form.addRow("Uso de ptr:", self.lbl_spf_ptr)
        layout.addLayout(form)

        layout.addWidget(QLabel("Termos e Mecanismos SPF:"))
        self.table_spf_terms = QTableWidget(0, 4)
        self.table_spf_terms.setHorizontalHeaderLabels(["Qualificador", "Mecanismo", "Valor / Alvo", "DNS Lookup?"])
        self.table_spf_terms.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_spf_terms.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table_spf_terms)


    def _setup_dkim_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Selectors DKIM consultados:"))
        self.table_dkim = QTableWidget(0, 8)
        self.table_dkim.setHorizontalHeaderLabels(
            ["Selector", "Query", "Status", "Tipo", "Bits", "Flags", "Serviços", "Erros / Notas"]
        )
        self.table_dkim.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_dkim.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        layout.addWidget(self.table_dkim)

    def _setup_dmarc_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        form = QFormLayout()

        self.lbl_dmarc_raw = self._create_raw_record_view()
        self.btn_copy_dmarc = QPushButton("Copiar")
        self.btn_copy_dmarc.setObjectName("secondaryButton")
        self.btn_copy_dmarc.clicked.connect(lambda: self._copy_raw_record(self.lbl_dmarc_raw))
        self.lbl_dmarc_status = QLabel("-")
        self.lbl_dmarc_policy = QLabel("-")
        self.lbl_dmarc_sp = QLabel("-")
        self.lbl_dmarc_pct = QLabel("-")
        self.lbl_dmarc_align = QLabel("-")
        self.lbl_dmarc_org = QLabel("-")
        self.lbl_dmarc_rua = QLabel("-")

        form.addRow("Registro Publicado:", self._raw_record_row(self.lbl_dmarc_raw, self.btn_copy_dmarc))
        form.addRow("Status:", self.lbl_dmarc_status)
        form.addRow("Política p:", self.lbl_dmarc_policy)
        form.addRow("Política sp (subdomínio):", self.lbl_dmarc_sp)
        form.addRow("Percentual pct:", self.lbl_dmarc_pct)
        form.addRow("Alinhamento (DKIM/SPF):", self.lbl_dmarc_align)
        form.addRow("Organizational Domain:", self.lbl_dmarc_org)
        form.addRow("Relatórios RUA:", self.lbl_dmarc_rua)
        layout.addLayout(form)

    def _setup_findings_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        splitter = QSplitter(Qt.Vertical)

        # Findings Table
        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["Severidade", "Categoria", "ID", "Título"])
        self.table_findings.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_findings.setSelectionBehavior(QTableWidget.SelectionBehavior.SelectRows)
        self.table_findings.itemSelectionChanged.connect(self._on_finding_selected)
        splitter.addWidget(self.table_findings)

        # Details Box
        details_box = QGroupBox("Detalhes do Achado Selecionado")
        details_layout = QFormLayout(details_box)

        self.txt_finding_desc = QTextEdit()
        self.txt_finding_desc.setReadOnly(True)
        self.txt_finding_evidence = QTextEdit()
        self.txt_finding_evidence.setReadOnly(True)
        self.txt_finding_rec = QTextEdit()
        self.txt_finding_rec.setReadOnly(True)

        details_layout.addRow("Descrição:", self.txt_finding_desc)
        details_layout.addRow("Evidência:", self.txt_finding_evidence)
        details_layout.addRow("Recomendação:", self.txt_finding_rec)

        splitter.addWidget(details_box)
        layout.addWidget(splitter)

    # --- ACTIONS ---

    def _start_diagnostics(self) -> None:
        raw_domain = self.domain_input.text().strip()
        if not raw_domain:
            self.status_label.setText("Por favor, informe um domínio válido.")
            return

        self.run_button.setEnabled(False)
        self.cancel_button.setEnabled(True)
        self.progress_bar.setVisible(True)
        self.progress_bar.setValue(0)
        self.status_label.setText("Iniciando diagnóstico Mail DNS...")

        worker = MailDNSDiagnosticsWorker(self.coordinator, raw_domain, self.dkim_selectors_input.text())
        worker.signals.started.connect(self._on_started)
        worker.signals.progress.connect(self._on_progress)
        worker.signals.finished.connect(self._on_finished)
        worker.signals.failed.connect(self._on_failed)

        self._active_worker = worker
        self._mail_dns_thread_pool.start(worker)

    def _cancel_diagnostics(self) -> None:
        if self._active_worker:
            self._active_worker.cancel()
            self._active_worker = None
        self._reset_action_buttons()
        self.progress_bar.setVisible(False)
        self.status_label.setText("Diagnóstico cancelado pelo usuário.")

    def _reset_action_buttons(self) -> None:
        self.run_button.setEnabled(True)
        self.cancel_button.setEnabled(False)

    # --- WORKER SIGNALS ---

    def _on_started(self) -> None:
        self.status_label.setText("Diagnóstico iniciado...")

    def _on_progress(self, step: int, text: str) -> None:
        self.progress_bar.setValue(step)
        self.status_label.setText(text)

    def _on_finished(self, result_tuple: tuple) -> None:
        outcome, snapshot = result_tuple
        self._current_outcome = outcome
        self._reset_action_buttons()
        self.progress_bar.setValue(6)
        self.progress_bar.setVisible(False)

        if outcome.partial:
            self.status_label.setText("Diagnóstico parcial concluído com avisos.")
        else:
            self.status_label.setText(f"Diagnóstico concluído para '{outcome.target.domain}'.")

        self.render_outcome(outcome)

    def _on_failed(self, error_msg: str) -> None:
        self._reset_action_buttons()
        self.progress_bar.setVisible(False)
        self.status_label.setText(f"Falha no diagnóstico: {error_msg}")

    # --- RENDERING ---

    def render_outcome(self, outcome: MailDNSDiagnosticsOutcome) -> None:
        """Renders outcome data across summary cards and detail tabs."""
        # 1. Render Summary Cards
        lbl_mx_stat = self.card_mx.property("lbl_status")
        lbl_mx_det = self.card_mx.property("lbl_details")
        if outcome.routing.mx_record.status == MXStatus.NULL_MX:
            lbl_mx_stat.setText(self._card_status("Atenção", "Null MX"))
            lbl_mx_det.setText("Domínio declara recusa explícita de e-mail.")
        elif outcome.routing.mx_record.status == MXStatus.NO_MX:
            lbl_mx_stat.setText(self._card_status("Erro", "Sem MX"))
            lbl_mx_det.setText("Nenhum servidor MX publicado.")
        else:
            count = len(outcome.routing.mx_record.records)
            lbl_mx_stat.setText(self._card_status("OK", f"MX válido ({count})"))
            lbl_mx_det.setText(f"{count} servidor(es) MX configurado(s).")

        lbl_ptr_stat = self.card_ptr.property("lbl_status")
        lbl_ptr_det = self.card_ptr.property("lbl_details")
        summary = outcome.identity_summary
        lbl_ptr_stat.setText(self._card_status("OK", f"FCRDNS {summary.fcrdns_aligned_ips}/{summary.fcrdns_total_ips}"))
        lbl_ptr_det.setText(f"{summary.fcrdns_aligned_ips} IP(s) com FCRDNS alinhado.")

        lbl_spf_stat = self.card_spf.property("lbl_status")
        lbl_spf_det = self.card_spf.property("lbl_details")
        if outcome.spf.status == SPFStatus.VALID_SINGLE:
            lbl_spf_stat.setText(self._card_status("OK", f"SPF válido ({outcome.spf.all_qualifier or ''}all)"))
            lbl_spf_det.setText(f"{outcome.spf.dns_lookup_count}/10 DNS lookups.")
        else:
            lbl_spf_stat.setText(self._card_status("Atenção", f"SPF {outcome.spf.status.value}"))
            lbl_spf_det.setText(outcome.spf.validation_error or "Atenção na política SPF.")

        lbl_dmarc_stat = self.card_dmarc.property("lbl_status")
        lbl_dmarc_det = self.card_dmarc.property("lbl_details")
        if outcome.dmarc.status == DMARCStatus.VALID:
            lbl_dmarc_stat.setText(self._card_status("OK", f"DMARC p={outcome.dmarc.policy}"))
            lbl_dmarc_det.setText(f"Organizational: {outcome.dmarc.organizational_domain}")
        else:
            lbl_dmarc_stat.setText(self._card_status("Atenção", f"DMARC {outcome.dmarc.status.value}"))
            lbl_dmarc_det.setText("Nenhum registro DMARC válido.")

        # 2. Render Routing Tab
        self.table_mx.setRowCount(0)
        for r in outcome.routing.mx_record.records:
            row = self.table_mx.rowCount()
            self.table_mx.insertRow(row)
            v4_str = ", ".join(a.ip for a in r.addresses_v4) or "-"
            v6_str = ", ".join(a.ip for a in r.addresses_v6) or "-"
            cname_str = "Sim" if r.cname_detected else "Não"
            self._set_table_item(self.table_mx, row, 0, str(r.preference))
            self._set_table_item(self.table_mx, row, 1, r.exchange)
            self._set_table_item(self.table_mx, row, 2, v4_str)
            self._set_table_item(self.table_mx, row, 3, v6_str)
            self._set_table_item(self.table_mx, row, 4, cname_str)

        self.table_ptr.setRowCount(0)
        for p in outcome.routing.ptr_record.results:
            row = self.table_ptr.rowCount()
            self.table_ptr.insertRow(row)
            ptr_hosts = ", ".join(p.ptr_hostnames) or "-"
            fwd_ips = ", ".join(p.forward_ips) or "-"
            self._set_table_item(self.table_ptr, row, 0, p.ip)
            self._set_table_item(self.table_ptr, row, 1, ptr_hosts)
            self._set_table_item(self.table_ptr, row, 2, fwd_ips)
            self._set_table_item(self.table_ptr, row, 3, p.status.value)

        # 3. Render SPF Tab
        self.lbl_spf_raw.setPlainText(outcome.spf.raw_record or "-")
        self.lbl_spf_status.setText(outcome.spf.status.value)
        lookups_str = f"{outcome.spf.dns_lookup_count} (limite: 10) | Void: {outcome.spf.void_lookup_count}"
        self.lbl_spf_lookups.setText(lookups_str)
        self.lbl_spf_all.setText(outcome.spf.all_qualifier or "-")
        self.lbl_spf_ptr.setText("Sim (Depreciado)" if outcome.spf.uses_ptr_mechanism else "Não")

        self.table_spf_terms.setRowCount(0)
        for t in outcome.spf.terms:
            row = self.table_spf_terms.rowCount()
            self.table_spf_terms.insertRow(row)
            self._set_table_item(self.table_spf_terms, row, 0, t.qualifier)
            self._set_table_item(self.table_spf_terms, row, 1, t.mechanism)
            self._set_table_item(self.table_spf_terms, row, 2, t.value or "-")
            self._set_table_item(self.table_spf_terms, row, 3, "Sim" if t.causes_dns_lookup else "Não")

        # 4. Render DKIM Tab
        self.table_dkim.setRowCount(0)
        for result in outcome.dkim.results:
            row = self.table_dkim.rowCount()
            self.table_dkim.insertRow(row)
            notes = "; ".join(result.validation_errors or result.notes) or "-"
            values = [
                result.selector,
                result.query_name,
                result.status.value,
                result.key_type or "-",
                str(result.public_key_bits) if result.public_key_bits is not None else "-",
                ", ".join(result.flags) or "-",
                ", ".join(result.services) or "-",
                notes,
            ]
            for column, value in enumerate(values):
                self._set_table_item(self.table_dkim, row, column, value)

        # 5. Render DMARC Tab
        self.lbl_dmarc_raw.setPlainText(outcome.dmarc.raw_record or "-")
        self.lbl_dmarc_status.setText(outcome.dmarc.status.value)
        self.lbl_dmarc_policy.setText(outcome.dmarc.policy or "-")
        self.lbl_dmarc_sp.setText(outcome.dmarc.subdomain_policy or "Herdada de p")
        self.lbl_dmarc_pct.setText(f"{outcome.dmarc.pct}%")
        self.lbl_dmarc_align.setText(f"DKIM: {outcome.dmarc.adkim.upper()} | SPF: {outcome.dmarc.aspf.upper()}")
        self.lbl_dmarc_org.setText(outcome.dmarc.organizational_domain)
        self.lbl_dmarc_rua.setText(", ".join(outcome.dmarc.rua) or "-")

        # 6. Render Findings Tab
        self.table_findings.setRowCount(0)
        for f in outcome.findings:
            row = self.table_findings.rowCount()
            self.table_findings.insertRow(row)
            self._set_table_item(self.table_findings, row, 0, f.severity.value)
            self._set_table_item(self.table_findings, row, 1, f.category)
            self._set_table_item(self.table_findings, row, 2, f.id)
            self._set_table_item(self.table_findings, row, 3, f.title)

        self.txt_finding_desc.clear()
        self.txt_finding_evidence.clear()
        self.txt_finding_rec.clear()

    def _on_finding_selected(self) -> None:
        selected_rows = self.table_findings.selectedItems()
        if not selected_rows or not self._current_outcome:
            return

        row_idx = self.table_findings.currentRow()
        if 0 <= row_idx < len(self._current_outcome.findings):
            finding: MailDNSFinding = self._current_outcome.findings[row_idx]
            self.txt_finding_desc.setText(finding.description)
            self.txt_finding_evidence.setText(finding.evidence)
            self.txt_finding_rec.setText(finding.recommendation)
