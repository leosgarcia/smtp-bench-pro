"""PySide6 Read-Only Historical Mail DNS Widget (FASE H)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QFormLayout,
    QGroupBox,
    QHBoxLayout,
    QHeaderView,
    QLabel,
    QSplitter,
    QTableWidget,
    QTableWidgetItem,
    QTabWidget,
    QTextEdit,
    QVBoxLayout,
    QWidget,
)

from smtp_bench_pro.domain.mail_dns import (
    DMARCStatus,
    MailDNSFinding,
    MailDNSRunSnapshot,
    MXStatus,
    SPFStatus,
)


class HistoricalMailDNSWidget(QWidget):
    """Read-only PySide6 view for displaying a historical MailDNSRunSnapshot."""

    def __init__(self, parent: QWidget | None = None) -> None:
        super().__init__(parent)
        self._snapshot: MailDNSRunSnapshot | None = None
        self._init_ui()

    def _init_ui(self) -> None:
        layout = QVBoxLayout(self)
        layout.setContentsMargins(12, 12, 12, 12)
        layout.setSpacing(10)

        # 1. Header Information Box
        self.header_box = QGroupBox("Histórico de DNS de E-mail")
        header_layout = QFormLayout(self.header_box)

        self.lbl_domain = QLabel("-")
        self.lbl_date = QLabel("-")
        self.lbl_status = QLabel("-")
        self.lbl_snapshot = QLabel("Persistido no SQLite Schema v4")

        header_layout.addRow("Domínio:", self.lbl_domain)
        header_layout.addRow("Data da Execução:", self.lbl_date)
        header_layout.addRow("Status do Diagnóstico:", self.lbl_status)
        header_layout.addRow("Fotografia:", self.lbl_snapshot)
        layout.addWidget(self.header_box)

        # 2. Empty / Unavailable Banner
        self.empty_label = QLabel("Esta execução não possui diagnóstico DNS de E-mail.")
        self.empty_label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.empty_label.setStyleSheet("color: #666; font-style: italic; padding: 20px;")
        layout.addWidget(self.empty_label)

        # 3. Main Content Container
        self.content_widget = QWidget()
        content_layout = QVBoxLayout(self.content_widget)
        content_layout.setContentsMargins(0, 0, 0, 0)
        content_layout.setSpacing(10)

        # Cards Layout
        cards_layout = QHBoxLayout()
        cards_layout.setSpacing(8)

        self.card_mx = self._create_card("Roteamento MX")
        self.card_ptr = self._create_card("PTR / FCRDNS")
        self.card_spf = self._create_card("Registro SPF")
        self.card_dkim = self._create_card("Registro DKIM")
        self.card_dmarc = self._create_card("Registro DMARC")

        cards_layout.addWidget(self.card_mx)
        cards_layout.addWidget(self.card_ptr)
        cards_layout.addWidget(self.card_spf)
        cards_layout.addWidget(self.card_dkim)
        cards_layout.addWidget(self.card_dmarc)
        content_layout.addLayout(cards_layout)

        # Details Sub-tabs
        self.detail_tabs = QTabWidget()

        # Tab 1: Routing
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

        # Tab 5: Findings
        self.tab_findings = QWidget()
        self._setup_findings_tab(self.tab_findings)
        self.detail_tabs.addTab(self.tab_findings, "Achados de Segurança")

        content_layout.addWidget(self.detail_tabs, 1)
        layout.addWidget(self.content_widget, 1)

        self.content_widget.setVisible(False)

    def _create_card(self, title: str) -> QGroupBox:
        box = QGroupBox(title)
        box_layout = QVBoxLayout(box)
        box_layout.setContentsMargins(8, 8, 8, 8)
        lbl_status = QLabel("-")
        lbl_status.setStyleSheet("font-weight: bold;")
        lbl_details = QLabel("-")
        lbl_details.setWordWrap(True)
        box_layout.addWidget(lbl_status)
        box_layout.addWidget(lbl_details)
        box.setProperty("lbl_status", lbl_status)
        box.setProperty("lbl_details", lbl_details)
        return box

    def _setup_routing_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Servidores MX Persistidos:"))
        self.table_mx = QTableWidget(0, 5)
        self.table_mx.setHorizontalHeaderLabels(["Prioridade", "Exchange", "IPv4", "IPv6", "CNAME?"])
        self.table_mx.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_mx)

        layout.addWidget(QLabel("Validação PTR e FCRDNS Persistida:"))
        self.table_ptr = QTableWidget(0, 4)
        self.table_ptr.setHorizontalHeaderLabels(["Endereço IP", "Hostname PTR", "Forward IPs", "FCRDNS Status"])
        self.table_ptr.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_ptr)

    def _setup_spf_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        form = QFormLayout()

        self.lbl_spf_raw = QLabel("-")
        self.lbl_spf_raw.setWordWrap(True)
        self.lbl_spf_status = QLabel("-")
        self.lbl_spf_lookups = QLabel("-")
        self.lbl_spf_all = QLabel("-")
        self.lbl_spf_ptr = QLabel("-")

        form.addRow("Registro Publicado:", self.lbl_spf_raw)
        form.addRow("Status Sintático:", self.lbl_spf_status)
        form.addRow("DNS Lookups:", self.lbl_spf_lookups)
        form.addRow("Política all Final:", self.lbl_spf_all)
        form.addRow("Uso de ptr:", self.lbl_spf_ptr)
        layout.addLayout(form)

        layout.addWidget(QLabel("Termos SPF Persistidos:"))
        self.table_spf_terms = QTableWidget(0, 4)
        self.table_spf_terms.setHorizontalHeaderLabels(["Qualificador", "Mecanismo", "Valor / Alvo", "DNS Lookup?"])
        self.table_spf_terms.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_spf_terms)


    def _setup_dkim_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        layout.addWidget(QLabel("Selectors DKIM Persistidos:"))
        self.table_dkim = QTableWidget(0, 8)
        self.table_dkim.setHorizontalHeaderLabels(
            ["Selector", "Query", "Status", "Tipo", "Bits", "Flags", "Serviços", "Erros / Notas"]
        )
        self.table_dkim.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        layout.addWidget(self.table_dkim)

    def _setup_dmarc_tab(self, widget: QWidget) -> None:
        layout = QVBoxLayout(widget)
        form = QFormLayout()

        self.lbl_dmarc_raw = QLabel("-")
        self.lbl_dmarc_raw.setWordWrap(True)
        self.lbl_dmarc_status = QLabel("-")
        self.lbl_dmarc_policy = QLabel("-")
        self.lbl_dmarc_sp = QLabel("-")
        self.lbl_dmarc_pct = QLabel("-")
        self.lbl_dmarc_align = QLabel("-")
        self.lbl_dmarc_org = QLabel("-")
        self.lbl_dmarc_rua = QLabel("-")

        form.addRow("Registro Publicado:", self.lbl_dmarc_raw)
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

        self.table_findings = QTableWidget(0, 4)
        self.table_findings.setHorizontalHeaderLabels(["Severidade", "Categoria", "ID", "Título"])
        self.table_findings.horizontalHeader().setSectionResizeMode(QHeaderView.Stretch)
        self.table_findings.itemSelectionChanged.connect(self._on_finding_selected)
        splitter.addWidget(self.table_findings)

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

    def set_snapshot(self, snapshot: MailDNSRunSnapshot | None) -> None:
        """Sets and renders the historical MailDNSRunSnapshot (Read-Only)."""
        self._snapshot = snapshot
        if not snapshot:
            self.empty_label.setVisible(True)
            self.content_widget.setVisible(False)
            self.lbl_domain.setText("-")
            self.lbl_date.setText("-")
            self.lbl_status.setText("Não disponível nesta execução.")
            return

        self.empty_label.setVisible(False)
        self.content_widget.setVisible(True)

        # Render Header
        self.lbl_domain.setText(snapshot.domain)
        self.lbl_date.setText(snapshot.created_at)
        self.lbl_status.setText("Concluído (Fotografia Persistida)")

        # Render Cards
        summary = snapshot.identity_summary

        lbl_mx_stat = self.card_mx.property("lbl_status")
        lbl_mx_det = self.card_mx.property("lbl_details")
        if snapshot.routing.mx_record.status == MXStatus.NULL_MX:
            lbl_mx_stat.setText("Null MX (Sem E-mail)")
            lbl_mx_det.setText("Domínio declara recusa explícita de e-mail.")
        else:
            count = len(snapshot.routing.mx_record.records)
            lbl_mx_stat.setText(f"MX Válido ({count})")
            lbl_mx_det.setText(f"{count} servidor(es) MX configurado(s).")

        lbl_ptr_stat = self.card_ptr.property("lbl_status")
        lbl_ptr_det = self.card_ptr.property("lbl_details")
        lbl_ptr_stat.setText(f"FCRDNS ({summary.fcrdns_aligned_ips}/{summary.fcrdns_total_ips})")
        lbl_ptr_det.setText(f"{summary.fcrdns_aligned_ips} IP(s) com FCRDNS alinhado.")

        lbl_spf_stat = self.card_spf.property("lbl_status")
        lbl_spf_det = self.card_spf.property("lbl_details")
        if snapshot.spf.status == SPFStatus.VALID_SINGLE:
            lbl_spf_stat.setText(f"SPF Válido ({snapshot.spf.all_qualifier or ''}all)")
            lbl_spf_det.setText(f"{snapshot.spf.dns_lookup_count}/10 DNS lookups.")
        else:
            lbl_spf_stat.setText(f"SPF: {snapshot.spf.status.value}")
            lbl_spf_det.setText(snapshot.spf.validation_error or "Atenção na política SPF.")

        lbl_dkim_stat = self.card_dkim.property("lbl_status")
        lbl_dkim_det = self.card_dkim.property("lbl_details")
        if snapshot.dkim.results:
            valid = sum(1 for result in snapshot.dkim.results if result.status.value == "VALID")
            lbl_dkim_stat.setText(f"DKIM ({valid}/{len(snapshot.dkim.results)})")
            lbl_dkim_det.setText(f"{len(snapshot.dkim.results)} selector(es) persistido(s).")
        else:
            lbl_dkim_stat.setText("DKIM: N/A")
            lbl_dkim_det.setText("Não disponível nesta execução.")

        lbl_dmarc_stat = self.card_dmarc.property("lbl_status")
        lbl_dmarc_det = self.card_dmarc.property("lbl_details")
        if snapshot.dmarc.status == DMARCStatus.VALID:
            lbl_dmarc_stat.setText(f"DMARC (p={snapshot.dmarc.policy})")
            lbl_dmarc_det.setText(f"Organizational: {snapshot.dmarc.organizational_domain}")
        else:
            lbl_dmarc_stat.setText(f"DMARC: {snapshot.dmarc.status.value}")
            lbl_dmarc_det.setText("Nenhum registro DMARC válido.")

        # Render Routing
        self.table_mx.setRowCount(0)
        for r in snapshot.routing.mx_record.records:
            row = self.table_mx.rowCount()
            self.table_mx.insertRow(row)
            v4_str = ", ".join(a.ip for a in r.addresses_v4) or "-"
            v6_str = ", ".join(a.ip for a in r.addresses_v6) or "-"
            cname_str = "Sim" if r.cname_detected else "Não"
            self.table_mx.setItem(row, 0, QTableWidgetItem(str(r.preference)))
            self.table_mx.setItem(row, 1, QTableWidgetItem(r.exchange))
            self.table_mx.setItem(row, 2, QTableWidgetItem(v4_str))
            self.table_mx.setItem(row, 3, QTableWidgetItem(v6_str))
            self.table_mx.setItem(row, 4, QTableWidgetItem(cname_str))

        self.table_ptr.setRowCount(0)
        for p in snapshot.routing.ptr_record.results:
            row = self.table_ptr.rowCount()
            self.table_ptr.insertRow(row)
            ptr_hosts = ", ".join(p.ptr_hostnames) or "-"
            fwd_ips = ", ".join(p.forward_ips) or "-"
            self.table_ptr.setItem(row, 0, QTableWidgetItem(p.ip))
            self.table_ptr.setItem(row, 1, QTableWidgetItem(ptr_hosts))
            self.table_ptr.setItem(row, 2, QTableWidgetItem(fwd_ips))
            self.table_ptr.setItem(row, 3, QTableWidgetItem(p.status.value))

        # Render SPF
        self.lbl_spf_raw.setText(snapshot.spf.raw_record or "-")
        self.lbl_spf_status.setText(snapshot.spf.status.value)
        lookups_str = f"{snapshot.spf.dns_lookup_count} (limite: 10) | Void: {snapshot.spf.void_lookup_count}"
        self.lbl_spf_lookups.setText(lookups_str)
        self.lbl_spf_all.setText(snapshot.spf.all_qualifier or "-")
        self.lbl_spf_ptr.setText("Sim (Depreciado)" if snapshot.spf.uses_ptr_mechanism else "Não")

        self.table_spf_terms.setRowCount(0)
        for t in snapshot.spf.terms:
            row = self.table_spf_terms.rowCount()
            self.table_spf_terms.insertRow(row)
            self.table_spf_terms.setItem(row, 0, QTableWidgetItem(t.qualifier))
            self.table_spf_terms.setItem(row, 1, QTableWidgetItem(t.mechanism))
            self.table_spf_terms.setItem(row, 2, QTableWidgetItem(t.value or "-"))
            self.table_spf_terms.setItem(row, 3, QTableWidgetItem("Sim" if t.causes_dns_lookup else "Não"))

        # Render DKIM
        self.table_dkim.setRowCount(0)
        for result in snapshot.dkim.results:
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
                self.table_dkim.setItem(row, column, QTableWidgetItem(value))

        # Render DMARC
        self.lbl_dmarc_raw.setText(snapshot.dmarc.raw_record or "-")
        self.lbl_dmarc_status.setText(snapshot.dmarc.status.value)
        self.lbl_dmarc_policy.setText(snapshot.dmarc.policy or "-")
        self.lbl_dmarc_sp.setText(snapshot.dmarc.subdomain_policy or "Herdada de p")
        self.lbl_dmarc_pct.setText(f"{snapshot.dmarc.pct}%")
        self.lbl_dmarc_align.setText(f"DKIM: {snapshot.dmarc.adkim.upper()} | SPF: {snapshot.dmarc.aspf.upper()}")
        self.lbl_dmarc_org.setText(snapshot.dmarc.organizational_domain)
        self.lbl_dmarc_rua.setText(", ".join(snapshot.dmarc.rua) or "-")

        # Render Findings
        self.table_findings.setRowCount(0)
        for f in snapshot.findings:
            row = self.table_findings.rowCount()
            self.table_findings.insertRow(row)
            self.table_findings.setItem(row, 0, QTableWidgetItem(f.severity.value))
            self.table_findings.setItem(row, 1, QTableWidgetItem(f.category))
            self.table_findings.setItem(row, 2, QTableWidgetItem(f.id))
            self.table_findings.setItem(row, 3, QTableWidgetItem(f.title))

        self.txt_finding_desc.clear()
        self.txt_finding_evidence.clear()
        self.txt_finding_rec.clear()

    def _on_finding_selected(self) -> None:
        selected_rows = self.table_findings.selectedItems()
        if not selected_rows or not self._snapshot:
            return

        row_idx = self.table_findings.currentRow()
        if 0 <= row_idx < len(self._snapshot.findings):
            finding: MailDNSFinding = self._snapshot.findings[row_idx]
            self.txt_finding_desc.setText(finding.description)
            self.txt_finding_evidence.setText(finding.evidence)
            self.txt_finding_rec.setText(finding.recommendation)
