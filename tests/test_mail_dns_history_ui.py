"""Offline PySide6 UI tests for HistoricalMailDNSWidget (FASE H)."""

from __future__ import annotations

import sys
from PySide6.QtWidgets import QApplication

from smtp_bench_pro.domain.mail_dns import (
    AddressRecord,
    DMARCDiagnosticResult,
    DMARCStatus,
    FCRDNSResult,
    FCRDNSStatus,
    MailDNSFinding,
    MailDNSSeverity,
    MailDNSRunSnapshot,
    MailIdentitySummary,
    MailRoutingDiagnosticResult,
    MXDiagnosticResult,
    MXRecord,
    MXStatus,
    PTRDiagnosticResult,
    SPFDiagnosticResult,
    SPFStatus,
    SPFTerm,
)
from smtp_bench_pro.ui.historical_mail_dns_widget import HistoricalMailDNSWidget


def test_historical_widget_architectural_purity() -> None:
    """Verifies HistoricalMailDNSWidget does not import network or parser libraries."""
    mod = "smtp_bench_pro.ui.historical_mail_dns_widget"
    assert mod in sys.modules
    imported = sys.modules[mod].__dict__
    for lib in ("dns.resolver", "spf_parser", "dmarc_parser", "sqlite3"):
        assert lib not in imported, f"Forbidden library '{lib}' imported directly in historical UI!"


def _sample_snapshot(domain: str = "history.example.com") -> MailDNSRunSnapshot:
    mx_record = MXRecord(
        preference=10,
        exchange=f"mx1.{domain}",
        is_null_mx=False,
        addresses_v4=(AddressRecord("192.0.2.10", "IPv4"),),
    )
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(mx_record,))
    ptr_res = FCRDNSResult(
        ip="192.0.2.10",
        ptr_hostnames=(f"mx1.{domain}",),
        status=FCRDNSStatus.MATCH,
        forward_ips=("192.0.2.10",),
    )
    ptr_diag = PTRDiagnosticResult(results=(ptr_res,))
    routing = MailRoutingDiagnosticResult(domain, "2026-08-08T22:15:00Z", mx_diag, ptr_diag)

    term1 = SPFTerm(qualifier="+", mechanism="ip4", value="192.0.2.0/24", causes_dns_lookup=False)
    term2 = SPFTerm(qualifier="-", mechanism="all", causes_dns_lookup=False)
    spf = SPFDiagnosticResult(
        status=SPFStatus.VALID_SINGLE,
        raw_record="v=spf1 ip4:192.0.2.0/24 -all",
        terms=(term1, term2),
        dns_lookup_count=0,
        void_lookup_count=0,
        all_qualifier="-",
    )

    dmarc = DMARCDiagnosticResult(
        status=DMARCStatus.VALID,
        raw_record="v=DMARC1; p=reject",
        policy="reject",
        subdomain_policy=None,
        pct=100,
        adkim="r",
        aspf="r",
        rua=(),
        ruf=(),
        organizational_domain=domain,
    )

    summary = MailIdentitySummary(
        domain=domain,
        organizational_domain=domain,
        mx_count=1,
        has_null_mx=False,
        spf_policy="VALID_SINGLE",
        dmarc_policy="reject",
        fcrdns_aligned_ips=1,
        fcrdns_total_ips=1,
    )

    finding = MailDNSFinding(
        id="MAILDNS-DMARC-002",
        title="DMARC Reject Policy",
        severity=MailDNSSeverity.INFO,
        category="DMARC",
        description="DMARC reject policy active.",
        evidence="v=DMARC1; p=reject",
        recommendation="Maintain policy.",
    )

    return MailDNSRunSnapshot(
        id=99,
        run_id=42,
        domain=domain,
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        findings=(finding,),
        created_at="2026-08-08T22:15:00Z",
    )


def test_historical_widget_render_snapshot(qtbot) -> None:
    _ = QApplication.instance() or QApplication([])

    widget = HistoricalMailDNSWidget()
    qtbot.addWidget(widget)
    widget.show()

    snapshot = _sample_snapshot()
    widget.set_snapshot(snapshot)

    assert widget.empty_label.isVisible() is False
    assert widget.content_widget.isVisible() is True
    assert widget.lbl_domain.text() == "history.example.com"
    assert widget.lbl_date.text() == "2026-08-08T22:15:00Z"

    # Tables rendering
    assert widget.table_mx.rowCount() == 1
    assert widget.table_mx.item(0, 1).text() == "mx1.history.example.com"
    assert widget.table_ptr.rowCount() == 1
    assert widget.table_ptr.item(0, 0).text() == "192.0.2.10"
    assert widget.table_spf_terms.rowCount() == 2
    assert widget.table_findings.rowCount() == 1


def test_historical_widget_render_none_legacy(qtbot) -> None:
    _ = QApplication.instance() or QApplication([])

    widget = HistoricalMailDNSWidget()
    qtbot.addWidget(widget)
    widget.show()

    widget.set_snapshot(None)

    assert widget.empty_label.isVisible() is True
    assert widget.content_widget.isVisible() is False
    assert widget.lbl_domain.text() == "-"
    assert "Não disponível" in widget.lbl_status.text()


def test_historical_widget_is_read_only(qtbot) -> None:
    _ = QApplication.instance() or QApplication([])

    widget = HistoricalMailDNSWidget()
    qtbot.addWidget(widget)

    # Assert read-only nature: no LineEdit or Run PushButtons
    assert not hasattr(widget, "domain_input")
    assert not hasattr(widget, "run_button")
    assert not hasattr(widget, "cancel_button")
