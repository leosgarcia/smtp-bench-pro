"""Offline PySide6 UI tests for Mail DNS Diagnostics (FASE G)."""

from __future__ import annotations

import base64
import sys
from PySide6.QtCore import QThreadPool
from PySide6.QtWidgets import QApplication

from smtp_bench_pro.application.mail_dns_coordinator import MailDNSDiagnosticsCoordinator
from smtp_bench_pro.domain.mail_dns import (
    DNSQueryResult,
    DNSQueryStatus,
)
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.ui.mail_dns_tab import MailDNSTabWidget
from smtp_bench_pro.ui.widgets.smtp_bench_widget import SMTPBenchWidget


def _dkim_key() -> str:
    return base64.b64encode(b"1" * 32).decode("ascii")


class FakeDNSResolver(IMailDNSResolver):
    """Fake offline DNS Resolver for testing UI."""

    def resolve_mx(self, domain: str) -> DNSQueryResult:
        return DNSQueryResult(
            name=domain,
            record_type="MX",
            status=DNSQueryStatus.SUCCESS,
            answers=("10 mail.example.com",),
        )

    def resolve_a(self, hostname: str) -> DNSQueryResult:
        return DNSQueryResult(
            name=hostname,
            record_type="A",
            status=DNSQueryStatus.SUCCESS,
            answers=("93.184.216.25",),
        )

    def resolve_aaaa(self, hostname: str) -> DNSQueryResult:
        return DNSQueryResult(
            name=hostname,
            record_type="AAAA",
            status=DNSQueryStatus.NXDOMAIN,
            answers=(),
        )

    def resolve_ptr(self, ip_address: str) -> DNSQueryResult:
        return DNSQueryResult(
            name=ip_address,
            record_type="PTR",
            status=DNSQueryStatus.SUCCESS,
            answers=("mail.example.com",),
        )

    def resolve_txt(self, name: str) -> DNSQueryResult:
        if name == "example.com":
            return DNSQueryResult(name, "TXT", DNSQueryStatus.SUCCESS, ("v=spf1 include:_spf.example.com -all",))
        if name == "_spf.example.com":
            return DNSQueryResult(name, "TXT", DNSQueryStatus.SUCCESS, ("v=spf1 ip4:93.184.216.25 -all",))
        if name == "default._domainkey.example.com":
            txt = f"v=DKIM1; k=ed25519; p={_dkim_key()}; s=email; h=sha256"
            return DNSQueryResult(name, "TXT", DNSQueryStatus.SUCCESS, (txt,))
        if name == "_dmarc.example.com":
            txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            return DNSQueryResult(name, "TXT", DNSQueryStatus.SUCCESS, (txt,))
        return DNSQueryResult(name, "TXT", DNSQueryStatus.NXDOMAIN, ())


def test_ui_architectural_purity() -> None:
    """Verifies MailDNSTabWidget does not import network or parser logic directly."""
    mod = "smtp_bench_pro.ui.mail_dns_tab"
    assert mod in sys.modules
    imported = sys.modules[mod].__dict__
    for lib in ("dns.resolver", "spf_parser", "dmarc_parser", "sqlite3"):
        assert lib not in imported, f"Forbidden library '{lib}' imported directly in UI!"


def test_tab_exists_standalone_and_integrated(qtbot) -> None:
    _ = QApplication.instance() or QApplication([])

    # Standalone mode
    standalone_widget = SMTPBenchWidget(include_about=True)
    qtbot.addWidget(standalone_widget)
    assert standalone_widget.tab_widget.count() == 6
    assert standalone_widget.tab_widget.tabText(4) == "DNS de E-mail"
    assert standalone_widget.tab_widget.tabText(5) == "Sobre"

    # Integrated mode
    integrated_widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(integrated_widget)
    assert integrated_widget.tab_widget.count() == 5
    assert integrated_widget.tab_widget.tabText(4) == "DNS de E-mail"


def test_mail_dns_tab_thread_pool_not_global(qtbot) -> None:
    tab = MailDNSTabWidget()
    qtbot.addWidget(tab)

    # ThreadPool MUST be dedicated, never globalInstance
    assert tab._mail_dns_thread_pool is not QThreadPool.globalInstance()
    assert tab._mail_dns_thread_pool.maxThreadCount() == 4


def test_mail_dns_tab_empty_state_and_render(qtbot) -> None:
    fake_resolver = FakeDNSResolver()
    coordinator = MailDNSDiagnosticsCoordinator(resolver=fake_resolver)

    tab = MailDNSTabWidget(coordinator=coordinator)
    qtbot.addWidget(tab)

    # Initial empty state
    assert tab.domain_input.text() == ""
    assert tab.run_button.isEnabled() is True
    assert tab.cancel_button.isEnabled() is False
    assert "Nenhum diagnóstico" in tab.status_label.text()

    # Set valid domain input and execute
    tab.domain_input.setText("example.com")
    outcome = coordinator.execute_diagnostics("example.com", dkim_selectors="default")
    tab.render_outcome(outcome)

    # Check rendering
    lbl_mx_stat = tab.card_mx.property("lbl_status")
    assert "MX válido" in lbl_mx_stat.text()

    lbl_dmarc_stat = tab.card_dmarc.property("lbl_status")
    assert "p=reject" in lbl_dmarc_stat.text()

    assert tab.table_mx.rowCount() == 1
    assert tab.table_mx.item(0, 1).text() == "mail.example.com"
    assert tab.detail_tabs.tabText(2) == "DKIM"
    assert tab.table_dkim.rowCount() == 1
    assert tab.table_dkim.item(0, 0).text() == "default"
    assert tab.table_dkim.item(0, 2).text() == "VALID"


def test_mail_dns_cards_are_compact_and_status_textual(qtbot) -> None:
    tab = MailDNSTabWidget()
    qtbot.addWidget(tab)

    assert tab.card_mx.objectName() == "mailDnsCard"
    assert tab.card_mx.maximumHeight() <= 92
    assert tab.card_mx.property("lbl_status").text().startswith("Status")


def test_spf_dmarc_raw_records_are_read_only_copyable(qtbot) -> None:
    fake_resolver = FakeDNSResolver()
    coordinator = MailDNSDiagnosticsCoordinator(resolver=fake_resolver)
    tab = MailDNSTabWidget(coordinator=coordinator)
    qtbot.addWidget(tab)

    outcome = coordinator.execute_diagnostics("example.com")
    tab.render_outcome(outcome)

    assert tab.lbl_spf_raw.isReadOnly() is True
    assert "v=spf1" in tab.lbl_spf_raw.toPlainText()
    assert tab.lbl_dmarc_raw.isReadOnly() is True
    assert "v=DMARC1" in tab.lbl_dmarc_raw.toPlainText()
