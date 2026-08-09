"""Offline unit tests for MailDNSDiagnosticsCoordinator (FASE G Application Layer)."""

from __future__ import annotations

import sys

from smtp_bench_pro.application.mail_dns_coordinator import (
    MailDNSDiagnosticsCoordinator,
    MailDNSDiagnosticsOutcome,
)
from smtp_bench_pro.domain.mail_dns import (
    DNSQueryResult,
    DNSQueryStatus,
    DMARCStatus,
    MailDNSRunSnapshot,
    MXStatus,
    SPFStatus,
)
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.persistence.database import SMTPDatabase
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository


class FakeDNSResolver(IMailDNSResolver):
    """Fake offline DNS Resolver for testing application coordinator."""

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
        if name == "_dmarc.example.com":
            txt = "v=DMARC1; p=reject; rua=mailto:dmarc@example.com"
            return DNSQueryResult(name, "TXT", DNSQueryStatus.SUCCESS, (txt,))
        return DNSQueryResult(name, "TXT", DNSQueryStatus.NXDOMAIN, ())


def test_coordinator_architectural_purity() -> None:
    """Verifies application coordinator does not import PySide6."""
    mod = "smtp_bench_pro.application.mail_dns_coordinator"
    assert mod in sys.modules
    imported = sys.modules[mod].__dict__
    assert "PySide6" not in imported
    assert "QWidget" not in imported


def test_coordinator_execute_diagnostics() -> None:
    fake_resolver = FakeDNSResolver()
    coordinator = MailDNSDiagnosticsCoordinator(resolver=fake_resolver)

    progress_log = []

    def on_progress(step: int, text: str) -> None:
        progress_log.append((step, text))

    outcome = coordinator.execute_diagnostics("example.com", progress_callback=on_progress)

    assert isinstance(outcome, MailDNSDiagnosticsOutcome)
    assert outcome.target.domain == "example.com"
    assert outcome.routing.mx_record.status == MXStatus.SINGLE_MX
    assert outcome.spf.status == SPFStatus.VALID_SINGLE
    assert outcome.dmarc.status == DMARCStatus.VALID
    assert outcome.identity_summary.domain == "example.com"
    assert outcome.identity_summary.dmarc_policy == "reject"
    assert outcome.partial is False
    assert len(progress_log) == 5


def test_coordinator_diagnose_and_persist(tmp_path) -> None:
    db_file = tmp_path / "coord.db"
    db = SMTPDatabase(path=db_file)
    repo = SMTPBenchmarkRepository(database=db)
    fake_resolver = FakeDNSResolver()

    coordinator = MailDNSDiagnosticsCoordinator(resolver=fake_resolver, repository=repo)

    outcome, snapshot = coordinator.diagnose_and_persist("example.com")

    assert outcome is not None
    assert snapshot is not None
    assert isinstance(snapshot, MailDNSRunSnapshot)
    assert snapshot.domain == "example.com"
    assert snapshot.id is not None and snapshot.id > 0

    # Verify repository loaded equal snapshot
    loaded = repo.get_mail_dns_snapshot(snapshot.run_id)
    assert loaded is not None
    assert loaded.domain == "example.com"
    assert loaded.identity_summary.domain == "example.com"
