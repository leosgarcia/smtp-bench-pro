"""Offline unit and integration tests for SQLite Schema v4 & Mail DNS Persistence (FASE F)."""

from __future__ import annotations

import sqlite3
import sys

import pytest

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
from smtp_bench_pro.persistence.database import SMTPDatabase
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository


def test_persistence_architectural_purity() -> None:
    """Verifies persistence modules do not import network or UI libraries."""
    for mod in ("smtp_bench_pro.persistence.database", "smtp_bench_pro.persistence.mail_dns_serializer"):
        assert mod in sys.modules
        imported = sys.modules[mod].__dict__
        for lib in ("dns.resolver", "socket", "smtplib", "requests", "httpx", "PySide6"):
            assert lib not in imported, f"Forbidden module '{lib}' imported in '{mod}'!"


def test_schema_v4_fresh_database_initialization(tmp_path) -> None:
    db_file = tmp_path / "fresh.db"
    db = SMTPDatabase(path=db_file)
    db.initialize()

    with db.connect() as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        assert version == 4

        # Check mail_dns_runs table columns
        cols = {row[1] for row in conn.execute("PRAGMA table_info(mail_dns_runs)").fetchall()}
        assert "run_id" in cols
        assert "mx_json" in cols
        assert "spf_json" in cols
        assert "dmarc_json" in cols


def test_schema_v3_to_v4_migration_upgrade(tmp_path) -> None:
    db_file = tmp_path / "v3.db"

    # 1. Create v3 database manually
    conn = sqlite3.connect(db_file)
    conn.execute("PRAGMA foreign_keys = ON")
    conn.executescript(
        """
        CREATE TABLE benchmark_runs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hostname TEXT NOT NULL,
            iterations INTEGER NOT NULL,
            timeout REAL NOT NULL,
            diagnostics_profile TEXT NOT NULL DEFAULT 'safe',
            diagnostics_options_json TEXT NOT NULL DEFAULT '{}',
            created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
        );
        INSERT INTO benchmark_runs (hostname, iterations, timeout) VALUES ('legacy.example.com', 1, 3.0);
        PRAGMA user_version = 3;
        """
    )
    conn.commit()
    conn.close()

    # 2. Run initialize() to upgrade v3 -> v4
    db = SMTPDatabase(path=db_file)
    db.initialize()

    with db.connect() as conn:
        version = int(conn.execute("PRAGMA user_version").fetchone()[0])
        assert version == 4

        # Assert legacy run survived
        row = conn.execute("SELECT hostname FROM benchmark_runs WHERE id = 1").fetchone()
        assert row["hostname"] == "legacy.example.com"


def test_mail_dns_snapshot_save_and_reconstruction_roundtrip(tmp_path) -> None:
    db_file = tmp_path / "roundtrip.db"
    db = SMTPDatabase(path=db_file)
    repo = SMTPBenchmarkRepository(database=db)

    # 1. Create benchmark run parent
    run_id = repo.save_run("example.com", 1, 3.0, [])

    # 2. Build complete MailDNSRunSnapshot
    mx_record = MXRecord(
        preference=10,
        exchange="mail.example.com",
        is_null_mx=False,
        addresses_v4=(AddressRecord("93.184.216.25", "IPv4"),),
        addresses_v6=(AddressRecord("2606:2800:220:1:248:1893:25c8:1946", "IPv6"),),
        cname_detected=False,
    )
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(mx_record,))
    ptr_res = FCRDNSResult(
        ip="93.184.216.25",
        ptr_hostnames=("mail.example.com",),
        status=FCRDNSStatus.MATCH,
        forward_ips=("93.184.216.25",),
    )
    ptr_diag = PTRDiagnosticResult(results=(ptr_res,))
    routing = MailRoutingDiagnosticResult("example.com", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    term1 = SPFTerm(qualifier="+", mechanism="include", value="_spf.example.com", causes_dns_lookup=True)
    term2 = SPFTerm(qualifier="+", mechanism="ip4", value="192.0.2.0/24", causes_dns_lookup=False)
    term3 = SPFTerm(qualifier="-", mechanism="all", causes_dns_lookup=False)
    spf = SPFDiagnosticResult(
        status=SPFStatus.VALID_SINGLE,
        raw_record="v=spf1 include:_spf.example.com ip4:192.0.2.0/24 -all",
        terms=(term1, term2, term3),
        dns_lookup_count=1,
        void_lookup_count=0,
        all_qualifier="-",
        uses_ptr_mechanism=False,
    )

    dmarc = DMARCDiagnosticResult(
        status=DMARCStatus.VALID,
        raw_record="v=DMARC1; p=reject; rua=mailto:dmarc@example.com",
        policy="reject",
        subdomain_policy=None,
        pct=100,
        adkim="r",
        aspf="r",
        rua=("mailto:dmarc@example.com",),
        ruf=(),
        organizational_domain="example.com",
    )

    summary = MailIdentitySummary(
        domain="example.com",
        organizational_domain="example.com",
        mx_count=1,
        has_null_mx=False,
        spf_policy="VALID_SINGLE",
        dmarc_policy="reject",
        fcrdns_aligned_ips=1,
        fcrdns_total_ips=1,
    )

    finding = MailDNSFinding(
        id="MAILDNS-DMARC-002",
        title="DMARC Test Title",
        severity=MailDNSSeverity.INFO,
        category="DMARC",
        description="Desc",
        evidence="Evid",
        recommendation="Rec",
    )

    original_snapshot = MailDNSRunSnapshot(
        id=None,
        run_id=run_id,
        domain="example.com",
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        findings=(finding,),
        created_at="2026-08-08T22:00:00Z",
    )

    # 3. Save snapshot
    snapshot_id = repo.save_mail_dns_snapshot(original_snapshot)
    assert snapshot_id > 0
    assert repo.has_mail_dns_snapshot(run_id) is True

    # 4. Reconstruct snapshot
    loaded = repo.get_mail_dns_snapshot(run_id)
    assert loaded is not None
    assert loaded.run_id == run_id
    assert loaded.domain == "example.com"

    # Compare inner frozen dataclasses
    assert loaded.routing == original_snapshot.routing
    assert loaded.spf == original_snapshot.spf
    assert loaded.dmarc == original_snapshot.dmarc
    assert loaded.identity_summary == original_snapshot.identity_summary
    assert loaded.findings == original_snapshot.findings
    assert loaded.spf.terms == original_snapshot.spf.terms  # Order preserved!


def test_cascade_delete_removes_mail_dns_snapshot(tmp_path) -> None:
    db_file = tmp_path / "cascade.db"
    db = SMTPDatabase(path=db_file)
    repo = SMTPBenchmarkRepository(database=db)

    run_id = repo.save_run("cascade.example.com", 1, 3.0, [])
    mx_diag = MXDiagnosticResult(status=MXStatus.NO_MX)
    ptr_diag = PTRDiagnosticResult(results=())
    routing = MailRoutingDiagnosticResult("cascade.example.com", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)
    spf = SPFDiagnosticResult(status=SPFStatus.ABSENT)
    dmarc = DMARCDiagnosticResult(status=DMARCStatus.ABSENT)
    summary = MailIdentitySummary("cascade.example.com", "cascade.example.com", 0, False, None, None, 0, 0)

    snapshot = MailDNSRunSnapshot(
        id=None,
        run_id=run_id,
        domain="cascade.example.com",
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        findings=(),
        created_at="2026-08-08T22:00:00Z",
    )

    repo.save_mail_dns_snapshot(snapshot)
    assert repo.has_mail_dns_snapshot(run_id) is True

    # Delete parent run
    with db.connect() as conn:
        conn.execute("DELETE FROM benchmark_runs WHERE id = ?", (run_id,))

    # Mail DNS snapshot must be deleted automatically via ON DELETE CASCADE
    assert repo.get_mail_dns_snapshot(run_id) is None
    assert repo.has_mail_dns_snapshot(run_id) is False


def test_duplicate_snapshot_rejection(tmp_path) -> None:
    db_file = tmp_path / "dup.db"
    db = SMTPDatabase(path=db_file)
    repo = SMTPBenchmarkRepository(database=db)

    run_id = repo.save_run("dup.example.com", 1, 3.0, [])
    routing = MailRoutingDiagnosticResult(
        "dup.example.com", "2026-08-08T22:00:00Z", MXDiagnosticResult(MXStatus.NO_MX), PTRDiagnosticResult()
    )
    spf = SPFDiagnosticResult(status=SPFStatus.ABSENT)
    dmarc = DMARCDiagnosticResult(status=DMARCStatus.ABSENT)
    summary = MailIdentitySummary("dup.example.com", "dup.example.com", 0, False, None, None, 0, 0)
    snapshot = MailDNSRunSnapshot(
        id=None,
        run_id=run_id,
        domain="dup.example.com",
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        findings=(),
        created_at="2026-08-08T22:00:00Z",
    )

    repo.save_mail_dns_snapshot(snapshot)

    # Second save attempt for same run_id must fail
    with pytest.raises(ValueError, match="already exists"):
        repo.save_mail_dns_snapshot(snapshot)


def test_legacy_run_returns_none(tmp_path) -> None:
    db_file = tmp_path / "legacy.db"
    db = SMTPDatabase(path=db_file)
    repo = SMTPBenchmarkRepository(database=db)

    run_id = repo.save_run("legacy.com", 1, 3.0, [])
    assert repo.get_mail_dns_snapshot(run_id) is None
    assert repo.has_mail_dns_snapshot(run_id) is False
