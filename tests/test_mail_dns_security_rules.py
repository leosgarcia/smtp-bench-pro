"""Offline unit and architectural purity tests for Mail DNS Security Rules (FASE E)."""

from __future__ import annotations

import sys

from smtp_bench_pro.domain.mail_dns import (
    DMARCDiagnosticResult,
    DMARCStatus,
    FCRDNSResult,
    FCRDNSStatus,
    MailDNSSeverity,
    MailRoutingDiagnosticResult,
    MXDiagnosticResult,
    MXRecord,
    MXStatus,
    PTRDiagnosticResult,
    SPFDiagnosticResult,
    SPFStatus,
    SPFTerm,
)
from smtp_bench_pro.security.mail_dns_rules import (
    count_findings_by_severity,
    evaluate_dmarc_findings,
    evaluate_mail_dns_findings,
    evaluate_mx_findings,
    evaluate_ptr_findings,
    evaluate_spf_findings,
)


def test_architectural_purity_imports() -> None:
    """Verifies that mail_dns_rules does not import network, db, or UI modules."""
    module_name = "smtp_bench_pro.security.mail_dns_rules"
    assert module_name in sys.modules

    imported_modules = sys.modules[module_name].__dict__
    forbidden = [
        "dns.resolver",
        "socket",
        "smtplib",
        "requests",
        "httpx",
        "PySide6",
        "sqlite3",
    ]
    for lib in forbidden:
        assert lib not in imported_modules, f"Forbidden library '{lib}' imported in rules module!"


# -----------------------------------------------------------------------------
# MX RULE TESTS
# -----------------------------------------------------------------------------


def test_mx_findings_no_mx_generates_mx_001() -> None:
    mx_diag = MXDiagnosticResult(status=MXStatus.NO_MX, records=())
    ptr_diag = PTRDiagnosticResult(results=())
    routing = MailRoutingDiagnosticResult("nomx.test", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    findings = evaluate_mx_findings(routing)
    assert len(findings) == 1
    assert findings[0].id == "MAILDNS-MX-001"
    assert findings[0].severity == MailDNSSeverity.HIGH


def test_mx_findings_null_mx_suppresses_mx_001() -> None:
    null_record = MXRecord(preference=0, exchange=".", is_null_mx=True)
    mx_diag = MXDiagnosticResult(status=MXStatus.NULL_MX, records=(null_record,))
    ptr_diag = PTRDiagnosticResult(results=())
    routing = MailRoutingDiagnosticResult("nullmx.test", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    findings = evaluate_mx_findings(routing)
    assert len(findings) == 0


def test_mx_findings_cname_detected_generates_mx_002() -> None:
    cname_record = MXRecord(
        preference=10, exchange="alias.example.com", is_null_mx=False, cname_detected=True
    )
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(cname_record,))
    ptr_diag = PTRDiagnosticResult(results=())
    routing = MailRoutingDiagnosticResult("cname.test", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    findings = evaluate_mx_findings(routing)
    assert len(findings) == 1
    assert findings[0].id == "MAILDNS-MX-002"
    assert findings[0].severity == MailDNSSeverity.MEDIUM


# -----------------------------------------------------------------------------
# PTR / FCRDNS RULE TESTS
# -----------------------------------------------------------------------------


def test_ptr_findings_no_ptr_and_mismatch() -> None:
    res1 = FCRDNSResult(ip="93.184.216.1", ptr_hostnames=(), status=FCRDNSStatus.NO_PTR)
    res2 = FCRDNSResult(
        ip="93.184.216.2",
        ptr_hostnames=("wrong.com",),
        status=FCRDNSStatus.MISMATCH,
        forward_ips=("93.184.216.99",),
    )
    res3 = FCRDNSResult(
        ip="93.184.216.3",
        ptr_hostnames=("mail.example.com",),
        status=FCRDNSStatus.MATCH,
        forward_ips=("93.184.216.3",),
    )
    res4 = FCRDNSResult(ip="192.168.1.1", ptr_hostnames=(), status=FCRDNSStatus.NOT_APPLICABLE)

    ptr_diag = PTRDiagnosticResult(results=(res1, res2, res3, res4))
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX)
    routing = MailRoutingDiagnosticResult("ptr.test", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    findings = evaluate_ptr_findings(routing)
    assert len(findings) == 2

    finding_ids = {f.id for f in findings}
    assert "MAILDNS-PTR-001" in finding_ids
    assert "MAILDNS-PTR-002" in finding_ids


# -----------------------------------------------------------------------------
# SPF RULE TESTS
# -----------------------------------------------------------------------------


def test_spf_findings_absent_multiple_limit_plusall_ptr() -> None:
    # 1. ABSENT
    spf_absent = SPFDiagnosticResult(status=SPFStatus.ABSENT)
    f_absent = evaluate_spf_findings(spf_absent)
    assert len(f_absent) == 1
    assert f_absent[0].id == "MAILDNS-SPF-001"

    # 2. MULTIPLE
    spf_mult = SPFDiagnosticResult(status=SPFStatus.MULTIPLE, raw_record="v=spf1 ...")
    f_mult = evaluate_spf_findings(spf_mult)
    assert len(f_mult) == 1
    assert f_mult[0].id == "MAILDNS-SPF-002"

    # 3. LOOKUP_LIMIT_EXCEEDED + +all + ptr
    ptr_term = SPFTerm(qualifier="+", mechanism="ptr", causes_dns_lookup=True)
    spf_complex = SPFDiagnosticResult(
        status=SPFStatus.LOOKUP_LIMIT_EXCEEDED,
        raw_record="v=spf1 ptr +all",
        terms=(ptr_term,),
        dns_lookup_count=11,
        all_qualifier="+",
        uses_ptr_mechanism=True,
    )
    f_complex = evaluate_spf_findings(spf_complex)
    complex_ids = {f.id for f in f_complex}

    assert "MAILDNS-SPF-003" in complex_ids
    assert "MAILDNS-SPF-004" in complex_ids
    assert "MAILDNS-SPF-005" in complex_ids


# -----------------------------------------------------------------------------
# DMARC RULE TESTS
# -----------------------------------------------------------------------------


def test_dmarc_findings_absent_and_none_policy() -> None:
    # 1. ABSENT
    dmarc_absent = DMARCDiagnosticResult(status=DMARCStatus.ABSENT)
    f_absent = evaluate_dmarc_findings(dmarc_absent)
    assert len(f_absent) == 1
    assert f_absent[0].id == "MAILDNS-DMARC-001"

    # 2. p=none (INFO finding)
    dmarc_none = DMARCDiagnosticResult(status=DMARCStatus.VALID, policy="none", raw_record="v=DMARC1; p=none")
    f_none = evaluate_dmarc_findings(dmarc_none)
    assert len(f_none) == 1
    assert f_none[0].id == "MAILDNS-DMARC-002"
    assert f_none[0].severity == MailDNSSeverity.INFO

    # 3. p=reject (no finding)
    dmarc_reject = DMARCDiagnosticResult(status=DMARCStatus.VALID, policy="reject", raw_record="v=DMARC1; p=reject")
    f_reject = evaluate_dmarc_findings(dmarc_reject)
    assert len(f_reject) == 0


# -----------------------------------------------------------------------------
# AGGREGATED ENGINE, ORDERING & DEDUPLICATION TESTS
# -----------------------------------------------------------------------------


def test_aggregated_mail_dns_findings_engine_ordering_and_dedup() -> None:
    # Setup routing with NO_MX (HIGH)
    mx_record = MXRecord(preference=10, exchange="mail.test", is_null_mx=False, cname_detected=True)
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(mx_record,))
    ptr_res = FCRDNSResult(ip="93.184.216.1", ptr_hostnames=(), status=FCRDNSStatus.NO_PTR)
    ptr_diag = PTRDiagnosticResult(results=(ptr_res,))
    routing = MailRoutingDiagnosticResult("agg.test", "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    # Setup SPF ABSENT (MEDIUM)
    spf = SPFDiagnosticResult(status=SPFStatus.ABSENT)

    # Setup DMARC p=none (INFO)
    dmarc = DMARCDiagnosticResult(status=DMARCStatus.VALID, policy="none", raw_record="v=DMARC1; p=none")

    findings = evaluate_mail_dns_findings(routing, spf, dmarc)
    assert len(findings) == 4

    # Verify severity ordering: HIGH (0) -> MEDIUM (1) -> INFO (3)
    severities = [f.severity for f in findings]
    assert severities[0] == MailDNSSeverity.HIGH  # PTR-001
    assert severities[1] == MailDNSSeverity.MEDIUM  # MX-002
    assert severities[2] == MailDNSSeverity.MEDIUM  # SPF-001
    assert severities[3] == MailDNSSeverity.INFO  # DMARC-002

    # Test count helper
    counts = count_findings_by_severity(findings)
    assert counts["HIGH"] == 1
    assert counts["MEDIUM"] == 2
    assert counts["LOW"] == 0
    assert counts["INFO"] == 1
