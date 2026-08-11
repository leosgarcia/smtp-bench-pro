"""Offline unit tests for Mail DNS JSON & HTML export integration (FASE H)."""

from __future__ import annotations

from html import escape
import json
import sys

from smtp_bench_pro.domain.mail_dns import (
    AddressRecord,
    DKIMDiagnosticResult,
    DKIMSelectorResult,
    DKIMStatus,
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
from smtp_bench_pro.export.historical_export import (
    HistoricalRunExportService,
    serialize_run_details,
)
from smtp_bench_pro.export.html_exporter import render_html
from smtp_bench_pro.persistence.repository import SMTPRunDetails


def test_export_no_network_or_recomputation_guarantee() -> None:
    """Verifies historical export does not import network libraries or diagnostic engines."""
    mod = "smtp_bench_pro.export.historical_export"
    assert mod in sys.modules
    imported = sys.modules[mod].__dict__
    for lib in ("dns.resolver", "socket", "smtplib", "requests", "httpx"):
        assert lib not in imported, f"Forbidden library '{lib}' imported in export module!"


def _sample_run_details() -> SMTPRunDetails:
    return SMTPRunDetails(
        run={
            "id": 42,
            "hostname": "example.com",
            "iterations": 1,
            "timeout": 3.0,
            "created_at": "2026-08-08T22:00:00Z",
        },
        results=[],
        diagnostics=[],
        findings=[],
        commands=[],
    )


def _sample_snapshot(domain: str = "example.com") -> MailDNSRunSnapshot:
    mx_record = MXRecord(
        preference=10,
        exchange=f"mail.{domain}",
        is_null_mx=False,
        addresses_v4=(AddressRecord("93.184.216.25", "IPv4"),),
    )
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(mx_record,))
    ptr_res = FCRDNSResult(
        ip="93.184.216.25",
        ptr_hostnames=(f"mail.{domain}",),
        status=FCRDNSStatus.MATCH,
        forward_ips=("93.184.216.25",),
    )
    ptr_diag = PTRDiagnosticResult(results=(ptr_res,))
    routing = MailRoutingDiagnosticResult(domain, "2026-08-08T22:00:00Z", mx_diag, ptr_diag)

    term1 = SPFTerm(qualifier="+", mechanism="include", value=f"_spf.{domain}", causes_dns_lookup=True)
    term2 = SPFTerm(qualifier="-", mechanism="all", causes_dns_lookup=False)
    spf = SPFDiagnosticResult(
        status=SPFStatus.VALID_SINGLE,
        raw_record=f"v=spf1 include:_spf.{domain} -all",
        terms=(term1, term2),
        dns_lookup_count=1,
        void_lookup_count=0,
        all_qualifier="-",
    )

    dmarc = DMARCDiagnosticResult(
        status=DMARCStatus.VALID,
        raw_record=f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
        policy="reject",
        subdomain_policy=None,
        pct=100,
        adkim="r",
        aspf="r",
        rua=(f"mailto:dmarc@{domain}",),
        ruf=(),
        organizational_domain=domain,
    )


    dkim = DKIMDiagnosticResult(
        domain=domain,
        selectors=("default",),
        results=(
            DKIMSelectorResult(
                selector="default",
                query_name=f"default._domainkey.{domain}",
                status=DKIMStatus.VALID,
                raw_record="v=DKIM1; k=ed25519; p=MTIz; s=email; h=sha256",
                key_type="ed25519",
                public_key_present=True,
                public_key_bits=24,
                services=("email",),
                hash_algorithms=("sha256",),
            ),
        ),
        checked_at="2026-08-08T22:00:00Z",
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
        dkim_valid_selectors=1,
        dkim_total_selectors=1,
    )

    finding = MailDNSFinding(
        id="MAILDNS-DMARC-002",
        title="DMARC Policy Enforcement",
        severity=MailDNSSeverity.INFO,
        category="DMARC",
        description="DMARC policy is set to reject.",
        evidence=f"v=DMARC1; p=reject; rua=mailto:dmarc@{domain}",
        recommendation="Maintain current reject policy.",
    )

    return MailDNSRunSnapshot(
        id=1,
        run_id=42,
        domain=domain,
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        dkim=dkim,
        findings=(finding,),
        created_at="2026-08-08T22:00:00Z",
    )


def test_json_export_with_mail_dns_snapshot() -> None:
    details = _sample_run_details()
    snapshot = _sample_snapshot()

    payload = serialize_run_details(details, mail_dns_snapshot=snapshot)

    assert "mail_dns" in payload
    mail_dns = payload["mail_dns"]
    assert mail_dns is not None
    assert mail_dns["domain"] == "example.com"
    assert mail_dns["spf"]["status"] == "VALID_SINGLE"
    assert mail_dns["dmarc"]["policy"] == "reject"
    assert mail_dns["dkim"]["results"][0]["selector"] == "default"
    assert mail_dns["dkim"]["results"][0]["status"] == "VALID"
    assert mail_dns["findings"][0]["id"] == "MAILDNS-DMARC-002"

    # Term order preservation
    assert len(mail_dns["spf"]["terms"]) == 2
    assert mail_dns["spf"]["terms"][0]["mechanism"] == "include"
    assert mail_dns["spf"]["terms"][1]["mechanism"] == "all"


def test_json_export_legacy_run_without_mail_dns() -> None:
    details = _sample_run_details()
    payload = serialize_run_details(details, mail_dns_snapshot=None)

    assert "mail_dns" in payload
    assert payload["mail_dns"] is None


def test_html_export_with_mail_dns_snapshot() -> None:
    details = _sample_run_details()
    snapshot = _sample_snapshot()
    payload = serialize_run_details(details, mail_dns_snapshot=snapshot)

    html_out = render_html(payload)

    assert "DNS de E-mail" in html_out
    assert "Resumo de Identidade" in html_out
    assert "example.com" in html_out
    assert "v=spf1 include:_spf.example.com -all" in html_out
    assert "Diagnóstico DKIM" in html_out
    assert "default._domainkey.example.com" in html_out
    assert "MAILDNS-DMARC-002" in html_out


def test_html_export_security_xss_escaping() -> None:
    """Verifies XSS vectors in TXT, domain, evidence, or recommendations are fully HTML escaped."""
    xss_domain = "xss<script>alert(1)</script>.com"
    xss_evidence = "<img src=x onerror=alert('xss')>"
    xss_rec = "\"><svg/onload=alert(1)>"

    mx_record = MXRecord(10, "mail.xss.com", False, ())
    mx_diag = MXDiagnosticResult(status=MXStatus.SINGLE_MX, records=(mx_record,))
    routing = MailRoutingDiagnosticResult(xss_domain, "2026-08-08T22:00:00Z", mx_diag, PTRDiagnosticResult())
    spf = SPFDiagnosticResult(status=SPFStatus.VALID_SINGLE, raw_record="v=spf1 <script> -all")
    dmarc = DMARCDiagnosticResult(status=DMARCStatus.VALID, raw_record="v=DMARC1; p=reject")
    dkim = DKIMDiagnosticResult(
        domain=xss_domain,
        selectors=("xss",),
        results=(
            DKIMSelectorResult(
                selector="xss",
                query_name="xss._domainkey.example.com",
                status=DKIMStatus.INVALID_SYNTAX,
                raw_record="v=DKIM1; p=<script>alert(1)</script>",
                validation_errors=("<script>alert(1)</script>",),
            ),
        ),
        checked_at="2026-08-08T22:00:00Z",
    )
    summary = MailIdentitySummary(xss_domain, xss_domain, 1, False, "VALID_SINGLE", "reject", 0, 0)

    finding = MailDNSFinding(
        id="MAILDNS-TEST-XSS",
        title="XSS Test",
        severity=MailDNSSeverity.HIGH,
        category="Test",
        description="Desc",
        evidence=xss_evidence,
        recommendation=xss_rec,
    )

    snapshot = MailDNSRunSnapshot(
        id=1,
        run_id=42,
        domain=xss_domain,
        routing=routing,
        spf=spf,
        dmarc=dmarc,
        identity_summary=summary,
        findings=(finding,),
        created_at="2026-08-08T22:00:00Z",
        dkim=dkim,
    )
    payload = serialize_run_details(_sample_run_details(), mail_dns_snapshot=snapshot)
    html_out = render_html(payload)

    # Must contain escaped strings
    assert escape(xss_domain) in html_out
    assert escape(xss_evidence) in html_out
    assert escape(xss_rec) in html_out
    assert escape("v=DKIM1; p=<script>alert(1)</script>") in html_out

    # Must NOT contain raw unescaped script or img tags
    assert "<script>alert(1)</script>" not in html_out
    assert "<img src=x onerror=alert('xss')>" not in html_out
    assert "\"><svg/onload=alert(1)>" not in html_out


def test_export_service_file_writing(tmp_path) -> None:
    service = HistoricalRunExportService()
    details = _sample_run_details()
    snapshot = _sample_snapshot()

    # JSON export
    json_path = tmp_path / "export.json"
    res_json = service.export(details, json_path, "json", mail_dns_snapshot=snapshot)
    assert res_json.path.exists()
    content_json = json.loads(json_path.read_text(encoding="utf-8"))
    assert content_json["mail_dns"]["domain"] == "example.com"

    # HTML export
    html_path = tmp_path / "export.html"
    res_html = service.export(details, html_path, "html", mail_dns_snapshot=snapshot)
    assert res_html.path.exists()
    content_html = html_path.read_text(encoding="utf-8")
    assert "DNS de E-mail" in content_html
