"""Offline unit and integration tests for DMARC Engine (FASE D)."""

from __future__ import annotations

from smtp_bench_pro.domain.mail_dns import DNSQueryResult, DNSQueryStatus, DMARCStatus
from smtp_bench_pro.engine.dmarc_diagnostics import DMARCDiagnosticsService
from smtp_bench_pro.engine.dmarc_parser import parse_dmarc_record, parse_dmarc_report_uris
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.engine.organizational_domain import _EXTRACTOR, get_organizational_domain


class FakeDMARCResolver(IMailDNSResolver):
    """Fake DNS Resolver for DMARC testing."""

    def __init__(self) -> None:
        self.txt_records: dict[str, tuple[str, ...]] = {}
        self.statuses: dict[str, DNSQueryStatus] = {}

    def set_txt(self, name: str, records: tuple[str, ...], status: DNSQueryStatus = DNSQueryStatus.SUCCESS) -> None:
        key = name.rstrip(".").lower()
        self.txt_records[key] = records
        self.statuses[key] = status

    def resolve_txt(self, name: str) -> DNSQueryResult:
        key = name.rstrip(".").lower()
        status = self.statuses.get(key, DNSQueryStatus.SUCCESS)

        if status != DNSQueryStatus.SUCCESS:
            return DNSQueryResult(
                name=name,
                record_type="TXT",
                status=status,
                error_type=status.value,
                error_message=f"DNS query failed with {status.value}",
                queried_at="2026-08-08T22:00:00+00:00",
            )

        if key in self.txt_records:
            return DNSQueryResult(
                name=name,
                record_type="TXT",
                status=DNSQueryStatus.SUCCESS,
                answers=self.txt_records[key],
                queried_at="2026-08-08T22:00:00+00:00",
            )

        return DNSQueryResult(
            name=name,
            record_type="TXT",
            status=DNSQueryStatus.NXDOMAIN,
            error_type="NXDOMAIN",
            error_message="Domain not found",
            queried_at="2026-08-08T22:00:00+00:00",
        )

    def resolve_mx(self, domain: str) -> DNSQueryResult:
        return DNSQueryResult(name=domain, record_type="MX", status=DNSQueryStatus.NO_ANSWER)

    def resolve_a(self, hostname: str) -> DNSQueryResult:
        return DNSQueryResult(name=hostname, record_type="A", status=DNSQueryStatus.NO_ANSWER)

    def resolve_aaaa(self, hostname: str) -> DNSQueryResult:
        return DNSQueryResult(name=hostname, record_type="AAAA", status=DNSQueryStatus.NO_ANSWER)

    def resolve_ptr(self, ip_address: str) -> DNSQueryResult:
        return DNSQueryResult(name=ip_address, record_type="PTR", status=DNSQueryStatus.NO_ANSWER)

    def detect_cname(self, hostname: str) -> bool:
        return False


# -----------------------------------------------------------------------------
# ORGANIZATIONAL DOMAIN TESTS
# -----------------------------------------------------------------------------


def test_tldextract_network_guard() -> None:
    """Verifies that tldextract is configured with suffix_list_urls=() to prevent network I/O."""
    assert _EXTRACTOR.suffix_list_urls == ()


def test_organizational_domain_psl_offline_resolution() -> None:
    assert get_organizational_domain("example.com") == "example.com"
    assert get_organizational_domain("sub.example.com") == "example.com"
    assert get_organizational_domain("empresa.com.br") == "empresa.com.br"
    assert get_organizational_domain("sub.empresa.com.br") == "empresa.com.br"
    assert get_organizational_domain("example.co.uk") == "example.co.uk"
    assert get_organizational_domain("deep.sub.example.co.uk") == "example.co.uk"
    assert get_organizational_domain("") == ""


# -----------------------------------------------------------------------------
# PARSER UNIT TESTS
# -----------------------------------------------------------------------------


def test_parse_dmarc_record_valid_policies() -> None:
    tags, errs = parse_dmarc_record("v=DMARC1; p=none")
    assert not errs
    assert tags["p"] == "none"

    tags, errs = parse_dmarc_record("v=DMARC1; p=quarantine; sp=reject; pct=50; adkim=s; aspf=r")
    assert not errs
    assert tags["p"] == "quarantine"
    assert tags["sp"] == "reject"
    assert tags["pct"] == "50"
    assert tags["adkim"] == "s"
    assert tags["aspf"] == "r"


def test_parse_dmarc_report_uris_parsing() -> None:
    uris = parse_dmarc_report_uris("mailto:dmarc@example.com, mailto:rep@example.com!10m")
    assert uris == ("mailto:dmarc@example.com", "mailto:rep@example.com!10m")


def test_parse_dmarc_record_invalid_cases() -> None:
    _, errs1 = parse_dmarc_record("v=DMARC1; p=invalid_policy")
    assert any("Invalid DMARC policy" in e for e in errs1)

    _, errs2 = parse_dmarc_record("v=DMARC1; p=none; pct=150")
    assert any("pct" in e for e in errs2)

    _, errs3 = parse_dmarc_record("v=DMARC1; p=none; p=reject")
    assert any("Duplicate DMARC tag" in e for e in errs3)

    _, errs4 = parse_dmarc_record("v=DMARC2; p=none")
    assert any("v=DMARC1" in e for e in errs4)


# -----------------------------------------------------------------------------
# DMARC DIAGNOSTICS DISCOVERY & FALLBACK TESTS
# -----------------------------------------------------------------------------


def test_dmarc_discovery_absent() -> None:
    resolver = FakeDMARCResolver()
    service = DMARCDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == DMARCStatus.ABSENT
    assert res.raw_record is None


def test_dmarc_discovery_multiple_records() -> None:
    resolver = FakeDMARCResolver()
    resolver.set_txt("_dmarc.example.com", ("v=DMARC1; p=none", "v=DMARC1; p=reject"))

    service = DMARCDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == DMARCStatus.MULTIPLE
    assert "Multiple DMARC records" in res.validation_errors[0]


def test_dmarc_direct_domain_valid() -> None:
    resolver = FakeDMARCResolver()
    resolver.set_txt("_dmarc.example.com", ("v=DMARC1; p=reject; rua=mailto:dmarc@example.com",))

    service = DMARCDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == DMARCStatus.VALID
    assert res.policy == "reject"
    assert res.rua == ("mailto:dmarc@example.com",)
    assert res.organizational_domain == "example.com"


def test_dmarc_subdomain_fallback_to_org_domain() -> None:
    resolver = FakeDMARCResolver()
    # Org domain has sp=quarantine
    resolver.set_txt("_dmarc.empresa.com.br", ("v=DMARC1; p=reject; sp=quarantine",))

    service = DMARCDiagnosticsService(resolver=resolver)
    # Query subdomain mail.empresa.com.br (has no DMARC record of its own)
    res = service.diagnose("mail.empresa.com.br")

    assert res.status == DMARCStatus.VALID
    assert res.organizational_domain == "empresa.com.br"
    # Inherits sp=quarantine
    assert res.policy == "quarantine"
    assert res.subdomain_policy == "quarantine"


def test_dmarc_dns_errors_not_masked_as_absent() -> None:
    resolver = FakeDMARCResolver()
    resolver.set_txt("_dmarc.fail.com", (), status=DNSQueryStatus.TIMEOUT)

    service = DMARCDiagnosticsService(resolver=resolver)
    res = service.diagnose("fail.com")

    assert res.status != DMARCStatus.ABSENT
    assert res.status == DMARCStatus.INVALID_SYNTAX
    assert "TIMEOUT" in res.validation_errors[0]
