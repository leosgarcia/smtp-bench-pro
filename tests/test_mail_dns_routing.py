"""Offline unit and integration tests for Mail DNS Diagnostics (FASE A & FASE B)."""

from __future__ import annotations

import pytest

from smtp_bench_pro.domain.mail_dns import (
    DNSQueryResult,
    DNSQueryStatus,
    FCRDNSStatus,
    MXStatus,
    normalize_mail_domain,
)
from smtp_bench_pro.engine.dns_resolver import (
    IMailDNSResolver,
    MailDNSResolver,
    MailRoutingDiagnosticsService,
    is_ip_private_or_reserved,
    parse_mx_answers,
)


class FakeDNSResolver(IMailDNSResolver):
    """In-memory Fake DNS Resolver for 100% offline testing."""

    def __init__(self, responses: dict[tuple[str, str], DNSQueryResult] | None = None) -> None:
        self.responses: dict[tuple[str, str], DNSQueryResult] = responses or {}
        self.cnames: set[str] = set()
        self.query_log: list[tuple[str, str]] = []

    def set_response(
        self,
        name: str,
        rdatatype: str,
        answers: tuple[str, ...],
        status: DNSQueryStatus = DNSQueryStatus.SUCCESS,
    ) -> None:
        self.responses[(name.lower(), rdatatype.upper())] = DNSQueryResult(
            name=name,
            record_type=rdatatype,
            status=status,
            answers=answers,
            queried_at="2026-08-08T22:00:00+00:00",
        )

    def set_error(
        self,
        name: str,
        rdatatype: str,
        status: DNSQueryStatus,
        error_type: str = "Error",
        error_message: str = "Error msg",
    ) -> None:
        self.responses[(name.lower(), rdatatype.upper())] = DNSQueryResult(
            name=name,
            record_type=rdatatype,
            status=status,
            error_type=error_type,
            error_message=error_message,
            queried_at="2026-08-08T22:00:00+00:00",
        )

    def set_cname(self, hostname: str) -> None:
        self.cnames.add(hostname.lower())

    def _get(self, qname: str, rdatatype: str) -> DNSQueryResult:
        self.query_log.append((qname.lower(), rdatatype.upper()))
        key = (qname.lower(), rdatatype.upper())
        if key in self.responses:
            return self.responses[key]
        return DNSQueryResult(
            name=qname,
            record_type=rdatatype,
            status=DNSQueryStatus.NXDOMAIN,
            error_type="NXDOMAIN",
            error_message="Domain not found",
            queried_at="2026-08-08T22:00:00+00:00",
        )

    def resolve_mx(self, domain: str) -> DNSQueryResult:
        return self._get(domain, "MX")

    def resolve_a(self, hostname: str) -> DNSQueryResult:
        return self._get(hostname, "A")

    def resolve_aaaa(self, hostname: str) -> DNSQueryResult:
        return self._get(hostname, "AAAA")

    def resolve_ptr(self, ip_address: str) -> DNSQueryResult:
        return self._get(ip_address, "PTR")

    def resolve_txt(self, name: str) -> DNSQueryResult:
        return self._get(name, "TXT")

    def detect_cname(self, hostname: str) -> bool:
        return hostname.lower() in self.cnames


# -----------------------------------------------------------------------------
# FASE A TESTS: Domain Normalization
# -----------------------------------------------------------------------------


def test_domain_normalization_valid_inputs() -> None:
    t1 = normalize_mail_domain("example.com")
    assert t1.domain == "example.com"
    assert t1.raw_input == "example.com"

    t2 = normalize_mail_domain("EXAMPLE.COM.")
    assert t2.domain == "example.com"

    t3 = normalize_mail_domain("empresa.com.br  ")
    assert t3.domain == "empresa.com.br"

    t4 = normalize_mail_domain("münchen.de")
    assert t4.domain == "xn--mnchen-3ya.de"


def test_domain_normalization_invalid_inputs() -> None:
    invalid_inputs = [
        "",
        "   ",
        "https://example.com",
        "http://example.com",
        "example.com:25",
        "example.com:443",
        "example.com/path",
        "example.com?query=1",
        "example .com",
        "user@example.com",
    ]
    for raw in invalid_inputs:
        with pytest.raises(ValueError):
            normalize_mail_domain(raw)


# -----------------------------------------------------------------------------
# FASE A/B TESTS: DNS Query Status & Parse MX
# -----------------------------------------------------------------------------


def test_parse_mx_answers_sorting_and_null_mx() -> None:
    mx_query = DNSQueryResult(
        name="example.com",
        record_type="MX",
        status=DNSQueryStatus.SUCCESS,
        answers=("20 mx2.example.com.", "10 mx1.example.com."),
    )
    records = parse_mx_answers(mx_query)
    assert len(records) == 2
    assert records[0].preference == 10
    assert records[0].exchange == "mx1.example.com"
    assert records[1].preference == 20
    assert records[1].exchange == "mx2.example.com"

    null_mx_query = DNSQueryResult(
        name="nomail.example",
        record_type="MX",
        status=DNSQueryStatus.SUCCESS,
        answers=("0 .",),
    )
    null_records = parse_mx_answers(null_mx_query)
    assert len(null_records) == 1
    assert null_records[0].is_null_mx is True
    assert null_records[0].exchange == "."


# -----------------------------------------------------------------------------
# FASE B TESTS: MX, Address, PTR, FCRDNS Orchestration
# -----------------------------------------------------------------------------


def test_null_mx_diagnostics_executes_no_address_or_ptr_queries() -> None:
    fake = FakeDNSResolver()
    fake.set_response("nomail.example", "MX", ("0 .",))

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("nomail.example")
    result = service.diagnose(target)

    assert result.mx_record.status == MXStatus.NULL_MX
    assert len(result.mx_record.records) == 1
    assert result.mx_record.records[0].is_null_mx is True
    # Ensure ONLY MX query was executed, no A/AAAA/PTR queries
    assert fake.query_log == [("nomail.example", "MX")]


def test_no_mx_diagnostics() -> None:
    fake = FakeDNSResolver()
    fake.set_error("nomy.example", "MX", DNSQueryStatus.NXDOMAIN)

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("nomy.example")
    result = service.diagnose(target)

    assert result.mx_record.status == MXStatus.NO_MX
    assert len(result.mx_record.records) == 0


def test_single_mx_a_aaaa_ptr_fcrdns_match() -> None:
    fake = FakeDNSResolver()
    fake.set_response("example.com", "MX", ("10 mail.example.com.",))
    fake.set_response("mail.example.com", "A", ("93.184.216.25",))
    fake.set_response("mail.example.com", "AAAA", ("2606:2800:220:1:248:1893:25c8:1946",))
    fake.set_response("93.184.216.25", "PTR", ("mail.example.com.",))
    fake.set_response("2606:2800:220:1:248:1893:25c8:1946", "PTR", ("mail.example.com.",))

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("example.com")
    result = service.diagnose(target)

    assert result.mx_record.status == MXStatus.SINGLE_MX
    mx = result.mx_record.records[0]
    assert mx.exchange == "mail.example.com"
    assert len(mx.addresses_v4) == 1
    assert mx.addresses_v4[0].ip == "93.184.216.25"
    assert len(mx.addresses_v6) == 1
    assert mx.addresses_v6[0].ip == "2606:2800:220:1:248:1893:25c8:1946"

    ptr_results = {p.ip: p for p in result.ptr_record.results}
    assert ptr_results["93.184.216.25"].status == FCRDNSStatus.MATCH
    assert ptr_results["93.184.216.25"].ptr_hostnames == ("mail.example.com",)
    assert ptr_results["2606:2800:220:1:248:1893:25c8:1946"].status == FCRDNSStatus.MATCH


def test_fcrdns_mismatch() -> None:
    fake = FakeDNSResolver()
    fake.set_response("example.org", "MX", ("10 mail.example.org.",))
    fake.set_response("mail.example.org", "A", ("93.184.216.50",))
    # PTR returns wrong.example.org, but wrong.example.org resolves to 93.184.216.99 (not 93.184.216.50)
    fake.set_response("93.184.216.50", "PTR", ("wrong.example.org.",))
    fake.set_response("wrong.example.org", "A", ("93.184.216.99",))

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("example.org")
    result = service.diagnose(target)

    ptr = result.ptr_record.results[0]
    assert ptr.ip == "93.184.216.50"
    assert ptr.status == FCRDNSStatus.MISMATCH
    assert ptr.ptr_hostnames == ("wrong.example.org",)


def test_cname_detection_on_mx() -> None:
    fake = FakeDNSResolver()
    fake.set_response("example.net", "MX", ("10 alias.example.net.",))
    fake.set_cname("alias.example.net")
    fake.set_response("alias.example.net", "A", ("93.184.216.100",))
    fake.set_response("93.184.216.100", "PTR", ("alias.example.net.",))

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("example.net")
    result = service.diagnose(target)

    assert result.mx_record.records[0].cname_detected is True


def test_private_and_reserved_ips_fcrdns_not_applicable() -> None:
    assert is_ip_private_or_reserved("127.0.0.1") is True
    assert is_ip_private_or_reserved("192.168.1.1") is True
    assert is_ip_private_or_reserved("10.0.0.1") is True
    assert is_ip_private_or_reserved("93.184.216.1") is False

    fake = FakeDNSResolver()
    fake.set_response("local.test", "MX", ("10 mx.local.test.",))
    fake.set_response("mx.local.test", "A", ("192.168.1.100",))

    service = MailRoutingDiagnosticsService(resolver=fake)
    target = normalize_mail_domain("local.test")
    result = service.diagnose(target)

    ptr = result.ptr_record.results[0]
    assert ptr.ip == "192.168.1.100"
    assert ptr.status == FCRDNSStatus.NOT_APPLICABLE


def test_mail_dns_resolver_real_instance_instantiation() -> None:
    resolver = MailDNSResolver(timeout=2.0)
    assert resolver.timeout == 2.0

    with pytest.raises(ValueError, match="Invalid custom nameserver"):
        MailDNSResolver(custom_nameserver="invalid_ip")
