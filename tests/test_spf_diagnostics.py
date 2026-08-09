"""Offline unit and integration tests for SPF Engine (FASE C)."""

from __future__ import annotations

from smtp_bench_pro.domain.mail_dns import DNSQueryResult, DNSQueryStatus, SPFStatus
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.engine.spf_diagnostics import SPFDiagnosticsService
from smtp_bench_pro.engine.spf_parser import parse_spf_record, parse_spf_term


class FakeSPFResolver(IMailDNSResolver):
    """Fake DNS Resolver tailored for SPF tests."""

    def __init__(self) -> None:
        self.txt_records: dict[str, tuple[str, ...]] = {}
        self.a_records: dict[str, tuple[str, ...]] = {}

    def set_txt(self, domain: str, records: tuple[str, ...]) -> None:
        self.txt_records[domain.rstrip(".").lower()] = records

    def set_a(self, domain: str, records: tuple[str, ...]) -> None:
        self.a_records[domain.rstrip(".").lower()] = records

    def resolve_txt(self, name: str) -> DNSQueryResult:
        key = name.rstrip(".").lower()
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

    def resolve_a(self, hostname: str) -> DNSQueryResult:
        key = hostname.rstrip(".").lower()
        if key in self.a_records:
            return DNSQueryResult(
                name=hostname,
                record_type="A",
                status=DNSQueryStatus.SUCCESS,
                answers=self.a_records[key],
                queried_at="2026-08-08T22:00:00+00:00",
            )
        return DNSQueryResult(
            name=hostname,
            record_type="A",
            status=DNSQueryStatus.NXDOMAIN,
            error_type="NXDOMAIN",
            error_message="Host not found",
            queried_at="2026-08-08T22:00:00+00:00",
        )

    def resolve_mx(self, domain: str) -> DNSQueryResult:
        return DNSQueryResult(name=domain, record_type="MX", status=DNSQueryStatus.NO_ANSWER)

    def resolve_aaaa(self, hostname: str) -> DNSQueryResult:
        return DNSQueryResult(name=hostname, record_type="AAAA", status=DNSQueryStatus.NO_ANSWER)

    def resolve_ptr(self, ip_address: str) -> DNSQueryResult:
        return DNSQueryResult(name=ip_address, record_type="PTR", status=DNSQueryStatus.NO_ANSWER)

    def detect_cname(self, hostname: str) -> bool:
        return False


# -----------------------------------------------------------------------------
# PARSER UNIT TESTS
# -----------------------------------------------------------------------------


def test_parse_spf_qualifiers() -> None:
    terms, err = parse_spf_record("v=spf1 +a -mx ~ip4:192.0.2.0/24 ?all")
    assert err is None
    assert len(terms) == 4

    assert terms[0].qualifier == "+"
    assert terms[0].mechanism == "a"
    assert terms[0].causes_dns_lookup is True

    assert terms[1].qualifier == "-"
    assert terms[1].mechanism == "mx"
    assert terms[1].causes_dns_lookup is True

    assert terms[2].qualifier == "~"
    assert terms[2].mechanism == "ip4"
    assert terms[2].value == "192.0.2.0/24"
    assert terms[2].causes_dns_lookup is False

    assert terms[3].qualifier == "?"
    assert terms[3].mechanism == "all"
    assert terms[3].causes_dns_lookup is False


def test_parse_spf_default_qualifier_is_plus() -> None:
    terms, err = parse_spf_record("v=spf1 include:_spf.example.com all")
    assert err is None
    assert terms[0].qualifier == "+"
    assert terms[0].mechanism == "include"
    assert terms[0].value == "_spf.example.com"
    assert terms[1].qualifier == "+"
    assert terms[1].mechanism == "all"


def test_parse_spf_modifiers() -> None:
    terms, err = parse_spf_record("v=spf1 redirect=_spf.example.com exp=exp.example.com foo=bar")
    assert err is None
    assert len(terms) == 3

    assert terms[0].mechanism == "redirect"
    assert terms[0].is_modifier is True
    assert terms[0].causes_dns_lookup is True

    assert terms[1].mechanism == "exp"
    assert terms[1].is_modifier is True
    assert terms[1].causes_dns_lookup is False

    assert terms[2].mechanism == "foo"
    assert terms[2].is_modifier is True
    assert terms[2].value == "bar"


def test_parse_spf_term_direct_test() -> None:
    term, err = parse_spf_term("a:mail.example.com")
    assert err is None
    assert term is not None
    assert term.mechanism == "a"
    assert term.value == "mail.example.com"


def test_parse_spf_invalid_ip4_and_ip6() -> None:
    _, err1 = parse_spf_record("v=spf1 ip4:999.999.999.999")
    assert err1 is not None
    assert "Invalid ip4" in err1

    _, err2 = parse_spf_record("v=spf1 ip6:invalid_ipv6")
    assert err2 is not None
    assert "Invalid ip6" in err2


def test_parse_spf_unknown_mechanism() -> None:
    _, err = parse_spf_record("v=spf1 unknownmech")
    assert err is not None
    assert "Unknown SPF mechanism" in err


# -----------------------------------------------------------------------------
# DISCOVERY & DIAGNOSTICS TESTS
# -----------------------------------------------------------------------------


def test_spf_discovery_absent() -> None:
    resolver = FakeSPFResolver()
    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.ABSENT
    assert res.raw_record is None


def test_spf_discovery_multiple_records() -> None:
    resolver = FakeSPFResolver()
    resolver.set_txt("example.com", ("v=spf1 a -all", "v=spf1 mx -all"))
    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.MULTIPLE
    assert "Multiple SPF records" in (res.validation_error or "")


def test_spf_valid_single_diagnostics() -> None:
    resolver = FakeSPFResolver()
    resolver.set_txt("example.com", ("v=spf1 ip4:192.0.2.1 include:_spf.example.net ~all",))
    resolver.set_txt("_spf.example.net", ("v=spf1 ip4:192.0.2.2 -all",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.VALID_SINGLE
    assert res.raw_record == "v=spf1 ip4:192.0.2.1 include:_spf.example.net ~all"
    assert res.dns_lookup_count == 1  # 1 lookup for include:_spf.example.net
    assert res.all_qualifier == "~"
    assert res.uses_ptr_mechanism is False


# -----------------------------------------------------------------------------
# LOOKUP BUDGET TESTS
# -----------------------------------------------------------------------------


def test_spf_lookup_budget_exact_10_allowed() -> None:
    resolver = FakeSPFResolver()
    # 10 terms causing DNS lookup: a:1, a:2, ..., a:10
    terms = " ".join([f"a:host{i}.example.com" for i in range(1, 11)]) + " -all"
    for i in range(1, 11):
        resolver.set_a(f"host{i}.example.com", ("192.0.2.1",))

    resolver.set_txt("example.com", (f"v=spf1 {terms}",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.VALID_SINGLE
    assert res.dns_lookup_count == 10


def test_spf_lookup_budget_11_exceeded() -> None:
    resolver = FakeSPFResolver()
    # 11 terms causing DNS lookup: a:1, ..., a:11
    terms = " ".join([f"a:host{i}.example.com" for i in range(1, 12)]) + " -all"
    for i in range(1, 12):
        resolver.set_a(f"host{i}.example.com", ("192.0.2.1",))

    resolver.set_txt("example.com", (f"v=spf1 {terms}",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.LOOKUP_LIMIT_EXCEEDED
    assert res.dns_lookup_count == 11
    assert "DNS lookup budget limit" in (res.validation_error or "")


# -----------------------------------------------------------------------------
# VOID LOOKUP BUDGET TESTS
# -----------------------------------------------------------------------------


def test_spf_void_lookup_budget_exceeded() -> None:
    resolver = FakeSPFResolver()
    # 3 a: mechanisms pointing to non-existent hosts (NXDOMAIN)
    resolver.set_txt("example.com", ("v=spf1 a:void1.example.com a:void2.example.com a:void3.example.com -all",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("example.com")

    assert res.status == SPFStatus.VOID_LIMIT_EXCEEDED
    assert res.void_lookup_count == 3
    assert "Void lookup budget limit" in (res.validation_error or "")


# -----------------------------------------------------------------------------
# RECURSION & LOOP TESTS
# -----------------------------------------------------------------------------


def test_spf_recursion_loop_detection() -> None:
    resolver = FakeSPFResolver()
    # Circular include: a.com -> include:b.com -> include:a.com
    resolver.set_txt("a.com", ("v=spf1 include:b.com -all",))
    resolver.set_txt("b.com", ("v=spf1 include:a.com -all",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("a.com")

    assert res.status == SPFStatus.RECURSION_LOOP
    assert "Recursion loop" in (res.validation_error or "")


def test_spf_redirect_loop_detection() -> None:
    resolver = FakeSPFResolver()
    resolver.set_txt("loop.com", ("v=spf1 redirect=loop.com",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("loop.com")

    assert res.status == SPFStatus.RECURSION_LOOP


# -----------------------------------------------------------------------------
# PTR MECHANISM & MACROS TESTS
# -----------------------------------------------------------------------------


def test_spf_ptr_mechanism_detected() -> None:
    resolver = FakeSPFResolver()
    resolver.set_txt("ptr.example", ("v=spf1 ptr -all",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("ptr.example")

    assert res.status == SPFStatus.VALID_SINGLE
    assert res.uses_ptr_mechanism is True


def test_spf_macro_domain_spec_counted_without_crash() -> None:
    resolver = FakeSPFResolver()
    resolver.set_txt("macro.example", ("v=spf1 include:spf.%{d} -all",))

    service = SPFDiagnosticsService(resolver=resolver)
    res = service.diagnose("macro.example")

    assert res.status == SPFStatus.VALID_SINGLE
    assert res.dns_lookup_count == 1
