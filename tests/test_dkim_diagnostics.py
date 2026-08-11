"""Offline tests for DKIM diagnostics."""

from __future__ import annotations

import base64

from smtp_bench_pro.domain.mail_dns import DNSQueryResult, DNSQueryStatus, DKIMStatus
from smtp_bench_pro.engine.dkim_diagnostics import DKIMDiagnosticsService
from smtp_bench_pro.engine.dkim_parser import dkim_query_name, parse_dkim_record
from smtp_bench_pro.security.mail_dns_rules import evaluate_dkim_findings


def _der_int(value: bytes) -> bytes:
    if value[0] & 0x80:
        value = b"\x00" + value
    return b"\x02" + _der_len(len(value)) + value


def _der_len(length: int) -> bytes:
    if length < 128:
        return bytes([length])
    raw = length.to_bytes((length.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(raw)]) + raw


def _rsa_key(bits: int) -> str:
    modulus = bytes([0xC3]) + b"\x11" * ((bits // 8) - 1)
    exponent = b"\x01\x00\x01"
    body = _der_int(modulus) + _der_int(exponent)
    der = b"\x30" + _der_len(len(body)) + body
    return base64.b64encode(der).decode("ascii")


class FakeResolver:
    def __init__(self, txt: dict[str, tuple[str, ...]]):
        self.txt = txt
        self.queries: list[str] = []

    def resolve_txt(self, name: str) -> DNSQueryResult:
        self.queries.append(name)
        answers = self.txt.get(name, ())
        status = DNSQueryStatus.SUCCESS if answers else DNSQueryStatus.NO_ANSWER
        return DNSQueryResult(name=name, record_type="TXT", status=status, answers=answers)

    def resolve_mx(self, domain: str): raise NotImplementedError
    def resolve_a(self, hostname: str): raise NotImplementedError
    def resolve_aaaa(self, hostname: str): raise NotImplementedError
    def resolve_ptr(self, ip_address: str): raise NotImplementedError
    def detect_cname(self, hostname: str) -> bool: return False


def test_parse_valid_rsa_selector() -> None:
    raw = f"v=DKIM1; k=rsa; p={_rsa_key(2048)}; t=y:s; s=email:*; h=sha256"
    result = parse_dkim_record("default", "default._domainkey.example.com", raw)

    assert result.status == DKIMStatus.VALID
    assert result.key_type == "rsa"
    assert result.public_key_bits == 2048
    assert result.flags == ("y", "s")
    assert result.services == ("email", "*")
    assert result.hash_algorithms == ("sha256",)


def test_parse_valid_ed25519_selector() -> None:
    key = base64.b64encode(b"1" * 32).decode("ascii")
    result = parse_dkim_record("ed", "ed._domainkey.example.com", f"v=DKIM1; k=ed25519; p={key}")

    assert result.status == DKIMStatus.VALID
    assert result.key_type == "ed25519"
    assert result.public_key_bits == 256


def test_k_absent_defaults_to_rsa() -> None:
    result = parse_dkim_record("default", "default._domainkey.example.com", f"v=DKIM1; p={_rsa_key(1024)}")

    assert result.key_type == "rsa"
    assert result.public_key_bits == 1024


def test_invalid_public_key_base64_and_revoked() -> None:
    invalid = parse_dkim_record("default", "default._domainkey.example.com", "v=DKIM1; p=%%%")
    revoked = parse_dkim_record("default", "default._domainkey.example.com", "v=DKIM1; p=")

    assert invalid.status == DKIMStatus.INVALID_PUBLIC_KEY
    assert revoked.status == DKIMStatus.REVOKED


def test_unknown_key_type_version_invalid_and_duplicate_tags() -> None:
    unknown = parse_dkim_record("default", "default._domainkey.example.com", "v=DKIM1; k=ecdsa; p=abc")
    bad_version = parse_dkim_record("default", "default._domainkey.example.com", f"v=DKIM2; p={_rsa_key(1024)}")
    duplicate = parse_dkim_record("default", "default._domainkey.example.com", f"v=DKIM1; p={_rsa_key(1024)}; p=abc")

    assert unknown.status == DKIMStatus.UNSUPPORTED_KEY_TYPE
    assert bad_version.status == DKIMStatus.INVALID_SYNTAX
    assert duplicate.status == DKIMStatus.INVALID_SYNTAX
    assert any("duplicada" in error for error in duplicate.validation_errors)


def test_selector_absent_multiple_invalid_selector_and_multiple_selectors() -> None:
    valid_name = dkim_query_name("default", "example.com")
    resolver = FakeResolver({valid_name: (f"v=DKIM1; p={_rsa_key(2048)}",)})
    service = DKIMDiagnosticsService(resolver)

    result = service.diagnose("example.com", "default, missing, bad/selector")

    assert [item.selector for item in result.results] == ["default", "missing", "bad/selector"]
    assert result.results[0].status == DKIMStatus.VALID
    assert result.results[1].status == DKIMStatus.ABSENT
    assert result.results[2].status == DKIMStatus.INVALID_SYNTAX
    assert "bad/selector._domainkey.example.com" not in resolver.queries


def test_multiple_records_and_findings() -> None:
    name = dkim_query_name("default", "example.com")
    weak = dkim_query_name("weak", "example.com")
    resolver = FakeResolver(
        {
            name: ("v=DKIM1; p=abc", "v=DKIM1; p=def"),
            weak: (f"v=DKIM1; p={_rsa_key(1024)}",),
        }
    )
    result = DKIMDiagnosticsService(resolver).diagnose("example.com", ("default", "weak", "missing"))
    findings = evaluate_dkim_findings(result)
    ids = {finding.id for finding in findings}

    assert result.results[0].status == DKIMStatus.MULTIPLE
    assert "MAILDNS-DKIM-002" in ids
    assert "MAILDNS-DKIM-006" in ids
    assert "MAILDNS-DKIM-001" in ids

