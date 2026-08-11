"""Domain models and normalization for Mail DNS Diagnostics."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
import re

# Strict validation patterns to reject URLs, schemes, ports, paths, or whitespace
_SCHEME_PATTERN = re.compile(r"^[a-zA-Z][a-zA-Z0-9+-.]*://")
_INVALID_CHAR_PATTERN = re.compile(r"[@:/\?#\s]")


class DNSQueryStatus(StrEnum):
    SUCCESS = "SUCCESS"
    NXDOMAIN = "NXDOMAIN"
    NO_ANSWER = "NO_ANSWER"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    ERROR = "ERROR"


class MXStatus(StrEnum):
    NO_MX = "NO_MX"
    SINGLE_MX = "SINGLE_MX"
    MULTIPLE_MX = "MULTIPLE_MX"
    NULL_MX = "NULL_MX"


class FCRDNSStatus(StrEnum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NO_PTR = "NO_PTR"
    MULTIPLE_PTR = "MULTIPLE_PTR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"


class SPFStatus(StrEnum):
    ABSENT = "ABSENT"
    VALID_SINGLE = "VALID_SINGLE"
    MULTIPLE = "MULTIPLE"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    LOOKUP_LIMIT_EXCEEDED = "LOOKUP_LIMIT_EXCEEDED"
    VOID_LIMIT_EXCEEDED = "VOID_LIMIT_EXCEEDED"
    RECURSION_LOOP = "RECURSION_LOOP"


class DMARCStatus(StrEnum):
    ABSENT = "ABSENT"
    VALID = "VALID"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    MULTIPLE = "MULTIPLE"


class DKIMStatus(StrEnum):
    ABSENT = "ABSENT"
    VALID = "VALID"
    MULTIPLE = "MULTIPLE"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    REVOKED = "REVOKED"
    UNSUPPORTED_KEY_TYPE = "UNSUPPORTED_KEY_TYPE"
    INVALID_PUBLIC_KEY = "INVALID_PUBLIC_KEY"


class MailDNSSeverity(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class MailDomainTarget:
    domain: str  # ASCII-normalized domain name (no trailing dot)
    raw_input: str  # Original raw input from user/caller
    timeout: float = 3.0
    custom_nameserver: str | None = None


def normalize_mail_domain(
    raw_input: str,
    timeout: float = 3.0,
    custom_nameserver: str | None = None,
) -> MailDomainTarget:
    """Normalizes and validates a domain name for Mail DNS Diagnostics.

    Rules:
    - Strips leading/trailing whitespace.
    - Rejects empty strings, URLs, schemes, ports, paths, query strings, or internal whitespace.
    - Strips trailing dot for display/canonical form.
    - Encodes/decodes via IDNA to validate internationalized domain names.
    - Converts domain to lowercase ASCII.
    """
    if not raw_input or not raw_input.strip():
        raise ValueError("Domain name cannot be empty.")

    cleaned = raw_input.strip()

    if _SCHEME_PATTERN.search(cleaned):
        raise ValueError(f"Invalid domain input '{raw_input}': URLs and schemes are not allowed.")

    if _INVALID_CHAR_PATTERN.search(cleaned):
        err = f"Invalid domain input '{raw_input}': ports, paths, query strings, and spaces are not allowed."
        raise ValueError(err)

    # Remove trailing dot if present
    if cleaned.endswith("."):
        cleaned = cleaned[:-1]

    if not cleaned:
        raise ValueError("Domain name cannot be empty.")

    try:
        # IDNA encoding validation & ASCII conversion
        ascii_domain = cleaned.encode("idna").decode("ascii").lower()
    except Exception as exc:
        raise ValueError(f"Invalid IDNA domain '{raw_input}': {exc}") from exc

    # Ensure domain contains at least one dot or is valid host label
    if not ascii_domain:
        raise ValueError(f"Invalid domain input '{raw_input}'.")

    return MailDomainTarget(
        domain=ascii_domain,
        raw_input=raw_input,
        timeout=timeout,
        custom_nameserver=custom_nameserver,
    )


@dataclass(frozen=True)
class DNSQueryResult:
    name: str
    record_type: str
    status: DNSQueryStatus
    answers: tuple[str, ...] = ()
    error_type: str | None = None
    error_message: str | None = None
    queried_at: str = ""


@dataclass(frozen=True)
class AddressRecord:
    ip: str
    family: str  # "IPv4" or "IPv6"


@dataclass(frozen=True)
class MXRecord:
    preference: int
    exchange: str
    is_null_mx: bool
    addresses_v4: tuple[AddressRecord, ...] = ()
    addresses_v6: tuple[AddressRecord, ...] = ()
    cname_detected: bool = False


@dataclass(frozen=True)
class MXDiagnosticResult:
    status: MXStatus
    records: tuple[MXRecord, ...] = ()
    raw_records: tuple[str, ...] = ()


@dataclass(frozen=True)
class FCRDNSResult:
    ip: str
    ptr_hostnames: tuple[str, ...]
    status: FCRDNSStatus
    forward_ips: tuple[str, ...] = ()


@dataclass(frozen=True)
class PTRDiagnosticResult:
    results: tuple[FCRDNSResult, ...] = ()


@dataclass(frozen=True)
class MailRoutingDiagnosticResult:
    domain: str
    queried_at: str
    mx_record: MXDiagnosticResult
    ptr_record: PTRDiagnosticResult


@dataclass(frozen=True)
class SPFTerm:
    qualifier: str  # "+", "-", "~", "?"
    mechanism: str  # "all", "include", "a", "mx", "ip4", "ip6", "ptr", "exists", "redirect", "exp"
    value: str | None = None
    raw: str = ""
    is_modifier: bool = False
    causes_dns_lookup: bool = False


@dataclass(frozen=True)
class SPFDiagnosticResult:
    status: SPFStatus
    raw_record: str | None = None
    terms: tuple[SPFTerm, ...] = ()
    dns_lookup_count: int = 0
    void_lookup_count: int = 0
    all_qualifier: str | None = None
    uses_ptr_mechanism: bool = False
    validation_error: str | None = None




@dataclass(frozen=True)
class DKIMSelectorResult:
    selector: str
    query_name: str
    status: DKIMStatus
    raw_record: str | None = None
    key_type: str | None = None
    public_key_present: bool = False
    public_key_bits: int | None = None
    flags: tuple[str, ...] = ()
    services: tuple[str, ...] = ()
    hash_algorithms: tuple[str, ...] = ()
    notes: tuple[str, ...] = ()
    validation_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class DKIMDiagnosticResult:
    domain: str
    selectors: tuple[str, ...]
    results: tuple[DKIMSelectorResult, ...]
    checked_at: str

@dataclass(frozen=True)
class DMARCDiagnosticResult:
    status: DMARCStatus
    raw_record: str | None = None
    policy: str | None = None  # "none", "quarantine", "reject"
    subdomain_policy: str | None = None
    pct: int = 100
    adkim: str = "r"  # "r" (relaxed) or "s" (strict)
    aspf: str = "r"   # "r" (relaxed) or "s" (strict)
    rua: tuple[str, ...] = ()
    ruf: tuple[str, ...] = ()
    organizational_domain: str = ""
    validation_errors: tuple[str, ...] = ()


@dataclass(frozen=True)
class MailDNSFinding:
    id: str
    title: str
    severity: MailDNSSeverity
    category: str  # "MX", "PTR", "SPF", "DKIM", "DMARC"
    description: str
    evidence: str
    recommendation: str


@dataclass(frozen=True)
class MailIdentitySummary:
    domain: str
    organizational_domain: str
    mx_count: int
    has_null_mx: bool
    spf_policy: str | None
    dmarc_policy: str | None
    fcrdns_aligned_ips: int
    fcrdns_total_ips: int
    dkim_valid_selectors: int = 0
    dkim_total_selectors: int = 0


@dataclass(frozen=True)
class MailDNSRunSnapshot:
    id: int | None
    run_id: int
    domain: str
    routing: MailRoutingDiagnosticResult
    spf: SPFDiagnosticResult
    dmarc: DMARCDiagnosticResult
    identity_summary: MailIdentitySummary
    findings: tuple[MailDNSFinding, ...]
    created_at: str
    dkim: DKIMDiagnosticResult = field(
        default_factory=lambda: DKIMDiagnosticResult(domain="", selectors=(), results=(), checked_at="")
    )
