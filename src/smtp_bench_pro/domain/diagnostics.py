"""Structured SMTP diagnostics and security findings."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from smtp_bench_pro.domain.diagnostic_options import CommandDiagnosticResult, DiagnosticsOptions
from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.results import TLSInformation


class ServerRole(StrEnum):
    AUTO = "auto"
    MX = "mx"
    SUBMISSION = "submission"
    RELAY = "relay"


class FindingSeverity(StrEnum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


@dataclass(frozen=True)
class CapabilityDiagnostic:
    name: str
    present_before_tls: bool = False
    present_after_tls: bool = False
    parameters_before_tls: list[str] = field(default_factory=list)
    parameters_after_tls: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class CommandDiagnostic:
    command: str
    attempted: bool
    response_code: str | None = None
    response: str | None = None
    enabled: bool | None = None
    note: str | None = None


@dataclass(frozen=True)
class CertificateDiagnostic:
    certificate_valid: bool
    hostname_valid: bool
    expired: bool
    expires_soon_days: int | None
    self_signed: bool
    issuer: str | None
    subject: str | None
    san: list[str]
    key_type: str | None = None
    key_size: int | None = None
    signature_algorithm: str | None = None
    limitation: str | None = None


@dataclass(frozen=True)
class SMTPDiagnosticReport:
    hostname: str
    resolved_ip: str | None
    port: int
    security_mode: SecurityMode
    role: ServerRole
    banner: str | None
    capabilities_before_tls: dict[str, list[str]] = field(default_factory=dict)
    capabilities_after_tls: dict[str, list[str]] = field(default_factory=dict)
    capability_diagnostics: list[CapabilityDiagnostic] = field(default_factory=list)
    auth_mechanisms_before_tls: list[str] = field(default_factory=list)
    auth_mechanisms_after_tls: list[str] = field(default_factory=list)
    starttls_advertised: bool = False
    starttls_successful: bool | None = None
    ehlo_after_tls_successful: bool | None = None
    tls_information: TLSInformation | None = None
    certificate_diagnostic: CertificateDiagnostic | None = None
    command_diagnostics: list[CommandDiagnosticResult] = field(default_factory=list)
    diagnostics_options: DiagnosticsOptions = field(default_factory=DiagnosticsOptions)
    success: bool = False
    error_type: str | None = None
    error_message: str | None = None


@dataclass(frozen=True)
class SecurityFinding:
    id: str
    title: str
    severity: FindingSeverity
    category: str
    description: str
    evidence: str
    recommendation: str
    port: int
    security_mode: SecurityMode
