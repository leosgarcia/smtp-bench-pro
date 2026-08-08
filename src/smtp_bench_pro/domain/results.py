"""Structured result models for SMTP Bench Pro."""

from dataclasses import dataclass, field
from datetime import datetime

from smtp_bench_pro.domain.diagnostic_options import CommandDiagnosticResult, DiagnosticsOptions
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode


@dataclass
class TLSInformation:
    tls_version: str | None = None
    cipher: str | None = None
    cipher_bits: int | None = None
    certificate_subject: str | None = None
    certificate_issuer: str | None = None
    serial_number: str | None = None
    not_before: str | None = None
    not_after: str | None = None
    days_remaining: int | None = None
    subject_alt_names: list[str] = field(default_factory=list)
    hostname_valid: bool = False
    certificate_valid: bool = False


@dataclass
class SMTPProbeResult:
    hostname: str
    resolved_ip: str | None
    port: int
    security_mode: SecurityMode
    success: bool
    status: ProbeStatus
    error_type: str | None = None
    error_message: str | None = None
    tcp_connect_ms: float | None = None
    banner_ms: float | None = None
    ehlo_ms: float | None = None
    starttls_ms: float | None = None
    tls_handshake_ms: float | None = None
    total_ms: float | None = None
    banner: str | None = None
    ehlo_hostname: str | None = None
    capabilities: dict[str, list[str]] = field(default_factory=dict)
    capabilities_before_tls: dict[str, list[str]] = field(default_factory=dict)
    capabilities_after_tls: dict[str, list[str]] = field(default_factory=dict)
    auth_mechanisms_before_tls: list[str] = field(default_factory=list)
    auth_mechanisms_after_tls: list[str] = field(default_factory=list)
    command_responses: dict[str, str] = field(default_factory=dict)
    command_diagnostic_results: list[CommandDiagnosticResult] = field(default_factory=list)
    diagnostics_options: DiagnosticsOptions = field(default_factory=DiagnosticsOptions)
    tls_information: TLSInformation | None = None
    timestamp: datetime = field(default_factory=datetime.now)


@dataclass
class BenchmarkSummary:
    min_ms: float
    median_ms: float
    mean_ms: float
    max_ms: float
    stddev_ms: float
    jitter_ms: float


@dataclass
class BenchmarkRunResult:
    target: object
    iterations: int
    results: list[SMTPProbeResult]
    summary: BenchmarkSummary | None
