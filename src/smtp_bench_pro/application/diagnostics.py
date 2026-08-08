"""SMTP diagnostics service."""

from __future__ import annotations

from smtp_bench_pro.domain.diagnostics import (
    CapabilityDiagnostic,
    CertificateDiagnostic,
    SMTPDiagnosticReport,
    SecurityFinding,
    ServerRole,
)
from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
)
from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.results import SMTPProbeResult, TLSInformation
from smtp_bench_pro.engine.capabilities import supports_starttls
from smtp_bench_pro.security.rules import evaluate_security_findings

EHLO_CAPABILITIES = (
    "STARTTLS",
    "AUTH",
    "PIPELINING",
    "SIZE",
    "8BITMIME",
    "DSN",
    "ENHANCEDSTATUSCODES",
    "SMTPUTF8",
    "CHUNKING",
    "BINARYMIME",
    "HELP",
)


class SMTPDiagnosticsService:
    """Builds configuration diagnostics and security findings from probe results."""

    def analyze_results(
        self, results: list[SMTPProbeResult]
    ) -> tuple[list[SMTPDiagnosticReport], list[SecurityFinding]]:
        reports = [self.analyze_result(result) for result in results]
        findings: list[SecurityFinding] = []
        for report in reports:
            findings.extend(evaluate_security_findings(report))
        return reports, findings

    def analyze_result(self, result: SMTPProbeResult) -> SMTPDiagnosticReport:
        before_tls = result.capabilities_before_tls or result.capabilities
        after_tls = result.capabilities_after_tls
        role = infer_server_role(result.port, result.security_mode)
        tls_info = result.tls_information
        certificate = build_certificate_diagnostic(tls_info) if tls_info is not None else None
        starttls_advertised = supports_starttls(before_tls)
        starttls_successful = None
        if result.security_mode == SecurityMode.STARTTLS:
            starttls_successful = result.success and result.tls_information is not None
        elif result.security_mode == SecurityMode.SMTPS:
            starttls_successful = True

        return SMTPDiagnosticReport(
            hostname=result.hostname,
            resolved_ip=result.resolved_ip,
            port=result.port,
            security_mode=result.security_mode,
            role=role,
            banner=result.banner,
            capabilities_before_tls=before_tls,
            capabilities_after_tls=after_tls,
            capability_diagnostics=build_capability_diagnostics(before_tls, after_tls),
            auth_mechanisms_before_tls=result.auth_mechanisms_before_tls,
            auth_mechanisms_after_tls=result.auth_mechanisms_after_tls,
            starttls_advertised=starttls_advertised,
            starttls_successful=starttls_successful,
            ehlo_after_tls_successful=bool(after_tls) if result.security_mode == SecurityMode.STARTTLS else None,
            tls_information=tls_info,
            certificate_diagnostic=certificate,
            command_diagnostics=build_command_diagnostics(
                result.command_diagnostic_results, result.command_responses, result.diagnostics_options
            ),
            diagnostics_options=result.diagnostics_options,
            success=result.success,
            error_type=result.error_type,
            error_message=result.error_message,
        )


def infer_server_role(port: int, security_mode: SecurityMode) -> ServerRole:
    if port in {465, 587} or security_mode == SecurityMode.SMTPS:
        return ServerRole.SUBMISSION
    if port == 25:
        return ServerRole.MX
    return ServerRole.AUTO


def build_capability_diagnostics(
    before_tls: dict[str, list[str]], after_tls: dict[str, list[str]]
) -> list[CapabilityDiagnostic]:
    diagnostics: list[CapabilityDiagnostic] = []
    for name in EHLO_CAPABILITIES:
        diagnostics.append(
            CapabilityDiagnostic(
                name=name,
                present_before_tls=name in before_tls,
                present_after_tls=name in after_tls,
                parameters_before_tls=before_tls.get(name, []),
                parameters_after_tls=after_tls.get(name, []),
            )
        )
    return diagnostics


def build_command_diagnostics(
    command_results: list[CommandDiagnosticResult],
    command_responses: dict[str, str],
    options: DiagnosticsOptions | None = None,
) -> list[CommandDiagnosticResult]:
    if command_results:
        return command_results

    options = options or DiagnosticsOptions()
    diagnostics: list[CommandDiagnosticResult] = []
    for command in ("NOOP", "HELP", "VRFY", "EXPN"):
        response = command_responses.get(command)
        if response is None:
            diagnostics.append(
                CommandDiagnosticResult(
                    command=command,
                    executed=False,
                    status=CommandDiagnosticStatus.NOT_TESTED,
                    reason=f"Disabled by {options.profile.value.upper()} diagnostics profile",
                )
            )
            continue
        code = response[:3] if len(response) >= 3 and response[:3].isdigit() else None
        status = CommandDiagnosticStatus.UNKNOWN
        supported = None
        if command in {"VRFY", "EXPN"} and code in {"250", "251", "252"}:
            status = CommandDiagnosticStatus.ENABLED
            supported = True
        elif code and code.startswith(("4", "5")):
            status = CommandDiagnosticStatus.DISABLED
            supported = False
        elif code and code.startswith("2"):
            status = CommandDiagnosticStatus.ENABLED
            supported = True
        diagnostics.append(
            CommandDiagnosticResult(
                command=command,
                executed=True,
                supported=supported,
                response_code=code,
                response_message=response,
                status=status,
            )
        )
    return diagnostics

def build_certificate_diagnostic(tls_info: TLSInformation) -> CertificateDiagnostic:
    subject = tls_info.certificate_subject
    issuer = tls_info.certificate_issuer
    days = tls_info.days_remaining
    return CertificateDiagnostic(
        certificate_valid=tls_info.certificate_valid,
        hostname_valid=tls_info.hostname_valid,
        expired=days is not None and days < 0,
        expires_soon_days=days,
        self_signed=bool(subject and issuer and subject == issuer),
        issuer=issuer,
        subject=subject,
        san=tls_info.subject_alt_names,
        limitation="Python stdlib does not expose portable certificate key details or full chain here.",
    )
