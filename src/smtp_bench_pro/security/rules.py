"""Contextual security rules for SMTP diagnostics."""

from __future__ import annotations

import re

from smtp_bench_pro.domain.diagnostics import FindingSeverity, SMTPDiagnosticReport, SecurityFinding, ServerRole
from smtp_bench_pro.domain.enums import SecurityMode

SENSITIVE_CLEAR_AUTH = {"PLAIN", "LOGIN"}
_VERSION_PATTERN = re.compile(
    r"\b(?:postfix|exim|sendmail|exchange|haraka|opensmtpd|mailenable|zimbra|carbonio)[/-]?\s*\d",
    re.I,
)


def evaluate_security_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    findings.extend(_auth_findings(report))
    findings.extend(_starttls_findings(report))
    findings.extend(_certificate_findings(report))
    findings.extend(_banner_findings(report))
    findings.extend(_command_findings(report))
    return findings


def _finding(
    report: SMTPDiagnosticReport,
    finding_id: str,
    title: str,
    severity: FindingSeverity,
    category: str,
    description: str,
    evidence: str,
    recommendation: str,
) -> SecurityFinding:
    return SecurityFinding(
        id=finding_id,
        title=title,
        severity=severity,
        category=category,
        description=description,
        evidence=evidence,
        recommendation=recommendation,
        port=report.port,
        security_mode=report.security_mode,
    )


def _auth_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    mechanisms = set(report.auth_mechanisms_before_tls)
    sensitive = sorted(mechanisms & SENSITIVE_CLEAR_AUTH)
    if not sensitive:
        return []
    if report.security_mode == SecurityMode.SMTPS:
        return []

    severity = FindingSeverity.HIGH if report.role == ServerRole.SUBMISSION else FindingSeverity.MEDIUM
    return [
        _finding(
            report,
            "SMTP-AUTH-001",
            "Sensitive AUTH mechanisms advertised before TLS",
            severity,
            "AUTH",
            "The server advertises credential-based AUTH mechanisms before an encrypted channel is active.",
            f"AUTH mechanisms before TLS: {', '.join(sensitive)}",
            (
                "Advertise PLAIN/LOGIN only after STARTTLS on submission services. "
                "For MX port 25, avoid AUTH unless required."
            ),
        )
    ]


def _starttls_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    if (
        report.role == ServerRole.SUBMISSION
        and report.security_mode == SecurityMode.STARTTLS
        and not report.starttls_advertised
    ):
        findings.append(
            _finding(
                report,
                "SMTP-TLS-001",
                "STARTTLS is not advertised on a submission port",
                FindingSeverity.HIGH,
                "STARTTLS",
                "Submission services are expected to offer STARTTLS when using explicit TLS.",
                "STARTTLS capability was absent before TLS.",
                "Enable STARTTLS on port 587 or use implicit TLS on port 465.",
            )
        )
    elif (
        report.role != ServerRole.SUBMISSION
        and report.security_mode == SecurityMode.STARTTLS
        and not report.starttls_advertised
    ):
        findings.append(
            _finding(
                report,
                "SMTP-TLS-002",
                "STARTTLS is not advertised",
                FindingSeverity.INFO,
                "STARTTLS",
                "The server did not advertise STARTTLS. This can be acceptable depending on the SMTP role.",
                "STARTTLS capability was absent before TLS.",
                (
                    "Confirm the intended role of this SMTP service and enable STARTTLS "
                    "when encrypted transport is required."
                ),
            )
        )
    if report.starttls_advertised and report.starttls_successful is False:
        findings.append(
            _finding(
                report,
                "SMTP-TLS-003",
                "STARTTLS was advertised but the handshake failed",
                FindingSeverity.HIGH,
                "STARTTLS",
                "A server advertising STARTTLS should complete the TLS handshake successfully.",
                report.error_message or "STARTTLS handshake did not complete.",
                "Review the SMTP TLS certificate, protocol configuration, and firewall/TLS inspection devices.",
            )
        )
    return findings


def _certificate_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    cert = report.certificate_diagnostic
    if cert is None:
        return []
    findings: list[SecurityFinding] = []
    if cert.expired:
        findings.append(
            _finding(
                report,
                "SMTP-CERT-001",
                "Certificate is expired",
                FindingSeverity.CRITICAL,
                "Certificate",
                "The SMTP TLS certificate is expired.",
                f"Certificate days remaining: {cert.expires_soon_days}",
                "Renew and deploy a valid certificate for this SMTP hostname.",
            )
        )
    if not cert.hostname_valid:
        findings.append(
            _finding(
                report,
                "SMTP-CERT-002",
                "Certificate hostname mismatch",
                FindingSeverity.CRITICAL,
                "Certificate",
                "The certificate identity does not match the probed SMTP hostname.",
                f"Subject={cert.subject or '-'} SAN={', '.join(cert.san) or '-'}",
                "Deploy a certificate whose SAN includes the SMTP hostname clients use.",
            )
        )
    if not cert.certificate_valid:
        findings.append(
            _finding(
                report,
                "SMTP-CERT-003",
                "Certificate is not trusted by the local trust store",
                FindingSeverity.HIGH,
                "Certificate",
                "The TLS certificate could not be validated as trusted.",
                "certificate_valid=False",
                "Use a certificate issued by a trusted CA, or configure the correct intermediate chain.",
            )
        )
    if cert.self_signed:
        findings.append(
            _finding(
                report,
                "SMTP-CERT-004",
                "Certificate appears to be self-signed",
                FindingSeverity.MEDIUM,
                "Certificate",
                "The certificate subject and issuer are identical.",
                f"Subject={cert.subject or '-'} Issuer={cert.issuer or '-'}",
                "Use a publicly trusted certificate for public SMTP services.",
            )
        )
    days = cert.expires_soon_days
    if days is not None and not cert.expired:
        if days <= 7:
            severity = FindingSeverity.HIGH
        elif days <= 30:
            severity = FindingSeverity.MEDIUM
        elif days <= 60:
            severity = FindingSeverity.LOW
        else:
            severity = None
        if severity is not None:
            findings.append(
                _finding(
                    report,
                    "SMTP-CERT-005",
                    "Certificate expires soon",
                    severity,
                    "Certificate",
                    "The SMTP TLS certificate is approaching expiration.",
                    f"Certificate expires in {days} day(s).",
                    "Schedule certificate renewal before expiration and verify deployment on all SMTP endpoints.",
                )
            )
    return findings


def _banner_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    banner = report.banner or ""
    if not banner:
        return []
    if _VERSION_PATTERN.search(banner):
        return [
            _finding(
                report,
                "SMTP-BANNER-001",
                "SMTP banner appears to disclose software version",
                FindingSeverity.MEDIUM,
                "Banner",
                "The SMTP banner appears to expose product and version information.",
                banner,
                (
                    "Consider reducing banner detail if operationally acceptable. "
                    "Do not hide information at the cost of RFC behavior."
                ),
            )
        ]
    known_products = ["postfix", "exim", "exchange", "haraka", "opensmtpd", "mailenable", "zimbra", "carbonio"]
    if any(product in banner.lower() for product in known_products):
        return [
            _finding(
                report,
                "SMTP-BANNER-002",
                "SMTP banner discloses mail software family",
                FindingSeverity.INFO,
                "Banner",
                "The SMTP banner identifies the mail software family. This is informational by itself.",
                banner,
                "Review banner policy; software family disclosure alone is not normally a vulnerability.",
            )
        ]
    return []


def _command_findings(report: SMTPDiagnosticReport) -> list[SecurityFinding]:
    findings: list[SecurityFinding] = []
    for command in report.command_diagnostics:
        if command.command in {"VRFY", "EXPN"} and command.executed and command.enabled:
            findings.append(
                _finding(
                    report,
                    "SMTP-CMD-001" if command.command == "VRFY" else "SMTP-CMD-002",
                    f"{command.command} appears to be enabled",
                    FindingSeverity.MEDIUM,
                    "SMTP Command",
                    f"The {command.command} command can expose address validity depending on server behavior.",
                    command.response_message or f"{command.command} returned an enabled response.",
                    f"Disable {command.command} on public SMTP services unless there is a clear operational need.",
                )
            )
    return findings
