from smtp_bench_pro.application.diagnostics import SMTPDiagnosticsService
from smtp_bench_pro.domain.diagnostic_options import CommandDiagnosticResult, CommandDiagnosticStatus
from smtp_bench_pro.domain.diagnostics import FindingSeverity
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.results import SMTPProbeResult, TLSInformation


def make_result(**overrides) -> SMTPProbeResult:
    data = {
        "hostname": "mail.example.com",
        "resolved_ip": "192.0.2.1",
        "port": 587,
        "security_mode": SecurityMode.STARTTLS,
        "success": True,
        "status": ProbeStatus.SUCCESS,
        "banner": "220 mail.example.com ESMTP Postfix",
        "capabilities_before_tls": {"STARTTLS": [], "SIZE": ["1024"], "AUTH": ["PLAIN", "LOGIN"]},
        "capabilities_after_tls": {"SIZE": ["1024"], "AUTH": ["PLAIN", "LOGIN", "XOAUTH2"]},
        "auth_mechanisms_before_tls": ["LOGIN", "PLAIN"],
        "auth_mechanisms_after_tls": ["LOGIN", "PLAIN", "XOAUTH2"],
        "command_responses": {
            "NOOP": "250 OK",
            "HELP": "214 Help",
            "VRFY": "252 Cannot VRFY user",
            "EXPN": "502 Disabled",
        },
        "tls_information": TLSInformation(
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            certificate_subject="commonName=mail.example.com",
            certificate_issuer="commonName=Example CA",
            days_remaining=45,
            subject_alt_names=["mail.example.com"],
            hostname_valid=True,
            certificate_valid=True,
        ),
    }
    data.update(overrides)
    return SMTPProbeResult(**data)


def test_diagnostics_preserves_ehlo_pre_post_tls_and_auth() -> None:
    report = SMTPDiagnosticsService().analyze_result(make_result())

    assert report.starttls_advertised is True
    assert report.auth_mechanisms_before_tls == ["LOGIN", "PLAIN"]
    assert report.auth_mechanisms_after_tls == ["LOGIN", "PLAIN", "XOAUTH2"]
    auth = next(item for item in report.capability_diagnostics if item.name == "AUTH")
    assert auth.present_before_tls is True
    assert auth.present_after_tls is True
    assert auth.parameters_after_tls == ["PLAIN", "LOGIN", "XOAUTH2"]


def test_security_rules_find_clear_auth_and_vrfy() -> None:
    _reports, findings = SMTPDiagnosticsService().analyze_results([make_result()])

    ids = {finding.id for finding in findings}
    assert "SMTP-AUTH-001" in ids
    assert "SMTP-CMD-001" in ids
    auth = next(finding for finding in findings if finding.id == "SMTP-AUTH-001")
    assert auth.severity == FindingSeverity.HIGH


def test_starttls_missing_on_submission_is_high() -> None:
    result = make_result(
        success=False,
        status=ProbeStatus.STARTTLS_NOT_SUPPORTED,
        capabilities_before_tls={"SIZE": ["1024"]},
        capabilities_after_tls={},
        auth_mechanisms_before_tls=[],
        auth_mechanisms_after_tls=[],
        tls_information=None,
    )

    _reports, findings = SMTPDiagnosticsService().analyze_results([result])

    finding = next(item for item in findings if item.id == "SMTP-TLS-001")
    assert finding.severity == FindingSeverity.HIGH


def test_certificate_findings_expired_hostname_self_signed_and_expiring() -> None:
    expired = make_result(
        tls_information=TLSInformation(
            certificate_subject="commonName=wrong.example.com",
            certificate_issuer="commonName=wrong.example.com",
            days_remaining=-1,
            hostname_valid=False,
            certificate_valid=False,
        )
    )
    expiring = make_result(
        tls_information=TLSInformation(
            certificate_subject="commonName=mail.example.com",
            certificate_issuer="commonName=Example CA",
            days_remaining=6,
            hostname_valid=True,
            certificate_valid=True,
        )
    )

    _reports, findings = SMTPDiagnosticsService().analyze_results([expired, expiring])
    ids = {finding.id for finding in findings}

    assert {"SMTP-CERT-001", "SMTP-CERT-002", "SMTP-CERT-003", "SMTP-CERT-004", "SMTP-CERT-005"} <= ids


def test_banner_version_disclosure_is_medium() -> None:
    result = make_result(banner="220 mail.example.com ESMTP Postfix 3.7.1")

    _reports, findings = SMTPDiagnosticsService().analyze_results([result])

    finding = next(item for item in findings if item.id == "SMTP-BANNER-001")
    assert finding.severity == FindingSeverity.MEDIUM



def test_starttls_advertised_but_handshake_failed_is_high() -> None:
    result = make_result(
        success=False,
        status=ProbeStatus.TLS_ERROR,
        error_message="handshake failed",
        capabilities_before_tls={"STARTTLS": []},
        capabilities_after_tls={},
        auth_mechanisms_before_tls=[],
        auth_mechanisms_after_tls=[],
        tls_information=None,
    )

    _reports, findings = SMTPDiagnosticsService().analyze_results([result])

    finding = next(item for item in findings if item.id == "SMTP-TLS-003")
    assert finding.severity == FindingSeverity.HIGH



def test_vrfy_not_tested_does_not_generate_finding() -> None:
    result = make_result(
        command_responses={},
        command_diagnostic_results=[
            CommandDiagnosticResult(command="VRFY", executed=False, status=CommandDiagnosticStatus.NOT_TESTED)
        ],
    )

    _reports, findings = SMTPDiagnosticsService().analyze_results([result])

    assert "SMTP-CMD-001" not in {finding.id for finding in findings}
