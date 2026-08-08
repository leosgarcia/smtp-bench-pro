from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
    DiagnosticsProfile,
)
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.results import SMTPProbeResult, TLSInformation
from smtp_bench_pro.persistence.database import SMTPDatabase
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository


def test_repository_lists_run_summaries_and_lazy_details_payload(tmp_path) -> None:
    database = SMTPDatabase(tmp_path / "smtp.db")
    repository = SMTPBenchmarkRepository(database)
    options = DiagnosticsOptions.from_profile(DiagnosticsProfile.EXTENDED)
    result = SMTPProbeResult(
        hostname="mail.example.com",
        resolved_ip="192.0.2.10",
        port=587,
        security_mode=SecurityMode.STARTTLS,
        success=True,
        status=ProbeStatus.SUCCESS,
        total_ms=123.4,
        banner="220 mail.example.com ESMTP Postfix",
        capabilities_before_tls={"STARTTLS": [], "SIZE": ["35882577"]},
        capabilities_after_tls={"AUTH": ["PLAIN", "LOGIN"]},
        auth_mechanisms_after_tls=["PLAIN", "LOGIN"],
        diagnostics_options=options,
        command_diagnostic_results=[
            CommandDiagnosticResult(
                command="VRFY",
                executed=True,
                supported=True,
                response_code="252",
                response_message="252 Cannot VRFY user",
                status=CommandDiagnosticStatus.ENABLED,
            )
        ],
        tls_information=TLSInformation(
            tls_version="TLSv1.3",
            cipher="TLS_AES_256_GCM_SHA384",
            cipher_bits=256,
            certificate_subject="mail.example.com",
            certificate_issuer="Example CA",
            subject_alt_names=["mail.example.com"],
            not_after="2026-12-31T00:00:00",
            days_remaining=145,
            hostname_valid=True,
            certificate_valid=True,
        ),
    )

    run_id = repository.save_run("mail.example.com", 1, 3.0, [result], diagnostics_options=options)
    summaries = repository.list_run_summaries(limit=100)
    details = repository.get_run_details(run_id)

    assert summaries[0]["id"] == run_id
    assert summaries[0]["ports"] == "587"
    assert summaries[0]["diagnostics_profile"] == "extended"
    assert summaries[0]["result_status"] == "Concluído"
    assert summaries[0]["findings_count"] >= 1
    assert details is not None
    assert details.run["diagnostics_profile"] == "extended"
    assert details.results[0]["tls_json"]["tls_version"] == "TLSv1.3"
    assert details.results[0]["command_diagnostics_json"][0]["command"] == "VRFY"
    assert any(finding["payload"]["id"] == "SMTP-CMD-001" for finding in details.findings)

