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


def test_repository_saves_run(tmp_path) -> None:
    database = SMTPDatabase(tmp_path / "smtp.db")
    repository = SMTPBenchmarkRepository(database)
    result = SMTPProbeResult(
        hostname="mail.example.com",
        resolved_ip="192.0.2.1",
        port=465,
        security_mode=SecurityMode.SMTPS,
        success=True,
        status=ProbeStatus.SUCCESS,
        total_ms=42.0,
        banner="220 mail.example.com ESMTP",
        capabilities={"AUTH": ["LOGIN"]},
        tls_information=TLSInformation(tls_version="TLSv1.3", cipher="TLS_AES_256_GCM_SHA384"),
    )

    run_id = repository.save_run("mail.example.com", 1, 3.0, [result])
    runs = repository.list_runs()

    assert run_id == 1
    assert runs[0]["hostname"] == "mail.example.com"



def test_repository_persists_diagnostics_profile(tmp_path) -> None:
    database = SMTPDatabase(tmp_path / "smtp.db")
    repository = SMTPBenchmarkRepository(database)
    options = DiagnosticsOptions.from_profile(DiagnosticsProfile.EXTENDED)
    result = SMTPProbeResult(
        hostname="mail.example.com",
        resolved_ip="192.0.2.1",
        port=25,
        security_mode=SecurityMode.PLAIN,
        success=True,
        status=ProbeStatus.SUCCESS,
        diagnostics_options=options,
    )

    repository.save_run("mail.example.com", 1, 3.0, [result], diagnostics_options=options)
    runs = repository.list_runs()

    assert runs[0]["diagnostics_profile"] == "extended"
    assert "test_vrfy" in runs[0]["diagnostics_options_json"]



def test_repository_loads_historical_security_context(tmp_path) -> None:
    database = SMTPDatabase(tmp_path / "smtp.db")
    repository = SMTPBenchmarkRepository(database)
    options = DiagnosticsOptions(profile=DiagnosticsProfile.MANUAL, test_help=True, test_vrfy=False)
    result = SMTPProbeResult(
        hostname="mail.example.com",
        resolved_ip="192.0.2.1",
        port=25,
        security_mode=SecurityMode.PLAIN,
        success=True,
        status=ProbeStatus.SUCCESS,
        diagnostics_options=options,
        command_diagnostic_results=[
            CommandDiagnosticResult(
                command="HELP",
                executed=True,
                response_code="214",
                response_message="214 Help",
                status=CommandDiagnosticStatus.ENABLED,
            )
        ],
    )

    run_id = repository.save_run("mail.example.com", 1, 3.0, [result], diagnostics_options=options)
    context = repository.get_security_context_for_run(run_id)

    assert context is not None
    assert context["run"]["diagnostics_profile"] == "manual"
    assert "HELP" in context["commands"][0]["command_diagnostics_json"]
