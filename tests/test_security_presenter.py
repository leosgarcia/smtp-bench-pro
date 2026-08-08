from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
    DiagnosticsProfile,
)
from smtp_bench_pro.domain.diagnostics import FindingSeverity, SecurityFinding
from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.ui.security_presenter import (
    command_finding_for,
    command_presentation,
    profile_description,
    profile_display_name,
    severity_counters_text,
)


def test_profile_summary_texts() -> None:
    assert profile_display_name(DiagnosticsProfile.SAFE) == "Seguro (Recomendado)"
    assert "não executa VRFY" in profile_description(DiagnosticsOptions())
    assert "eventos nos logs" in profile_description(DiagnosticsOptions.from_profile("extended"))
    assert "VRFY: desabilitado" in profile_description(
        DiagnosticsOptions(profile=DiagnosticsProfile.MANUAL, test_vrfy=False)
    )


def test_command_status_rendering() -> None:
    cases = [
        (CommandDiagnosticStatus.NOT_TESTED, "Não testado"),
        (CommandDiagnosticStatus.ENABLED, "Habilitado"),
        (CommandDiagnosticStatus.DISABLED, "Desabilitado"),
        (CommandDiagnosticStatus.UNKNOWN, "Desconhecido"),
    ]
    for status, label in cases:
        rendered = command_presentation(CommandDiagnosticResult(command="VRFY", executed=True, status=status))
        assert rendered.result == label


def test_not_tested_rendering_keeps_reason() -> None:
    rendered = command_presentation(
        CommandDiagnosticResult(
            command="EXPN",
            executed=False,
            status=CommandDiagnosticStatus.NOT_TESTED,
            reason="Disabled by SAFE diagnostics profile",
        )
    )

    assert rendered.executed == "Não"
    assert rendered.result == "Não testado"
    assert "SAFE" in rendered.note


def test_command_finding_association() -> None:
    finding = SecurityFinding(
        id="SMTP-CMD-001",
        title="VRFY appears to be enabled",
        severity=FindingSeverity.MEDIUM,
        category="SMTP Command",
        description="desc",
        evidence="252 Cannot VRFY user",
        recommendation="Disable VRFY",
        port=25,
        security_mode=SecurityMode.PLAIN,
    )

    assert command_finding_for("VRFY", [finding]) is finding
    assert command_finding_for("EXPN", [finding]) is None


def test_severity_counters_text() -> None:
    finding = SecurityFinding(
        id="SMTP-CMD-001",
        title="VRFY",
        severity=FindingSeverity.MEDIUM,
        category="SMTP Command",
        description="desc",
        evidence="evidence",
        recommendation="rec",
        port=25,
        security_mode=SecurityMode.PLAIN,
    )

    rendered = severity_counters_text([finding])

    assert "Medium: 1" in rendered
    assert "Critical: 0" in rendered
