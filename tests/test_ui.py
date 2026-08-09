from PySide6.QtWidgets import QTabWidget

from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
    DiagnosticsProfile,
)
from smtp_bench_pro.domain.enums import ProbeStatus, SecurityMode
from smtp_bench_pro.domain.results import SMTPProbeResult
from smtp_bench_pro.ui.main_window import SMTPBenchMainWindow
from smtp_bench_pro.ui.widgets.smtp_bench_widget import SMTPBenchWidget


def test_main_window_instantiates(qtbot) -> None:
    window = SMTPBenchMainWindow()
    qtbot.addWidget(window)

    assert window.windowTitle() == "SMTP Bench Pro"
    assert isinstance(window.bench_widget.tab_widget, QTabWidget)


def test_integrated_widget_hides_about_tab(qtbot, tmp_path) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)

    labels = [widget.tab_widget.tabText(index) for index in range(widget.tab_widget.count())]
    assert labels == ["Benchmark", "Diagnóstico", "Segurança", "Histórico", "DNS de E-mail"]



def test_profile_selector_defaults_to_safe(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)

    options = widget._current_diagnostics_options()

    assert options.profile.value == "safe"
    assert options.test_vrfy is False
    assert options.test_expn is False
    assert widget.vrfy_check.isEnabled() is False
    assert widget.expn_check.isEnabled() is False


def test_manual_controls_enable_disable(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)

    widget.profile_combo.setCurrentIndex(2)

    assert widget.vrfy_check.isEnabled() is True
    assert widget.expn_check.isEnabled() is True
    widget.vrfy_check.setChecked(True)
    assert widget._current_diagnostics_options().test_vrfy is True
    assert widget.extended_warning.isHidden() is False




def _security_result(options=None, command_results=None, success=True):
    return SMTPProbeResult(
        hostname="mail.example.com",
        resolved_ip="192.0.2.1",
        port=25,
        security_mode=SecurityMode.PLAIN,
        success=success,
        status=ProbeStatus.SUCCESS if success else ProbeStatus.UNKNOWN_ERROR,
        diagnostics_options=options or DiagnosticsOptions(),
        command_diagnostic_results=command_results or [
            CommandDiagnosticResult(
                command="NOOP",
                executed=True,
                response_code="250",
                response_message="250 OK",
                status=CommandDiagnosticStatus.ENABLED,
            ),
            CommandDiagnosticResult(
                command="VRFY",
                executed=False,
                status=CommandDiagnosticStatus.NOT_TESTED,
                reason="Disabled by SAFE diagnostics profile",
            ),
        ],
    )


def test_security_summary_safe_rendering(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)
    reports, findings = widget.diagnostics_service.analyze_results([_security_result()])

    widget._render_security(reports, findings)

    assert "Perfil utilizado: Seguro (Recomendado)" in widget.security_summary.text()
    assert "não executa VRFY" in widget.security_summary.text()
    assert widget.command_table.rowCount() == 2
    assert widget.command_table.item(1, 2).text() == "Não testado"


def test_security_summary_extended_rendering_and_finding_association(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)
    options = DiagnosticsOptions.from_profile(DiagnosticsProfile.EXTENDED)
    result = _security_result(
        options=options,
        command_results=[
            CommandDiagnosticResult(
                command="VRFY",
                executed=True,
                supported=True,
                response_code="252",
                response_message="252 Cannot VRFY user",
                status=CommandDiagnosticStatus.ENABLED,
            )
        ],
    )
    reports, findings = widget.diagnostics_service.analyze_results([result])

    widget._render_security(reports, findings)
    widget.command_table.setCurrentCell(0, 0)
    widget._update_command_details_from_selection()

    assert "Perfil utilizado: Estendido" in widget.security_summary.text()
    assert widget.command_table.item(0, 2).text() == "Habilitado"
    assert "Finding: SMTP-CMD-001" in widget.command_details.toPlainText()


def test_security_summary_manual_rendering(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)
    options = DiagnosticsOptions(profile=DiagnosticsProfile.MANUAL, test_help=True, test_vrfy=False)
    reports, findings = widget.diagnostics_service.analyze_results([_security_result(options=options)])

    widget._render_security(reports, findings)

    assert "Perfil utilizado: Manual" in widget.security_summary.text()
    assert "VRFY: desabilitado" in widget.security_summary.text()


def test_security_partial_and_empty_states(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)

    widget._render_empty_findings()
    assert "Nenhum diagnóstico de segurança disponível" in widget.security_summary.text()

    reports, findings = widget.diagnostics_service.analyze_results([_security_result(success=False)])
    widget._render_security(reports, findings)
    assert "Diagnóstico parcial" in widget.security_summary.text()


def test_no_finding_state_for_command(qtbot) -> None:
    widget = SMTPBenchWidget(include_about=False)
    qtbot.addWidget(widget)
    reports, findings = widget.diagnostics_service.analyze_results([_security_result()])

    widget._render_security(reports, findings)
    widget.command_table.setCurrentCell(0, 0)
    widget._update_command_details_from_selection()

    assert "Nenhum achado de segurança associado" in widget.command_details.toPlainText()
