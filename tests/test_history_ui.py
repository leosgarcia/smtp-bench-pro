from smtp_bench_pro.persistence.repository import SMTPRunDetails
from smtp_bench_pro.ui.widgets.smtp_bench_widget import SMTPBenchWidget


TLS_DEFAULT = object()


class FakeHistoryRepository:
    def __init__(self, details: SMTPRunDetails | None = None):
        self.details = details
        self.details_calls: list[int] = []
        self.security_context_calls: list[int] = []
        self.summaries = [] if details is None else [
            {
                "id": details.run["id"],
                "created_at": details.run["created_at"],
                "hostname": details.run["hostname"],
                "ports": "587",
                "diagnostics_profile": details.run["diagnostics_profile"],
                "result_status": "Concluído",
                "findings_count": len(details.findings),
            }
        ]

    def list_run_summaries(self, limit: int = 100):
        self.limit = limit
        return self.summaries

    def get_security_context_for_run(self, run_id: int):
        self.security_context_calls.append(run_id)
        return {"run_id": run_id}

    def get_run_details(self, run_id: int):
        self.details_calls.append(run_id)
        return self.details if self.details and self.details.run["id"] == run_id else None


def _manual_details(findings=None, command_diagnostics=None, tls=TLS_DEFAULT) -> SMTPRunDetails:
    tls_json = {
        "tls_version": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "cipher_bits": 256,
        "certificate_subject": "mail.example.com",
        "certificate_issuer": "Example CA",
        "subject_alt_names": ["mail.example.com"],
        "not_after": "2026-12-31T00:00:00",
        "days_remaining": 145,
        "hostname_valid": True,
        "certificate_valid": True,
    }
    if tls is not TLS_DEFAULT:
        tls_json = tls
    return SMTPRunDetails(
        run={
            "id": 18,
            "hostname": "mail.example.com",
            "iterations": 5,
            "timeout": 3.0,
            "diagnostics_profile": "manual",
            "diagnostics_options_json": (
                '{"profile":"manual","test_noop":true,"test_help":true,'
                '"test_vrfy":false,"test_expn":false}'
            ),
            "created_at": "2026-08-08 18:15:32",
        },
        results=[
            {
                "id": 1,
                "hostname": "mail.example.com",
                "resolved_ip": "192.0.2.10",
                "port": 587,
                "security_mode": "starttls",
                "success": 1,
                "status": "SUCCESS",
                "total_ms": 42.0,
                "banner": "220 mail.example.com ESMTP",
                "ehlo_hostname": "client.example",
                "capabilities_before_tls_json": {"STARTTLS": [], "SIZE": ["1024"]},
                "capabilities_after_tls_json": {"AUTH": ["PLAIN", "LOGIN"]},
                "auth_before_tls_json": [],
                "auth_after_tls_json": ["PLAIN", "LOGIN"],
                "command_diagnostics_json": command_diagnostics
                if command_diagnostics is not None
                else [
                    {
                        "command": "HELP",
                        "executed": True,
                        "supported": True,
                        "response_code": "214",
                        "response_message": "214 Help follows",
                        "status": "ENABLED",
                        "reason": None,
                    }
                ],
                "tls_json": tls_json,
            }
        ],
        diagnostics=[],
        findings=findings or [],
        commands=[],
    )


def _select_first_history_row(widget: SMTPBenchWidget) -> None:
    widget.history_table.setCurrentCell(0, 0)
    widget._on_history_selection_changed()


def test_history_empty_state_and_lazy_loading(qtbot) -> None:
    repository = FakeHistoryRepository()
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    assert widget.history_table.rowCount() == 0
    assert repository.details_calls == []
    assert "Nenhuma execução disponível" in widget.history_header.text()


def test_history_selection_loads_run_details_and_uses_persisted_manual_profile(qtbot) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    widget.profile_combo.setCurrentIndex(0)

    assert repository.details_calls == []
    _select_first_history_row(widget)

    assert repository.security_context_calls[-1:] == [18]
    assert repository.details_calls[-1:] == [18]
    assert "Execução #18" in widget.history_header.text()
    assert "Perfil: Manual" in widget.history_header.text()
    assert "Perfil utilizado: Manual" in widget.history_security_summary.text()
    assert "VRFY: desabilitado" in widget.history_security_summary.text()
    assert "HELP" in widget.history_smtp_view.toPlainText()
    assert widget.history_command_table.item(0, 2).text() == "Habilitado"


def test_history_renders_persisted_tls_and_legacy_missing_fields(qtbot) -> None:
    repository = FakeHistoryRepository(_manual_details(command_diagnostics=[], tls=None))
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    _select_first_history_row(widget)

    assert "Não disponível nesta execução" in widget.history_tls_view.toPlainText()
    assert widget.history_command_table.rowCount() == 4
    assert widget.history_command_table.item(2, 2).text() == "Não testado"


def test_history_does_not_reevaluate_findings(qtbot) -> None:
    repository = FakeHistoryRepository(
        _manual_details(
            findings=[],
            command_diagnostics=[
                {
                    "command": "VRFY",
                    "executed": True,
                    "supported": True,
                    "response_code": "252",
                    "response_message": "252 Cannot VRFY user",
                    "status": "ENABLED",
                    "reason": None,
                }
            ],
        )
    )
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    _select_first_history_row(widget)

    assert widget.history_findings_table.rowCount() == 0
    assert "Nenhum achado de segurança associado" in widget.history_command_details.toPlainText()


def test_history_export_button_disabled_without_selection(qtbot) -> None:
    repository = FakeHistoryRepository()
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    assert widget.export_history_button.isEnabled() is False


def test_history_export_json_from_selected_run(qtbot, tmp_path, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    output = tmp_path / "run.json"
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(output), "JSON Files (*.json)"),
    )

    _select_first_history_row(widget)
    widget._export_selected_history_run("json")

    assert widget.export_history_button.isEnabled() is True
    assert output.exists()
    assert '"id": 18' in output.read_text(encoding="utf-8")
    assert "exportada com sucesso" in widget.history_header.text()


def test_history_export_html_from_selected_run(qtbot, tmp_path, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    output = tmp_path / "run.html"
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(output), "HTML Files (*.html)"),
    )

    _select_first_history_row(widget)
    widget._export_selected_history_run("html")

    assert "Historical SMTP Diagnostic Report" in output.read_text(encoding="utf-8")


def test_history_export_cancel_does_not_create_file(qtbot, tmp_path, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: ("", ""),
    )

    _select_first_history_row(widget)
    widget._export_selected_history_run("json")

    assert list(tmp_path.iterdir()) == []


def test_history_export_write_error_is_handled(qtbot, tmp_path, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    missing = tmp_path / "missing" / "run.json"
    warnings = []
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(missing), "JSON Files (*.json)"),
    )
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QMessageBox.warning",
        lambda *args, **kwargs: warnings.append(args),
    )

    _select_first_history_row(widget)
    widget._export_selected_history_run("json")

    assert warnings


def test_history_export_does_not_reprobe_or_reevaluate_rules(qtbot, tmp_path, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details(findings=[]))
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    output = tmp_path / "run.json"
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QFileDialog.getSaveFileName",
        lambda *args, **kwargs: (str(output), "JSON Files (*.json)"),
    )
    monkeypatch.setattr(
        widget.diagnostics_service,
        "analyze_results",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("rule engine should not run")),
    )
    monkeypatch.setattr(
        widget.engine,
        "run_benchmark",
        lambda *args, **kwargs: (_ for _ in ()).throw(AssertionError("probe should not run")),
    )

    _select_first_history_row(widget)
    widget._export_selected_history_run("json")

    assert output.exists()


def test_history_compare_button_disabled_without_selection(qtbot) -> None:
    repository = FakeHistoryRepository()
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    assert widget.compare_history_button.isEnabled() is False


def test_history_compare_button_enabled_with_selection(qtbot) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)

    _select_first_history_row(widget)

    assert widget.compare_history_button.isEnabled() is True


def test_history_comparison_dialog_tabs(qtbot) -> None:
    from smtp_bench_pro.comparison.comparator import HistoricalRunComparator
    from smtp_bench_pro.ui.widgets.comparison_dialog import HistoricalComparisonDialog

    base = _manual_details()
    compared = _manual_details()
    compared.run["id"] = 19
    compared.run["diagnostics_profile"] = "extended"
    compared.results[0]["total_ms"] = 80.0
    comparison = HistoricalRunComparator().compare(base, compared)
    dialog = HistoricalComparisonDialog(comparison)
    qtbot.addWidget(dialog)

    labels = [dialog.tabs.tabText(index) for index in range(dialog.tabs.count())]
    assert labels == ["Resumo", "Performance", "SMTP", "TLS", "Segurança"]


def test_history_compare_same_run_is_rejected(qtbot, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    warnings = []
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.QMessageBox.warning",
        lambda *args, **kwargs: warnings.append(args),
    )
    monkeypatch.setattr(widget, "_select_compared_run_id", lambda details: 18)

    _select_first_history_row(widget)
    widget._compare_selected_history_run()

    assert warnings
    assert "Selecione duas execuções diferentes" in str(warnings[0])


def test_history_compare_cancel_does_not_open_dialog(qtbot, monkeypatch) -> None:
    repository = FakeHistoryRepository(_manual_details())
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    opened = []
    monkeypatch.setattr(widget, "_select_compared_run_id", lambda details: None)
    monkeypatch.setattr(
        "smtp_bench_pro.ui.widgets.smtp_bench_widget.HistoricalComparisonDialog",
        lambda *args, **kwargs: opened.append(args),
    )

    _select_first_history_row(widget)
    widget._compare_selected_history_run()

    assert opened == []


def test_history_compare_opens_dialog(qtbot, monkeypatch) -> None:
    base = _manual_details()
    compared = _manual_details()
    compared.run["id"] = 19
    compared.results[0]["total_ms"] = 80.0
    repository = FakeHistoryRepository(base)
    repository.extra_details = compared

    def get_run_details(run_id: int):
        return compared if run_id == 19 else base

    repository.get_run_details = get_run_details
    widget = SMTPBenchWidget(include_about=False, repository=repository)
    qtbot.addWidget(widget)
    calls = []

    class FakeDialog:
        def __init__(self, comparison, parent=None):
            calls.append(comparison)

        def exec(self):
            return None

    monkeypatch.setattr(widget, "_select_compared_run_id", lambda details: 19)
    monkeypatch.setattr("smtp_bench_pro.ui.widgets.smtp_bench_widget.HistoricalComparisonDialog", FakeDialog)

    _select_first_history_row(widget)
    widget._compare_selected_history_run()

    assert calls
    assert calls[0].baseline.run_id == 18
    assert calls[0].compared.run_id == 19
