from datetime import UTC, datetime
import json
import sys

from smtp_bench_pro.comparison.comparator import HistoricalRunComparator
from smtp_bench_pro.export.comparison_export import ComparisonExportService, serialize_comparison
from smtp_bench_pro.export.comparison_html_exporter import render_comparison_html
from helpers import _details, _finding

FIXED_EXPORT_TIME = datetime(2026, 8, 8, 22, 0, 0, tzinfo=UTC)


def _comparison():
    baseline = _details(
        run_id=18,
        hostname="mail.example.com",
        profile="safe",
        total=100.0,
        tls_version="TLSv1.2",
        capabilities_before={"STARTTLS": [], "SIZE": ["1024"]},
        auth_after=["LOGIN"],
        command_status="NOT_TESTED",
        findings=[_finding("SMTP-BANNER-001", severity="LOW", evidence="220 Postfix")],
    )
    compared = _details(
        run_id=25,
        hostname="mail.example.com",
        profile="extended",
        total=130.0,
        tls_version="TLSv1.3",
        capabilities_before={"STARTTLS": [], "SIZE": ["2048"], "SMTPUTF8": []},
        auth_after=["XOAUTH2"],
        command_status="ENABLED",
        findings=[
            _finding("SMTP-BANNER-001", severity="LOW", evidence="220 Postfix"),
            _finding("SMTP-CMD-001", severity="MEDIUM", evidence="252 Cannot VRFY user"),
        ],
    )
    return HistoricalRunComparator().compare(baseline, compared)


def test_serialize_comparison_is_canonical_and_uses_run_comparison_only() -> None:
    payload = serialize_comparison(_comparison(), exported_at=FIXED_EXPORT_TIME)

    assert payload["export"] == {
        "application": "SMTP Bench Pro",
        "application_version": "0.2.6",
        "export_type": "historical_comparison",
        "exported_at": "2026-08-08T22:00:00+00:00",
        "format_version": 1,
    }
    assert payload["comparison"]["baseline"]["run_id"] == 18
    assert payload["comparison"]["candidate"]["run_id"] == 25
    assert payload["comparison"]["summary"]
    assert payload["performance"][-1]["trend"] == "REGRESSED"
    assert payload["smtp"]["capabilities"]["before_tls"]["added"] == ["SMTPUTF8"]
    assert payload["smtp"]["auth"]["after_tls"]["added"] == ["XOAUTH2"]
    assert payload["commands"][-1]["comparability"] == "NOT_COMPARABLE"
    assert payload["security"]["new_findings"][0]["finding_id"] == "SMTP-CMD-001"


def test_comparison_json_export_writes_utf8_and_null_values(tmp_path) -> None:
    comparison = _comparison()
    output = tmp_path / "comparação.json"

    result = ComparisonExportService().export(comparison, output, "json")
    data = json.loads(output.read_text(encoding="utf-8"))

    assert result.baseline_run_id == 18
    assert result.compared_run_id == 25
    assert data["export"]["export_type"] == "historical_comparison"
    assert data["comparison"]["baseline"]["run_id"] == 18
    assert data["performance"][-1]["percentage_delta"] == 30.0
    vrfy = next(command for command in data["commands"] if command["command"] == "VRFY")
    assert vrfy["baseline"] == "NOT_TESTED"


def test_comparison_html_export_writes_standalone_escaped_report(tmp_path) -> None:
    comparison = _comparison()
    comparison.compared.__dict__["hostname"] = "<script>alert(1)</script>"
    output = tmp_path / "compare.html"

    ComparisonExportService().export(comparison, output, "html")
    html = output.read_text(encoding="utf-8")

    assert "<meta charset=\"utf-8\">" in html
    assert "Historical Comparison Report" in html
    assert "Execução Base" in html
    assert "Execução Comparada" in html
    assert "Performance" in html
    assert "Security Findings" in html
    assert "@media print" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "<script" not in html.lower()


def test_html_handles_legacy_missing_data_and_partial_warning() -> None:
    comparison = _comparison()
    payload = serialize_comparison(comparison, exported_at=FIXED_EXPORT_TIME)
    payload["tls"][0]["candidate"] = None
    payload["comparison"]["warnings"].append(
        "Uma das execuções possui diagnóstico parcial. Algumas diferenças podem não ser comparáveis."
    )

    html = render_comparison_html(payload)

    assert "Não disponível" in html
    assert "diagnóstico parcial" in html


def test_comparison_export_has_no_comparator_network_or_rule_engine_dependencies(tmp_path) -> None:
    imported_before = set(sys.modules)
    ComparisonExportService().export(_comparison(), tmp_path / "comparison.json", "json")
    imported_after = set(sys.modules)
    imported = imported_after - imported_before

    assert not any(name.endswith("smtp_probe") for name in imported)
    assert not any(name.endswith("rules") for name in imported)


def test_export_rejects_invalid_format(tmp_path) -> None:
    service = ComparisonExportService()

    try:
        service.export(_comparison(), tmp_path / "comparison.txt", "txt")
    except ValueError as exc:
        assert "Unsupported export format" in str(exc)
    else:
        raise AssertionError("invalid export format should fail")


