from datetime import UTC, datetime
import json

from smtp_bench_pro.export.historical_export import HistoricalRunExportService, serialize_run_details
from smtp_bench_pro.export.html_exporter import render_html
from smtp_bench_pro.persistence.repository import SMTPRunDetails
from smtp_bench_pro.version import __version__


FIXED_EXPORT_TIME = datetime(2026, 8, 8, 21, 0, 0, tzinfo=UTC)


def _details(*, findings=True, banner="220 mail.example.com ESMTP", success=1, tls=True) -> SMTPRunDetails:
    finding_rows = []
    if findings:
        finding_rows = [
            {
                "finding_id": "SMTP-CMD-001",
                "severity": "MEDIUM",
                "category": "smtp_command",
                "title": "VRFY habilitado",
                "port": 587,
                "security_mode": "starttls",
                "payload": {
                    "id": "SMTP-CMD-001",
                    "severity": "MEDIUM",
                    "category": "smtp_command",
                    "title": "VRFY habilitado",
                    "description": "Servidor respondeu ao comando VRFY.",
                    "evidence": "252 Cannot VRFY user",
                    "recommendation": "Desabilitar VRFY quando não necessário.",
                    "port": 587,
                    "security_mode": "starttls",
                },
            }
        ]
    return SMTPRunDetails(
        run={
            "id": 18,
            "hostname": "mail.example.com",
            "iterations": 5,
            "timeout": 3.0,
            "diagnostics_profile": "manual",
            "diagnostics_options_json": (
                '{"profile":"manual","test_noop":true,"test_help":true,'
                '"test_vrfy":true,"test_expn":false}'
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
                "success": success,
                "status": "SUCCESS" if success else "TLS_ERROR",
                "error_type": None if success else "TLS_ERROR",
                "error_message": None if success else "handshake failed",
                "tcp_connect_ms": 10.0,
                "banner_ms": 11.0,
                "ehlo_ms": 12.0,
                "starttls_ms": 13.0,
                "tls_handshake_ms": 14.0,
                "total_ms": 60.0,
                "banner": banner,
                "ehlo_hostname": "client.example",
                "capabilities_json": {"STARTTLS": []},
                "capabilities_before_tls_json": {"STARTTLS": [], "SIZE": ["1024"]},
                "capabilities_after_tls_json": {"AUTH": ["PLAIN", "LOGIN"]},
                "auth_before_tls_json": [],
                "auth_after_tls_json": ["PLAIN", "LOGIN"],
                "command_diagnostics_json": [
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
                "tls_json": {
                    "tls_version": "TLSv1.3",
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "cipher_bits": 256,
                    "certificate_subject": "mail.example.com",
                    "certificate_issuer": "Example CA",
                    "serial_number": "01",
                    "not_before": "2026-01-01T00:00:00",
                    "not_after": "2026-12-31T00:00:00",
                    "days_remaining": 145,
                    "subject_alt_names": ["mail.example.com"],
                    "hostname_valid": True,
                    "certificate_valid": True,
                }
                if tls
                else None,
                "created_at": "2026-08-08 18:15:33",
            }
        ],
        diagnostics=[],
        findings=finding_rows,
        commands=[],
    )


def test_serialize_run_details_is_canonical_and_preserves_timestamps() -> None:
    payload = serialize_run_details(_details(), exported_at=FIXED_EXPORT_TIME)

    assert payload["export"]["application"] == "SMTP Bench Pro"
    assert payload["export"]["application_version"] == __version__
    assert payload["export"]["format_version"] == 1
    assert payload["export"]["exported_at"] == "2026-08-08T21:00:00+00:00"
    assert payload["run"]["created_at"] == "2026-08-08 18:15:32"
    assert payload["run"]["created_at"] != payload["export"]["exported_at"]
    assert payload["diagnostics_profile"]["profile"] == "manual"
    assert payload["run"]["ports"] == [587]
    assert payload["command_diagnostics"][0]["status"] == "ENABLED"
    assert payload["security_findings"][0]["id"] == "SMTP-CMD-001"


def test_json_export_writes_utf8_file(tmp_path) -> None:
    service = HistoricalRunExportService()
    output = tmp_path / "relatório.json"

    result = service.export(_details(banner="220 mail.example.com ESMTP Ação"), output, "json")
    data = json.loads(output.read_text(encoding="utf-8"))

    assert result.path == output
    assert data["run"]["id"] == 18
    assert "Ação" in data["smtp"][0]["banner"]
    assert data["security_findings"][0]["recommendation"] == "Desabilitar VRFY quando não necessário."


def test_html_export_writes_standalone_escaped_report(tmp_path) -> None:
    service = HistoricalRunExportService()
    output = tmp_path / "report.html"

    service.export(_details(banner="220 <script>alert(1)</script>"), output, "html")
    html = output.read_text(encoding="utf-8")

    assert "<meta charset=\"utf-8\">" in html
    assert "Historical SMTP Diagnostic Report" in html
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in html
    assert "<script>alert(1)</script>" not in html
    assert "SMTP-CMD-001" in html
    assert "<script" not in html.lower()


def test_html_export_without_findings_does_not_claim_server_safe() -> None:
    html = render_html(serialize_run_details(_details(findings=False), exported_at=FIXED_EXPORT_TIME))

    assert "Nenhum achado de segurança foi registrado nesta execução." in html
    assert "Servidor seguro" not in html


def test_export_handles_legacy_missing_tls_and_partial_diagnostic() -> None:
    payload = serialize_run_details(_details(success=0, tls=False), exported_at=FIXED_EXPORT_TIME)
    html = render_html(payload)

    assert payload["run"]["status"] == "Falhou"
    assert payload["tls"][0]["tls_version"] is None
    assert "Não disponível nesta execução" in html


def test_json_and_html_share_canonical_payload_fundamentals(tmp_path) -> None:
    service = HistoricalRunExportService()
    details = _details()
    json_path = tmp_path / "run.json"
    html_path = tmp_path / "run.html"

    service.export(details, json_path, "json")
    service.export(details, html_path, "html")
    data = json.loads(json_path.read_text(encoding="utf-8"))
    html = html_path.read_text(encoding="utf-8")

    assert f"Run #{data['run']['id']}" in html
    assert data["run"]["hostname"] in html
    assert data["diagnostics_profile"]["profile"] in html
    assert str(len(data["security_findings"]))


