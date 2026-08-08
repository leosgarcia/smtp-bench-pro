"""Standalone HTML exporter for persisted historical SMTP comparisons."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

UNAVAILABLE = "Não disponível"


def _text(value: Any) -> str:
    if value is None or value == "":
        return UNAVAILABLE
    return str(value)


def _esc(value: Any) -> str:
    return escape(_text(value), quote=True)


def _cell(value: Any) -> str:
    return f"<td>{_esc(value)}</td>"


def _section(title: str, body: str) -> str:
    return f"<section><h2>{escape(title)}</h2>{body}</section>"


def _list(items: Any, empty: str = "Nenhum item registrado.") -> str:
    if not isinstance(items, list) or not items:
        return f"<p>{escape(empty)}</p>"
    return "<ul>" + "".join(f"<li>{_esc(item)}</li>" for item in items) + "</ul>"


def _identity_card(title: str, identity: dict[str, Any]) -> str:
    rows = [
        ("Run", identity.get("run_id")),
        ("Servidor", identity.get("hostname")),
        ("Data da execução", identity.get("created_at")),
        ("Perfil", identity.get("profile")),
        ("Status", identity.get("status")),
    ]
    body = "".join(f"<tr><th>{escape(label)}</th><td>{_esc(value)}</td></tr>" for label, value in rows)
    return f"<div class=\"identity\"><h3>{escape(title)}</h3><table class=\"kv\"><tbody>{body}</tbody></table></div>"


def _change_table(changes: list[dict[str, Any]], title: str = "Campo") -> str:
    if not changes:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for change in changes:
        rows.append(
            "<tr>"
            + _cell(change.get("name"))
            + _cell(change.get("baseline"))
            + _cell(change.get("candidate"))
            + _cell(change.get("status"))
            + _cell(change.get("note"))
            + "</tr>"
        )
    return (
        f"<table><thead><tr><th>{escape(title)}</th><th>Execução Base</th>"
        "<th>Execução Comparada</th><th>Status</th><th>Observação</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _performance_table(items: list[dict[str, Any]]) -> str:
    if not items:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for item in items:
        rows.append(
            f"<tr class=\"trend-{_esc(item.get('trend')).lower()}\">"
            + _cell(item.get("metric"))
            + _cell(_ms(item.get("baseline")))
            + _cell(_ms(item.get("candidate")))
            + _cell(_delta_ms(item.get("absolute_delta")))
            + _cell(_percent(item.get("percentage_delta")))
            + _cell(_trend_label(item.get("trend")))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Métrica</th><th>Base</th><th>Comparada</th><th>Delta</th>"
        "<th>Variação</th><th>Resultado</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _set_table(change: dict[str, Any] | None) -> str:
    if not isinstance(change, dict):
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = [
        ("Adicionadas", change.get("added")),
        ("Removidas", change.get("removed")),
        ("Mantidas", change.get("maintained")),
    ]
    body = "".join(f"<tr><th>{escape(label)}</th><td>{_esc(_join(value))}</td></tr>" for label, value in rows)
    parameter_changes = change.get("changed_parameters")
    if isinstance(parameter_changes, list) and parameter_changes:
        body += f"<tr><th>Parâmetros alterados</th><td>{_esc(_parameter_text(parameter_changes))}</td></tr>"
    return f"<table class=\"kv\"><tbody>{body}</tbody></table>"


def _commands_table(commands: list[dict[str, Any]]) -> str:
    if not commands:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for command in commands:
        rows.append(
            "<tr>"
            + _cell(command.get("command"))
            + _cell(command.get("baseline"))
            + _cell(command.get("candidate"))
            + _cell(command.get("comparability"))
            + _cell(command.get("reason"))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Comando</th><th>Execução Base</th><th>Execução Comparada</th>"
        "<th>Comparabilidade</th><th>Motivo</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _security_summary_table(summary: dict[str, Any]) -> str:
    baseline = summary.get("baseline", {}) if isinstance(summary.get("baseline"), dict) else {}
    candidate = summary.get("compared", {}) if isinstance(summary.get("compared"), dict) else {}
    delta = summary.get("delta", {}) if isinstance(summary.get("delta"), dict) else {}
    rows = []
    for severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        rows.append(
            "<tr>"
            + _cell(severity)
            + _cell(baseline.get(severity))
            + _cell(candidate.get(severity))
            + _cell(_signed(delta.get(severity)))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Severidade</th><th>Base</th><th>Comparada</th><th>Delta</th>"
        "</tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _finding_sections(security: dict[str, Any]) -> str:
    sections = []
    for key, label in (
        ("new_findings", "Novos"),
        ("resolved_findings", "Resolvidos"),
        ("persistent_findings", "Persistentes"),
        ("changed_findings", "Alterados"),
    ):
        findings = security.get(key)
        sections.append(f"<h3>{escape(label)}</h3>{_findings_table(findings if isinstance(findings, list) else [])}")
    return "".join(sections)


def _findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p>Nenhum finding nesta categoria.</p>"
    rows = []
    for finding in findings:
        baseline = finding.get("baseline") if isinstance(finding.get("baseline"), dict) else None
        candidate = finding.get("candidate") if isinstance(finding.get("candidate"), dict) else None
        rows.append(
            "<tr>"
            + _cell(finding.get("finding_id"))
            + _cell(finding.get("lifecycle"))
            + _cell(_finding_text(baseline))
            + _cell(_finding_text(candidate))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>ID</th><th>Ciclo</th><th>Execução Base</th>"
        "<th>Execução Comparada</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _finding_text(finding: dict[str, Any] | None) -> str:
    if not finding:
        return UNAVAILABLE
    return " | ".join(
        _text(finding.get(field))
        for field in ("severity", "title", "evidence", "recommendation")
        if finding.get(field) is not None
    )


def _join(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return UNAVAILABLE
    return ", ".join(str(item) for item in value)


def _parameter_text(changes: list[dict[str, Any]]) -> str:
    parts = []
    for change in changes:
        parts.append(f"{change.get('name')}: {change.get('baseline')} -> {change.get('candidate')}")
    return "; ".join(parts) if parts else UNAVAILABLE


def _ms(value: Any) -> str:
    return UNAVAILABLE if value is None else f"{float(value):.2f} ms"


def _delta_ms(value: Any) -> str:
    return "N/A" if value is None else f"{float(value):+.2f} ms"


def _percent(value: Any) -> str:
    return "N/A" if value is None else f"{float(value):+.1f}%"


def _signed(value: Any) -> str:
    return UNAVAILABLE if value is None else f"{int(value):+d}"


def _trend_label(value: Any) -> str:
    labels = {
        "IMPROVED": "Melhorou",
        "REGRESSED": "Piorou",
        "UNCHANGED": "Estável",
        "UNKNOWN": "Desconhecido",
    }
    return labels.get(str(value), _text(value))


def render_comparison_html(payload: dict[str, Any]) -> str:
    export = payload.get("export", {}) if isinstance(payload.get("export"), dict) else {}
    comparison = payload.get("comparison", {}) if isinstance(payload.get("comparison"), dict) else {}
    baseline = comparison.get("baseline", {}) if isinstance(comparison.get("baseline"), dict) else {}
    candidate = comparison.get("candidate", {}) if isinstance(comparison.get("candidate"), dict) else {}
    smtp = payload.get("smtp", {}) if isinstance(payload.get("smtp"), dict) else {}
    capabilities = smtp.get("capabilities", {}) if isinstance(smtp.get("capabilities"), dict) else {}
    auth = smtp.get("auth", {}) if isinstance(smtp.get("auth"), dict) else {}
    security = payload.get("security", {}) if isinstance(payload.get("security"), dict) else {}
    warnings = comparison.get("warnings") if isinstance(comparison.get("warnings"), list) else []
    summary = comparison.get("summary") if isinstance(comparison.get("summary"), list) else []
    body = "".join(
        [
            _section(
                "Execuções Comparadas",
                "<div class=\"identities\">"
                + _identity_card("Execução Base", baseline)
                + _identity_card("Execução Comparada", candidate)
                + "</div>",
            ),
            _section("Avisos da Comparação", _list(warnings, "Nenhum aviso registrado.")),
            _section("Resumo das Mudanças", _list(summary, "Nenhuma mudança significativa identificada.")),
            _section("Metadata", _change_table(payload.get("metadata_changes", []))),
            _section("Performance", _performance_table(payload.get("performance", []))),
            _section(
                "SMTP",
                "<h3>Campos SMTP</h3>"
                + _change_table(smtp.get("fields", []))
                + "<h3>Capabilities EHLO pré-TLS</h3>"
                + _set_table(capabilities.get("before_tls"))
                + "<h3>Capabilities EHLO pós-TLS</h3>"
                + _set_table(capabilities.get("after_tls"))
                + "<h3>AUTH antes TLS</h3>"
                + _set_table(auth.get("before_tls"))
                + "<h3>AUTH após TLS</h3>"
                + _set_table(auth.get("after_tls")),
            ),
            _section("TLS", _change_table(payload.get("tls", []))),
            _section("Command Diagnostics", _commands_table(payload.get("commands", []))),
            _section(
                "Security Findings",
                _security_summary_table(security.get("summary", {})) + _finding_sections(security),
            ),
        ]
    )
    title = "SMTP Bench Pro - Historical Comparison Report"
    return f"""<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
:root {{ color-scheme: light; font-family: Segoe UI, Arial, sans-serif; }}
body {{ margin: 0; background: #f4f6f8; color: #18202a; }}
header {{ background: #101820; color: #fff; padding: 24px 32px; }}
main {{ max-width: 1180px; margin: 0 auto; padding: 24px; }}
section {{ background: #fff; border: 1px solid #d8dee6; border-radius: 6px; margin-bottom: 18px; padding: 18px; }}
h1, h2, h3 {{ margin: 0 0 12px; }}
h1 {{ font-size: 24px; }}
h2 {{ font-size: 18px; color: #101820; }}
h3 {{ font-size: 15px; color: #243447; margin-top: 14px; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; margin-bottom: 12px; }}
th, td {{ border: 1px solid #d8dee6; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #eef2f6; }}
.kv th {{ width: 180px; }}
.identities {{ display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 16px; }}
.identity {{ min-width: 0; }}
.trend-improved td {{ background: #ecfdf5; }}
.trend-regressed td {{ background: #fef2f2; }}
.trend-unchanged td {{ background: #f8fafc; }}
footer {{ color: #52606d; font-size: 12px; padding: 0 32px 24px; }}
@media print {{
body {{ background: #fff; }}
section {{ break-inside: avoid; border-color: #bbb; }}
.identities {{ grid-template-columns: 1fr 1fr; }}
}}
@media (max-width: 760px) {{ .identities {{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<header>
<h1>SMTP Bench Pro</h1>
<p>Historical Comparison Report</p>
</header>
<main>{body}</main>
<footer>Exportado em {_esc(export.get('exported_at'))}. Versão do formato {_esc(export.get('format_version'))}.</footer>
</body>
</html>
"""


def write_comparison_html(path: Path, payload: dict[str, object]) -> None:
    path.write_text(render_comparison_html(payload), encoding="utf-8")


