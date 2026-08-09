"""Standalone HTML exporter for persisted historical SMTP runs."""

from __future__ import annotations

from html import escape
from pathlib import Path
from typing import Any

UNAVAILABLE = "Não disponível nesta execução."


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


def _kv_table(rows: list[tuple[str, Any]]) -> str:
    body = "".join(f"<tr><th>{escape(label)}</th><td>{_esc(value)}</td></tr>" for label, value in rows)
    return f"<table class=\"kv\"><tbody>{body}</tbody></table>"


def _list(value: Any) -> str:
    if not isinstance(value, list) or not value:
        return UNAVAILABLE
    return ", ".join(str(item) for item in value)


def _dict_caps(value: Any) -> str:
    if not isinstance(value, dict) or not value:
        return UNAVAILABLE
    parts = []
    for key in sorted(value):
        params = value[key]
        if isinstance(params, list) and params:
            parts.append(f"{key} {' '.join(str(item) for item in params)}")
        else:
            parts.append(str(key))
    return ", ".join(parts) if parts else UNAVAILABLE


def _results_table(results: list[dict[str, Any]]) -> str:
    if not results:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for result in results:
        rows.append(
            "<tr>"
            + _cell(result.get("port"))
            + _cell(result.get("security_mode"))
            + _cell(result.get("status"))
            + _cell(result.get("success"))
            + _cell(result.get("total_ms"))
            + _cell(result.get("banner"))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Porta</th><th>Modo</th><th>Status</th><th>Sucesso</th>"
        "<th>Total ms</th><th>Banner</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _smtp_table(smtp: list[dict[str, Any]]) -> str:
    if not smtp:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for item in smtp:
        rows.append(
            "<tr>"
            + _cell(item.get("port"))
            + _cell(item.get("banner"))
            + _cell(_dict_caps(item.get("capabilities_before_tls")))
            + _cell(_dict_caps(item.get("capabilities_after_tls")))
            + _cell(_list(item.get("auth_before_tls")))
            + _cell(_list(item.get("auth_after_tls")))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Porta</th><th>Banner</th><th>EHLO pré-TLS</th>"
        "<th>EHLO pós-TLS</th><th>AUTH antes TLS</th><th>AUTH após TLS</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _tls_table(tls_items: list[dict[str, Any]]) -> str:
    if not tls_items:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for item in tls_items:
        rows.append(
            "<tr>"
            + _cell(item.get("port"))
            + _cell(item.get("tls_version"))
            + _cell(item.get("cipher"))
            + _cell(item.get("cipher_bits"))
            + _cell(item.get("certificate_subject"))
            + _cell(item.get("certificate_issuer"))
            + _cell(_list(item.get("subject_alt_names")))
            + _cell(item.get("not_after"))
            + _cell(item.get("days_remaining"))
            + _cell(item.get("hostname_valid"))
            + _cell(item.get("certificate_valid"))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Porta</th><th>TLS</th><th>Cipher</th><th>Bits</th>"
        "<th>Subject</th><th>Issuer</th><th>SAN</th><th>Expiration</th><th>Days</th>"
        "<th>Hostname</th><th>Certificate</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _commands_table(commands: list[dict[str, Any]]) -> str:
    if not commands:
        return f"<p>{escape(UNAVAILABLE)}</p>"
    rows = []
    for command in commands:
        rows.append(
            "<tr>"
            + _cell(command.get("port"))
            + _cell(command.get("command"))
            + _cell(command.get("executed"))
            + _cell(command.get("status"))
            + _cell(command.get("response_code"))
            + _cell(command.get("response_message"))
            + _cell(command.get("reason"))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Porta</th><th>Comando</th><th>Executado</th><th>Status</th>"
        "<th>Código</th><th>Resposta</th><th>Motivo</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _findings_table(findings: list[dict[str, Any]]) -> str:
    if not findings:
        return "<p>Nenhum achado de segurança foi registrado nesta execução.</p>"
    rows = []
    for finding in findings:
        severity = _esc(finding.get("severity"))
        rows.append(
            f"<tr><td><span class=\"sev sev-{severity.lower()}\">{severity}</span></td>"
            + _cell(finding.get("id"))
            + _cell(finding.get("category"))
            + _cell(finding.get("title"))
            + _cell(finding.get("port"))
            + _cell(finding.get("evidence"))
            + _cell(finding.get("recommendation"))
            + "</tr>"
        )
    return (
        "<table><thead><tr><th>Severity</th><th>ID</th><th>Categoria</th><th>Título</th>"
        "<th>Porta</th><th>Evidência</th><th>Recomendação</th></tr></thead><tbody>"
        + "".join(rows)
        + "</tbody></table>"
    )


def _mail_dns_section(mail_dns: dict[str, Any] | None) -> str:
    if not isinstance(mail_dns, dict) or not mail_dns:
        return _section("DNS de E-mail", "<p>DNS de E-mail não disponível para esta execução.</p>")

    summary = mail_dns.get("identity_summary", {}) if isinstance(mail_dns.get("identity_summary"), dict) else {}
    summary_html = _kv_table(
        [
            ("Domínio", mail_dns.get("domain")),
            ("Organizational Domain", summary.get("organizational_domain")),
            ("Contagem de MX", summary.get("mx_count")),
            ("Null MX", "Sim" if summary.get("has_null_mx") else "Não"),
            ("Política SPF", summary.get("spf_policy")),
            ("Política DMARC", summary.get("dmarc_policy")),
            ("FCRDNS Alinhado", f"{summary.get('fcrdns_aligned_ips', 0)}/{summary.get('fcrdns_total_ips', 0)} IPs"),
        ]
    )

    # Routing (MX Table)
    mx_data = mail_dns.get("routing", {}) if isinstance(mail_dns.get("routing"), dict) else {}
    mx_records = mx_data.get("records", []) if isinstance(mx_data.get("records"), list) else []
    mx_rows = []
    for r in mx_records:
        if isinstance(r, dict):
            addrs_v4 = ", ".join(a.get("ip", "") for a in r.get("addresses_v4", []) if isinstance(a, dict)) or "-"
            addrs_v6 = ", ".join(a.get("ip", "") for a in r.get("addresses_v6", []) if isinstance(a, dict)) or "-"
            mx_rows.append(
                "<tr>"
                + _cell(r.get("preference"))
                + _cell(r.get("exchange"))
                + _cell(addrs_v4)
                + _cell(addrs_v6)
                + _cell("Sim" if r.get("cname_detected") else "Não")
                + "</tr>"
            )
    mx_body = "".join(mx_rows) or '<tr><td colspan="5">Nenhum MX</td></tr>'
    mx_table = (
        "<table><thead><tr><th>Prioridade</th><th>Exchange</th><th>IPv4</th><th>IPv6</th><th>CNAME?</th></tr></thead>"
        f"<tbody>{mx_body}</tbody></table>"
    )

    # PTR Table
    ptr_data = mx_data.get("ptr", {}).get("results", []) if isinstance(mx_data.get("ptr"), dict) else []
    ptr_rows = []
    if isinstance(ptr_data, list):
        for p in ptr_data:
            if isinstance(p, dict):
                ptr_hosts = ", ".join(p.get("ptr_hostnames", [])) or "-"
                fwd_ips = ", ".join(p.get("forward_ips", [])) or "-"
                ptr_rows.append(
                    "<tr>"
                    + _cell(p.get("ip"))
                    + _cell(ptr_hosts)
                    + _cell(fwd_ips)
                    + _cell(p.get("status"))
                    + "</tr>"
                )
    ptr_body = "".join(ptr_rows) or '<tr><td colspan="4">Nenhum PTR</td></tr>'
    ptr_table = (
        "<table><thead><tr><th>IP</th><th>PTR Hostnames</th><th>Forward IPs</th><th>Status</th></tr></thead>"
        f"<tbody>{ptr_body}</tbody></table>"
    )

    # SPF Details & Terms Table
    spf_data = mail_dns.get("spf", {}) if isinstance(mail_dns.get("spf"), dict) else {}
    spf_terms = spf_data.get("terms", []) if isinstance(spf_data.get("terms"), list) else []
    spf_term_rows = []
    for t in spf_terms:
        if isinstance(t, dict):
            spf_term_rows.append(
                "<tr>"
                + _cell(t.get("qualifier"))
                + _cell(t.get("mechanism"))
                + _cell(t.get("value"))
                + _cell("Sim" if t.get("causes_dns_lookup") else "Não")
                + "</tr>"
            )
    spf_body = "".join(spf_term_rows) or '<tr><td colspan="4">Nenhum termo</td></tr>'
    spf_table = (
        "<table><thead><tr><th>Qualificador</th><th>Mecanismo</th><th>Valor</th><th>Lookup?</th></tr></thead>"
        f"<tbody>{spf_body}</tbody></table>"
    )
    spf_kv = _kv_table(
        [
            ("Registro SPF", spf_data.get("raw_record")),
            ("Status", spf_data.get("status")),
            (
                "DNS Lookups",
                f"{spf_data.get('dns_lookup_count', 0)} / 10 (Void: {spf_data.get('void_lookup_count', 0)})",
            ),
            ("Qualificador all", spf_data.get("all_qualifier")),
            ("Uso de ptr", "Sim (Depreciado)" if spf_data.get("uses_ptr_mechanism") else "Não"),
            ("Erro de validação", spf_data.get("validation_error")),
        ]
    )

    # DMARC Details
    dmarc_data = mail_dns.get("dmarc", {}) if isinstance(mail_dns.get("dmarc"), dict) else {}
    dmarc_kv = _kv_table(
        [
            ("Registro DMARC", dmarc_data.get("raw_record")),
            ("Status", dmarc_data.get("status")),
            ("Política p", dmarc_data.get("policy")),
            ("Subdomínio sp", dmarc_data.get("subdomain_policy")),
            ("Percentual pct", f"{dmarc_data.get('pct', 100)}%"),
            ("Modo ADKIM", dmarc_data.get("adkim")),
            ("Modo ASPF", dmarc_data.get("aspf")),
            ("Organizational Domain", dmarc_data.get("organizational_domain")),
            ("Relatórios RUA", _list(dmarc_data.get("rua"))),
            ("Relatórios RUF", _list(dmarc_data.get("ruf"))),
            ("Erros de validação", _list(dmarc_data.get("validation_errors"))),
        ]
    )

    # Findings Table
    findings = mail_dns.get("findings", []) if isinstance(mail_dns.get("findings"), list) else []
    finding_rows = []
    for f in findings:
        if isinstance(f, dict):
            severity = _esc(f.get("severity"))
            sev_class = f'class="sev sev-{severity.lower()}"'
            finding_rows.append(
                f"<tr><td><span {sev_class}>{severity}</span></td>"
                + _cell(f.get("id"))
                + _cell(f.get("category"))
                + _cell(f.get("title"))
                + _cell(f.get("evidence"))
                + _cell(f.get("recommendation"))
                + "</tr>"
            )
    findings_body = "".join(finding_rows) or '<tr><td colspan="6">Nenhum achado Mail DNS</td></tr>'
    findings_table = (
        "<table><thead><tr><th>Severity</th><th>ID</th><th>Categoria</th><th>Título</th>"
        "<th>Evidência</th><th>Recomendação</th></tr></thead>"
        f"<tbody>{findings_body}</tbody></table>"
    )

    body = "".join(
        [
            "<h3>Resumo de Identidade</h3>",
            summary_html,
            "<h3>Servidores MX</h3>",
            mx_table,
            "<h3>Validação PTR / FCRDNS</h3>",
            ptr_table,
            "<h3>Diagnóstico SPF</h3>",
            spf_kv,
            spf_table,
            "<h3>Diagnóstico DMARC</h3>",
            dmarc_kv,
            "<h3>Achados de Segurança Mail DNS</h3>",
            findings_table,
        ]
    )
    return _section("DNS de E-mail", body)


def render_html(payload: dict[str, Any]) -> str:
    run = payload.get("run", {}) if isinstance(payload.get("run"), dict) else {}
    profile = payload.get("diagnostics_profile", {}) if isinstance(payload.get("diagnostics_profile"), dict) else {}
    export = payload.get("export", {}) if isinstance(payload.get("export"), dict) else {}
    partial_notice = ""
    if run.get("status") == "Parcial":
        partial_notice = (
            "<p class=\"notice\"><strong>Diagnóstico parcial.</strong> "
            "Algumas verificações não puderam ser concluídas.</p>"
        )
    body = "".join(
        [
            _section(
                "Resumo",
                partial_notice
                + _kv_table(
                    [
                        ("Run", run.get("id")),
                        ("Timestamp da execução", run.get("created_at")),
                        ("Target", run.get("hostname")),
                        ("Portas", _list(run.get("ports"))),
                        ("Perfil", profile.get("profile")),
                        ("Status", run.get("status")),
                        ("Exportado em", export.get("exported_at")),
                    ]
                ),
            ),
            _section("Resultados", _results_table(payload.get("results", []))),
            _section("SMTP", _smtp_table(payload.get("smtp", []))),
            _section("TLS", _tls_table(payload.get("tls", []))),
            _section("Command Diagnostics", _commands_table(payload.get("command_diagnostics", []))),
            _section("Security Findings", _findings_table(payload.get("security_findings", []))),
            _mail_dns_section(payload.get("mail_dns")),
        ]
    )
    title = f"SMTP Bench Pro - Historical SMTP Diagnostic Report - Run #{_esc(run.get('id'))}"
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
h1, h2 {{ margin: 0 0 12px; }}
h1 {{ font-size: 24px; }}
h2 {{ font-size: 18px; color: #101820; }}
table {{ width: 100%; border-collapse: collapse; font-size: 13px; }}
th, td {{ border: 1px solid #d8dee6; padding: 8px; text-align: left; vertical-align: top; }}
th {{ background: #eef2f6; }}
.kv th {{ width: 220px; }}
.notice {{ border-left: 4px solid #b45309; background: #fff7ed; padding: 10px; }}
.sev {{ display: inline-block; border-radius: 4px; padding: 2px 6px; font-weight: 700; }}
.sev-critical, .sev-high {{ background: #fee2e2; color: #991b1b; }}
.sev-medium {{ background: #fef3c7; color: #92400e; }}
.sev-low {{ background: #dbeafe; color: #1e40af; }}
.sev-info {{ background: #e5e7eb; color: #374151; }}
footer {{ color: #52606d; font-size: 12px; padding: 0 32px 24px; }}
@media print {{ body {{ background: #fff; }} section {{ break-inside: avoid; border-color: #bbb; }} }}
</style>
</head>
<body>
<header>
<h1>SMTP Bench Pro</h1>
<p>Historical SMTP Diagnostic Report</p>
</header>
<main>{body}</main>
<footer>Generated by SMTP Bench Pro. Export format version {_esc(export.get('format_version'))}.</footer>
</body>
</html>
"""


def write_html(path: Path, payload: dict[str, Any]) -> None:
    path.write_text(render_html(payload), encoding="utf-8")

