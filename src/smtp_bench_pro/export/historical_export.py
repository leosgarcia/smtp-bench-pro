"""Canonical historical run serialization and export service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import json
from pathlib import Path
import re
from typing import Any, Literal

from smtp_bench_pro.domain.mail_dns import MailDNSRunSnapshot
from smtp_bench_pro.export.html_exporter import write_html
from smtp_bench_pro.export.io import atomic_write, safe_filename_part
from smtp_bench_pro.export.json_exporter import write_json
from smtp_bench_pro.persistence.mail_dns_serializer import (
    serialize_dmarc_result,
    serialize_identity_summary,
    serialize_mail_dns_findings,
    serialize_routing_result,
    serialize_spf_result,
)
from smtp_bench_pro.persistence.repository import SMTPRunDetails
from smtp_bench_pro.version import __version__

EXPORT_FORMAT_VERSION = 1
APPLICATION_NAME = "SMTP Bench Pro"
ExportFormat = Literal["json", "html"]


@dataclass(frozen=True)
class ExportResult:
    path: Path
    format: ExportFormat
    run_id: int | None


def _json_value(value: Any) -> Any:
    if value is None or isinstance(value, (str, int, float, bool)):
        return value
    if isinstance(value, datetime):
        return value.isoformat()
    if isinstance(value, Path):
        return str(value)
    if isinstance(value, dict):
        return {str(key): _json_value(value[key]) for key in sorted(value)}
    if isinstance(value, (list, tuple)):
        return [_json_value(item) for item in value]
    if isinstance(value, set):
        return [_json_value(item) for item in sorted(value, key=str)]
    if hasattr(value, "value"):
        return _json_value(value.value)
    return str(value)


def _payload(row: dict[str, Any]) -> dict[str, Any]:
    payload = row.get("payload")
    return payload if isinstance(payload, dict) else {}


def _ports(results: list[dict[str, Any]]) -> list[int]:
    ports = []
    for result in results:
        try:
            ports.append(int(result.get("port")))
        except (TypeError, ValueError):
            continue
    return sorted(set(ports))


def _status(results: list[dict[str, Any]]) -> str:
    if not results:
        return "Falhou"
    successes = sum(1 for result in results if int(result.get("success") or 0) == 1)
    if successes == len(results):
        return "Concluído"
    if successes == 0:
        return "Falhou"
    return "Parcial"


def _result_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "id": result.get("id"),
        "hostname": result.get("hostname"),
        "resolved_ip": result.get("resolved_ip"),
        "port": result.get("port"),
        "security_mode": result.get("security_mode"),
        "success": bool(result.get("success")) if result.get("success") is not None else None,
        "status": result.get("status"),
        "error_type": result.get("error_type"),
        "error_message": result.get("error_message"),
        "timings_ms": {
            "tcp_connect": result.get("tcp_connect_ms"),
            "banner": result.get("banner_ms"),
            "ehlo": result.get("ehlo_ms"),
            "starttls": result.get("starttls_ms"),
            "tls_handshake": result.get("tls_handshake_ms"),
            "total": result.get("total_ms"),
        },
        "created_at": result.get("created_at"),
    }


def _smtp_payload(result: dict[str, Any]) -> dict[str, Any]:
    return {
        "port": result.get("port"),
        "security_mode": result.get("security_mode"),
        "banner": result.get("banner"),
        "ehlo_hostname": result.get("ehlo_hostname"),
        "capabilities": result.get("capabilities_json") or {},
        "capabilities_before_tls": result.get("capabilities_before_tls_json") or {},
        "capabilities_after_tls": result.get("capabilities_after_tls_json") or {},
        "auth_before_tls": result.get("auth_before_tls_json") or [],
        "auth_after_tls": result.get("auth_after_tls_json") or [],
    }


def _tls_payload(result: dict[str, Any]) -> dict[str, Any]:
    tls = result.get("tls_json")
    if not isinstance(tls, dict) or not tls:
        return {
            "port": result.get("port"),
            "security_mode": result.get("security_mode"),
            "tls_version": None,
            "cipher": None,
            "cipher_bits": None,
            "certificate_subject": None,
            "certificate_issuer": None,
            "serial_number": None,
            "not_before": None,
            "not_after": None,
            "days_remaining": None,
            "subject_alt_names": [],
            "hostname_valid": None,
            "certificate_valid": None,
        }
    return {
        "port": result.get("port"),
        "security_mode": result.get("security_mode"),
        "tls_version": tls.get("tls_version"),
        "cipher": tls.get("cipher"),
        "cipher_bits": tls.get("cipher_bits"),
        "certificate_subject": tls.get("certificate_subject"),
        "certificate_issuer": tls.get("certificate_issuer"),
        "serial_number": tls.get("serial_number"),
        "not_before": tls.get("not_before"),
        "not_after": tls.get("not_after"),
        "days_remaining": tls.get("days_remaining"),
        "subject_alt_names": tls.get("subject_alt_names") or [],
        "hostname_valid": tls.get("hostname_valid"),
        "certificate_valid": tls.get("certificate_valid"),
    }


def _command_payload(result: dict[str, Any]) -> list[dict[str, Any]]:
    raw = result.get("command_diagnostics_json")
    if not isinstance(raw, list):
        return []
    commands = []
    for item in raw:
        if not isinstance(item, dict):
            continue
        commands.append(
            {
                "port": result.get("port"),
                "security_mode": result.get("security_mode"),
                "command": item.get("command"),
                "executed": item.get("executed"),
                "status": item.get("status"),
                "supported": item.get("supported"),
                "response_code": item.get("response_code"),
                "response_message": item.get("response_message"),
                "reason": item.get("reason"),
            }
        )
    return commands


def _finding_payload(row: dict[str, Any]) -> dict[str, Any]:
    payload = _payload(row)
    return {
        "id": payload.get("id") or row.get("finding_id"),
        "severity": payload.get("severity") or row.get("severity"),
        "category": payload.get("category") or row.get("category"),
        "title": payload.get("title") or row.get("title"),
        "description": payload.get("description"),
        "evidence": payload.get("evidence"),
        "recommendation": payload.get("recommendation"),
        "port": payload.get("port") or row.get("port"),
        "security_mode": payload.get("security_mode") or row.get("security_mode"),
    }


def _diagnostics_profile(run: dict[str, Any]) -> dict[str, Any]:
    options = run.get("diagnostics_options_json")
    if isinstance(options, str) and options:
        try:
            options = json.loads(options)
        except json.JSONDecodeError:
            options = {}
    if not isinstance(options, dict):
        options = {}
    profile = options.get("profile") or run.get("diagnostics_profile")
    return {
        "profile": profile,
        "test_noop": options.get("test_noop"),
        "test_help": options.get("test_help"),
        "test_vrfy": options.get("test_vrfy"),
        "test_expn": options.get("test_expn"),
    }


def serialize_mail_dns_snapshot_to_dict(snapshot: MailDNSRunSnapshot | None) -> dict[str, Any] | None:
    if snapshot is None:
        return None

    mx_json, ptr_json = serialize_routing_result(snapshot.routing)
    spf_json = serialize_spf_result(snapshot.spf)
    dmarc_json = serialize_dmarc_result(snapshot.dmarc)
    summary_json = serialize_identity_summary(snapshot.identity_summary)
    findings_json = serialize_mail_dns_findings(snapshot.findings)

    mx_dict = json.loads(mx_json)
    ptr_dict = json.loads(ptr_json)
    mx_dict["ptr"] = ptr_dict

    return {
        "domain": snapshot.domain,
        "created_at": snapshot.created_at,
        "routing": mx_dict,
        "spf": json.loads(spf_json),
        "dmarc": json.loads(dmarc_json),
        "identity_summary": json.loads(summary_json),
        "findings": json.loads(findings_json),
    }


def serialize_run_details(
    run_details: SMTPRunDetails,
    *,
    exported_at: datetime | None = None,
    mail_dns_snapshot: MailDNSRunSnapshot | None = None,
) -> dict[str, Any]:
    """Build a deterministic external representation from persisted SMTPRunDetails only."""
    exported_at = exported_at or datetime.now(UTC)
    if exported_at.tzinfo is None:
        exported_at = exported_at.replace(tzinfo=UTC)
    run = run_details.run
    results = run_details.results
    payload = {
        "export": {
            "application": APPLICATION_NAME,
            "application_version": __version__,
            "format_version": EXPORT_FORMAT_VERSION,
            "exported_at": exported_at.isoformat(),
        },
        "run": {
            "id": run.get("id"),
            "created_at": run.get("created_at"),
            "hostname": run.get("hostname"),
            "ports": _ports(results),
            "iterations": run.get("iterations"),
            "timeout": run.get("timeout"),
            "status": _status(results),
        },
        "diagnostics_profile": _diagnostics_profile(run),
        "results": [_result_payload(result) for result in results],
        "smtp": [_smtp_payload(result) for result in results],
        "tls": [_tls_payload(result) for result in results],
        "command_diagnostics": [command for result in results for command in _command_payload(result)],
        "security_findings": [_finding_payload(row) for row in run_details.findings],
        "mail_dns": serialize_mail_dns_snapshot_to_dict(mail_dns_snapshot),
    }
    return _json_value(payload)


class HistoricalRunExportService:
    """Exports a historical SMTP run without re-querying, reprobe, or rule evaluation."""

    def export(
        self,
        run_details: SMTPRunDetails,
        destination: str | Path,
        export_format: ExportFormat,
        mail_dns_snapshot: MailDNSRunSnapshot | None = None,
    ) -> ExportResult:
        path = Path(destination)
        if export_format not in {"json", "html"}:
            raise ValueError(f"Unsupported export format: {export_format}")
        if path.suffix.lower() != f".{export_format}":
            path = path.with_suffix(f".{export_format}")
        if not path.parent.exists():
            raise FileNotFoundError(str(path.parent))
        payload = serialize_run_details(run_details, mail_dns_snapshot=mail_dns_snapshot)
        writer = write_json if export_format == "json" else write_html
        atomic_write(path, payload, writer)
        run_id = run_details.run.get("id")
        return ExportResult(path=path, format=export_format, run_id=int(run_id) if run_id is not None else None)

    def suggested_filename(self, run_details: SMTPRunDetails, export_format: ExportFormat) -> str:
        run = run_details.run
        run_id = run.get("id") or "unknown"
        created_at = re.sub(r"\D", "", str(run.get("created_at") or ""))[:14] or "unknown-date"
        hostname = safe_filename_part(str(run.get("hostname") or "smtp"))
        return f"smtp-bench-pro-run-{run_id}-{hostname}-{created_at}.{export_format}"

