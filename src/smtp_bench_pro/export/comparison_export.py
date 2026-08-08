"""Canonical historical comparison serialization and export service."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, Literal

from smtp_bench_pro.comparison.models import RunComparison
from smtp_bench_pro.export.comparison_html_exporter import write_comparison_html
from smtp_bench_pro.export.historical_export import APPLICATION_NAME, _json_value
from smtp_bench_pro.export.io import atomic_write, safe_filename_part
from smtp_bench_pro.export.json_exporter import write_json
from smtp_bench_pro.version import __version__

COMPARISON_EXPORT_FORMAT_VERSION = 1
COMPARISON_EXPORT_TYPE = "historical_comparison"
ComparisonExportFormat = Literal["json", "html"]


@dataclass(frozen=True)
class ComparisonExportResult:
    path: Path
    format: ComparisonExportFormat
    baseline_run_id: int | None
    compared_run_id: int | None


def _export_time(exported_at: datetime | None) -> datetime:
    timestamp = exported_at or datetime.now(UTC)
    if timestamp.tzinfo is None:
        timestamp = timestamp.replace(tzinfo=UTC)
    return timestamp


def _identity_payload(identity) -> dict[str, Any]:
    return {
        "run_id": identity.run_id,
        "hostname": identity.hostname,
        "created_at": identity.created_at,
        "profile": identity.profile,
        "status": identity.status,
    }


def _field_payload(change) -> dict[str, Any]:
    return {
        "name": change.name,
        "baseline": change.baseline,
        "candidate": change.compared,
        "status": change.status.value,
        "note": change.note,
    }


def _set_payload(change) -> dict[str, Any]:
    return {
        "name": change.name,
        "added": change.added,
        "removed": change.removed,
        "maintained": change.maintained,
        "changed_parameters": [_field_payload(parameter) for parameter in change.parameter_changes],
        "note": change.note,
    }


def _finding_payload(change) -> dict[str, Any]:
    return {
        "finding_id": change.finding_id,
        "lifecycle": change.lifecycle.value,
        "baseline": change.baseline,
        "candidate": change.compared,
    }


def _finding_bucket(comparison: RunComparison, lifecycle: str) -> list[dict[str, Any]]:
    return [_finding_payload(change) for change in comparison.finding_changes if change.lifecycle.value == lifecycle]


def serialize_comparison(
    comparison: RunComparison,
    *,
    exported_at: datetime | None = None,
) -> dict[str, Any]:
    """Build a deterministic external representation from an already computed RunComparison."""
    timestamp = _export_time(exported_at)
    payload = {
        "export": {
            "application": APPLICATION_NAME,
            "application_version": __version__,
            "export_type": COMPARISON_EXPORT_TYPE,
            "format_version": COMPARISON_EXPORT_FORMAT_VERSION,
            "exported_at": timestamp.isoformat(),
        },
        "comparison": {
            "baseline": _identity_payload(comparison.baseline),
            "candidate": _identity_payload(comparison.compared),
            "warnings": comparison.warnings,
            "summary": comparison.summary,
        },
        "metadata_changes": [_field_payload(change) for change in comparison.metadata_changes],
        "performance": [
            {
                "metric": change.metric,
                "baseline": change.baseline_ms,
                "candidate": change.compared_ms,
                "absolute_delta": change.delta_ms,
                "percentage_delta": change.delta_percent,
                "trend": change.trend.value,
                "note": change.note,
            }
            for change in comparison.performance_changes
        ],
        "smtp": {
            "fields": [_field_payload(change) for change in comparison.smtp_changes],
            "capabilities": {
                "before_tls": next(
                    (
                        _set_payload(change)
                        for change in comparison.capability_changes
                        if change.name == "EHLO before TLS"
                    ),
                    None,
                ),
                "after_tls": next(
                    (
                        _set_payload(change)
                        for change in comparison.capability_changes
                        if change.name == "EHLO after TLS"
                    ),
                    None,
                ),
            },
            "auth": {
                "before_tls": next(
                    (_set_payload(change) for change in comparison.auth_changes if change.name == "AUTH before TLS"),
                    None,
                ),
                "after_tls": next(
                    (_set_payload(change) for change in comparison.auth_changes if change.name == "AUTH after TLS"),
                    None,
                ),
            },
        },
        "tls": [_field_payload(change) for change in comparison.tls_changes],
        "commands": [
            {
                "command": change.command,
                "baseline": change.baseline_status,
                "candidate": change.compared_status,
                "comparability": change.status.value,
                "reason": change.note,
            }
            for change in comparison.command_changes
        ],
        "security": {
            "summary": comparison.security_summary,
            "new_findings": _finding_bucket(comparison, "NEW"),
            "resolved_findings": _finding_bucket(comparison, "RESOLVED"),
            "persistent_findings": _finding_bucket(comparison, "PERSISTENT"),
            "changed_findings": _finding_bucket(comparison, "CHANGED"),
        },
    }
    return _json_value(payload)


class ComparisonExportService:
    """Exports an already computed historical comparison without recomputing it."""

    def export(
        self,
        comparison: RunComparison,
        destination: str | Path,
        export_format: ComparisonExportFormat,
    ) -> ComparisonExportResult:
        path = Path(destination)
        if export_format not in {"json", "html"}:
            raise ValueError(f"Unsupported export format: {export_format}")
        if path.suffix.lower() != f".{export_format}":
            path = path.with_suffix(f".{export_format}")
        if not path.parent.exists():
            raise FileNotFoundError(str(path.parent))
        payload = serialize_comparison(comparison)
        writer = write_json if export_format == "json" else write_comparison_html
        atomic_write(path, payload, writer)
        return ComparisonExportResult(
            path=path,
            format=export_format,
            baseline_run_id=comparison.baseline.run_id,
            compared_run_id=comparison.compared.run_id,
        )

    def suggested_filename(self, comparison: RunComparison, export_format: ComparisonExportFormat) -> str:
        baseline = comparison.baseline.run_id or "unknown"
        compared = comparison.compared.run_id or "unknown"
        timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
        host = safe_filename_part(comparison.compared.hostname or comparison.baseline.hostname or "smtp")
        return f"smtp-bench-pro-compare-run-{baseline}-vs-{compared}-{host}-{timestamp}.{export_format}"


