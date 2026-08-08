"""Repository for SMTP benchmark and diagnostic runs."""

from __future__ import annotations

from dataclasses import asdict, dataclass, is_dataclass
from enum import Enum
import json

from smtp_bench_pro.application.diagnostics import SMTPDiagnosticsService
from smtp_bench_pro.domain.diagnostic_options import DiagnosticsOptions
from smtp_bench_pro.domain.results import BenchmarkRunResult, SMTPProbeResult
from smtp_bench_pro.persistence.database import SMTPDatabase


def _json_default(value):
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return asdict(value)
    if hasattr(value, "isoformat"):
        return value.isoformat()
    return str(value)


def _to_json(value) -> str:
    return json.dumps(value, default=_json_default, sort_keys=True)


def _from_json(value: object, default: object) -> object:
    if not value:
        return default
    if not isinstance(value, str):
        return value
    try:
        return json.loads(value)
    except json.JSONDecodeError:
        return default


@dataclass(frozen=True)
class SMTPRunDetails:
    """Immutable persisted view of a benchmark run."""

    run: dict[str, object]
    results: list[dict[str, object]]
    diagnostics: list[dict[str, object]]
    findings: list[dict[str, object]]
    commands: list[dict[str, object]]


class SMTPBenchmarkRepository:
    """Persists benchmark runs without exposing SQLite to the UI or Core."""

    def __init__(self, database: SMTPDatabase | None = None):
        self.database = database or SMTPDatabase()
        self.database.initialize()
        self.diagnostics_service = SMTPDiagnosticsService()

    def save_run(
        self,
        hostname: str,
        iterations: int,
        timeout: float,
        results: list[SMTPProbeResult],
        diagnostics_options: DiagnosticsOptions | None = None,
    ) -> int:
        options = diagnostics_options or (results[0].diagnostics_options if results else DiagnosticsOptions())
        diagnostics, findings = self.diagnostics_service.analyze_results(results)
        with self.database.connect() as connection:
            cursor = connection.execute(
                """
                INSERT INTO benchmark_runs (
                    hostname, iterations, timeout, diagnostics_profile, diagnostics_options_json
                ) VALUES (?, ?, ?, ?, ?)
                """,
                (hostname, iterations, timeout, options.profile.value, _to_json(options.as_dict())),
            )
            run_id = int(cursor.lastrowid)
            for result in results:
                self._insert_result(connection, run_id, result)
            for report in diagnostics:
                connection.execute(
                    """
                    INSERT INTO smtp_diagnostics (run_id, hostname, port, security_mode, payload_json)
                    VALUES (?, ?, ?, ?, ?)
                    """,
                    (run_id, report.hostname, report.port, report.security_mode.value, _to_json(report)),
                )
            for finding in findings:
                connection.execute(
                    """
                    INSERT INTO security_findings (
                        run_id, finding_id, severity, category, title, port, security_mode, payload_json
                    ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        run_id,
                        finding.id,
                        finding.severity.value,
                        finding.category,
                        finding.title,
                        finding.port,
                        finding.security_mode.value,
                        _to_json(finding),
                    ),
                )
            return run_id

    def save_run_result(self, run_result: BenchmarkRunResult) -> int:
        return self.save_run(
            hostname=run_result.target.hostname,
            iterations=run_result.iterations,
            timeout=run_result.target.timeout,
            results=run_result.results,
            diagnostics_options=run_result.results[0].diagnostics_options if run_result.results else None,
        )

    def list_runs(self, limit: int = 50) -> list[dict[str, object]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT id, hostname, iterations, timeout, diagnostics_profile, diagnostics_options_json, created_at
                FROM benchmark_runs
                ORDER BY id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        return [dict(row) for row in rows]

    def list_run_summaries(self, limit: int = 100) -> list[dict[str, object]]:
        """Return lightweight rows for the history master list."""
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT
                    benchmark_runs.id,
                    benchmark_runs.hostname,
                    benchmark_runs.iterations,
                    benchmark_runs.timeout,
                    benchmark_runs.diagnostics_profile,
                    benchmark_runs.diagnostics_options_json,
                    benchmark_runs.created_at,
                    GROUP_CONCAT(DISTINCT smtp_results.port) AS ports,
                    COUNT(smtp_results.id) AS result_count,
                    SUM(CASE WHEN smtp_results.success = 1 THEN 1 ELSE 0 END) AS success_count,
                    COUNT(DISTINCT security_findings.id) AS findings_count
                FROM benchmark_runs
                LEFT JOIN smtp_results ON smtp_results.run_id = benchmark_runs.id
                LEFT JOIN security_findings ON security_findings.run_id = benchmark_runs.id
                GROUP BY benchmark_runs.id
                ORDER BY benchmark_runs.id DESC
                LIMIT ?
                """,
                (limit,),
            ).fetchall()
        summaries = []
        for row in rows:
            summary = dict(row)
            result_count = int(summary.get("result_count") or 0)
            success_count = int(summary.get("success_count") or 0)
            if result_count == 0:
                status = "Falhou"
            elif success_count == result_count:
                status = "Concluído"
            elif success_count == 0:
                status = "Falhou"
            else:
                status = "Parcial"
            summary["result_status"] = status
            summary["ports"] = self._format_ports(summary.get("ports"))
            summary["findings_count"] = int(summary.get("findings_count") or 0)
            summaries.append(summary)
        return summaries

    def list_findings_for_run(self, run_id: int) -> list[dict[str, object]]:
        with self.database.connect() as connection:
            rows = connection.execute(
                """
                SELECT finding_id, severity, category, title, port, security_mode, payload_json, created_at
                FROM security_findings
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        return [dict(row) for row in rows]

    def get_security_context_for_run(self, run_id: int) -> dict[str, object] | None:
        with self.database.connect() as connection:
            run = connection.execute(
                """
                SELECT id, hostname, diagnostics_profile, diagnostics_options_json, created_at
                FROM benchmark_runs
                WHERE id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                return None
            command_rows = connection.execute(
                """
                SELECT port, security_mode, command_diagnostics_json
                FROM smtp_results
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        return {
            "run": dict(run),
            "commands": [dict(row) for row in command_rows],
            "findings": self.list_findings_for_run(run_id),
        }

    def get_run_details(self, run_id: int) -> SMTPRunDetails | None:
        """Load all persisted data needed to reproduce a historical execution view."""
        with self.database.connect() as connection:
            run = connection.execute(
                """
                SELECT id, hostname, iterations, timeout, diagnostics_profile,
                       diagnostics_options_json, created_at
                FROM benchmark_runs
                WHERE id = ?
                """,
                (run_id,),
            ).fetchone()
            if run is None:
                return None
            results = connection.execute(
                """
                SELECT id, hostname, resolved_ip, port, security_mode, success, status,
                       error_type, error_message, tcp_connect_ms, banner_ms, ehlo_ms,
                       starttls_ms, tls_handshake_ms, total_ms, banner, ehlo_hostname,
                       capabilities_json, tls_json, capabilities_before_tls_json,
                       capabilities_after_tls_json, auth_before_tls_json, auth_after_tls_json,
                       command_responses_json, command_diagnostics_json, created_at
                FROM smtp_results
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
            diagnostics = connection.execute(
                """
                SELECT id, hostname, port, security_mode, payload_json, created_at
                FROM smtp_diagnostics
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
            findings = connection.execute(
                """
                SELECT id, finding_id, severity, category, title, port, security_mode,
                       payload_json, created_at
                FROM security_findings
                WHERE run_id = ?
                ORDER BY id ASC
                """,
                (run_id,),
            ).fetchall()
        result_dicts = [self._expand_result_json(dict(row)) for row in results]
        return SMTPRunDetails(
            run=dict(run),
            results=result_dicts,
            diagnostics=[self._expand_payload(dict(row)) for row in diagnostics],
            findings=[self._expand_payload(dict(row)) for row in findings],
            commands=[
                {
                    "port": row.get("port"),
                    "security_mode": row.get("security_mode"),
                    "command_diagnostics": row.get("command_diagnostics_json"),
                }
                for row in result_dicts
            ],
        )

    def _insert_result(self, connection, run_id: int, result: SMTPProbeResult) -> None:
        tls_payload = _to_json(result.tls_information) if result.tls_information else None
        connection.execute(
            """
            INSERT INTO smtp_results (
                run_id, hostname, resolved_ip, port, security_mode, success, status,
                error_type, error_message, tcp_connect_ms, banner_ms, ehlo_ms,
                starttls_ms, tls_handshake_ms, total_ms, banner, ehlo_hostname,
                capabilities_json, tls_json, capabilities_before_tls_json,
                capabilities_after_tls_json, auth_before_tls_json, auth_after_tls_json,
                command_responses_json, command_diagnostics_json
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                result.hostname,
                result.resolved_ip,
                result.port,
                result.security_mode.value,
                1 if result.success else 0,
                result.status.value,
                result.error_type,
                result.error_message,
                result.tcp_connect_ms,
                result.banner_ms,
                result.ehlo_ms,
                result.starttls_ms,
                result.tls_handshake_ms,
                result.total_ms,
                result.banner,
                result.ehlo_hostname,
                _to_json(result.capabilities),
                tls_payload,
                _to_json(result.capabilities_before_tls),
                _to_json(result.capabilities_after_tls),
                _to_json(result.auth_mechanisms_before_tls),
                _to_json(result.auth_mechanisms_after_tls),
                _to_json(result.command_responses),
                _to_json(result.command_diagnostic_results),
            ),
        )

    def _expand_result_json(self, row: dict[str, object]) -> dict[str, object]:
        for field_name, default in (
            ("capabilities_json", {}),
            ("tls_json", None),
            ("capabilities_before_tls_json", {}),
            ("capabilities_after_tls_json", {}),
            ("auth_before_tls_json", []),
            ("auth_after_tls_json", []),
            ("command_responses_json", {}),
            ("command_diagnostics_json", []),
        ):
            row[field_name] = _from_json(row.get(field_name), default)
        return row

    def _expand_payload(self, row: dict[str, object]) -> dict[str, object]:
        row["payload"] = _from_json(row.get("payload_json"), {})
        return row

    def _format_ports(self, ports: object) -> str:
        if not ports:
            return "-"
        values = []
        for value in str(ports).split(","):
            try:
                values.append(int(value))
            except ValueError:
                continue
        return ", ".join(str(value) for value in sorted(set(values))) or "-"
