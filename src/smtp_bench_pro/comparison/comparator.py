"""Comparator for persisted historical SMTP runs."""

from __future__ import annotations

from collections import Counter
from typing import Any

from smtp_bench_pro.comparison.models import (
    ChangeStatus,
    CommandChange,
    FieldChange,
    FindingChange,
    FindingLifecycle,
    PerformanceChange,
    RunComparison,
    RunIdentity,
    SetChange,
    Trend,
)
from smtp_bench_pro.persistence.repository import SMTPRunDetails

PERFORMANCE_ABSOLUTE_THRESHOLD_MS = 1.0
PERFORMANCE_RELATIVE_THRESHOLD = 0.05
SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")


class HistoricalRunComparator:
    """Compares two persisted SMTP run snapshots without network or rule evaluation."""

    def compare(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> RunComparison:
        baseline_id = self._run_id(baseline)
        compared_id = self._run_id(compared)
        if baseline_id is not None and compared_id is not None and baseline_id == compared_id:
            raise ValueError("Selecione duas execuções diferentes.")
        warnings = self._warnings(baseline, compared)
        metadata = self._metadata_changes(baseline, compared)
        performance = self._performance_changes(baseline, compared)
        smtp = self._smtp_changes(baseline, compared)
        capabilities = self._capability_changes(baseline, compared)
        auth = self._auth_changes(baseline, compared)
        tls = self._tls_changes(baseline, compared)
        commands = self._command_changes(baseline, compared)
        findings = self._finding_changes(baseline, compared)
        security_summary = self._security_summary(baseline, compared)
        summary = self._summary(performance, capabilities, tls, findings)
        return RunComparison(
            baseline=self._identity(baseline),
            compared=self._identity(compared),
            metadata_changes=metadata,
            performance_changes=performance,
            smtp_changes=smtp,
            capability_changes=capabilities,
            auth_changes=auth,
            tls_changes=tls,
            command_changes=commands,
            finding_changes=findings,
            security_summary=security_summary,
            summary=summary,
            warnings=warnings,
        )

    def _warnings(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[str]:
        warnings = []
        if baseline.run.get("hostname") != compared.run.get("hostname"):
            warnings.append("Você está comparando execuções de servidores diferentes.")
        if self._profile(baseline) != self._profile(compared):
            warnings.append("Perfis de diagnóstico diferentes podem limitar a comparação de comandos SMTP.")
        if self._status(baseline.results) == "Parcial" or self._status(compared.results) == "Parcial":
            warnings.append(
                "Uma das execuções possui diagnóstico parcial. Algumas diferenças podem não ser comparáveis."
            )
        return warnings

    def _identity(self, details: SMTPRunDetails) -> RunIdentity:
        return RunIdentity(
            run_id=self._run_id(details),
            hostname=self._text(details.run.get("hostname")),
            created_at=self._text(details.run.get("created_at")),
            profile=self._profile(details),
            status=self._status(details.results),
        )

    def _metadata_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[FieldChange]:
        fields = [
            ("hostname", baseline.run.get("hostname"), compared.run.get("hostname")),
            ("ports", self._ports(baseline), self._ports(compared)),
            ("iterations", baseline.run.get("iterations"), compared.run.get("iterations")),
            ("timeout", baseline.run.get("timeout"), compared.run.get("timeout")),
            ("diagnostics_profile", self._profile(baseline), self._profile(compared)),
            ("created_at", baseline.run.get("created_at"), compared.run.get("created_at")),
            ("run_status", self._status(baseline.results), self._status(compared.results)),
        ]
        return [self._field_change(name, base, comp) for name, base, comp in fields]

    def _performance_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[PerformanceChange]:
        metrics = [
            ("TCP", "tcp_connect_ms"),
            ("Banner", "banner_ms"),
            ("EHLO", "ehlo_ms"),
            ("STARTTLS", "starttls_ms"),
            ("TLS handshake", "tls_handshake_ms"),
            ("Total", "total_ms"),
        ]
        changes = []
        for label, key in metrics:
            base_value = self._mean_metric(baseline.results, key)
            compared_value = self._mean_metric(compared.results, key)
            changes.append(self._performance_change(label, base_value, compared_value))
        return changes

    def _smtp_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[FieldChange]:
        return [
            self._field_change("banner", self._first_value(baseline, "banner"), self._first_value(compared, "banner")),
            self._field_change(
                "ehlo_hostname",
                self._first_value(baseline, "ehlo_hostname"),
                self._first_value(compared, "ehlo_hostname"),
            ),
        ]

    def _capability_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[SetChange]:
        return [
            self._capability_change(
                "EHLO before TLS",
                self._merged_capabilities(baseline, "capabilities_before_tls_json"),
                self._merged_capabilities(compared, "capabilities_before_tls_json"),
            ),
            self._capability_change(
                "EHLO after TLS",
                self._merged_capabilities(baseline, "capabilities_after_tls_json"),
                self._merged_capabilities(compared, "capabilities_after_tls_json"),
            ),
        ]

    def _auth_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[SetChange]:
        return [
            self._set_change(
                "AUTH before TLS",
                self._merged_list(baseline, "auth_before_tls_json"),
                self._merged_list(compared, "auth_before_tls_json"),
            ),
            self._set_change(
                "AUTH after TLS",
                self._merged_list(baseline, "auth_after_tls_json"),
                self._merged_list(compared, "auth_after_tls_json"),
            ),
        ]

    def _tls_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[FieldChange]:
        fields = [
            "tls_version",
            "cipher",
            "cipher_bits",
            "certificate_subject",
            "certificate_issuer",
            "serial_number",
            "not_after",
            "days_remaining",
            "hostname_valid",
            "certificate_valid",
        ]
        base_tls = self._first_tls(baseline)
        compared_tls = self._first_tls(compared)
        return [self._field_change(field, base_tls.get(field), compared_tls.get(field)) for field in fields]

    def _command_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[CommandChange]:
        base_commands = self._commands(baseline)
        compared_commands = self._commands(compared)
        commands = sorted(set(base_commands) | set(compared_commands) | {"NOOP", "HELP", "VRFY", "EXPN"})
        changes = []
        for command in commands:
            base_status = base_commands.get(command)
            compared_status = compared_commands.get(command)
            if base_status is None or compared_status is None:
                status = ChangeStatus.NOT_COMPARABLE
                note = "Comando ausente em uma das execuções."
            elif base_status == "NOT_TESTED" or compared_status == "NOT_TESTED":
                status = ChangeStatus.NOT_COMPARABLE
                note = "Comparação limitada: comando não foi executado em uma das execuções."
            elif base_status == compared_status:
                status = ChangeStatus.UNCHANGED
                note = None
            else:
                status = ChangeStatus.CHANGED
                note = None
            changes.append(CommandChange(command, base_status, compared_status, status, note))
        return changes

    def _finding_changes(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> list[FindingChange]:
        base_findings = self._findings_by_id(baseline)
        compared_findings = self._findings_by_id(compared)
        changes = []
        for finding_id in sorted(set(base_findings) | set(compared_findings)):
            base = base_findings.get(finding_id)
            comp = compared_findings.get(finding_id)
            if base is None:
                lifecycle = FindingLifecycle.NEW
            elif comp is None:
                lifecycle = FindingLifecycle.RESOLVED
            elif self._finding_signature(base) != self._finding_signature(comp):
                lifecycle = FindingLifecycle.CHANGED
            else:
                lifecycle = FindingLifecycle.PERSISTENT
            changes.append(FindingChange(finding_id, lifecycle, base, comp))
        return changes

    def _security_summary(self, baseline: SMTPRunDetails, compared: SMTPRunDetails) -> dict[str, dict[str, int]]:
        base_counts = self._severity_counts(baseline)
        compared_counts = self._severity_counts(compared)
        delta = {severity: compared_counts[severity] - base_counts[severity] for severity in SEVERITIES}
        return {"baseline": base_counts, "compared": compared_counts, "delta": delta}

    def _summary(
        self,
        performance: list[PerformanceChange],
        capabilities: list[SetChange],
        tls: list[FieldChange],
        findings: list[FindingChange],
    ) -> list[str]:
        lines = []
        for change in tls:
            if change.name == "tls_version" and change.status == ChangeStatus.CHANGED:
                lines.append(f"TLS mudou de {change.baseline} para {change.compared}.")
        total = next((change for change in performance if change.metric == "Total"), None)
        if total and total.trend == Trend.REGRESSED:
            lines.append("Latência total aumentou.")
        elif total and total.trend == Trend.IMPROVED:
            lines.append("Latência total reduziu.")
        for capability in capabilities:
            for added in capability.added:
                lines.append(f"{added} foi adicionado em {capability.name}.")
            for removed in capability.removed:
                lines.append(f"{removed} foi removido em {capability.name}.")
        resolved = sum(1 for finding in findings if finding.lifecycle == FindingLifecycle.RESOLVED)
        new = sum(1 for finding in findings if finding.lifecycle == FindingLifecycle.NEW)
        if resolved:
            lines.append(f"{resolved} finding(s) resolvido(s).")
        if new:
            lines.append(f"{new} novo(s) finding(s).")
        return lines or ["Nenhuma mudança significativa identificada nos snapshots persistidos."]

    def _field_change(self, name: str, baseline: Any, compared: Any) -> FieldChange:
        if baseline is None or compared is None:
            status = ChangeStatus.NOT_COMPARABLE
            note = "Dado ausente em uma das execuções."
        elif baseline == compared:
            status = ChangeStatus.UNCHANGED
            note = None
        else:
            status = ChangeStatus.CHANGED
            note = None
        return FieldChange(name, baseline, compared, status, note)

    def _performance_change(self, metric: str, baseline: float | None, compared: float | None) -> PerformanceChange:
        if baseline is None or compared is None:
            return PerformanceChange(metric, baseline, compared, None, None, Trend.UNKNOWN, "Dado ausente.")
        delta = compared - baseline
        percent = None if baseline == 0 else (delta / baseline) * 100
        absolute = abs(delta)
        relative = abs(delta / baseline) if baseline else 0
        if absolute < PERFORMANCE_ABSOLUTE_THRESHOLD_MS and relative < PERFORMANCE_RELATIVE_THRESHOLD:
            trend = Trend.UNCHANGED
        elif delta < 0:
            trend = Trend.IMPROVED
        else:
            trend = Trend.REGRESSED
        return PerformanceChange(metric, baseline, compared, delta, percent, trend)

    def _capability_change(
        self, name: str, baseline: dict[str, list[str]], compared: dict[str, list[str]]
    ) -> SetChange:
        set_change = self._set_change(name, set(baseline), set(compared))
        parameter_changes = []
        for capability in sorted(set(baseline) & set(compared)):
            base_params = sorted(str(item) for item in baseline.get(capability, []))
            compared_params = sorted(str(item) for item in compared.get(capability, []))
            if base_params != compared_params:
                parameter_changes.append(self._field_change(capability, base_params, compared_params))
        return SetChange(
            name=name,
            added=set_change.added,
            removed=set_change.removed,
            maintained=set_change.maintained,
            parameter_changes=parameter_changes,
        )

    def _set_change(self, name: str, baseline: set[str], compared: set[str]) -> SetChange:
        return SetChange(
            name=name,
            added=sorted(compared - baseline),
            removed=sorted(baseline - compared),
            maintained=sorted(baseline & compared),
        )

    def _mean_metric(self, results: list[dict[str, Any]], key: str) -> float | None:
        values = [float(result[key]) for result in results if result.get(key) is not None]
        return sum(values) / len(values) if values else None

    def _merged_capabilities(self, details: SMTPRunDetails, field: str) -> dict[str, list[str]]:
        merged: dict[str, set[str]] = {}
        for result in details.results:
            capabilities = result.get(field)
            if not isinstance(capabilities, dict):
                continue
            for name, params in capabilities.items():
                bucket = merged.setdefault(str(name), set())
                if isinstance(params, list):
                    bucket.update(str(param) for param in params)
        return {name: sorted(params) for name, params in sorted(merged.items())}

    def _merged_list(self, details: SMTPRunDetails, field: str) -> set[str]:
        values = set()
        for result in details.results:
            items = result.get(field)
            if isinstance(items, list):
                values.update(str(item) for item in items)
        return values

    def _first_tls(self, details: SMTPRunDetails) -> dict[str, Any]:
        for result in details.results:
            tls = result.get("tls_json")
            if isinstance(tls, dict):
                return tls
        return {}

    def _first_value(self, details: SMTPRunDetails, field: str) -> Any:
        for result in details.results:
            if result.get(field) is not None:
                return result.get(field)
        return None

    def _commands(self, details: SMTPRunDetails) -> dict[str, str]:
        commands = {}
        for result in details.results:
            raw = result.get("command_diagnostics_json")
            if not isinstance(raw, list):
                continue
            for item in raw:
                if isinstance(item, dict) and item.get("command"):
                    commands[str(item["command"])] = str(item.get("status")) if item.get("status") else None
        return commands

    def _findings_by_id(self, details: SMTPRunDetails) -> dict[str, dict[str, Any]]:
        findings = {}
        for row in details.findings:
            payload = row.get("payload") if isinstance(row.get("payload"), dict) else {}
            finding_id = payload.get("id") or row.get("finding_id")
            if finding_id:
                findings[str(finding_id)] = {
                    "id": finding_id,
                    "severity": payload.get("severity") or row.get("severity"),
                    "category": payload.get("category") or row.get("category"),
                    "title": payload.get("title") or row.get("title"),
                    "description": payload.get("description"),
                    "evidence": payload.get("evidence"),
                    "recommendation": payload.get("recommendation"),
                    "port": payload.get("port") or row.get("port"),
                    "security_mode": payload.get("security_mode") or row.get("security_mode"),
                }
        return findings

    def _severity_counts(self, details: SMTPRunDetails) -> dict[str, int]:
        counter = Counter()
        for finding in self._findings_by_id(details).values():
            severity = finding.get("severity")
            if severity in SEVERITIES:
                counter[str(severity)] += 1
        return {severity: counter[severity] for severity in SEVERITIES}

    def _finding_signature(self, finding: dict[str, Any]) -> tuple[Any, ...]:
        return (
            finding.get("severity"),
            finding.get("evidence"),
            finding.get("port"),
            finding.get("recommendation"),
        )

    def _ports(self, details: SMTPRunDetails) -> list[int]:
        ports = []
        for result in details.results:
            try:
                ports.append(int(result.get("port")))
            except (TypeError, ValueError):
                continue
        return sorted(set(ports))

    def _status(self, results: list[dict[str, Any]]) -> str:
        if not results:
            return "Falhou"
        successes = sum(1 for result in results if int(result.get("success") or 0) == 1)
        if successes == len(results):
            return "Concluído"
        if successes == 0:
            return "Falhou"
        return "Parcial"

    def _profile(self, details: SMTPRunDetails) -> str | None:
        return self._text(details.run.get("diagnostics_profile"))

    def _run_id(self, details: SMTPRunDetails) -> int | None:
        try:
            return int(details.run.get("id"))
        except (TypeError, ValueError):
            return None

    def _text(self, value: Any) -> str | None:
        return str(value) if value is not None else None

