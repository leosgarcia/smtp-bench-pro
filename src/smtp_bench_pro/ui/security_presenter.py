"""Presentation helpers for SMTP security audit UI."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum

from smtp_bench_pro.domain.diagnostic_options import (
    CommandDiagnosticResult,
    CommandDiagnosticStatus,
    DiagnosticsOptions,
    DiagnosticsProfile,
)
from smtp_bench_pro.domain.diagnostics import FindingSeverity, SecurityFinding

COMMAND_TOOLTIPS = {
    "NOOP": "Verifica se a sessão SMTP responde a um comando inofensivo de no operation.",
    "HELP": "Solicita ajuda/capacidades textuais do servidor quando permitido pelo perfil.",
    "VRFY": (
        "Solicita ao servidor informações sobre validade de um destinatário. "
        "SMTP Bench Pro utiliza somente um valor neutro no modo Estendido/Manual e não executa enumeração."
    ),
    "EXPN": (
        "Solicita expansão de listas/aliases quando suportado. "
        "Utilizado somente de forma controlada e opcional."
    ),
}


@dataclass(frozen=True)
class CommandPresentation:
    command: str
    executed: str
    result: str
    response_code: str
    note: str
    evidence: str


def profile_display_name(profile: DiagnosticsProfile) -> str:
    if profile == DiagnosticsProfile.SAFE:
        return "Seguro (Recomendado)"
    if profile == DiagnosticsProfile.EXTENDED:
        return "Estendido"
    return "Manual"


def profile_description(options: DiagnosticsOptions) -> str:
    if options.profile == DiagnosticsProfile.SAFE:
        return "Executa apenas verificações conservadoras e não executa VRFY ou EXPN."
    if options.profile == DiagnosticsProfile.EXTENDED:
        return "Executa verificações adicionais de comandos SMTP que podem gerar eventos nos logs do servidor."
    enabled = []
    for label, flag in (
        ("NOOP", options.test_noop),
        ("HELP", options.test_help),
        ("VRFY", options.test_vrfy),
        ("EXPN", options.test_expn),
    ):
        enabled.append(f"{label}: {'habilitado' if flag else 'desabilitado'}")
    return "Manual - " + ", ".join(enabled)


def severity_counters(findings: list[SecurityFinding]) -> dict[FindingSeverity, int]:
    counters = {severity: 0 for severity in FindingSeverity}
    for finding in findings:
        counters[finding.severity] += 1
    return counters


def severity_counters_text(findings: list[SecurityFinding]) -> str:
    counters = severity_counters(findings)
    return " | ".join(
        f"{severity.value.title()}: {counters[severity]}" for severity in FindingSeverity
    )


def command_presentation(result: CommandDiagnosticResult) -> CommandPresentation:
    executed = "Sim" if result.executed else "Não"
    response_code = result.response_code or "-"
    evidence = result.response_message or "-"
    if result.status == CommandDiagnosticStatus.NOT_TESTED:
        return CommandPresentation(
            command=result.command,
            executed=executed,
            result="Não testado",
            response_code=response_code,
            note=result.reason or "Não executado pelo perfil de diagnóstico",
            evidence=evidence,
        )
    if result.status == CommandDiagnosticStatus.ENABLED:
        return CommandPresentation(
            command=result.command,
            executed=executed,
            result="Habilitado",
            response_code=response_code,
            note="Comando aceito pelo servidor",
            evidence=evidence,
        )
    if result.status == CommandDiagnosticStatus.DISABLED:
        return CommandPresentation(
            command=result.command,
            executed=executed,
            result="Desabilitado",
            response_code=response_code,
            note="Servidor recusou ou desabilitou o comando",
            evidence=evidence,
        )
    return CommandPresentation(
        command=result.command,
        executed=executed,
        result="Desconhecido",
        response_code=response_code,
        note=result.reason or "Resposta inconclusiva ou indisponível",
        evidence=evidence,
    )


def command_finding_for(command: str, findings: list[SecurityFinding]) -> SecurityFinding | None:
    expected_ids = {"VRFY": "SMTP-CMD-001", "EXPN": "SMTP-CMD-002"}
    expected = expected_ids.get(command)
    if expected is None:
        return None
    return next((finding for finding in findings if finding.id == expected), None)


def enum_value(value: object) -> object:
    return value.value if isinstance(value, Enum) else value
