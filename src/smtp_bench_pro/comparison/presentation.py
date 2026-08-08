"""Presentation helpers for historical comparisons."""

from __future__ import annotations

from typing import Any

from smtp_bench_pro.comparison.models import ChangeStatus, FindingLifecycle, Trend

UNAVAILABLE = "Não disponível"


CHANGE_LABELS = {
    ChangeStatus.UNCHANGED: "Sem mudança",
    ChangeStatus.CHANGED: "Alterado",
    ChangeStatus.NOT_COMPARABLE: "Não comparável",
}

TREND_LABELS = {
    Trend.IMPROVED: "Melhorou",
    Trend.REGRESSED: "Piorou",
    Trend.UNCHANGED: "Estável",
    Trend.UNKNOWN: "Desconhecido",
}

FINDING_LABELS = {
    FindingLifecycle.NEW: "Novo",
    FindingLifecycle.RESOLVED: "Resolvido",
    FindingLifecycle.PERSISTENT: "Persistente",
    FindingLifecycle.CHANGED: "Alterado",
}


def value_text(value: Any) -> str:
    if value is None or value == "":
        return UNAVAILABLE
    if isinstance(value, float):
        return f"{value:.2f}"
    if isinstance(value, list):
        return ", ".join(str(item) for item in value) if value else UNAVAILABLE
    return str(value)


def percent_text(value: float | None) -> str:
    return "N/A" if value is None else f"{value:+.1f}%"


def delta_text(value: float | None) -> str:
    return "N/A" if value is None else f"{value:+.2f} ms"


def change_label(status: ChangeStatus) -> str:
    return CHANGE_LABELS[status]


def trend_label(trend: Trend) -> str:
    return TREND_LABELS[trend]


def finding_label(lifecycle: FindingLifecycle) -> str:
    return FINDING_LABELS[lifecycle]
