"""Models for historical SMTP run comparisons."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class ChangeStatus(StrEnum):
    UNCHANGED = "UNCHANGED"
    CHANGED = "CHANGED"
    NOT_COMPARABLE = "NOT_COMPARABLE"


class Trend(StrEnum):
    IMPROVED = "IMPROVED"
    REGRESSED = "REGRESSED"
    UNCHANGED = "UNCHANGED"
    UNKNOWN = "UNKNOWN"


class FindingLifecycle(StrEnum):
    NEW = "NEW"
    RESOLVED = "RESOLVED"
    PERSISTENT = "PERSISTENT"
    CHANGED = "CHANGED"


@dataclass(frozen=True)
class RunIdentity:
    run_id: int | None
    hostname: str | None
    created_at: str | None
    profile: str | None
    status: str


@dataclass(frozen=True)
class FieldChange:
    name: str
    baseline: Any
    compared: Any
    status: ChangeStatus
    note: str | None = None


@dataclass(frozen=True)
class PerformanceChange:
    metric: str
    baseline_ms: float | None
    compared_ms: float | None
    delta_ms: float | None
    delta_percent: float | None
    trend: Trend
    note: str | None = None


@dataclass(frozen=True)
class SetChange:
    name: str
    added: list[str] = field(default_factory=list)
    removed: list[str] = field(default_factory=list)
    maintained: list[str] = field(default_factory=list)
    parameter_changes: list[FieldChange] = field(default_factory=list)
    note: str | None = None


@dataclass(frozen=True)
class CommandChange:
    command: str
    baseline_status: str | None
    compared_status: str | None
    status: ChangeStatus
    note: str | None = None


@dataclass(frozen=True)
class FindingChange:
    finding_id: str
    lifecycle: FindingLifecycle
    baseline: dict[str, Any] | None
    compared: dict[str, Any] | None


@dataclass(frozen=True)
class RunComparison:
    baseline: RunIdentity
    compared: RunIdentity
    metadata_changes: list[FieldChange]
    performance_changes: list[PerformanceChange]
    smtp_changes: list[FieldChange]
    capability_changes: list[SetChange]
    auth_changes: list[SetChange]
    tls_changes: list[FieldChange]
    command_changes: list[CommandChange]
    finding_changes: list[FindingChange]
    security_summary: dict[str, dict[str, int]]
    summary: list[str]
    warnings: list[str]
