"""Diagnostics profile and command options."""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class DiagnosticsProfile(StrEnum):
    SAFE = "safe"
    EXTENDED = "extended"
    MANUAL = "manual"

    @classmethod
    def normalize(cls, value: DiagnosticsProfile | str | None) -> DiagnosticsProfile:
        if value is None:
            return cls.SAFE
        if isinstance(value, cls):
            return value
        return cls(value.strip().lower())


class CommandDiagnosticStatus(StrEnum):
    NOT_TESTED = "NOT_TESTED"
    ENABLED = "ENABLED"
    DISABLED = "DISABLED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True)
class CommandDiagnosticResult:
    command: str
    executed: bool
    supported: bool | None = None
    response_code: str | None = None
    response_message: str | None = None
    status: CommandDiagnosticStatus = CommandDiagnosticStatus.NOT_TESTED
    reason: str | None = None

    @property
    def enabled(self) -> bool:
        return self.status == CommandDiagnosticStatus.ENABLED

    @property
    def response(self) -> str | None:
        return self.response_message


@dataclass(frozen=True)
class DiagnosticsOptions:
    profile: DiagnosticsProfile = DiagnosticsProfile.SAFE
    test_noop: bool = True
    test_help: bool = False
    test_vrfy: bool = False
    test_expn: bool = False

    def __post_init__(self) -> None:
        profile = DiagnosticsProfile.normalize(self.profile)
        object.__setattr__(self, "profile", profile)
        if profile == DiagnosticsProfile.SAFE:
            object.__setattr__(self, "test_noop", True)
            object.__setattr__(self, "test_help", False)
            object.__setattr__(self, "test_vrfy", False)
            object.__setattr__(self, "test_expn", False)
        elif profile == DiagnosticsProfile.EXTENDED:
            object.__setattr__(self, "test_noop", True)
            object.__setattr__(self, "test_help", True)
            object.__setattr__(self, "test_vrfy", True)
            object.__setattr__(self, "test_expn", True)
        elif profile == DiagnosticsProfile.MANUAL:
            object.__setattr__(self, "test_noop", bool(self.test_noop))
            object.__setattr__(self, "test_help", bool(self.test_help))
            object.__setattr__(self, "test_vrfy", bool(self.test_vrfy))
            object.__setattr__(self, "test_expn", bool(self.test_expn))

    @classmethod
    def from_profile(cls, profile: DiagnosticsProfile | str | None) -> DiagnosticsOptions:
        return cls(profile=DiagnosticsProfile.normalize(profile))

    def allowed_commands(self) -> tuple[str, ...]:
        commands: list[str] = []
        if self.test_noop:
            commands.append("NOOP")
        if self.test_help:
            commands.append("HELP")
        if self.test_vrfy:
            commands.append("VRFY postmaster")
        if self.test_expn:
            commands.append("EXPN postmaster")
        return tuple(commands)

    def as_dict(self) -> dict[str, object]:
        return {
            "profile": self.profile.value,
            "test_noop": self.test_noop,
            "test_help": self.test_help,
            "test_vrfy": self.test_vrfy,
            "test_expn": self.test_expn,
        }
