"""Application services that keep UI code away from probing details."""

from __future__ import annotations

from dataclasses import dataclass, field

from smtp_bench_pro.domain.diagnostic_options import DiagnosticsOptions
from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget

DEFAULT_PORTS = (25, 465, 587)


@dataclass(frozen=True)
class BenchmarkRequest:
    hostname: str
    ports: tuple[int, ...] = DEFAULT_PORTS
    iterations: int = 1
    timeout: float = 3.0
    diagnostics_options: DiagnosticsOptions = field(default_factory=DiagnosticsOptions)


class SMTPBenchmarkService:
    """Builds validated benchmark targets for the engine."""

    def build_targets(self, request: BenchmarkRequest) -> list[SMTPServerTarget]:
        hostname = request.hostname.strip()
        if not hostname:
            raise ValueError("Hostname is required")
        if request.iterations <= 0:
            raise ValueError("Iterations must be greater than zero")
        if not request.ports:
            raise ValueError("Select at least one SMTP port")

        targets: list[SMTPServerTarget] = []
        for port in request.ports:
            targets.append(
                SMTPServerTarget(
                    hostname=hostname,
                    port=port,
                    security_mode=self.security_mode_for_port(port),
                    timeout=request.timeout,
                )
            )
        return targets

    def security_mode_for_port(self, port: int) -> SecurityMode:
        if port == 465:
            return SecurityMode.SMTPS
        if port in {25, 587, 2525}:
            return SecurityMode.STARTTLS
        return SecurityMode.PLAIN
