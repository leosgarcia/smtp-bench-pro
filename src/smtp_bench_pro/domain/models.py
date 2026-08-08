"""Domain models for SMTP Bench Pro."""

from dataclasses import dataclass

from smtp_bench_pro.domain.enums import SecurityMode


@dataclass(frozen=True)
class SMTPServerTarget:
    hostname: str
    port: int
    security_mode: SecurityMode
    timeout: float = 3.0

    def __post_init__(self) -> None:
        if not self.hostname.strip():
            raise ValueError("hostname must not be empty")
        if not (1 <= self.port <= 65535):
            raise ValueError("port must be between 1 and 65535")
        if self.timeout <= 0:
            raise ValueError("timeout must be greater than zero")
