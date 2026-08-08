"""Domain enums for SMTP Bench Pro."""

from enum import StrEnum


class SecurityMode(StrEnum):
    PLAIN = "plain"
    STARTTLS = "starttls"
    SMTPS = "smtps"

    @classmethod
    def from_value(cls, value: str) -> "SecurityMode":
        normalized = value.strip().lower()
        aliases = {
            "plain": cls.PLAIN,
            "none": cls.PLAIN,
            "starttls": cls.STARTTLS,
            "tls": cls.STARTTLS,
            "smtps": cls.SMTPS,
            "ssl": cls.SMTPS,
        }
        if normalized not in aliases:
            raise ValueError(f"Unsupported security mode: {value}")
        return aliases[normalized]


class ProbeStatus(StrEnum):
    SUCCESS = "SUCCESS"
    TIMEOUT = "TIMEOUT"
    CONNECTION_REFUSED = "CONNECTION_REFUSED"
    DNS_ERROR = "DNS_ERROR"
    TLS_ERROR = "TLS_ERROR"
    CERTIFICATE_ERROR = "CERTIFICATE_ERROR"
    PROTOCOL_ERROR = "PROTOCOL_ERROR"
    STARTTLS_NOT_SUPPORTED = "STARTTLS_NOT_SUPPORTED"
    UNKNOWN_ERROR = "UNKNOWN_ERROR"
