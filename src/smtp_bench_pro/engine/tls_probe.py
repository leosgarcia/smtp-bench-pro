"""TLS certificate inspection helpers."""

from datetime import UTC, datetime
import ssl
from typing import Any

from smtp_bench_pro.domain.results import TLSInformation


def _name_to_string(value: Any) -> str | None:
    if not value:
        return None
    parts: list[str] = []
    for group in value:
        for key, item in group:
            parts.append(f"{key}={item}")
    return ", ".join(parts) if parts else None


def _days_remaining(not_after: str | None) -> int | None:
    if not not_after:
        return None
    try:
        timestamp = ssl.cert_time_to_seconds(not_after)
    except (TypeError, ValueError):
        return None
    expires = datetime.fromtimestamp(timestamp, tz=UTC)
    now = datetime.now(UTC)
    return int((expires - now).total_seconds() // 86400)


def inspect_tls_socket(sock: ssl.SSLSocket) -> TLSInformation:
    """Extract TLS and certificate details from an established SSL socket."""
    cipher_info = sock.cipher()
    cert = sock.getpeercert() or {}
    subject_alt_names = [value for key, value in cert.get("subjectAltName", []) if key.lower() == "dns"]
    not_after = cert.get("notAfter")

    return TLSInformation(
        tls_version=sock.version(),
        cipher=cipher_info[0] if cipher_info else None,
        cipher_bits=cipher_info[2] if cipher_info and len(cipher_info) > 2 else None,
        certificate_subject=_name_to_string(cert.get("subject")),
        certificate_issuer=_name_to_string(cert.get("issuer")),
        serial_number=cert.get("serialNumber"),
        not_before=cert.get("notBefore"),
        not_after=not_after,
        days_remaining=_days_remaining(not_after),
        subject_alt_names=subject_alt_names,
        hostname_valid=True,
        certificate_valid=True,
    )
