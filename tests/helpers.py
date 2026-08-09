from __future__ import annotations

from smtp_bench_pro.persistence.repository import SMTPRunDetails


def _finding(finding_id: str, severity: str = "HIGH", evidence: str = "evidence", port: int = 587) -> dict:
    return {
        "finding_id": finding_id,
        "severity": severity,
        "category": "security",
        "title": f"Finding {finding_id}",
        "port": port,
        "security_mode": "starttls",
        "payload": {
            "id": finding_id,
            "severity": severity,
            "category": "security",
            "title": f"Finding {finding_id}",
            "description": "description",
            "evidence": evidence,
            "recommendation": "recommendation",
            "port": port,
            "security_mode": "starttls",
        },
    }


def _details(
    run_id: int = 1,
    hostname: str = "mail.example.com",
    profile: str = "safe",
    success: int = 1,
    total: float | None = 100.0,
    tls_version: str | None = "TLSv1.2",
    capabilities_before: dict | None = None,
    capabilities_after: dict | None = None,
    auth_after: list[str] | None = None,
    command_status: str = "NOT_TESTED",
    findings: list[dict] | None = None,
) -> SMTPRunDetails:
    return SMTPRunDetails(
        run={
            "id": run_id,
            "hostname": hostname,
            "iterations": 3,
            "timeout": 3.0,
            "diagnostics_profile": profile,
            "diagnostics_options_json": {"profile": profile},
            "created_at": f"2026-08-08 18:{run_id:02d}:00",
        },
        results=[
            {
                "id": run_id,
                "hostname": hostname,
                "resolved_ip": "192.0.2.10",
                "port": 587,
                "security_mode": "starttls",
                "success": success,
                "status": "SUCCESS" if success else "TLS_ERROR",
                "tcp_connect_ms": total / 10 if total is not None else None,
                "banner_ms": 5.0 if total is not None else None,
                "ehlo_ms": 5.0 if total is not None else None,
                "starttls_ms": 10.0 if total is not None else None,
                "tls_handshake_ms": 40.0 if total is not None else None,
                "total_ms": total,
                "banner": "220 mail.example.com ESMTP",
                "ehlo_hostname": "client.example",
                "capabilities_before_tls_json": capabilities_before or {"STARTTLS": [], "SIZE": ["1024"]},
                "capabilities_after_tls_json": capabilities_after or {"AUTH": ["PLAIN"]},
                "auth_before_tls_json": [],
                "auth_after_tls_json": auth_after or ["PLAIN"],
                "command_diagnostics_json": [
                    {
                        "command": "VRFY",
                        "executed": command_status != "NOT_TESTED",
                        "status": command_status,
                        "response_code": "252" if command_status == "ENABLED" else None,
                        "response_message": "252 Cannot VRFY user" if command_status == "ENABLED" else None,
                        "reason": "Disabled by profile" if command_status == "NOT_TESTED" else None,
                    }
                ],
                "tls_json": {
                    "tls_version": tls_version,
                    "cipher": "TLS_AES_256_GCM_SHA384",
                    "cipher_bits": 256,
                    "certificate_subject": "mail.example.com",
                    "certificate_issuer": "Example CA",
                    "serial_number": f"0{run_id}",
                    "not_after": "2026-12-31T00:00:00",
                    "days_remaining": 145,
                    "hostname_valid": True,
                    "certificate_valid": True,
                }
                if tls_version is not None
                else None,
            }
        ],
        diagnostics=[],
        findings=findings or [],
        commands=[],
    )
