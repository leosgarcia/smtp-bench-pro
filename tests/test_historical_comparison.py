import sys

import pytest

from smtp_bench_pro.comparison.comparator import HistoricalRunComparator
from smtp_bench_pro.comparison.models import ChangeStatus, FindingLifecycle, Trend
from smtp_bench_pro.persistence.repository import SMTPRunDetails


def _finding(finding_id, severity="HIGH", evidence="evidence", port=587):
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
    run_id=1,
    hostname="mail.example.com",
    profile="safe",
    success=1,
    total=100.0,
    tls_version="TLSv1.2",
    capabilities_before=None,
    capabilities_after=None,
    auth_after=None,
    command_status="NOT_TESTED",
    findings=None,
):
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


def test_same_run_rejected() -> None:
    comparator = HistoricalRunComparator()
    details = _details(run_id=1)

    with pytest.raises(ValueError, match="Selecione duas execuções diferentes"):
        comparator.compare(details, details)


def test_different_host_and_profile_warnings() -> None:
    comparison = HistoricalRunComparator().compare(
        _details(run_id=1, profile="safe"),
        _details(run_id=2, hostname="smtp.example.net", profile="extended"),
    )

    assert "servidores diferentes" in comparison.warnings[0]
    assert any("Perfis" in warning for warning in comparison.warnings)


def test_performance_improved_regressed_unchanged_zero_and_missing() -> None:
    comparator = HistoricalRunComparator()
    improved = comparator.compare(_details(run_id=1, total=100.0), _details(run_id=2, total=80.0))
    regressed = comparator.compare(_details(run_id=1, total=100.0), _details(run_id=2, total=130.0))
    unchanged = comparator.compare(_details(run_id=1, total=100.0), _details(run_id=2, total=100.5))
    zero = comparator.compare(_details(run_id=1, total=0.0), _details(run_id=2, total=10.0))
    missing = comparator.compare(_details(run_id=1, total=None), _details(run_id=2, total=10.0))

    total_improved = next(change for change in improved.performance_changes if change.metric == "Total")
    total_regressed = next(change for change in regressed.performance_changes if change.metric == "Total")
    total_unchanged = next(change for change in unchanged.performance_changes if change.metric == "Total")
    total_zero = next(change for change in zero.performance_changes if change.metric == "Total")
    total_missing = next(change for change in missing.performance_changes if change.metric == "Total")

    assert total_improved.trend == Trend.IMPROVED
    assert total_regressed.trend == Trend.REGRESSED
    assert total_unchanged.trend == Trend.UNCHANGED
    assert total_zero.delta_percent is None
    assert total_missing.trend == Trend.UNKNOWN


def test_ehlo_capability_added_removed_and_parameter_changed() -> None:
    comparison = HistoricalRunComparator().compare(
        _details(run_id=1, capabilities_before={"STARTTLS": [], "SIZE": ["1024"]}),
        _details(run_id=2, capabilities_before={"SMTPUTF8": [], "SIZE": ["2048"]}),
    )

    before = next(change for change in comparison.capability_changes if change.name == "EHLO before TLS")

    assert before.added == ["SMTPUTF8"]
    assert before.removed == ["STARTTLS"]
    assert before.parameter_changes[0].name == "SIZE"


def test_auth_tls_and_certificate_changes() -> None:
    comparison = HistoricalRunComparator().compare(
        _details(run_id=1, tls_version="TLSv1.2", auth_after=["LOGIN"]),
        _details(run_id=2, tls_version="TLSv1.3", auth_after=["XOAUTH2"]),
    )

    auth_after = next(change for change in comparison.auth_changes if change.name == "AUTH after TLS")
    tls_version = next(change for change in comparison.tls_changes if change.name == "tls_version")
    serial = next(change for change in comparison.tls_changes if change.name == "serial_number")

    assert auth_after.added == ["XOAUTH2"]
    assert auth_after.removed == ["LOGIN"]
    assert tls_version.status == ChangeStatus.CHANGED
    assert serial.status == ChangeStatus.CHANGED


def test_command_not_tested_vs_enabled_is_not_comparable() -> None:
    comparison = HistoricalRunComparator().compare(
        _details(run_id=1, profile="safe", command_status="NOT_TESTED"),
        _details(run_id=2, profile="extended", command_status="ENABLED"),
    )

    vrfy = next(change for change in comparison.command_changes if change.command == "VRFY")

    assert vrfy.status == ChangeStatus.NOT_COMPARABLE
    assert "não foi executado" in vrfy.note


def test_finding_lifecycle_new_resolved_persistent_changed() -> None:
    comparison = HistoricalRunComparator().compare(
        _details(run_id=1, findings=[_finding("A"), _finding("B"), _finding("C", evidence="old")]),
        _details(run_id=2, findings=[_finding("A"), _finding("C", evidence="new"), _finding("D")]),
    )
    lifecycles = {change.finding_id: change.lifecycle for change in comparison.finding_changes}

    assert lifecycles == {
        "A": FindingLifecycle.PERSISTENT,
        "B": FindingLifecycle.RESOLVED,
        "C": FindingLifecycle.CHANGED,
        "D": FindingLifecycle.NEW,
    }
    assert comparison.security_summary["baseline"]["HIGH"] == 3
    assert comparison.security_summary["compared"]["HIGH"] == 3


def test_partial_run_warning_and_missing_tls_not_comparable() -> None:
    partial = _details(run_id=1, success=0, tls_version=None)
    successful_result = dict(partial.results[0])
    successful_result["success"] = 1
    successful_result["status"] = "SUCCESS"
    successful_result["port"] = 465
    partial.results.append(successful_result)

    comparison = HistoricalRunComparator().compare(partial, _details(run_id=2, success=1, tls_version="TLSv1.3"))
    tls_version = next(change for change in comparison.tls_changes if change.name == "tls_version")

    assert any("diagnóstico parcial" in warning for warning in comparison.warnings)
    assert tls_version.status == ChangeStatus.NOT_COMPARABLE


def test_comparator_has_no_network_or_rule_engine_dependencies() -> None:
    imported_before = set(sys.modules)
    HistoricalRunComparator().compare(_details(run_id=1), _details(run_id=2))
    imported_after = set(sys.modules)
    imported = imported_after - imported_before

    assert not any(name.endswith("smtp_probe") for name in imported)
    assert not any(name.endswith("rules") for name in imported)

