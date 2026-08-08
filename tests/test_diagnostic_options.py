import pytest

from smtp_bench_pro.domain.diagnostic_options import DiagnosticsOptions, DiagnosticsProfile


def test_default_profile_is_safe() -> None:
    options = DiagnosticsOptions()

    assert options.profile == DiagnosticsProfile.SAFE
    assert options.allowed_commands() == ("NOOP",)


def test_extended_profile_enables_optional_commands() -> None:
    options = DiagnosticsOptions.from_profile("extended")

    assert options.allowed_commands() == ("NOOP", "HELP", "VRFY postmaster", "EXPN postmaster")


def test_manual_profile_respects_flags() -> None:
    options = DiagnosticsOptions(
        profile=DiagnosticsProfile.MANUAL,
        test_noop=False,
        test_help=True,
        test_vrfy=False,
        test_expn=True,
    )

    assert options.allowed_commands() == ("HELP", "EXPN postmaster")


def test_safe_profile_overrides_sensitive_flags() -> None:
    options = DiagnosticsOptions(profile=DiagnosticsProfile.SAFE, test_vrfy=True, test_expn=True)

    assert options.test_vrfy is False
    assert options.test_expn is False
    assert options.allowed_commands() == ("NOOP",)


def test_invalid_profile_is_rejected() -> None:
    with pytest.raises(ValueError):
        DiagnosticsOptions.from_profile("aggressive")
