import pytest

from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget


def test_target_validates_hostname() -> None:
    with pytest.raises(ValueError):
        SMTPServerTarget("  ", 25, SecurityMode.STARTTLS)


def test_target_validates_port() -> None:
    with pytest.raises(ValueError):
        SMTPServerTarget("mail.example.com", 70000, SecurityMode.STARTTLS)
