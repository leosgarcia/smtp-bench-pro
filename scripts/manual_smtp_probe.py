"""Manual SMTP probe helper.

Usage:
    python scripts/manual_smtp_probe.py mail.example.com 587 STARTTLS
"""

from __future__ import annotations

import argparse

from smtp_bench_pro.domain.enums import SecurityMode
from smtp_bench_pro.domain.models import SMTPServerTarget
from smtp_bench_pro.engine.smtp_probe import SMTPProbe


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("hostname")
    parser.add_argument("port", type=int)
    parser.add_argument("security_mode", choices=[mode.value for mode in SecurityMode])
    args = parser.parse_args()
    result = SMTPProbe().run(
        SMTPServerTarget(args.hostname, args.port, SecurityMode(args.security_mode))
    )
    print(result)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
