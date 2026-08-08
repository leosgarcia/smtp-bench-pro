# SMTP Bench Pro

Status: Early Development / Alpha
Version: 0.2.5

SMTP Bench Pro is a professional SMTP benchmark, diagnostics, and security posture desktop application by WL Tech.

This release keeps the application standalone-first while exposing Bench Pro Integration API v1 for Bench Pro Core.

## Current Features

- Standalone PySide6 desktop application
- SMTP probes for ports 25 and 587
- SMTPS probe for port 465
- Banner capture
- EHLO capability capture before and after STARTTLS
- AUTH mechanism inspection without credentials
- STARTTLS detection and handshake validation
- TLS certificate inspection
- SMTP command diagnostics for NOOP, HELP, VRFY, and EXPN without enumeration or mail sending
- Per-step timings and benchmark iterations
- Security findings with stable IDs and severities
- Auditable History master/detail view reconstructed from persisted run data
- Faithful historical export for selected runs in JSON and standalone HTML
- Historical comparison between two persisted executions
- SQLite persistence with migrations v1 -> v3
- Bench Pro Integration API v1 module

## Security Boundaries

SMTP Bench Pro 0.2.5 does not authenticate, does not send email, does not test Open Relay, and does not issue MAIL FROM, RCPT TO, or DATA.

VRFY/EXPN checks are limited to command posture diagnostics and must not be used for user enumeration.


## Diagnostics Profiles

The default diagnostics profile is `safe`.

| Profile | Commands |
| --- | --- |
| Safe | TCP, banner, EHLO, STARTTLS/TLS, certificate diagnostics, AUTH discovery via EHLO, NOOP. |
| Extended | Safe plus HELP, VRFY, and EXPN posture checks using a documented neutral argument. |
| Manual | Safe baseline plus individually selected NOOP, HELP, VRFY, and EXPN command diagnostics. |

No profile performs AUTH, MAIL FROM, RCPT TO, DATA, Open Relay testing, brute force, or user enumeration.
Extended and Manual VRFY/EXPN checks can generate SMTP server security log events and must be chosen explicitly.

## Not Implemented Yet

This version does not implement SPF, DKIM, DMARC, MTA-STS, TLS-RPT, PTR, RBL checks, Open Relay testing, AUTH with credentials, OAuth, reputation scoring, PDF reports, unified Core history, PDF reports, or email sending.

## Architecture

```text
UI
  -> Application / Diagnostics Services
      -> Benchmark Engine
          -> SMTP/TLS Probes
              -> Domain Models
      -> Security Rule Engine
```

The UI does not open sockets directly. SMTP Bench Pro is standalone-first and optionally integratable into Bench Pro Core.

## Installation

```bash
python -m pip install -e ".[dev]"
```

## Run

```bash
python -m smtp_bench_pro
```

## Tests

```bash
pytest -m "not network"
ruff check .
bandit -r src/
```

## Integration API

SMTP Bench Pro exposes:

```toml
[project.entry-points."benchpro.modules"]
smtp = "smtp_bench_pro.integration.module:SMTPBenchModule"
```

Module metadata:

```text
module_id = smtp
display_name = SMTP Bench Pro
version = 0.2.5
integration_api = 1
capabilities = benchmark, diagnostics, history, security_audit
```

SMTP Bench Pro does not import Bench Pro Core.

## Roadmap

- 0.3: DNS/MX/SPF
- 0.4: DKIM/DMARC
- 0.5: Security Audit expansion
- 0.6: History/Comparison
- 0.7: Reports
- 0.8: Core integration hardening
- 0.9: Release Candidate
- 1.0: Stable

## License

MIT License.

Copyright (c) 2026 WL Tech.






