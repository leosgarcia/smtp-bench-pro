# Changelog

## 0.2.3

- Added auditable History master/detail view.
- Added persisted run detail loading for SMTP, TLS, command diagnostics, and findings.
- Added historical security rendering from stored session data only.
- Added lazy detail loading when a historical run is selected.
- Added regression coverage for historical profile/options reproducibility.
## 0.2.2

- Added Security tab diagnostic summary panel.
- Added command diagnostics table with user-facing status labels.
- Added command-to-finding association details.
- Improved empty states and partial diagnostic presentation.
- Added UI/test coverage for profile summary rendering and command diagnostic states.

## 0.2.1

- Added diagnostics profiles: Safe, Extended, and Manual.
- Made Safe the default diagnostics behavior.
- Disabled VRFY/EXPN by default and exposed them only through explicit Extended/Manual profile selection.
- Added structured command diagnostic states: NOT_TESTED, ENABLED, DISABLED, UNKNOWN.
- Added SQLite schema migration v3 for diagnostics profile/options audit data.
- Added GUI profile selector and Manual command controls.

## 0.2.0

- Added SMTP Diagnostics Service.
- Added EHLO before/after TLS snapshots.
- Added AUTH mechanism inspection without credentials.
- Added STARTTLS, TLS, certificate, banner, and SMTP command posture analysis.
- Added security rule engine with stable finding IDs.
- Added Diagnostics and Security GUI tabs.
- Added SQLite schema migration v1 -> v2 for diagnostics and findings.
- Updated module capabilities to `benchmark`, `diagnostics`, `history`, and `security_audit`.

## 0.1.0

- Initial standalone SMTP benchmark foundation.
- Added SMTP/STARTTLS/SMTPS probes, timings, SQLite persistence, PySide6 UI, and Integration API v1 adapter.




