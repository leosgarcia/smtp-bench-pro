"""DKIM DNS diagnostics service."""

from __future__ import annotations

from datetime import UTC, datetime

from smtp_bench_pro.domain.mail_dns import DKIMDiagnosticResult, DKIMSelectorResult, DKIMStatus, DNSQueryStatus
from smtp_bench_pro.engine.dkim_parser import (
    dkim_query_name,
    is_valid_selector,
    normalize_dkim_selectors,
    parse_dkim_record,
)
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver


class DKIMDiagnosticsService:
    """Runs static DKIM TXT checks for manually supplied selectors."""

    def __init__(self, resolver: IMailDNSResolver) -> None:
        self.resolver = resolver

    def diagnose(self, domain: str, selectors: str | tuple[str, ...] | list[str] | None) -> DKIMDiagnosticResult:
        normalized = normalize_dkim_selectors(selectors)
        checked_at = datetime.now(UTC).isoformat()
        results: list[DKIMSelectorResult] = []
        for selector in normalized:
            query_name = dkim_query_name(selector, domain)
            if not is_valid_selector(selector):
                results.append(parse_dkim_record(selector, query_name, None))
                continue
            txt = self.resolver.resolve_txt(query_name)
            dkim_records = tuple(answer.strip().strip('"') for answer in txt.answers if "p=" in answer.lower())
            if txt.status != DNSQueryStatus.SUCCESS or not dkim_records:
                results.append(
                    DKIMSelectorResult(
                        selector=selector,
                        query_name=query_name,
                        status=DKIMStatus.ABSENT,
                        validation_errors=("Registro DKIM ausente.",),
                    )
                )
            elif len(dkim_records) > 1:
                results.append(
                    DKIMSelectorResult(
                        selector=selector,
                        query_name=query_name,
                        status=DKIMStatus.MULTIPLE,
                        raw_record=" | ".join(dkim_records),
                        validation_errors=("Múltiplos registros DKIM encontrados para o selector.",),
                    )
                )
            else:
                results.append(parse_dkim_record(selector, query_name, dkim_records[0]))
        return DKIMDiagnosticResult(domain=domain, selectors=normalized, results=tuple(results), checked_at=checked_at)
