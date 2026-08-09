"""DMARC Diagnostics Engine according to RFC 7489."""

from __future__ import annotations

import logging

from smtp_bench_pro.domain.mail_dns import (
    DNSQueryStatus,
    DMARCDiagnosticResult,
    DMARCStatus,
)
from smtp_bench_pro.engine.dmarc_parser import parse_dmarc_record, parse_dmarc_report_uris
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.engine.organizational_domain import get_organizational_domain

logger = logging.getLogger("smtp_bench_pro.mail_dns")

_ERR_STATUSES = (
    DNSQueryStatus.TIMEOUT,
    DNSQueryStatus.SERVFAIL,
    DNSQueryStatus.REFUSED,
    DNSQueryStatus.ERROR,
)


class DMARCDiagnosticsService:
    """Evaluates published DMARC configuration (RFC 7489)."""

    def __init__(self, resolver: IMailDNSResolver) -> None:
        self.resolver = resolver

    def diagnose(self, domain: str) -> DMARCDiagnosticResult:
        """Discovers and evaluates published DMARC record for a domain or its Organizational Domain."""
        clean_domain = domain.rstrip(".").lower()
        org_domain = get_organizational_domain(clean_domain)

        dmarc_name = f"_dmarc.{clean_domain}"
        txt_res = self.resolver.resolve_txt(dmarc_name)

        # Handle DNS Query Errors (TIMEOUT, SERVFAIL, REFUSED) without masking as ABSENT
        if txt_res.status in _ERR_STATUSES:
            err_msg = (
                f"DNS query for '{dmarc_name}' failed with status {txt_res.status.value}: "
                f"{txt_res.error_message or ''}"
            )
            return DMARCDiagnosticResult(
                status=DMARCStatus.INVALID_SYNTAX,
                raw_record=None,
                organizational_domain=org_domain,
                validation_errors=(err_msg,),
            )

        # Check for DMARC records at _dmarc.<domain>
        dmarc_records = self._extract_dmarc_records(
            txt_res.answers if txt_res.status == DNSQueryStatus.SUCCESS else ()
        )

        is_subdomain = clean_domain != org_domain

        # If no record at subdomain and it is a subdomain, fallback to _dmarc.<org_domain> (RFC 7489 §6.6.3)
        if not dmarc_records and is_subdomain:
            org_dmarc_name = f"_dmarc.{org_domain}"
            org_txt_res = self.resolver.resolve_txt(org_dmarc_name)

            if org_txt_res.status in _ERR_STATUSES:
                err_msg = f"DNS fallback query for '{org_dmarc_name}' failed with status {org_txt_res.status.value}"
                return DMARCDiagnosticResult(
                    status=DMARCStatus.INVALID_SYNTAX,
                    raw_record=None,
                    organizational_domain=org_domain,
                    validation_errors=(err_msg,),
                )

            if org_txt_res.status == DNSQueryStatus.SUCCESS and org_txt_res.answers:
                dmarc_records = self._extract_dmarc_records(org_txt_res.answers)

        if not dmarc_records:
            return DMARCDiagnosticResult(
                status=DMARCStatus.ABSENT,
                raw_record=None,
                organizational_domain=org_domain,
                validation_errors=("No DMARC '_dmarc' record found.",),
            )

        if len(dmarc_records) > 1:
            err = f"Multiple DMARC records found ({len(dmarc_records)}). RFC 7489 prohibits multiple records."
            return DMARCDiagnosticResult(
                status=DMARCStatus.MULTIPLE,
                raw_record=dmarc_records[0],
                organizational_domain=org_domain,
                validation_errors=(err,),
            )

        raw_record = dmarc_records[0]
        tags, errors = parse_dmarc_record(raw_record)

        if errors:
            return DMARCDiagnosticResult(
                status=DMARCStatus.INVALID_SYNTAX,
                raw_record=raw_record,
                policy=tags.get("p"),
                subdomain_policy=tags.get("sp"),
                organizational_domain=org_domain,
                validation_errors=tuple(errors),
            )

        # Extract tags
        policy = tags["p"].lower()
        subdomain_policy = tags.get("sp", "").lower() or None
        pct_val = int(tags.get("pct", "100"))
        adkim = tags.get("adkim", "r").lower()
        aspf = tags.get("aspf", "r").lower()
        rua_uris = parse_dmarc_report_uris(tags.get("rua", ""))
        ruf_uris = parse_dmarc_report_uris(tags.get("ruf", ""))

        # If inherited from Organizational Domain for a subdomain, determine effective policy
        effective_policy = policy
        if is_subdomain:
            effective_policy = subdomain_policy if subdomain_policy else policy

        return DMARCDiagnosticResult(
            status=DMARCStatus.VALID,
            raw_record=raw_record,
            policy=effective_policy,
            subdomain_policy=subdomain_policy,
            pct=pct_val,
            adkim=adkim,
            aspf=aspf,
            rua=rua_uris,
            ruf=ruf_uris,
            organizational_domain=org_domain,
            validation_errors=(),
        )

    def _extract_dmarc_records(self, answers: tuple[str, ...]) -> list[str]:
        records: list[str] = []
        for ans in answers:
            cleaned = ans.strip('"').strip()
            if cleaned.lower().startswith("v=dmarc1"):
                records.append(cleaned)
        return records
