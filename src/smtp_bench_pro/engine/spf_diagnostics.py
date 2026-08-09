"""SPF Diagnostics Engine according to RFC 7208."""

from __future__ import annotations

import logging

from smtp_bench_pro.domain.mail_dns import (
    DNSQueryStatus,
    SPFDiagnosticResult,
    SPFStatus,
    SPFTerm,
)
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver
from smtp_bench_pro.engine.spf_parser import parse_spf_record

logger = logging.getLogger("smtp_bench_pro.mail_dns")

MAX_LOOKUP_BUDGET = 10
MAX_VOID_LOOKUP_BUDGET = 2
MAX_RECURSION_DEPTH = 5


class SPFDiagnosticsService:
    """Evaluates published SPF configuration (RFC 7208) using static DNS diagnostics."""

    def __init__(self, resolver: IMailDNSResolver) -> None:
        self.resolver = resolver

    def diagnose(self, domain: str) -> SPFDiagnosticResult:
        """Discovers and evaluates published SPF record for a domain."""
        clean_domain = domain.rstrip(".").lower()

        # 1. Discover TXT records
        txt_query = self.resolver.resolve_txt(clean_domain)
        if txt_query.status != DNSQueryStatus.SUCCESS or not txt_query.answers:
            return SPFDiagnosticResult(
                status=SPFStatus.ABSENT,
                raw_record=None,
                terms=(),
                validation_error="No TXT records found or DNS query failed.",
            )

        # Filter records starting with 'v=spf1' (RFC 7208 §3.2)
        spf_records: list[str] = []
        for ans in txt_query.answers:
            # Handle quoted strings or chunked TXT records
            cleaned_ans = ans.strip('"').strip()
            if cleaned_ans.lower().startswith("v=spf1"):
                spf_records.append(cleaned_ans)

        if not spf_records:
            return SPFDiagnosticResult(
                status=SPFStatus.ABSENT,
                raw_record=None,
                terms=(),
                validation_error="No SPF 'v=spf1' record found.",
            )

        if len(spf_records) > 1:
            err = f"Multiple SPF records found ({len(spf_records)}). RFC 7208 §3.2 prohibits multiple records."
            return SPFDiagnosticResult(
                status=SPFStatus.MULTIPLE,
                raw_record=spf_records[0],
                terms=(),
                validation_error=err,
            )

        raw_record = spf_records[0]

        # 2. Parse primary SPF record
        root_terms, parse_err = parse_spf_record(raw_record)
        if parse_err:
            return SPFDiagnosticResult(
                status=SPFStatus.INVALID_SYNTAX,
                raw_record=raw_record,
                terms=root_terms,
                validation_error=parse_err,
            )

        # 3. Evaluate lookup budget, recursion, and void lookups
        evaluator = _SPFEvaluator(self.resolver)
        status, lookup_count, void_count, err = evaluator.evaluate(clean_domain, root_terms)

        return SPFDiagnosticResult(
            status=status,
            raw_record=raw_record,
            terms=root_terms,
            dns_lookup_count=lookup_count,
            void_lookup_count=void_count,
            all_qualifier=evaluator.all_qualifier,
            uses_ptr_mechanism=evaluator.uses_ptr_mechanism,
            validation_error=err,
        )


class _SPFEvaluator:
    """Internal evaluator tracking DNS lookup budgets and recursion tree."""

    def __init__(self, resolver: IMailDNSResolver) -> None:
        self.resolver = resolver
        self.lookup_count = 0
        self.void_count = 0
        self.visited_domains: set[str] = set()
        self.all_qualifier: str | None = None
        self.uses_ptr_mechanism = False
        self.limit_exceeded = False
        self.void_limit_exceeded = False
        self.loop_detected = False

    def evaluate(
        self,
        current_domain: str,
        terms: tuple[SPFTerm, ...],
        depth: int = 0,
    ) -> tuple[SPFStatus, int, int, str | None]:
        current_domain = current_domain.lower()

        if depth > MAX_RECURSION_DEPTH or current_domain in self.visited_domains:
            self.loop_detected = True
            err = f"Recursion loop or depth limit exceeded at '{current_domain}'"
            return SPFStatus.RECURSION_LOOP, self.lookup_count, self.void_count, err

        self.visited_domains.add(current_domain)

        for term in terms:
            if term.mechanism == "all":
                self.all_qualifier = term.qualifier

            if term.mechanism == "ptr":
                self.uses_ptr_mechanism = True

            if term.causes_dns_lookup:
                self.lookup_count += 1
                if self.lookup_count > MAX_LOOKUP_BUDGET:
                    self.limit_exceeded = True
                    err = f"DNS lookup budget limit ({MAX_LOOKUP_BUDGET}) exceeded."
                    return SPFStatus.LOOKUP_LIMIT_EXCEEDED, self.lookup_count, self.void_count, err

            # Perform recursive evaluation for include and redirect
            if term.mechanism == "include" and term.value:
                target_domain = term.value.lower()
                # Check for macro in target domain
                if "%" in target_domain:
                    continue

                txt_res = self.resolver.resolve_txt(target_domain)
                if txt_res.status in (DNSQueryStatus.NXDOMAIN, DNSQueryStatus.NO_ANSWER):
                    self.void_count += 1
                    if self.void_count > MAX_VOID_LOOKUP_BUDGET:
                        self.void_limit_exceeded = True
                        err = f"Void lookup budget limit ({MAX_VOID_LOOKUP_BUDGET}) exceeded at '{target_domain}'."
                        return SPFStatus.VOID_LIMIT_EXCEEDED, self.lookup_count, self.void_count, err

                if txt_res.status == DNSQueryStatus.SUCCESS and txt_res.answers:
                    inc_spf = [
                        a.strip('"').strip()
                        for a in txt_res.answers
                        if a.strip('"').strip().lower().startswith("v=spf1")
                    ]
                    if len(inc_spf) == 1:
                        inc_terms, inc_err = parse_spf_record(inc_spf[0])
                        if not inc_err:
                            sub_status, _, _, sub_err = self.evaluate(target_domain, inc_terms, depth + 1)
                            if sub_status != SPFStatus.VALID_SINGLE:
                                return sub_status, self.lookup_count, self.void_count, sub_err

            elif term.mechanism == "redirect" and term.value:
                target_domain = term.value.lower()
                if "%" in target_domain:
                    continue

                txt_res = self.resolver.resolve_txt(target_domain)
                if txt_res.status in (DNSQueryStatus.NXDOMAIN, DNSQueryStatus.NO_ANSWER):
                    self.void_count += 1
                    if self.void_count > MAX_VOID_LOOKUP_BUDGET:
                        self.void_limit_exceeded = True
                        err = f"Void lookup budget limit ({MAX_VOID_LOOKUP_BUDGET}) exceeded at '{target_domain}'."
                        return SPFStatus.VOID_LIMIT_EXCEEDED, self.lookup_count, self.void_count, err

                if txt_res.status == DNSQueryStatus.SUCCESS and txt_res.answers:
                    redir_spf = [
                        a.strip('"').strip()
                        for a in txt_res.answers
                        if a.strip('"').strip().lower().startswith("v=spf1")
                    ]
                    if len(redir_spf) == 1:
                        redir_terms, redir_err = parse_spf_record(redir_spf[0])
                        if not redir_err:
                            sub_status, _, _, sub_err = self.evaluate(target_domain, redir_terms, depth + 1)
                            if sub_status != SPFStatus.VALID_SINGLE:
                                return sub_status, self.lookup_count, self.void_count, sub_err

            elif term.mechanism in ("a", "mx") and term.value:
                # Check for void lookup on static a: or mx: domains
                spec_domain = term.value.split("/")[0]
                if "%" not in spec_domain and spec_domain:
                    a_res = self.resolver.resolve_a(spec_domain)
                    if a_res.status in (DNSQueryStatus.NXDOMAIN, DNSQueryStatus.NO_ANSWER):
                        self.void_count += 1
                        if self.void_count > MAX_VOID_LOOKUP_BUDGET:
                            self.void_limit_exceeded = True
                            err = f"Void lookup budget limit ({MAX_VOID_LOOKUP_BUDGET}) exceeded at '{spec_domain}'."
                            return SPFStatus.VOID_LIMIT_EXCEEDED, self.lookup_count, self.void_count, err

        return SPFStatus.VALID_SINGLE, self.lookup_count, self.void_count, None
