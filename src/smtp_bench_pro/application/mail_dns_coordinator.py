"""Application Orchestrator for Mail DNS Diagnostics."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
import logging

from smtp_bench_pro.domain.mail_dns import (
    DMARCDiagnosticResult,
    DMARCStatus,
    FCRDNSStatus,
    MailDNSFinding,
    MailDNSRunSnapshot,
    MailDomainTarget,
    MailIdentitySummary,
    MailRoutingDiagnosticResult,
    MXStatus,
    normalize_mail_domain,
    SPFDiagnosticResult,
    SPFStatus,
)
from smtp_bench_pro.engine.dmarc_diagnostics import DMARCDiagnosticsService
from smtp_bench_pro.engine.dns_resolver import IMailDNSResolver, MailDNSResolver
from smtp_bench_pro.engine.organizational_domain import get_organizational_domain
from smtp_bench_pro.engine.spf_diagnostics import SPFDiagnosticsService
from smtp_bench_pro.engine.dns_resolver import MailRoutingDiagnosticsService
from smtp_bench_pro.persistence.repository import SMTPBenchmarkRepository
from smtp_bench_pro.security.mail_dns_rules import evaluate_mail_dns_findings

logger = logging.getLogger("smtp_bench_pro.mail_dns")


@dataclass(frozen=True)
class MailDNSDiagnosticsOutcome:
    target: MailDomainTarget
    routing: MailRoutingDiagnosticResult
    spf: SPFDiagnosticResult
    dmarc: DMARCDiagnosticResult
    identity_summary: MailIdentitySummary
    findings: tuple[MailDNSFinding, ...]
    started_at: str
    completed_at: str
    partial: bool = False
    errors: tuple[str, ...] = ()


class MailDNSDiagnosticsCoordinator:
    """Orchestrates Mail DNS Diagnostics across routing, SPF, DMARC, rules, and persistence."""

    def __init__(
        self,
        resolver: IMailDNSResolver | None = None,
        repository: SMTPBenchmarkRepository | None = None,
    ) -> None:
        self.resolver = resolver or MailDNSResolver()
        self.repository = repository

    def execute_diagnostics(
        self,
        raw_domain_input: str,
        progress_callback: callable | None = None,
    ) -> MailDNSDiagnosticsOutcome:
        """Executes full static Mail DNS diagnostics pipeline.

        Returns MailDNSDiagnosticsOutcome without PySide6 dependencies.
        """
        started_at = datetime.now(UTC).isoformat()

        # 1. Normalize domain
        target = normalize_mail_domain(raw_domain_input)
        domain = target.domain

        if progress_callback:
            progress_callback(1, "Consultando registros MX e rotas de e-mail...")

        # 2. Routing Diagnostics (MX, A/AAAA, PTR, FCRDNS)
        routing_service = MailRoutingDiagnosticsService(self.resolver)
        routing = routing_service.diagnose(target)

        if progress_callback:
            progress_callback(2, "Validando PTR e FCRDNS para servidores MX...")

        # 3. SPF Diagnostics
        if progress_callback:
            progress_callback(3, "Analisando publicação e estrutura SPF...")

        spf_service = SPFDiagnosticsService(self.resolver)
        spf = spf_service.diagnose(domain)

        # 4. DMARC Diagnostics
        if progress_callback:
            progress_callback(4, "Analisando política DMARC e Organizational Domain...")

        dmarc_service = DMARCDiagnosticsService(self.resolver)
        dmarc = dmarc_service.diagnose(domain)

        # 5. Security Rules Engine
        if progress_callback:
            progress_callback(5, "Avaliando regras de segurança e gerando achados...")

        findings = evaluate_mail_dns_findings(routing, spf, dmarc)

        # 6. Build Identity Summary
        org_domain = get_organizational_domain(domain)
        mx_count = len(routing.mx_record.records)
        has_null_mx = routing.mx_record.status == MXStatus.NULL_MX

        fcrdns_aligned = sum(1 for r in routing.ptr_record.results if r.status == FCRDNSStatus.MATCH)
        fcrdns_total = len(routing.ptr_record.results)

        summary = MailIdentitySummary(
            domain=domain,
            organizational_domain=org_domain,
            mx_count=mx_count,
            has_null_mx=has_null_mx,
            spf_policy=spf.status.value,
            dmarc_policy=dmarc.policy or dmarc.status.value,
            fcrdns_aligned_ips=fcrdns_aligned,
            fcrdns_total_ips=fcrdns_total,
        )

        completed_at = datetime.now(UTC).isoformat()
        errors: list[str] = []

        if (
            spf.status in (SPFStatus.INVALID_SYNTAX, SPFStatus.LOOKUP_LIMIT_EXCEEDED, SPFStatus.VOID_LIMIT_EXCEEDED)
            and spf.validation_error
        ):
            errors.append(f"SPF: {spf.validation_error}")

        if dmarc.status in (DMARCStatus.INVALID_SYNTAX, DMARCStatus.MULTIPLE) and dmarc.validation_errors:
            errors.extend([f"DMARC: {e}" for e in dmarc.validation_errors])

        partial = len(errors) > 0

        return MailDNSDiagnosticsOutcome(
            target=target,
            routing=routing,
            spf=spf,
            dmarc=dmarc,
            identity_summary=summary,
            findings=findings,
            started_at=started_at,
            completed_at=completed_at,
            partial=partial,
            errors=tuple(errors),
        )

    def diagnose_and_persist(
        self,
        raw_domain_input: str,
        run_id: int | None = None,
        progress_callback: callable | None = None,
    ) -> tuple[MailDNSDiagnosticsOutcome, MailDNSRunSnapshot | None]:
        """Executes diagnostics and persists MailDNSRunSnapshot to SQLite repository."""
        outcome = self.execute_diagnostics(raw_domain_input, progress_callback)

        if not self.repository:
            return outcome, None

        # Determine target run_id (create benchmark_runs parent row if standalone)
        target_run_id = run_id
        if target_run_id is None:
            target_run_id = self.repository.save_run(
                hostname=outcome.target.domain,
                iterations=0,
                timeout=outcome.target.timeout,
                results=[],
            )

        snapshot = MailDNSRunSnapshot(
            id=None,
            run_id=target_run_id,
            domain=outcome.target.domain,
            routing=outcome.routing,
            spf=outcome.spf,
            dmarc=outcome.dmarc,
            identity_summary=outcome.identity_summary,
            findings=outcome.findings,
            created_at=outcome.completed_at,
        )

        try:
            snapshot_id = self.repository.save_mail_dns_snapshot(snapshot)
            persisted_snapshot = MailDNSRunSnapshot(
                id=snapshot_id,
                run_id=snapshot.run_id,
                domain=snapshot.domain,
                routing=snapshot.routing,
                spf=snapshot.spf,
                dmarc=snapshot.dmarc,
                identity_summary=snapshot.identity_summary,
                findings=snapshot.findings,
                created_at=snapshot.created_at,
            )
            return outcome, persisted_snapshot
        except Exception as exc:
            logger.warning("Failed to persist Mail DNS snapshot: %s", exc)
            return outcome, None
