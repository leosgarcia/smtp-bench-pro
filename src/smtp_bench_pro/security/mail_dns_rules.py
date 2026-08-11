"""Pure rule engine for Mail DNS Security Findings."""

from __future__ import annotations

from smtp_bench_pro.domain.mail_dns import (
    DKIMDiagnosticResult,
    DKIMStatus,
    DMARCDiagnosticResult,
    DMARCStatus,
    FCRDNSStatus,
    MailDNSFinding,
    MailDNSSeverity,
    MailRoutingDiagnosticResult,
    MXStatus,
    SPFDiagnosticResult,
    SPFStatus,
)

# Severity sorting priority (lower rank = higher priority)
_SEVERITY_RANK = {
    MailDNSSeverity.HIGH: 0,
    MailDNSSeverity.MEDIUM: 1,
    MailDNSSeverity.LOW: 2,
    MailDNSSeverity.INFO: 3,
}


def evaluate_mx_findings(routing: MailRoutingDiagnosticResult) -> list[MailDNSFinding]:
    """Evaluates security findings related to MX routing."""
    findings: list[MailDNSFinding] = []

    # MAILDNS-MX-001: Explicit MX record missing
    if routing.mx_record.status == MXStatus.NO_MX:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-MX-001",
                title="Registro MX explícito ausente",
                severity=MailDNSSeverity.HIGH,
                category="MX",
                description="Nenhum registro MX explícito foi publicado no DNS para este domínio.",
                evidence="Domain has no MX records published.",
                recommendation=(
                    "Publique MX explícito se o domínio deve receber e-mail e "
                    "valide o comportamento esperado de roteamento."
                ),
            )
        )

    # MAILDNS-MX-002: MX exchange points to a CNAME alias
    for record in routing.mx_record.records:
        if record.cname_detected:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-MX-002",
                    title="MX aponta para CNAME",
                    severity=MailDNSSeverity.MEDIUM,
                    category="MX",
                    description=(
                        "O servidor de e-mail especificado no registro MX é um alias CNAME "
                        "(violação RFC 2181 §10.3 / RFC 5321 §5.1)."
                    ),
                    evidence=(
                        f"MX exchange '{record.exchange}' (preference {record.preference}) "
                        "points to a CNAME alias."
                    ),
                    recommendation=(
                        "Altere o registro MX para apontar diretamente para um hostname A/AAAA "
                        "canônico, e não para um alias CNAME."
                    ),
                )
            )

    return findings


def evaluate_ptr_findings(routing: MailRoutingDiagnosticResult) -> list[MailDNSFinding]:
    """Evaluates security findings related to PTR and FCRDNS."""
    findings: list[MailDNSFinding] = []

    for res in routing.ptr_record.results:
        if res.status == FCRDNSStatus.NO_PTR:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-PTR-001",
                    title="PTR ausente para IP do MX",
                    severity=MailDNSSeverity.HIGH,
                    category="PTR",
                    description="O endereço IP do servidor MX não possui registro DNS reverso (PTR).",
                    evidence=f"IP {res.ip} returned no PTR record.",
                    recommendation=(
                        "Configure um registro DNS reverso (PTR) válido apontando para "
                        "o hostname do servidor MX."
                    ),
                )
            )

        elif res.status == FCRDNSStatus.MISMATCH:
            ptr_str = ",".join(res.ptr_hostnames)
            fwd_str = ",".join(res.forward_ips)
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-PTR-002",
                    title="Falha de FCRDNS",
                    severity=MailDNSSeverity.HIGH,
                    category="PTR",
                    description=(
                        "O registro PTR do IP do servidor MX resolve para um hostname que "
                        "não resolve de volta para o mesmo IP (FCRDNS mismatch)."
                    ),
                    evidence=f"IP {res.ip} PTR '{ptr_str}' forward resolved to '{fwd_str}'.",
                    recommendation=(
                        "Garanta a consistência FCRDNS alinhando os registros A/AAAA do "
                        "hostname PTR com o IP do servidor de envio."
                    ),
                )
            )

    return findings


def evaluate_spf_findings(spf: SPFDiagnosticResult) -> list[MailDNSFinding]:
    """Evaluates security findings related to SPF."""
    findings: list[MailDNSFinding] = []

    # MAILDNS-SPF-001: SPF record missing
    if spf.status == SPFStatus.ABSENT:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-SPF-001",
                title="Registro SPF ausente",
                severity=MailDNSSeverity.MEDIUM,
                category="SPF",
                description="Nenhum registro SPF (v=spf1) foi publicado no DNS para este domínio.",
                evidence="No v=spf1 record was observed.",
                recommendation=(
                    "Publique um registro SPF válido definindo os servidores autorizados a "
                    "enviar e-mails em nome deste domínio."
                ),
            )
        )

    # MAILDNS-SPF-002: Multiple SPF records published
    elif spf.status == SPFStatus.MULTIPLE:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-SPF-002",
                title="Múltiplos registros SPF publicados",
                severity=MailDNSSeverity.HIGH,
                category="SPF",
                description=(
                    "Foram encontrados múltiplos registros SPF no mesmo domínio "
                    "(violação da RFC 7208 §3.2)."
                ),
                evidence=f"Multiple SPF records observed for domain (raw: '{spf.raw_record or ''}').",
                recommendation="Combine todos os termos e mecanismos em um único registro SPF v=spf1.",
            )
        )

    # MAILDNS-SPF-003: SPF DNS lookup limit exceeded
    if spf.status == SPFStatus.LOOKUP_LIMIT_EXCEEDED or spf.dns_lookup_count > 10:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-SPF-003",
                title="Limite de DNS lookups SPF excedido",
                severity=MailDNSSeverity.HIGH,
                category="SPF",
                description=(
                    "A avaliação da política SPF requer mais de 10 consultas DNS "
                    "(violação da RFC 7208 §4.6.4)."
                ),
                evidence=f"SPF policy required {spf.dns_lookup_count} DNS lookups (limit: 10).",
                recommendation=(
                    "Achate o registro SPF reduzindo 'include', 'a', 'mx', 'ptr' ou "
                    "utilize prefixos IP4/IP6 diretos."
                ),
            )
        )

    # MAILDNS-SPF-004: Permissive SPF +all policy
    if spf.all_qualifier == "+":
        findings.append(
            MailDNSFinding(
                id="MAILDNS-SPF-004",
                title="Política SPF +all permissiva",
                severity=MailDNSSeverity.HIGH,
                category="SPF",
                description=(
                    "O registro SPF finaliza com '+all', autorizando qualquer IP na internet "
                    "a enviar e-mails em nome do domínio."
                ),
                evidence=f"SPF record '{spf.raw_record or ''}' uses '+all' qualifier.",
                recommendation="Altere a política final de '+all' para '~all' (SoftFail) ou '-all' (Fail).",
            )
        )

    # MAILDNS-SPF-005: Deprecated ptr mechanism used
    if spf.uses_ptr_mechanism:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-SPF-005",
                title="Mecanismo ptr depreciado no SPF",
                severity=MailDNSSeverity.LOW,
                category="SPF",
                description=(
                    "O registro SPF utiliza o mecanismo 'ptr', considerado lento e "
                    "desaconselhado pela RFC 7208 §5.5."
                ),
                evidence="SPF record uses the deprecated 'ptr' mechanism.",
                recommendation="Remova o mecanismo 'ptr' e substitua por 'ip4', 'ip6' ou 'include'.",
            )
        )

    return findings




def evaluate_dkim_findings(dkim: DKIMDiagnosticResult | None) -> list[MailDNSFinding]:
    """Evaluates security findings related to DKIM selectors."""
    findings: list[MailDNSFinding] = []
    if dkim is None:
        return findings

    for result in dkim.results:
        if result.status == DKIMStatus.ABSENT:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-001",
                    title="Selector DKIM sem registro",
                    severity=MailDNSSeverity.MEDIUM,
                    category="DKIM",
                    description="Nenhum registro DKIM foi encontrado para o selector informado.",
                    evidence=f"{result.query_name} returned no DKIM TXT record.",
                    recommendation=(
                        "Confirme o selector utilizado pelo serviço de envio e publique o "
                        "registro DKIM correto."
                    ),
                )
            )
        elif result.status == DKIMStatus.MULTIPLE:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-002",
                    title="Múltiplos registros DKIM no selector",
                    severity=MailDNSSeverity.HIGH,
                    category="DKIM",
                    description="Mais de um registro DKIM foi encontrado para o mesmo selector.",
                    evidence=f"{result.query_name}: {result.raw_record or ''}",
                    recommendation="Mantenha apenas um registro TXT DKIM válido por selector.",
                )
            )
        elif result.status == DKIMStatus.INVALID_SYNTAX:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-003",
                    title="Registro DKIM com sintaxe inválida",
                    severity=MailDNSSeverity.MEDIUM,
                    category="DKIM",
                    description="O registro DKIM possui tags inválidas, duplicadas ou versão incompatível.",
                    evidence=f"{result.query_name}: {'; '.join(result.validation_errors) or result.raw_record or ''}",
                    recommendation="Corrija a sintaxe do registro DKIM e valide as tags publicadas.",
                )
            )
        elif result.status == DKIMStatus.REVOKED:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-004",
                    title="Chave DKIM revogada ou vazia",
                    severity=MailDNSSeverity.HIGH,
                    category="DKIM",
                    description="O selector DKIM possui p= vazio, indicando chave revogada ou inutilizável.",
                    evidence=f"{result.query_name}: p= vazio.",
                    recommendation=(
                        "Remova selectors revogados de configurações ativas ou publique uma "
                        "chave DKIM válida."
                    ),
                )
            )
        elif result.status == DKIMStatus.INVALID_PUBLIC_KEY:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-005",
                    title="Chave pública DKIM inválida",
                    severity=MailDNSSeverity.HIGH,
                    category="DKIM",
                    description="A chave pública DKIM não pôde ser decodificada ou está ausente.",
                    evidence=f"{result.query_name}: {'; '.join(result.validation_errors) or 'invalid public key'}",
                    recommendation="Publique uma chave pública DKIM base64 válida no campo p=.",
                )
            )
        if result.key_type == "rsa" and result.public_key_bits is not None and result.public_key_bits < 2048:
            findings.append(
                MailDNSFinding(
                    id="MAILDNS-DKIM-006",
                    title="Chave RSA DKIM fraca",
                    severity=MailDNSSeverity.MEDIUM,
                    category="DKIM",
                    description="A chave RSA DKIM possui tamanho inferior a 2048 bits.",
                    evidence=f"{result.query_name}: RSA {result.public_key_bits} bits.",
                    recommendation=(
                        "Rotacione a chave DKIM para RSA 2048 bits ou superior, "
                        "ou Ed25519 quando suportado."
                    ),
                )
            )
    return findings

def evaluate_dmarc_findings(dmarc: DMARCDiagnosticResult) -> list[MailDNSFinding]:
    """Evaluates security findings related to DMARC."""
    findings: list[MailDNSFinding] = []

    # MAILDNS-DMARC-001: DMARC record missing
    if dmarc.status == DMARCStatus.ABSENT:
        findings.append(
            MailDNSFinding(
                id="MAILDNS-DMARC-001",
                title="Registro DMARC ausente",
                severity=MailDNSSeverity.MEDIUM,
                category="DMARC",
                description=(
                    "Nenhuma política DMARC válida foi encontrada no domínio ou no seu "
                    "Organizational Domain."
                ),
                evidence="No valid DMARC policy record was observed at the applicable policy location.",
                recommendation=(
                    "Publique um registro DMARC em '_dmarc.<dominio>' iniciando com a "
                    "política de monitoramento 'p=none'."
                ),
            )
        )

    # MAILDNS-DMARC-002: DMARC policy in monitoring mode (p=none)
    elif dmarc.status == DMARCStatus.VALID and dmarc.policy == "none":
        findings.append(
            MailDNSFinding(
                id="MAILDNS-DMARC-002",
                title="Política DMARC em modo monitoramento (p=none)",
                severity=MailDNSSeverity.INFO,
                category="DMARC",
                description="O domínio possui uma política DMARC válida em modo de monitoramento (p=none).",
                evidence=f"DMARC record '{dmarc.raw_record or ''}' sets policy p=none.",
                recommendation=(
                    "Após analisar os relatórios agregados RUA, evolua a política DMARC para "
                    "'p=quarantine' e posteriormente 'p=reject'."
                ),
            )
        )

    return findings


def evaluate_mail_dns_findings(
    routing: MailRoutingDiagnosticResult,
    spf: SPFDiagnosticResult,
    dmarc: DMARCDiagnosticResult,
    dkim: DKIMDiagnosticResult | None = None,
) -> tuple[MailDNSFinding, ...]:
    """Pure Mail DNS Security Findings Engine.

    Receives structured diagnostic snapshots and returns a deterministically ordered,
    deduplicated tuple of MailDNSFinding objects.
    """
    raw_findings: list[MailDNSFinding] = []
    raw_findings.extend(evaluate_mx_findings(routing))
    raw_findings.extend(evaluate_ptr_findings(routing))
    raw_findings.extend(evaluate_spf_findings(spf))
    raw_findings.extend(evaluate_dkim_findings(dkim))
    raw_findings.extend(evaluate_dmarc_findings(dmarc))

    # Deduplicate findings by (id, evidence)
    dedup_dict: dict[tuple[str, str], MailDNSFinding] = {}
    for f in raw_findings:
        key = (f.id, f.evidence)
        if key not in dedup_dict:
            dedup_dict[key] = f

    unique_findings = list(dedup_dict.values())

    # Deterministic sorting: severity rank -> category -> id -> evidence
    unique_findings.sort(
        key=lambda f: (_SEVERITY_RANK.get(f.severity, 99), f.category, f.id, f.evidence)
    )

    return tuple(unique_findings)


def count_findings_by_severity(findings: tuple[MailDNSFinding, ...]) -> dict[str, int]:
    """Helper to count findings grouped by severity for future UI presentation."""
    counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
    for f in findings:
        counts[f.severity.value] += 1
    return counts
