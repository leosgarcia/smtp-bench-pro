# SMTP Bench Pro 0.3 — Mail DNS Diagnostics Specification (Scope Frozen)

## Executive Summary

Este documento especifica a arquitetura e o design técnico para a introdução da camada de **Mail DNS Diagnostics** no **SMTP Bench Pro 0.3.0**.

Diferente do *DNS Bench Pro*, cujo propósito é o benchmark de velocidade e resiliência de servidores DNS genéricos, o *SMTP Bench Pro 0.3.0* utilizará DNS exclusivamente no contexto de **infraestrutura de e-mail e segurança de mensagens**, respondendo à pergunta fundamental: **"O domínio está corretamente configurado e preparado para enviar e receber e-mails de forma segura e autêntica?"**

---

## Scope & Deferred Features

### Escopo Congelado da v0.3.0 (MVP Requerido)
- **Normalização de Domínio**: Trimming, lowercase, validação IDNA, rejeição de portas/URLs.
- **Resolver DNS Dedicado (`MailDNSResolver`)**: Baseado em `dnspython` com distinção estrita de erros (`NXDOMAIN`, `NO_ANSWER`, `TIMEOUT`, `SERVFAIL`, `REFUSED`, `SUCCESS`).
- **Diagnóstico MX**: Registros MX, prioridades, detecção de Null MX (`0 .`), resolução A/AAAA e verificação CNAME.
- **Diagnóstico PTR / FCRDNS**: Reverse DNS para todos os IPs dos MXs e validação de Forward-Confirmed Reverse DNS.
- **Diagnóstico SPF (RFC 7208)**: Parser formal de mecanismos/qualificadores, contagem de DNS lookups (máximo 10), void lookup budget (máximo 2), detecção de recursão e loops de `include`.
- **Diagnóstico DMARC (RFC 7489)**: Parser de `_dmarc.<domain>`, políticas (`none`, `quarantine`, `reject`), alinhamentos (`adkim`, `aspf`), URIs de relatórios (`rua`, `ruf`), herança de subdomínio e resolução via Public Suffix List (`tldextract`).
- **Persistência SQLite v4**: Tabela `mail_dns_runs` para retenção snapshot sem re-execução de rede no histórico.
- **UI "DNS de E-mail"**: Nova aba isolada no `SMTPBenchWidget`.
- **Exportadores JSON / HTML**: Suporte estendido para chave opcional `"mail_dns"` sem quebrar `format_version = 1`.

### Recursos Adiados para a v0.4.0+ (Fora do Escopo 0.3.0)
- **DKIM**: Consultas e parsing de chaves públicas por seletor.
- **MTA-STS**: Consulta DNS `_mta-sts` e busca HTTPS `.well-known/mta-sts.txt`.
- **TLS-RPT**: Consulta DNS `_smtp._tls`.
- **Comparação Histórica Mail DNS**: Comparação de deltas entre execuções passadas de Mail DNS.
- **DANE / TLSA & DNSSEC Validation**: Diagnóstico de certificados e validação formal de DNSSEC.
- **BIMI & CAA**: Registros de marca e Autoridade de Certificação.

---

## Domain Models 0.3 (Frozen)

### `MailDomainTarget`
```python
@dataclass(frozen=True)
class MailDomainTarget:
    domain: str  # Normalizado (ASCII / IDN, sem trailing dot)
    raw_input: str  # Input original do usuário
    timeout: float = 3.0
    custom_nameserver: str | None = None
```

### `MailDNSReport`
```python
@dataclass(frozen=True)
class MailDNSReport:
    domain: str
    queried_at: str  # ISO 8601 UTC
    mx_record: MXDiagnosticResult
    ptr_record: PTRDiagnosticResult
    spf_record: SPFDiagnosticResult
    dmarc_record: DMARCDiagnosticResult
    identity_summary: MailIdentitySummary
```

---

## DNS Resolver Contract

O resolvedor `MailDNSResolver` em `smtp_bench_pro.engine.dns_resolver` expõe o contrato genérico:

```python
class MailDNSResolver:
    def resolve_mx(self, domain: str) -> DNSQueryResult: ...
    def resolve_a(self, hostname: str) -> DNSQueryResult: ...
    def resolve_aaaa(self, hostname: str) -> DNSQueryResult: ...
    def resolve_ptr(self, ip_address: str) -> DNSQueryResult: ...
    def resolve_txt(self, name: str) -> DNSQueryResult: ...
```

---

## Security Findings & Severities 0.3

| ID | Categoria | Severidade | Condição | Razão / Mitigação de Falso-Positivo |
| :--- | :--- | :--- | :--- | :--- |
| `MAILDNS-MX-001` | MX | `HIGH` | Nenhum MX nem Null MX encontrado | Domínio sem MX não pode receber e-mail. |
| `MAILDNS-MX-002` | MX | `MEDIUM` | Hostname MX aponta para CNAME | Violação RFC 2181 §10.3 / RFC 5321 §5.1. |
| `MAILDNS-PTR-001` | PTR | `HIGH` | IP do MX não possui registro PTR | Alto risco de rejeição por antispam. |
| `MAILDNS-PTR-002` | PTR | `HIGH` | Falha de FCRDNS | Hostname PTR não resolve para o IP do MX. |
| `MAILDNS-SPF-001` | SPF | `MEDIUM` | Registro SPF ausente | Classificado como MEDIUM (não HIGH), pois SPF nem sempre é obrigatório se DMARC não exigir. |
| `MAILDNS-SPF-002` | SPF | `HIGH` | Múltiplos registros `v=spf1` | Violação RFC 7208 §3.2 (torna o SPF inválido). |
| `MAILDNS-SPF-003` | SPF | `HIGH` | SPF DNS lookups > 10 | Excede limite RFC 7208 §4.6.4. |
| `MAILDNS-SPF-004` | SPF | `HIGH` | Registro SPF utiliza `+all` | Permite que qualquer IP envie em nome do domínio. |
| `MAILDNS-SPF-005` | SPF | `LOW` | Registro SPF utiliza mecanismo `ptr` | Descorajado pela RFC 7208 §5.5 (lento e não confiável). |
| `MAILDNS-DMARC-001`| DMARC | `MEDIUM` | Registro DMARC ausente (`_dmarc`) | Ausência de política de autenticação de domínio. |
| `MAILDNS-DMARC-002`| DMARC | `INFO` | DMARC com política `p=none` | Válido para fase de monitoramento inicial. |

---

## Persistence Schema v4

```sql
CREATE TABLE IF NOT EXISTS mail_dns_runs (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id INTEGER NOT NULL,
    domain TEXT NOT NULL,
    mx_json TEXT NOT NULL,
    ptr_json TEXT NOT NULL,
    spf_json TEXT NOT NULL,
    dmarc_json TEXT NOT NULL,
    identity_summary_json TEXT NOT NULL,
    findings_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    FOREIGN KEY(run_id) REFERENCES runs(id) ON DELETE CASCADE
);
```

---

## Export Format Contract

- Mantém `format_version = 1`.
- Chave opcional `"mail_dns"` adicionada ao payload exportado quando o relatório contiver dados de DNS de E-mail.
- Leitores existentes ignoram chaves desconhecidas mantendo compatibilidade total.

---

## Threading Model

- `MailDNSResolver` submeterá os workers ao `QThreadPool` interno do `SMTPBenchWidget` com `maxThreadCount = 4`.
- Não utilizará `QThreadPool.globalInstance()`.

---

## Dependencies

- `dnspython>=2.4.0`
- `tldextract>=5.0.0` (configurado para execução offline determinística usando arquivo PSL empacotado localmente).
