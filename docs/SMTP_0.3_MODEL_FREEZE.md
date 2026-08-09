# SMTP Bench Pro 0.3.0 — Model & Scope Freeze Document

## 1. Escopo Congelado (Scope Freeze)

### Incluído na v0.3.0:
- Normalização rigorosa de domínio (`MailDomainTarget`).
- Resolução e consulta estruturada DNS (`MailDNSResolver` via `dnspython`).
- Diagnóstico MX & Null MX (`0 .`), resolução A/AAAA e verificação CNAME.
- Diagnóstico PTR (Reverse DNS) e FCRDNS (Forward-Confirmed Reverse DNS).
- Diagnóstico SPF completo (RFC 7208) com parser sintático, limite de 10 DNS lookups, void lookup budget e detecção de recursão/loop.
- Diagnóstico DMARC completo (RFC 7489) com alinhamento de identidade e herança de domínio via Public Suffix List (`tldextract`).
- Matriz de Regras e Security Findings (`MAILDNS-MX-*`, `MAILDNS-PTR-*`, `MAILDNS-SPF-*`, `MAILDNS-DMARC-*`).
- Persistência em banco de dados SQLite (Schema v4).
- Aba GUI "DNS de E-mail" no `SMTPBenchWidget`.
- Histórico Snapshot 100% offline.
- Exportação JSON/HTML compatível (`format_version = 1`).

### Adiado para v0.4.0+:
- DKIM (Seletores & Parsing de Chaves Públicas).
- MTA-STS (DNS `_mta-sts` + Política HTTPS).
- TLS-RPT (DNS `_smtp._tls`).
- Comparação Histórica entre relatórios Mail DNS.
- Validação DNSSEC & DANE / TLSA.
- Registros BIMI & CAA.

---

## 2. Enums Congelados

```python
from enum import Enum

class DNSQueryStatus(str, Enum):
    SUCCESS = "SUCCESS"
    NXDOMAIN = "NXDOMAIN"
    NO_ANSWER = "NO_ANSWER"
    TIMEOUT = "TIMEOUT"
    SERVFAIL = "SERVFAIL"
    REFUSED = "REFUSED"
    ERROR = "ERROR"

class MXStatus(str, Enum):
    NO_MX = "NO_MX"
    SINGLE_MX = "SINGLE_MX"
    MULTIPLE_MX = "MULTIPLE_MX"
    NULL_MX = "NULL_MX"

class FCRDNSStatus(str, Enum):
    MATCH = "MATCH"
    MISMATCH = "MISMATCH"
    NO_PTR = "NO_PTR"
    MULTIPLE_PTR = "MULTIPLE_PTR"
    NOT_APPLICABLE = "NOT_APPLICABLE"
    ERROR = "ERROR"

class SPFStatus(str, Enum):
    ABSENT = "ABSENT"
    VALID_SINGLE = "VALID_SINGLE"
    MULTIPLE = "MULTIPLE"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    LOOKUP_LIMIT_EXCEEDED = "LOOKUP_LIMIT_EXCEEDED"
    VOID_LIMIT_EXCEEDED = "VOID_LIMIT_EXCEEDED"
    RECURSION_LOOP = "RECURSION_LOOP"

class DMARCStatus(str, Enum):
    ABSENT = "ABSENT"
    VALID = "VALID"
    INVALID_SYNTAX = "INVALID_SYNTAX"
    MULTIPLE = "MULTIPLE"

class MailDNSSeverity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
```

---

## 3. Domain Models Congelados (Python 3.11 Dataclasses)

```python
from dataclasses import dataclass

@dataclass(frozen=True)
class MailDomainTarget:
    domain: str  # Domínio normalizado (ASCII / IDN, sem trailing dot)
    raw_input: str
    timeout: float = 3.0
    custom_nameserver: str | None = None

@dataclass(frozen=True)
class DNSQueryResult:
    name: str
    record_type: str
    status: DNSQueryStatus
    answers: tuple[str, ...] = ()
    error_type: str | None = None
    error_message: str | None = None
    queried_at: str = ""

@dataclass(frozen=True)
class AddressRecord:
    ip: str
    family: str  # "IPv4" ou "IPv6"

@dataclass(frozen=True)
class MXRecord:
    preference: int
    exchange: str
    is_null_mx: bool
    addresses_v4: tuple[AddressRecord, ...] = ()
    addresses_v6: tuple[AddressRecord, ...] = ()
    cname_detected: bool = False

@dataclass(frozen=True)
class MXDiagnosticResult:
    status: MXStatus
    records: tuple[MXRecord, ...] = ()
    raw_records: tuple[str, ...] = ()

@dataclass(frozen=True)
class FCRDNSResult:
    ip: str
    ptr_hostnames: tuple[str, ...]
    status: FCRDNSStatus
    forward_ips: tuple[str, ...] = ()

@dataclass(frozen=True)
class PTRDiagnosticResult:
    results: tuple[FCRDNSResult, ...] = ()

@dataclass(frozen=True)
class SPFTerm:
    qualifier: str  # "+", "-", "~", "?"
    mechanism: str  # "all", "include", "a", "mx", "ip4", "ip6", "ptr", "exists", "redirect"
    value: str | None = None
    raw: str = ""
    is_modifier: bool = False
    causes_dns_lookup: bool = False

@dataclass(frozen=True)
class SPFDiagnosticResult:
    status: SPFStatus
    raw_record: str | None = None
    terms: tuple[SPFTerm, ...] = ()
    dns_lookup_count: int = 0
    void_lookup_count: int = 0
    all_qualifier: str | None = None
    uses_ptr_mechanism: bool = False
    validation_error: str | None = None

@dataclass(frozen=True)
class DMARCDiagnosticResult:
    status: DMARCStatus
    raw_record: str | None = None
    policy: str | None = None  # "none", "quarantine", "reject"
    subdomain_policy: str | None = None
    pct: int = 100
    adkim: str = "r"  # "r" (relaxed) ou "s" (strict)
    aspf: str = "r"   # "r" (relaxed) ou "s" (strict)
    rua: tuple[str, ...] = ()
    ruf: tuple[str, ...] = ()
    organizational_domain: str = ""
    validation_errors: tuple[str, ...] = ()

@dataclass(frozen=True)
class MailIdentitySummary:
    domain: str
    organizational_domain: str
    mx_count: int
    has_null_mx: bool
    spf_policy: str | None
    dmarc_policy: str | None
    fcrdns_aligned_ips: int
    fcrdns_total_ips: int

@dataclass(frozen=True)
class MailDNSFinding:
    id: str
    title: str
    severity: MailDNSSeverity
    category: str
    description: str
    evidence: str
    recommendation: str

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

## 4. Contrato do Resolver (`MailDNSResolver`)

```python
class MailDNSResolver:
    def __init__(self, timeout: float = 3.0, custom_nameserver: str | None = None): ...
    
    def resolve_mx(self, domain: str) -> DNSQueryResult: ...
    def resolve_a(self, hostname: str) -> DNSQueryResult: ...
    def resolve_aaaa(self, hostname: str) -> DNSQueryResult: ...
    def resolve_ptr(self, ip_address: str) -> DNSQueryResult: ...
    def resolve_txt(self, name: str) -> DNSQueryResult: ...
```

---

## 5. Tabela de Severidades & Security Findings

| ID | Condição | Severidade | Justificativa Técnica | Mitigação de Falso-Positivo |
| :--- | :--- | :--- | :--- | :--- |
| `MAILDNS-MX-001` | Nenhum registro MX nem Null MX encontrado | `HIGH` | Domínio incapaz de receber e-mail. | Rejeitado se houver Null MX. |
| `MAILDNS-MX-002` | Hostname MX aponta para um registro CNAME | `MEDIUM` | Incompatível com a RFC 2181 §10.3 e RFC 5321 §5.1. | Valida se A/AAAA é CNAME indireto. |
| `MAILDNS-PTR-001` | IP do MX não possui registro PTR | `HIGH` | Servidores antispam rejeitam conexões de IPs sem PTR. | Ignora IPs privados (RFC 1918). |
| `MAILDNS-PTR-002` | Falha de FCRDNS | `HIGH` | O PTR do IP não resolve de volta para o próprio IP. | Valida lista de IPs resolvidos. |
| `MAILDNS-SPF-001` | Registro SPF ausente (`v=spf1`) | `MEDIUM` | Domínio vulnerável a falsificação direta de envelope. | Classificado como MEDIUM (não HIGH/CRITICAL). |
| `MAILDNS-SPF-002` | Múltiplos registros `v=spf1` | `HIGH` | Torna a avaliação SPF inválida segundo a RFC 7208 §3.2. | Verifica se há mais de uma string `v=spf1`. |
| `MAILDNS-SPF-003` | Consultas DNS do SPF > 10 | `HIGH` | Excede o limite da RFC 7208 §4.6.4 (gera `PermError`). | Contagem exata conforme spec. |
| `MAILDNS-SPF-004` | Registro SPF utiliza `+all` | `HIGH` | Autoriza explicitamente qualquer IP da internet a enviar e-mails. | Detecta especificamente o qualificador `+all`. |
| `MAILDNS-SPF-005` | Registro SPF utiliza mecanismo `ptr` | `LOW` | Mecanismo descontinuado e descorajado pela RFC 7208 §5.5. | Notificação de boas práticas. |
| `MAILDNS-DMARC-001`| Registro DMARC ausente (`_dmarc`) | `MEDIUM` | Ausência de política de validação de remetente e relatórios. | Classificado como MEDIUM. |
| `MAILDNS-DMARC-002`| Registro DMARC com política `p=none` | `INFO` | Política válida de monitoramento inicial. | Informacional; não é falha. |

---

## 6. Persistência SQLite Schema v4

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

## 7. Dependências e Threads

- **Dependências**:
  - `dnspython>=2.4.0`
  - `tldextract>=5.0.0`
- **Threading**:
  - `QThreadPool` dedicado no `SMTPBenchWidget` com `maxThreadCount = 4`.

---

## 8. Matriz de Testes Automatizados (100% Offline)

| Teste | Descrição |
| :--- | :--- |
| `test_domain_normalization` | Normalização de domínios (IDN, trailing dot, uppercase, rejeição de URL/porta). |
| `test_mx_resolution_success` | Resolução normal de múltiplos MXs com prioridades. |
| `test_null_mx_handling` | Tratamento de Null MX (`0 .`) ignorando resolução de IP. |
| `test_mx_cname_detection` | Detecção de MX apontando para CNAME. |
| `test_fcrdns_match_and_mismatch` | Validação de PTR e verificação de retorno FCRDNS (MATCH vs MISMATCH). |
| `test_spf_parser_and_qualifiers` | Parsing de termos SPF (`+`, `-`, `~`, `?`) e mecanismos. |
| `test_spf_lookup_budget` | Contagem exata de DNS lookups (detecta limite > 10). |
| `test_spf_recursion_loop` | Detecção de loops circulares em `include:`. |
| `test_dmarc_parser_and_alignment` | Parsing de tags DMARC, alinhamento `adkim`/`aspf` e URIs `rua`. |
| `test_organizational_domain_tldextract` | Herança de domínio usando `tldextract` (`.com.br`, `.co.uk`). |
| `test_persistence_v4_migration` | Migração idempotente do banco SQLite de v3 para v4. |
