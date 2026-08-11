# SMTP Bench Pro 0.4.0 — DKIM Diagnostics Specification

Data: 2026-08-11
Status: Accepted for implementation
Escopo: DKIM estático via DNS TXT, sem SMTP ativo e sem validação de assinatura real.

## Objetivo

Completar o trio SPF/DKIM/DMARC no SMTP Bench Pro antes da preparação para 1.0.0, adicionando diagnóstico estático de registros DKIM por selectors informados manualmente pelo usuário.

## Segurança e Fronteiras

DKIM Diagnostics 0.4.0 executa somente consultas DNS TXT em:

```text
<selector>._domainkey.<domain>
```

Fora do escopo:

- autodiscovery de selectors;
- validação de assinatura real;
- parsing de e-mail bruto;
- ARC;
- BIMI;
- MTA-STS;
- TLS-RPT;
- DNSSEC/DANE;
- AUTH real;
- envio de e-mail;
- Open Relay test.

## Modelos finais

### DKIMStatus

- `ABSENT`
- `VALID`
- `MULTIPLE`
- `INVALID_SYNTAX`
- `REVOKED`
- `UNSUPPORTED_KEY_TYPE`
- `INVALID_PUBLIC_KEY`

### DKIMSelectorResult

Campos:

- `selector`
- `query_name`
- `status`
- `raw_record`
- `key_type`
- `public_key_present`
- `public_key_bits`
- `flags`
- `services`
- `hash_algorithms`
- `notes`
- `validation_errors`

### DKIMDiagnosticResult

Campos:

- `domain`
- `selectors`
- `results`
- `checked_at`

## Parser

O parser DKIM deve ser separado de rules e UI.

Tags suportadas:

- `v`
- `k`
- `p`
- `h`
- `t`
- `s`
- `n`

Decisões:

- `k` ausente assume `rsa`.
- `v` ausente é aceito como DKIM record compatível; `v` presente e diferente de `DKIM1` é inválido.
- Tags duplicadas tornam o registro inválido.
- `p=` vazio indica chave revogada.
- `p` ausente ou base64 inválido torna a chave inválida.
- `k=rsa` e `k=ed25519` são suportados para parsing.
- Outros valores de `k` geram `UNSUPPORTED_KEY_TYPE`.

## RSA fraca

Quando possível via stdlib, detectar tamanho de chave RSA a partir do DER/base64.

Critério 0.4.0:

- RSA menor que 2048 bits gera finding `MAILDNS-DKIM-006`.
- Se não for possível determinar bits, manter diagnóstico válido quando a chave DER/base64 for decodificável, com nota técnica.

## Selector validation

Selectors são informados manualmente e devem ser conservadores:

- não podem ser vazios;
- não podem conter espaços;
- não podem conter `@`, `:`, `/`, `?`, `#`;
- devem aceitar labels DNS simples separados por ponto quando necessário.

Selector inválido não deve consultar DNS e deve gerar resultado `INVALID_SYNTAX`.

## Persistência

Decisão: **schema v4 é suficiente**.

DKIM será persistido dentro do JSON existente `mail_dns_runs.identity_summary_json`? Não.

Decisão final: DKIM será persistido em uma nova chave opcional dentro do payload serializado de snapshot via serializer dedicado, mantendo a tabela `mail_dns_runs` e sem criar schema v5. Como a tabela v4 possui colunas específicas para `mx_json`, `ptr_json`, `spf_json`, `dmarc_json`, `identity_summary_json` e `findings_json`, a implementação 0.4.0 armazenará DKIM dentro de `identity_summary_json` como campo opcional controlado por serializer, ou alternativamente em `findings_json` apenas para findings.

Após inspeção do schema v4, a opção mais limpa sem schema v5 é estender `MailDNSRunSnapshot` em memória e incluir DKIM no `identity_summary_json` sob chave `dkim_json` somente pelo serializer/deserializer. Legado sem DKIM deve carregar como `DKIMDiagnosticResult(domain, selectors=(), results=(), checked_at="")`.

Se essa abordagem ficar confusa durante implementação, schema v5 deverá ser documentado antes de ser criado. Preferência: **sem schema v5**.

## Findings DKIM

| ID | Severidade | Categoria | Condição |
|---|---|---|---|
| `MAILDNS-DKIM-001` | MEDIUM | DKIM | Selector sem registro DKIM. |
| `MAILDNS-DKIM-002` | HIGH | DKIM | Múltiplos registros DKIM para o mesmo selector. |
| `MAILDNS-DKIM-003` | MEDIUM | DKIM | Registro DKIM com sintaxe inválida. |
| `MAILDNS-DKIM-004` | HIGH | DKIM | Chave revogada ou `p=` vazio. |
| `MAILDNS-DKIM-005` | HIGH | DKIM | Chave pública inválida ou base64 inválido. |
| `MAILDNS-DKIM-006` | MEDIUM | DKIM | Chave RSA fraca menor que 2048 bits. |

## UI

A aba `DNS de E-mail` deve adicionar selectors DKIM informados manualmente em campo compacto.

Formato aceito:

```text
default, selector1, google, s1
```

A UI deve exibir uma sub-aba DKIM com:

- selector;
- query name;
- status;
- key type;
- bits;
- flags;
- services;
- hash algorithms;
- erros/notas.

## Histórico

A visualização histórica deve ser read-only e usar apenas snapshot persistido. Snapshot legado sem DKIM deve mostrar:

```text
Não disponível nesta execução.
```

## Export

JSON/HTML de Mail DNS deve incluir DKIM quando disponível.

HTML deve escapar todo conteúdo de DNS, incluindo raw DKIM e notas.

## Testes obrigatórios

- selector válido RSA;
- selector válido Ed25519;
- selector ausente;
- múltiplos registros;
- `p=` vazio/revogado;
- base64 inválido;
- `k` ausente assumindo rsa;
- `k` desconhecido;
- versão inválida;
- tags duplicadas;
- flags `t=y` / `t=s`;
- serviços `s=email` / `s=*`;
- hash algorithms `h=sha256`;
- selector com caracteres inválidos;
- múltiplos selectors informados;
- legacy snapshot sem DKIM carrega normalmente;
- export HTML escapa conteúdo malicioso;
- UI mostra DKIM sem bloquear SPF/DMARC;
- Core continua passando.
