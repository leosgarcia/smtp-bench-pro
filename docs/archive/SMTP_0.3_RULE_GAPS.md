# SMTP Bench Pro 0.3.0 — Mail DNS Security Rule Gaps

Este documento registra explicitamente todos os estados de diagnóstico DNS de e-mail que existem nos motores de análise (`MailRoutingDiagnosticsService`, `SPFDiagnosticsService`, `DMARCDiagnosticsService`), mas que **NÃO** possuem um `Finding ID` congelado na especificação da v0.3.0.

Nenhum `Finding ID` sintético foi inventado para esses estados durante a Fase E, garantindo estrita conformidade com a tabela de modelos congelados (`docs/SMTP_0.3_MODEL_FREEZE.md`).

---

## Tabela de Gaps de Regras de Segurança

| Categoria | Estado de Diagnóstico Sem Finding Frozen | Comportamento Atual no Engine de Regras | Recomendação para v0.4 / Revisão Futura |
| :--- | :--- | :--- | :--- |
| **SPF** | `SPFStatus.INVALID_SYNTAX` | Nenhum finding gerado. O erro é preservado em `validation_error`. | Propor `MAILDNS-SPF-006` (HIGH): Registro SPF com erro sintático publicado. |
| **SPF** | `SPFStatus.VOID_LIMIT_EXCEEDED` | Nenhum finding gerado. | Propor `MAILDNS-SPF-007` (HIGH): Limite de 2 void lookups excedido na avaliação SPF. |
| **SPF** | `SPFStatus.RECURSION_LOOP` | Nenhum finding gerado. | Propor `MAILDNS-SPF-008` (HIGH): Ciclo de recursão ou profundidade máxima excedida no SPF. |
| **DMARC** | `DMARCStatus.INVALID_SYNTAX` | Nenhum finding gerado. O erro é preservado em `validation_errors`. | Propor `MAILDNS-DMARC-003` (HIGH): Registro DMARC publicado com sintaxe inválida. |
| **DMARC** | `DMARCStatus.MULTIPLE` | Nenhum finding gerado. | Propor `MAILDNS-DMARC-004` (HIGH): Múltiplos registros DMARC publicados no mesmo nome. |
| **PTR / FCRDNS**| `FCRDNSStatus.MULTIPLE_PTR` | Nenhum finding gerado (salvo se houver `MISMATCH` correspondente). | Propor `MAILDNS-PTR-003` (MEDIUM): Múltiplos registros PTR associados ao mesmo IP sem FCRDNS válido. |
| **DNS Geral** | `DNSQueryStatus.TIMEOUT` / `SERVFAIL` | Nenhum finding de ausência gerado (controle de falso-positivo). | Preservar como erro temporário de infraestrutura DNS, sem confundir com `ABSENT`. |

---

## Decisão Normativa

1. O `MailDNSFindingsEngine` processa exclusivamente os 11 IDs de segurança congelados na v0.3.0:
   - `MAILDNS-MX-001`, `MAILDNS-MX-002`
   - `MAILDNS-PTR-001`, `MAILDNS-PTR-002`
   - `MAILDNS-SPF-001`, `MAILDNS-SPF-002`, `MAILDNS-SPF-003`, `MAILDNS-SPF-004`, `MAILDNS-SPF-005`
   - `MAILDNS-DMARC-001`, `MAILDNS-DMARC-002`
2. Os estados não cobertos acima permanecem visíveis nos relatórios de diagnóstico brutos (`SPFDiagnosticResult`, `DMARCDiagnosticResult`), sem emissão de achados sintéticos não auditados.
