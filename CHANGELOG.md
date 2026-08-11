# Changelog

Todas as mudanças relevantes do SMTP Bench Pro são documentadas neste arquivo.

O projeto segue versionamento semântico enquanto estiver em desenvolvimento incremental.

## 1.0.0-rc1

- Consolidado o ciclo funcional do SMTP Bench Pro como candidata estável à versão 1.0.
- Mantidos benchmark SMTP, diagnostics, TLS/certificate, histórico, exportação, comparação, Mail DNS, SPF, DKIM e DMARC.
- Consolidada a fundação de empacotamento Windows com artefato PyInstaller e smoke test.
- Mantida a convergência visual do About com o DNS Bench Pro.

## 0.4.0

- Adicionado DKIM Diagnostics estático por selectors informados manualmente.
- Adicionado parser DKIM para tags `v`, `k`, `p`, `h`, `t`, `s` e `n`, com suporte de parsing para RSA e Ed25519.
- Adicionada detecção de selector ausente, múltiplos registros DKIM, sintaxe inválida, `p=` vazio/revogado, chave pública inválida, tipo de chave não suportado e RSA fraca quando determinável.
- Adicionados findings DKIM estáveis `MAILDNS-DKIM-001` a `MAILDNS-DKIM-006`.
- Integrado DKIM à aba DNS de E-mail, histórico read-only e exports JSON/HTML de snapshots históricos.
- Mantido SQLite Schema v4, com compatibilidade para snapshots legados sem DKIM.
- Mantida fronteira de segurança: DKIM usa somente DNS TXT, sem SMTP ativo, sem AUTH, sem envio e sem validação de assinatura real.

## 0.3.0

- Adicionada aba "DNS de E-mail" para diagnóstico estático de Mail DNS.
- Adicionada camada MailDNSResolver para consulta de MX, A/AAAA, PTR e FCRDNS.
- Adicionado motor de análise SPF (RFC 7208) com parser de termos, limitação de 10 lookups DNS e 2 void lookups.
- Adicionado motor de análise DMARC (RFC 7489) com extração de políticas, alinhamento e resolução de Organizational Domain via tldextract (Public Suffix List) 100% offline.
- Adicionado MailDNSFindingsEngine com 11 regras de segurança congeladas para MX, PTR, SPF e DMARC.
- Adicionada migration SQLite Schema v4 para persistência de snapshots `MailDNSRunSnapshot`.
- Adicionada visualização histórica read-only na aba Histórico para snapshots Mail DNS.
- Adicionada exportação JSON e HTML para snapshots Mail DNS com sanitização XSS de 100% dos campos.

## 0.2.6

- Adicionada exportação de comparação histórica em JSON e HTML.
- Adicionada serialização canônica de `RunComparison` para exportação determinística.
- Adicionado relatório HTML standalone de comparação com escaping completo e CSS de impressão.
- Adicionada ação `Exportar Comparação` no diálogo de comparação histórica.
- Mantida fidelidade histórica: exportação não reconsulta repository, não reexecuta probes, não recalcula comparação e não reavalia regras.
## 0.2.5

- Adicionada comparação entre duas execuções históricas persistidas.
- Adicionados deltas de performance com classificação semântica: melhorou, piorou, estável ou desconhecido.
- Adicionada comparação de capabilities EHLO, AUTH, command diagnostics, TLS e metadata.
- Adicionado lifecycle de findings: novo, resolvido, persistente e alterado.
- Adicionada ação Comparar Execuções na aba Histórico.
- Adicionado diálogo read-only de comparação com abas Resumo, Performance, SMTP, TLS e Segurança.

## 0.2.4

- Adicionada exportação fiel de uma execução histórica persistida.
- Adicionada serialização canônica compartilhada por JSON e HTML.
- Adicionado export JSON UTF-8 com versão de formato de exportação.
- Adicionado relatório HTML standalone com dados de servidor escapados.
- Adicionada ação Exportar Execução na aba Histórico.

## 0.2.3

- Adicionada visualização Histórico em master/detail.
- Adicionado carregamento de detalhes persistidos para SMTP, TLS, command diagnostics e findings.
- Adicionada renderização de segurança histórica usando somente dados armazenados.
- Adicionado lazy loading de detalhes ao selecionar execução histórica.
- Adicionada cobertura de regressão para reprodutibilidade de perfil e opções históricas.

## 0.2.2

- Adicionado painel Resumo do Diagnóstico na aba Segurança.
- Adicionada tabela de command diagnostics com labels amigáveis ao usuário.
- Adicionada associação entre comandos e findings.
- Melhorados estados vazios e apresentação de diagnósticos parciais.
- Adicionada cobertura de UI para perfis, estados de comandos e findings associados.

## 0.2.1

- Adicionados perfis de diagnóstico: Seguro, Estendido e Manual.
- Definido o perfil Seguro como padrão.
- VRFY/EXPN desabilitados por padrão e disponíveis somente por escolha explícita.
- Adicionados estados estruturados de command diagnostics: `NOT_TESTED`, `ENABLED`, `DISABLED`, `UNKNOWN`.
- Adicionada migration SQLite schema v3 para perfil/opções de diagnóstico.
- Adicionados controles de perfil e seleção manual na GUI.

## 0.2.0

- Adicionado SMTP Diagnostics Service.
- Adicionados snapshots EHLO antes e depois do TLS.
- Adicionada inspeção de AUTH sem credenciais.
- Adicionada análise de STARTTLS, TLS, certificado, banner e comandos SMTP.
- Adicionado Security Rule Engine com IDs estáveis de findings.
- Adicionadas abas Diagnóstico e Segurança na GUI.
- Adicionada migration SQLite v1 para v2 com diagnostics e findings.
- Capabilities atualizadas para `benchmark`, `diagnostics`, `history` e `security_audit`.

## 0.1.0

- Fundação inicial da aplicação SMTP Bench Pro standalone.
- Adicionados probes SMTP, STARTTLS e SMTPS.
- Adicionados timings por etapa, persistência SQLite, GUI PySide6 e adapter Integration API v1.

