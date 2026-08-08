# Changelog

Todas as mudanças relevantes do SMTP Bench Pro são documentadas neste arquivo.

O projeto segue versionamento semântico enquanto estiver em desenvolvimento incremental.

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
