# SMTP Bench Pro 0.3.0 — Workflow Gaps

Documentação de lacunas de fluxo e decisões temporárias de modelo em 0.3.0.

---

## WG-001: Synthetic `benchmark_runs` Row for Standalone Mail DNS

- **Identificador**: WG-001
- **Descrição**: Quando o diagnóstico de Mail DNS é executado de forma standalone (sem um teste SMTP probe associado), a camada de aplicação cria um registro sintético na tabela pai `benchmark_runs` com `iterations=0`.
- **Impacto**: Na listagem mestra da aba Histórico, execuções standalone de Mail DNS aparecem lado a lado com benchmarks de probe SMTP.
- **Prioridade**: Revisar antes da release final do 0.3.0.
- **Status**: Congelado para 0.3.0 (Não alterar schema ou modelo na Fase H).
