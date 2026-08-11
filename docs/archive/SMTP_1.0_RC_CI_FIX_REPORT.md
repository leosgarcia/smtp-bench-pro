# SMTP Bench Pro CI Fix Report

## Executive Summary
O GitHub Actions falhava no job de testes Linux ao importar PySide6 dentro do `pytestqt` por ausência de `libEGL.so.1` no runner Ubuntu. A correção foi mínima e ficou restrita ao workflow de CI, adicionando a dependência de sistema `libegl1` antes da instalação do pacote.

## Workflow Affected
- `.github/workflows/ci.yml`

## Root Cause
- O workflow executava `pytest -m "not network"` em `ubuntu-latest` com `QT_QPA_PLATFORM=offscreen`.
- O ambiente ainda precisava da biblioteca de sistema `libEGL.so.1` para importar os módulos Qt carregados por `pytest-qt`.
- O erro observado nos logs foi: `ImportError: libEGL.so.1: cannot open shared object file: No such file or directory`.

## Fix Applied
- Adicionada a etapa `Install Qt runtime dependencies` no workflow.
- O passo instala `libegl1` via `apt-get` antes dos testes.

## Local Validation
- `python -m pytest -q`: 174 passed
- `ruff check .`: PASS
- `bandit -q -r src`: PASS
- `python -m smtp_bench_pro --version`: PASS
- build Windows: PASS
- smoke test: PASS
- Core `python -m pytest -q`: 51 passed

## Remote CI Status
- Falha original confirmada no commit `f4028db` para `main` e `v1.0.0-rc1`.
- Depois da correção do workflow, o próximo run de CI deve ser observado para confirmação de verde.

## RC Decision
- Não foi necessário criar `v1.0.0-rc2`.
- A correção é apenas de CI, sem alteração de código, build artefact ou release artifact.
- `v1.0.0-rc1` permanece válida.

## Remaining Risk
- Se o runner Ubuntu exigir outras bibliotecas Qt adicionais em mudanças futuras de dependência, o workflow poderá precisar de mais um passo de apt-get.
- O smoke GUI continua sendo local; o CI permanece focado em testes, lint e segurança.
