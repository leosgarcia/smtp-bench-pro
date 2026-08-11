# Operações de Release do SMTP Bench Pro

Estes procedimentos documentam o fluxo operacional de release do SMTP Bench Pro. Revise os comandos antes de executar em qualquer ambiente.

## Versão atual

```text
SMTP Bench Pro v1.0.0-rc1
```

Notas públicas da versão:

```text
docs/releases/v1.0.0-rc1.md
```

## Remote oficial

```bash
git remote set-url origin https://github.com/leosgarcia/smtp-bench-pro.git
git remote -v
```

## Metadados do repositório

```bash
gh repo edit leosgarcia/smtp-bench-pro --homepage https://wltech.com.br --description "SMTP Bench Pro — benchmark, diagnóstico e auditoria profissional de servidores SMTP."
```

## Validação antes de release

```bash
pytest
ruff check .
bandit -r src
python -m smtp_bench_pro --version
```

Validações manuais recomendadas:

- abrir GUI standalone;
- listar módulo no Bench Pro Core;
- abrir SMTP integrado no Core;
- exportar uma execução histórica para JSON e HTML;
- comparar duas execuções históricas;
- exportar uma comparação histórica para JSON e HTML.

## Empacotamento Windows

```powershell
.\scripts\build_windows.ps1
.\scripts\smoke_windows.ps1
```

## Criar tag

```bash
git fetch --tags
git tag -a v1.0.0-rc1 -m "SMTP Bench Pro v1.0.0-rc1"
git push origin main
git push origin v1.0.0-rc1
```

## Criar release manualmente

```bash
gh release create v1.0.0-rc1 \
  --repo leosgarcia/smtp-bench-pro \
  --title "SMTP Bench Pro v1.0.0-rc1" \
  --notes-file docs/releases/v1.0.0-rc1.md
```

## Artefatos esperados

```text
SMTP-Bench-Pro-1.0.0-rc1-Windows-x64.zip
SMTP-Bench-Pro-1.0.0-rc1-Windows-x64.zip.sha256
```

## Observações

- A versão atual já possui fundação de build Windows com PyInstaller.
- O pacote inicial é Windows-first.
- Não incluir SQLite local, logs, caches ou `.env`.
- O executável continua compatível com `python -m smtp_bench_pro`.
