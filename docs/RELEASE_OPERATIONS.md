# Operações de Release do SMTP Bench Pro

Estes procedimentos documentam o fluxo operacional de release do SMTP Bench Pro. Revise os comandos antes de executar em qualquer ambiente.

## Versão atual

```text
SMTP Bench Pro v0.2.6
```

Notas públicas da versão:

```text
docs/releases/v0.2.6.md
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

## Criar tag

```bash
git fetch --tags
git tag -a v0.2.6 -m "SMTP Bench Pro v0.2.6"
git push origin main
git push origin v0.2.6
```

## Criar release manualmente

```bash
gh release create v0.2.6 \
  --repo leosgarcia/smtp-bench-pro \
  --title "SMTP Bench Pro v0.2.6" \
  --notes-file docs/releases/v0.2.6.md
```

## Artefatos futuros

A versão atual ainda não publica build PyInstaller oficial.

Quando o empacotamento for habilitado, os artefatos devem seguir padrão semelhante:

```text
SMTP-Bench-Pro-vX.Y.Z-Windows-x64.zip
SMTP-Bench-Pro-vX.Y.Z-Windows-x64.zip.sha256
SMTP-Bench-Pro-vX.Y.Z-Linux-x64.tar.gz
SMTP-Bench-Pro-vX.Y.Z-Linux-x64.tar.gz.sha256
```



