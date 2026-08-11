# Packaging Windows

## Objetivo

Esta documentação descreve a fundação de empacotamento Windows do SMTP Bench Pro.

O pacote inicial deve:

- gerar um executável Windows com PyInstaller;
- preservar o comportamento standalone;
- continuar compatível com Bench Pro Core;
- gravar dados em AppData, nunca ao lado do executável;
- evitar incluir bancos SQLite, logs, caches, segredos ou arquivos temporários no bundle.

## Requisitos

- Python 3.11+ para build;
- dependências de desenvolvimento instaladas;
- PyInstaller disponível no ambiente;
- repositório limpo antes do build.

## Estrutura esperada

```text
dist/
└── SMTP-Bench-Pro-0.4.0-Windows-x64/
    ├── SMTP Bench Pro.exe
    ├── _internal/
    └── assets/
```

O nome exato da pasta pode variar conforme a estratégia de build, mas o executável deve levar o nome do produto.

## Comando de build

```powershell
.\scripts\build_windows.ps1
```

O script deve:

- limpar `build/` e `dist/` anteriores;
- executar o PyInstaller a partir do spec versionado;
- falhar se o build retornar erro;
- produzir saída versionada.

## Smoke test

```powershell
.\scripts\smoke_windows.ps1
```

O smoke test deve validar:

- `--version` do executável;
- inicialização sem crash;
- uso de AppData para logs e banco;
- ausência de escrita ao lado do binário.

## Troubleshooting

- Se o build não localizar módulos, reinstale o pacote em editable ou revise os metadados do PyInstaller.
- Se o executável abrir sem widgets, valide o `QT_QPA_PLATFORM` e a inclusão de `PySide6`.
- Se o AppData não for criado, revise `smtp_bench_pro.paths`.

## Observações

- Não incluir SQLite local dentro do pacote.
- Não incluir `.env`, logs, caches ou arquivos temporários.
- Não empacotar o Core.
- Não alterar a Integration API.
