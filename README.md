<h1 align="center">SMTP Bench Pro</h1>

<p align="center">
  <strong>Benchmark, diagnóstico e auditoria profissional de servidores SMTP</strong>
</p>

<p align="center">
  <a href="https://github.com/leosgarcia/smtp-bench-pro"><img src="https://img.shields.io/badge/Reposit%C3%B3rio-smtp--bench--pro-111827?style=for-the-badge&logo=github" alt="Repositório smtp-bench-pro" /></a>
  <a href="https://python.org"><img src="https://img.shields.io/badge/Python-3.11%2B-3776AB?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" /></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/Licen%C3%A7a-MIT-blue.svg?style=for-the-badge" alt="Licença MIT" /></a>
  <a href="https://github.com/leosgarcia/smtp-bench-pro/actions"><img src="https://img.shields.io/github/actions/workflow/status/leosgarcia/smtp-bench-pro/ci.yml?branch=main&style=for-the-badge&label=CI" alt="Status da CI" /></a>
</p>

## Visão geral

**SMTP Bench Pro** é uma aplicação desktop desenvolvida pela **WL Tech** para benchmark, diagnóstico e análise de postura de segurança de servidores SMTP.

A ferramenta foi criada para administradores de sistemas, consultores de infraestrutura, equipes MSP, DevOps, NOC/SOC e profissionais de segurança que precisam avaliar servidores SMTP de forma reproduzível, conservadora e auditável.

A versão atual é **0.2.6** e já valida a arquitetura federada do ecossistema Bench Pro: funciona como aplicação standalone e também como módulo integrável no **Bench Pro Core** via Integration API v1.

## Recursos

- Interface desktop nativa em PySide6.
- Probes SMTP para portas 25 e 587.
- Probe SMTPS para porta 465.
- Captura de banner SMTP.
- Captura de EHLO antes e depois do STARTTLS.
- Inspeção de mecanismos AUTH sem credenciais.
- Detecção e handshake STARTTLS.
- Diagnóstico TLS e certificado.
- Perfis de diagnóstico: Seguro, Estendido e Manual.
- Diagnóstico controlado de comandos NOOP, HELP, VRFY e EXPN sem enumeração.
- Tempos por etapa e benchmark com múltiplas iterações.
- Findings de segurança com IDs estáveis, severidade, evidência e recomendação.
- Histórico master/detail reconstruído a partir de dados persistidos.
- Exportação fiel de execução histórica em JSON e HTML standalone.
- Comparação entre duas execuções históricas persistidas.
- SQLite próprio com migrations até schema v3.
- Integration API v1 para hospedagem no Bench Pro Core.

## Fronteiras de segurança

SMTP Bench Pro **não** é cliente de e-mail e **não** é scanner agressivo.

A versão 0.2.6 não executa:

- autenticação real;
- envio de e-mail;
- teste de Open Relay;
- `MAIL FROM`;
- `RCPT TO`;
- `DATA`;
- brute force;
- enumeração de usuários.

VRFY e EXPN são usados apenas como diagnóstico controlado de postura quando o usuário escolhe explicitamente perfis Estendido ou Manual.

## Perfis de diagnóstico

| Perfil | Comportamento |
| :--- | :--- |
| Seguro | Executa TCP, banner, EHLO, STARTTLS/TLS, certificado, AUTH discovery via EHLO e NOOP. Não executa VRFY/EXPN. |
| Estendido | Inclui HELP, VRFY e EXPN com argumento neutro documentado. Pode gerar eventos nos logs do servidor SMTP. |
| Manual | Mantém a base segura e permite selecionar individualmente NOOP, HELP, VRFY e EXPN. |

O perfil padrão é **Seguro**.

## Histórico auditável

Cada execução persistida é tratada como fotografia imutável.

A aba Histórico permite:

- selecionar execução antiga;
- visualizar target, portas, perfil, opções e resultados;
- reconstruir SMTP, TLS, command diagnostics e findings;
- exportar a execução para JSON ou HTML;
- comparar duas execuções históricas;
- exportar comparações históricas para JSON ou HTML.

A visualização histórica nunca consulta o servidor novamente e nunca reavalia rules atuais.

## Exportação histórica

Formatos suportados:

- JSON UTF-8, legível e versionado por `format_version`;
- HTML standalone, sem JavaScript, sem CDN e com CSS embutido.

A exportação usa exclusivamente `SMTPRunDetails`.

Dados fornecidos por servidores são escapados no HTML para evitar interpolação insegura.

## Comparação histórica

A comparação responde:

```text
O que mudou entre estas duas fotografias persistidas?
```

Ela compara:

- metadata;
- performance por etapa;
- capabilities EHLO pre/post TLS;
- AUTH pre/post TLS;
- TLS e certificado;
- command diagnostics;
- lifecycle de findings: novo, resolvido, persistente e alterado.

Não há rede, reprobe ou reavaliação de regras durante a comparação. A comparação já calculada também pode ser exportada para JSON ou HTML diretamente a partir de `RunComparison`.

## Arquitetura

```text
smtp-bench-pro/
├── src/smtp_bench_pro/
│   ├── application/        # Serviços de aplicação e orquestração
│   ├── comparison/         # Comparação entre execuções históricas
│   ├── domain/             # Modelos e enums de domínio
│   ├── engine/             # Probes SMTP/TLS e benchmark engine
│   ├── export/             # Exportação histórica JSON/HTML
│   ├── integration/        # Adapter Integration API v1
│   ├── persistence/        # SQLite, migrations e repository
│   ├── security/           # Rule engine e findings
│   ├── ui/                 # PySide6 widgets, janelas e diálogos
│   ├── paths.py            # Diretórios por plataforma
│   ├── version.py          # Versão do produto
│   └── __main__.py         # Entrada standalone
├── tests/                  # Testes unitários, UI, persistência e contrato
├── scripts/                # Utilitários manuais
├── docs/                   # Operações e notas de release
├── pyproject.toml          # Metadados e ferramentas
└── requirements-dev.txt    # Dependências de desenvolvimento
```

## Instalação para desenvolvimento

```bash
git clone https://github.com/leosgarcia/smtp-bench-pro.git
cd smtp-bench-pro
python -m pip install -e ".[dev]"
```

## Uso

### Interface gráfica standalone

```bash
python -m smtp_bench_pro
```

### Versão

```bash
python -m smtp_bench_pro --version
```

### Integração com Bench Pro Core

Instalar em modo editable ao lado do Core:

```bash
cd benchpro-core
python -m pip install -e ..\smtp-bench-pro
python -m benchpro_core --list-modules
```

Exemplo esperado:

```text
SMTP Bench Pro 0.2.6 [API 1]
```

## Integration API

Entry point:

```toml
[project.entry-points."benchpro.modules"]
smtp = "smtp_bench_pro.integration.module:SMTPBenchModule"
```

Metadados:

```text
module_id = smtp
display_name = SMTP Bench Pro
version = 0.2.6
integration_api = 1
vendor = WL Tech
capabilities = benchmark, diagnostics, history, security_audit
```

SMTP Bench Pro não importa Bench Pro Core.

## Qualidade

```bash
pytest
ruff check .
bandit -r src
```

Estado atual validado:

- `pytest`: 80 testes passando
- `ruff`: sem violações
- `bandit`: sem achados relevantes
- standalone: validado
- integrado no Bench Pro Core: validado

## Fora de escopo nesta versão

- SPF
- DKIM
- DMARC
- MTA-STS
- TLS-RPT
- PTR
- RBL
- Open Relay
- AUTH real
- OAuth
- envio de e-mail
- score 0-100
- PDF
- dashboard do Core

## Roadmap

- 0.3: diagnósticos DNS de e-mail, incluindo MX/SPF.
- 0.4: DKIM e DMARC.
- 0.5: expansão de auditoria de segurança SMTP.
- 0.6: relatórios avançados.
- 0.7: empacotamento desktop.
- 0.8: hardening de integração com Core.
- 0.9: release candidate.
- 1.0: versão estável.

## Licença

SMTP Bench Pro é distribuído sob a [Licença MIT](LICENSE).

© 2026 WL Tech. Website: https://wltech.com.br





