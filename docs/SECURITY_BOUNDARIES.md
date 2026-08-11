# Fronteiras de Segurança

## Padrão

SMTP Bench Pro opera em modo conservador por padrão.

## O que não faz

- autenticação SMTP real;
- envio de e-mail;
- `MAIL FROM`;
- `RCPT TO`;
- `DATA`;
- teste de Open Relay;
- brute force;
- enumeração de usuários por padrão.

## Perfis

| Perfil | Comportamento |
| :--- | :--- |
| `SAFE` | Executa apenas verificações conservadoras. |
| `EXTENDED` | Pode incluir `VRFY`, `EXPN` e `HELP`, de forma controlada. |
| `MANUAL` | Permite selecionar os comandos opcionais expostos pela interface. |

## DKIM

DKIM 0.4.0 usa apenas DNS TXT para selectors informados manualmente.

Não há autodiscovery, validação de assinatura real ou parsing de e-mail bruto.
