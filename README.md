# WhatsWeb

App Node.js (Express + Socket.IO + Baileys + SQLite) para enviar/receber mensagens WhatsApp com múltiplas contas, UI web e API.

## Avisos importantes
- **Não suba** banco (`whatsweb.db`), pastas de credenciais (`auth/`) ou logs no Git.
- **Nunca** publique segredos (RB_TOKEN, COOKIE_SECRET, senhas) no repositório.

## Requisitos
- Node.js 20+
- SQLite (via `better-sqlite3`)
- Linux com systemd (produção)

## Configuração
1. Copie `.env.example` para `.env` e preencha:
   - `COOKIE_SECRET`: gere com `openssl rand -hex 32`
   - `MASTER_EMAIL` e `MASTER_PASSWORD` (criam o usuário MASTER no primeiro boot)
   - `RB_TOKEN` (para a rota `/api/rb/<TOKEN>/send`)
2. Instale deps:
   ```bash
   npm install
   npm rebuild better-sqlite3 --build-from-source --unsafe-perm || true
   ```

## Rodar em desenvolvimento
```bash
NODE_ENV=development node server.js
# Abra http://localhost:3000
```

## Produção (systemd)
1. Edite `deploy/whatsweb.service.example` ou use `EnvironmentFile=/opt/whatsweb/.env`.
2. Instale o serviço:
   ```bash
   sudo cp deploy/whatsweb.service.example /etc/systemd/system/whatsweb.service
   sudo systemctl daemon-reload
   sudo systemctl enable --now whatsweb
   ```

## Segurança
- Rotacione `RB_TOKEN` e `COOKIE_SECRET` se houver suspeita de vazamento.
- Para transferir o projeto a terceiros, **limpe**: `whatsweb.db`, `auth/`, logs e substitua segredos.

## Endpoints principais
- **UI**: `/dashboard`, `/auth/:accId`, `/chat/:accId`
- **API**:
  - `POST /api/v1/:token/send` `{ account, to, message }`
  - `GET  /api/v1/:token/threads?account=ID`
  - `GET  /api/v1/:token/thread?account=ID&numero=5511...`
  - `ANY /api/rb/:token/send?account=ID&to=5511...&message=...`

## Licença
Escolha e inclua uma licença (ex.: MIT).
