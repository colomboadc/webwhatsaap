#!/usr/bin/env bash
set -euo pipefail

export DEBIAN_FRONTEND=noninteractive
TZ="America/Sao_Paulo"

# 0) Dependências básicas
apt-get update -y
apt-get install -y curl ca-certificates gnupg build-essential python3 make g++ chrony ufw libsqlite3-dev pkg-config git

# 1) Timezone & NTP
( timedatectl set-timezone "$TZ" || true )
systemctl enable --now chrony || true

# 2) Node.js 20 LTS
if ! command -v node >/dev/null || [ "$(node -v | sed 's/v//' | cut -d. -f1)" -lt 20 ]; then
  apt-get purge -y nodejs npm || true
  apt-get autoremove -y || true
  curl -fsSL https://deb.nodesource.com/setup_20.x | bash -
  apt-get install -y nodejs
else
  apt-get install -y npm || true
fi

# 3) App dir
mkdir -p /opt/whatsweb
cd /opt/whatsweb

# 4) Copie seus arquivos para /opt/whatsweb antes de rodar este script:
#    - server.js, package.json, package-lock.json (se houver)

# 5) Instalar deps
npm config set fund false
npm config set audit false
npm i @whiskeysockets/baileys socket.io express qrcode better-sqlite3 pino cors cookie-parser nanoid@3 axios --no-audit --no-fund
npm rebuild better-sqlite3 --build-from-source --unsafe-perm || true

# 6) .env
if [ ! -f .env ]; then
  echo "[INFO] Criando /opt/whatsweb/.env a partir do .env.example (preencha os valores)."
  if [ -f /root/.env.example ]; then
    cp /root/.env.example .env
  elif [ -f .env.example ]; then
    cp .env.example .env
  else
    cat > .env <<EOF
NODE_ENV=production
TZ=America/Sao_Paulo
COOKIE_SECRET=COLOQUE_AQUI_64_HEX
MASTER_EMAIL=provedor@provedor
MASTER_PASSWORD=0123456789
RB_TOKEN=DEFINA_AQUI
EOF
  fi
  echo "[ATENÇÃO] Edite /opt/whatsweb/.env antes de iniciar o serviço."
fi

# 7) Service file
install -d /etc/systemd/system
if [ ! -f /etc/systemd/system/whatsweb.service ]; then
  if [ -f ./deploy/whatsweb.service.example ]; then
    cp ./deploy/whatsweb.service.example /etc/systemd/system/whatsweb.service
  else
    cat > /etc/systemd/system/whatsweb.service <<'SERVICE'
[Unit]
Description=WhatsWeb (Baileys + SQLite + Multiusuarios + Webhook + API)
After=network-online.target
Wants=network-online.target

[Service]
User=root
WorkingDirectory=/opt/whatsweb
ExecStart=/usr/bin/node /opt/whatsweb/server.js
Restart=always
RestartSec=2
StandardOutput=append:/var/log/whatsweb.log
StandardError=append:/var/log/whatsweb.log
EnvironmentFile=/opt/whatsweb/.env

[Install]
WantedBy=multi-user.target
SERVICE
  fi
fi

# 8) Abrir porta
ufw allow 3000/tcp || true

# 9) Ativar serviço
systemctl daemon-reload
systemctl enable --now whatsweb

# 10) Saída
IP=$(hostname -I 2>/dev/null | awk "{print $1}") || true
[ -z "$IP" ] && IP="SEU_IP_DO_SERVIDOR"
cat <<OUT
=======================================================
✅ WhatsWeb instalado (serviço: whatsweb)
   Acesse:   http://$IP:3000/register
   Dashboard: http://$IP:3000/dashboard
-------------------------------------------------------
Preencha/valide /opt/whatsweb/.env antes de uso em produção.
Logs: /var/log/whatsweb.log
=======================================================
OUT
