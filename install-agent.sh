#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Esegui con sudo: sudo ./install-agent.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/etc/ge360-agent
PY_DST=/opt/ge360-agent

say(){ printf '\n==> %s\n' "$*"; }

say "Installazione dipendenze GE360 Linux Agent"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 iproute2 openssl

say "Installazione GE360 Linux Agent"
install -d -m 700 "$STATE_DIR"
install -d -m 755 "$PY_DST"
rm -rf "$PY_DST/ge360_bridge"
cp -a "$ROOT_DIR/ge360_bridge" "$PY_DST/"
install -m 755 "$ROOT_DIR/ge360-agent" /usr/local/sbin/ge360-agent

if [[ ! -s "$STATE_DIR/token" ]]; then
  umask 077
  python3 - <<'PY' > "$STATE_DIR/token"
import secrets
print(secrets.token_urlsafe(32))
PY
fi

if [[ ! -e "$STATE_DIR/agent.env" ]]; then
  cat > "$STATE_DIR/agent.env" <<'ENV'
GE360_AGENT_BIND=127.0.0.1
GE360_AGENT_PORT=8791
GE360_AGENT_DISCOVERY_TIMEOUT=0.6
ENV
else
  echo "Configurazione esistente preservata: $STATE_DIR/agent.env"
fi

if [[ ! -s "$STATE_DIR/tls.key" || ! -s "$STATE_DIR/tls.crt" ]]; then
  umask 077
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -keyout "$STATE_DIR/tls.key" \
    -out "$STATE_DIR/tls.crt" \
    -subj "/CN=GE360 Linux Agent" >/dev/null 2>&1
fi

chmod 600 "$STATE_DIR/token" "$STATE_DIR/agent.env" "$STATE_DIR/tls.key"
chmod 644 "$STATE_DIR/tls.crt"

install -m 644 "$ROOT_DIR/systemd/ge360-agent.service" /etc/systemd/system/ge360-agent.service

systemctl daemon-reload
systemctl enable --now ge360-agent.service

say "GE360 Linux Agent installato"
echo "Versione: GE360 Agent v0.23 - Fase 21 Multi-server"
echo "API locale: https://127.0.0.1:8791"
echo "Health pubblico minimo: https://127.0.0.1:8791/healthz"
echo "Manifest Agent: https://127.0.0.1:8791/.well-known/ge360-agent"
echo "TLS fingerprint SHA-256:"
openssl x509 -in "$STATE_DIR/tls.crt" -outform DER | sha256sum | awk '{print $1}'
echo "Token: sudo cat $STATE_DIR/token"
echo "Snapshot locale: sudo ge360-agent snapshot"
echo "Stato servizio: systemctl status ge360-agent --no-pager"
echo
echo "Default sicuro: bind solo loopback."
echo "Per un bind di rete modifica $STATE_DIR/agent.env soltanto se il trasporto verso l'Agent è già protetto."
