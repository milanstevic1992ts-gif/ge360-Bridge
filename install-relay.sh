#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Esegui con sudo: sudo ./install-relay.sh --public-host relay.example.com" >&2
  exit 1
fi

PUBLIC_HOST="${GE360_RELAY_PUBLIC_HOST:-}"
while [[ $# -gt 0 ]]; do
  case "$1" in
    --public-host) PUBLIC_HOST="${2:-}"; shift 2 ;;
    *) echo "Argomento sconosciuto: $1" >&2; exit 2 ;;
  esac
done

if [[ -z "$PUBLIC_HOST" ]]; then
  echo "Manca --public-host. Usa DNS o IPv4 pubblico del relay." >&2
  exit 2
fi
if [[ "$PUBLIC_HOST" == *"/"* || "$PUBLIC_HOST" == *" "* ]]; then
  echo "public-host non valido." >&2
  exit 2
fi
if [[ "$PUBLIC_HOST" == *:* ]]; then
  echo "Fase 20 relay richiede DNS o IPv4 pubblico; IPv6 usa il percorso direct/P2P." >&2
  exit 2
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/etc/ge360-relay
PY_DST=/opt/ge360-relay
CONTROL_PORT=8792
UDP_START=40000
UDP_END=40199

say(){ printf '\n==> %s\n' "$*"; }

say "Installazione dipendenze GE360 Relay"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y python3 openssl ca-certificates

say "Installazione software relay"
install -d -m 700 "$STATE_DIR"
install -d -m 755 "$PY_DST"
rm -rf "$PY_DST/ge360_bridge"
cp -a "$ROOT_DIR/ge360_bridge" "$PY_DST/"
install -m 755 "$ROOT_DIR/ge360-relay" /usr/local/sbin/ge360-relay

if [[ ! -s "$STATE_DIR/admin.token" ]]; then
  umask 077
  python3 - <<'PY' > "$STATE_DIR/admin.token"
import secrets
print(secrets.token_urlsafe(48))
PY
fi
chmod 600 "$STATE_DIR/admin.token"

if [[ ! -s "$STATE_DIR/tls.key" || ! -s "$STATE_DIR/tls.crt" ]]; then
  say "Generazione certificato TLS self-signed relay"
  SAN="$(python3 - "$PUBLIC_HOST" <<'PY'
import ipaddress,sys
value=sys.argv[1]
try:
    ipaddress.ip_address(value)
    print("IP:"+value)
except ValueError:
    print("DNS:"+value)
PY
)"
  umask 077
  openssl req -x509 -newkey rsa:3072 -sha256 -nodes \
    -keyout "$STATE_DIR/tls.key" \
    -out "$STATE_DIR/tls.crt" \
    -days 3650 \
    -subj "/CN=$PUBLIC_HOST" \
    -addext "subjectAltName=$SAN"
fi
chmod 600 "$STATE_DIR/tls.key"
chmod 644 "$STATE_DIR/tls.crt"

cat > "$STATE_DIR/relay.env" <<ENV
GE360_RELAY_BIND=0.0.0.0
GE360_RELAY_CONTROL_PORT=$CONTROL_PORT
GE360_RELAY_PUBLIC_HOST=$PUBLIC_HOST
GE360_RELAY_UDP_BIND=0.0.0.0
GE360_RELAY_UDP_START=$UDP_START
GE360_RELAY_UDP_END=$UDP_END
GE360_RELAY_MAX_SESSIONS=50
GE360_RELAY_IDLE_SECONDS=90
GE360_RELAY_MAX_SECONDS=86400
ENV
chmod 600 "$STATE_DIR/relay.env"

install -m 644 "$ROOT_DIR/systemd/ge360-relay.service" /etc/systemd/system/ge360-relay.service
systemctl daemon-reload
systemctl enable --now ge360-relay.service

FINGERPRINT="$(openssl x509 -in "$STATE_DIR/tls.crt" -outform DER | sha256sum | awk '{print $1}')"
TOKEN="$(cat "$STATE_DIR/admin.token")"

say "GE360 Relay installato"
echo "Versione: GE360 Relay v0.22 - Fase 20"
echo "Control HTTPS: https://$PUBLIC_HOST:$CONTROL_PORT"
echo "UDP session range: $UDP_START-$UDP_END"
echo "Health: https://$PUBLIC_HOST:$CONTROL_PORT/healthz"
echo
echo "Sul firewall/router/VPS devi consentire:"
echo "  TCP $CONTROL_PORT"
echo "  UDP $UDP_START-$UDP_END"
echo
echo "Configurazione da copiare sul Bridge:"
echo "  RELAY_ENABLED=true"
echo "  RELAY_URL=https://$PUBLIC_HOST:$CONTROL_PORT"
echo "  RELAY_CERT_SHA256=$FINGERPRINT"
echo
echo "Token amministrativo da copiare SOLO in /etc/ge360-bridge/relay.token:"
echo "  $TOKEN"
echo
echo "Poi sul Bridge:"
echo "  sudo chmod 600 /etc/ge360-bridge/relay.token"
echo "  sudo systemctl enable --now ge360-bridge-relay-monitor.service"
echo
echo "Il relay non apre automaticamente firewall e non vede Resource o payload in chiaro."
