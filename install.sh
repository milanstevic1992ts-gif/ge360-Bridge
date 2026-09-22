#!/usr/bin/env bash
set -euo pipefail

if [[ ${EUID:-$(id -u)} -ne 0 ]]; then
  echo "Esegui con sudo: sudo ./install.sh" >&2
  exit 1
fi

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
STATE_DIR=/etc/ge360-bridge
WG_DIR=/etc/wireguard
WG_IF=wg0
WG_ADDR=10.88.0.1/24
WG_PORT=51820
PY_DST=/opt/ge360-bridge

say(){ printf '\n==> %s\n' "$*"; }

say "Installazione dipendenze"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools nftables qrencode python3 miniupnpc iproute2 curl

say "Installazione GE360 Bridge"
install -d -m 700 "$STATE_DIR" "$STATE_DIR/pairings" "$WG_DIR"
install -d -m 755 "$PY_DST"
rm -rf "$PY_DST/ge360_bridge"
cp -a "$ROOT_DIR/ge360_bridge" "$PY_DST/"
install -m 755 "$ROOT_DIR/ge360-bridge" /usr/local/sbin/ge360-bridge

if [[ ! -s "$STATE_DIR/server.key" ]]; then
  umask 077
  wg genkey > "$STATE_DIR/server.key"
  wg pubkey < "$STATE_DIR/server.key" > "$STATE_DIR/server.pub"
fi
SERVER_PRIV="$(cat "$STATE_DIR/server.key")"

if [[ ! -s "$STATE_DIR/dashboard.token" ]]; then
  umask 077
  python3 - <<'PY' > "$STATE_DIR/dashboard.token"
import secrets
print(secrets.token_urlsafe(32))
PY
fi

if [[ ! -e "$STATE_DIR/bridge.env" ]]; then
  cat > "$STATE_DIR/bridge.env" <<ENV
WG_INTERFACE=$WG_IF
WG_ADDRESS=$WG_ADDR
WG_PORT=$WG_PORT
PUBLIC_ENDPOINT=CHANGE_ME:$WG_PORT
CLIENT_DNS=
ENV
else
  echo "Configurazione esistente preservata: $STATE_DIR/bridge.env"
fi

[[ -e "$STATE_DIR/services.json" ]] || printf '[]\n' > "$STATE_DIR/services.json"
[[ -e "$STATE_DIR/devices.json" ]] || printf '[]\n' > "$STATE_DIR/devices.json"
[[ -e "$STATE_DIR/groups.json" ]] || printf '[]\n' > "$STATE_DIR/groups.json"

say "Migrazione registry Fase 1 + ACL Fase 2"
PYTHONPATH="$PY_DST" python3 - <<'PY'
from ge360_bridge.core import upgrade_device_registry, upgrade_acl_registry
print(f"Device migrati/aggiornati: {upgrade_device_registry()}")
print(f"Servizi ACL migrati/aggiornati: {upgrade_acl_registry()}")
PY

chmod 600 "$STATE_DIR"/*.json "$STATE_DIR"/bridge.env "$STATE_DIR"/server.key "$STATE_DIR"/server.pub "$STATE_DIR"/dashboard.token
chmod 700 "$STATE_DIR/pairings"

if [[ ! -e "$WG_DIR/$WG_IF.conf" ]]; then
  cat > "$WG_DIR/$WG_IF.conf" <<WG
[Interface]
Address = $WG_ADDR
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIV
SaveConfig = false
WG
else
  echo "Configurazione WireGuard esistente preservata: $WG_DIR/$WG_IF.conf"
fi
chmod 600 "$WG_DIR/$WG_IF.conf"

install -m 644 "$ROOT_DIR/systemd/ge360-bridge.service" /etc/systemd/system/ge360-bridge.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-dashboard.service" /etc/systemd/system/ge360-bridge-dashboard.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-firewall.service" /etc/systemd/system/ge360-bridge-firewall.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-boot-verify.service" /etc/systemd/system/ge360-bridge-boot-verify.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-expiry.service" /etc/systemd/system/ge360-bridge-expiry.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-expiry.timer" /etc/systemd/system/ge360-bridge-expiry.timer
install -m 755 "$ROOT_DIR/scripts/apply-firewall.sh" /usr/local/sbin/ge360-bridge-firewall
install -m 755 "$ROOT_DIR/scripts/boot-verify.sh" /usr/local/sbin/ge360-bridge-boot-verify

systemctl daemon-reload
systemctl enable --now "wg-quick@$WG_IF"
systemctl enable --now ge360-bridge-firewall.service
systemctl enable --now ge360-bridge.service
systemctl enable --now ge360-bridge-dashboard.service
systemctl enable --now ge360-bridge-expiry.timer
systemctl enable ge360-bridge-boot-verify.service

ge360-bridge device-sync >/dev/null

say "Rilevamento endpoint"
CURRENT_ENDPOINT="$(sed -n 's/^PUBLIC_ENDPOINT=//p' "$STATE_DIR/bridge.env" | head -n1)"
if [[ -n "$CURRENT_ENDPOINT" && "$CURRENT_ENDPOINT" != CHANGE_ME:* ]]; then
  echo "Endpoint esistente preservato: $CURRENT_ENDPOINT"
  KEEP_ENDPOINT=1
else
  KEEP_ENDPOINT=0
fi
IPV6="$(ip -6 -o addr show scope global 2>/dev/null | awk '$4 !~ /^fe80/ {sub(/\/.*$/,"",$4); print $4; exit}')"
UPNP_OUT="$(upnpc -s 2>/dev/null || true)"
WAN4="$(printf '%s\n' "$UPNP_OUT" | sed -n 's/.*ExternalIPAddress = \([^ ]*\).*/\1/p' | head -n1)"

if [[ "$KEEP_ENDPOINT" -eq 1 ]]; then
  :
elif [[ -n "$IPV6" ]]; then
  sed -i "s#^PUBLIC_ENDPOINT=.*#PUBLIC_ENDPOINT=[$IPV6]:$WG_PORT#" "$STATE_DIR/bridge.env"
  echo "IPv6 globale rilevato: [$IPV6]:$WG_PORT"
elif [[ -n "$WAN4" ]] && python3 - "$WAN4" <<'PY'
import ipaddress,sys
ip=ipaddress.ip_address(sys.argv[1])
sys.exit(0 if ip.is_global else 1)
PY
then
  upnpc -e 'GE360 Bridge' -a "$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)" "$WG_PORT" "$WG_PORT" UDP >/dev/null 2>&1 || true
  sed -i "s#^PUBLIC_ENDPOINT=.*#PUBLIC_ENDPOINT=$WAN4:$WG_PORT#" "$STATE_DIR/bridge.env"
  echo "IPv4 WAN rilevato: $WAN4:$WG_PORT"
else
  echo "Endpoint pubblico non determinabile automaticamente."
  echo "Se sei sotto CGNAT e non hai IPv6 globale, una connessione diretta da Internet non è possibile senza relay/VPS esterno."
  echo "Altrimenti configura port-forward UDP $WG_PORT e PUBLIC_ENDPOINT in $STATE_DIR/bridge.env."
fi

say "Installazione completata"
echo "Versione: GE360 Bridge v0.4 - Fase 2 Gruppi e ACL"
echo "Dashboard locale: http://127.0.0.1:8789"
echo "Dashboard via Bridge: http://10.88.0.1:8789"
echo "Token dashboard: sudo cat $STATE_DIR/dashboard.token"
echo "Roadmap: docs/ROADMAP.md"
echo "Esempio: sudo ge360-bridge group-create amministratori"
echo "Esempio: sudo ge360-bridge group-device-add amministratori telefono"
echo "Esempio: sudo ge360-bridge group-service-grant amministratori rilievi"
