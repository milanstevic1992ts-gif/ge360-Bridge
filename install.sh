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
PAIRING_PORT=8790
PY_DST=/opt/ge360-bridge
UPDATE_DIR=/var/lib/ge360-bridge/updates

say(){ printf '\n==> %s\n' "$*"; }

say "Installazione dipendenze"
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard-tools nftables qrencode python3 miniupnpc iproute2 curl openssl iputils-ping traceroute

say "Installazione GE360 Bridge"
install -d -m 700 "$STATE_DIR" "$STATE_DIR/pairings" "$STATE_DIR/backups" "$WG_DIR" "$UPDATE_DIR"
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

if [[ ! -s "$STATE_DIR/enrollment.key" ]]; then
  umask 077
  openssl rand -hex 32 > "$STATE_DIR/enrollment.key"
fi

if [[ ! -s "$STATE_DIR/pairing-tls.key" || ! -s "$STATE_DIR/pairing-tls.crt" ]]; then
  umask 077
  openssl req -x509 -newkey rsa:3072 -nodes -sha256 -days 3650 \
    -keyout "$STATE_DIR/pairing-tls.key" \
    -out "$STATE_DIR/pairing-tls.crt" \
    -subj "/CN=GE360 Bridge Pairing" >/dev/null 2>&1
fi

if [[ ! -e "$STATE_DIR/bridge.env" ]]; then
  cat > "$STATE_DIR/bridge.env" <<ENV
WG_INTERFACE=$WG_IF
WG_ADDRESS=$WG_ADDR
WG_PORT=$WG_PORT
PUBLIC_ENDPOINT=CHANGE_ME:$WG_PORT
CLIENT_DNS=
PAIRING_PORT=$PAIRING_PORT
TRAVERSAL_ENABLED=true
RELAY_ENABLED=false
RELAY_URL=
RELAY_CERT_SHA256=
ENV
else
  echo "Configurazione esistente preservata: $STATE_DIR/bridge.env"
  grep -q '^PAIRING_PORT=' "$STATE_DIR/bridge.env" || echo "PAIRING_PORT=$PAIRING_PORT" >> "$STATE_DIR/bridge.env"
  grep -q '^TRAVERSAL_ENABLED=' "$STATE_DIR/bridge.env" || echo "TRAVERSAL_ENABLED=true" >> "$STATE_DIR/bridge.env"
  grep -q '^RELAY_ENABLED=' "$STATE_DIR/bridge.env" || echo "RELAY_ENABLED=false" >> "$STATE_DIR/bridge.env"
  grep -q '^RELAY_URL=' "$STATE_DIR/bridge.env" || echo "RELAY_URL=" >> "$STATE_DIR/bridge.env"
  grep -q '^RELAY_CERT_SHA256=' "$STATE_DIR/bridge.env" || echo "RELAY_CERT_SHA256=" >> "$STATE_DIR/bridge.env"
fi

[[ -e "$STATE_DIR/services.json" ]] || printf '[]\n' > "$STATE_DIR/services.json"
[[ -e "$STATE_DIR/devices.json" ]] || printf '[]\n' > "$STATE_DIR/devices.json"
[[ -e "$STATE_DIR/groups.json" ]] || printf '[]\n' > "$STATE_DIR/groups.json"
[[ -e "$STATE_DIR/enrollments.json" ]] || printf '[]\n' > "$STATE_DIR/enrollments.json"
[[ -e "$STATE_DIR/self_heal_state.json" ]] || printf '{}\n' > "$STATE_DIR/self_heal_state.json"

say "Migrazione registry Fasi 1-4 + Audit Fase 8"
PYTHONPATH="$PY_DST" python3 - <<'PY'
from ge360_bridge.core import upgrade_device_registry, upgrade_acl_registry, upgrade_resource_registry
from ge360_bridge.audit import init_db, audit_db_path
from ge360_bridge.metrics import init_db as init_metrics_db, metrics_db_path
print(f"Device migrati/aggiornati: {upgrade_device_registry()}")
print(f"ACL migrate/aggiornate: {upgrade_acl_registry()}")
print(f"Resource migrate/aggiornate: {upgrade_resource_registry()}")
init_db()
init_metrics_db()
print(f"Audit DB: {audit_db_path()}")
print(f"Metrics DB: {metrics_db_path()}")
PY

chmod 600 "$STATE_DIR"/*.json "$STATE_DIR"/audit.db "$STATE_DIR"/metrics.db "$STATE_DIR"/bridge.env "$STATE_DIR"/server.key "$STATE_DIR"/server.pub "$STATE_DIR"/dashboard.token "$STATE_DIR"/enrollment.key "$STATE_DIR"/pairing-tls.key "$STATE_DIR"/pairing-tls.crt
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
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-enrollment.service" /etc/systemd/system/ge360-bridge-enrollment.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-firewall.service" /etc/systemd/system/ge360-bridge-firewall.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-boot-verify.service" /etc/systemd/system/ge360-bridge-boot-verify.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-expiry.service" /etc/systemd/system/ge360-bridge-expiry.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-expiry.timer" /etc/systemd/system/ge360-bridge-expiry.timer
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-self-heal.service" /etc/systemd/system/ge360-bridge-self-heal.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-self-heal.timer" /etc/systemd/system/ge360-bridge-self-heal.timer
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-backup.service" /etc/systemd/system/ge360-bridge-backup.service
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-backup.timer" /etc/systemd/system/ge360-bridge-backup.timer
install -m 644 "$ROOT_DIR/systemd/ge360-bridge-relay-monitor.service" /etc/systemd/system/ge360-bridge-relay-monitor.service
install -m 755 "$ROOT_DIR/scripts/apply-firewall.sh" /usr/local/sbin/ge360-bridge-firewall
install -m 755 "$ROOT_DIR/scripts/boot-verify.sh" /usr/local/sbin/ge360-bridge-boot-verify

systemctl daemon-reload
systemctl enable --now "wg-quick@$WG_IF"
systemctl enable --now ge360-bridge-firewall.service
systemctl enable --now ge360-bridge.service
systemctl enable --now ge360-bridge-dashboard.service
systemctl enable --now ge360-bridge-enrollment.service
systemctl enable --now ge360-bridge-expiry.timer
systemctl enable --now ge360-bridge-self-heal.timer
systemctl enable --now ge360-bridge-backup.timer
systemctl enable ge360-bridge-boot-verify.service

ge360-bridge device-sync >/dev/null
ge360-bridge backup-create --scheduled --keep 10 >/dev/null

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
  LOCAL_IP="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
  upnpc -e 'GE360 Bridge' -a "$LOCAL_IP" "$WG_PORT" "$WG_PORT" UDP >/dev/null 2>&1 || true
  upnpc -e 'GE360 Pairing v2' -a "$LOCAL_IP" "$PAIRING_PORT" "$PAIRING_PORT" TCP >/dev/null 2>&1 || true
  sed -i "s#^PUBLIC_ENDPOINT=.*#PUBLIC_ENDPOINT=$WAN4:$WG_PORT#" "$STATE_DIR/bridge.env"
  echo "IPv4 WAN rilevato: $WAN4:$WG_PORT"
else
  echo "Endpoint pubblico non determinabile automaticamente."
  echo "Se sei sotto CGNAT e non hai IPv6 globale, una connessione diretta da Internet non è possibile senza relay/VPS esterno."
  echo "Altrimenti configura port-forward UDP $WG_PORT e PUBLIC_ENDPOINT in $STATE_DIR/bridge.env."
fi

if [[ -n "$WAN4" ]]; then
  LOCAL_IP="$(ip route get 1.1.1.1 | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -n1)"
  [[ -z "$LOCAL_IP" ]] || upnpc -e 'GE360 Pairing v2' -a "$LOCAL_IP" "$PAIRING_PORT" "$PAIRING_PORT" TCP >/dev/null 2>&1 || true
fi

say "Installazione completata"
echo "Versione: GE360 Bridge v0.22 - Fase 20 Relay opzionale"
echo "Dashboard locale: http://127.0.0.1:8789"
echo "Dashboard via Bridge: http://10.88.0.1:8789"
echo "Token dashboard: sudo cat $STATE_DIR/dashboard.token"
echo "Pairing HTTPS: porta TCP $PAIRING_PORT"
echo "Roadmap: docs/ROADMAP.md"
echo "Health Engine: ge360-bridge health-check"
echo "Diagnostica: ge360-bridge diagnose-resource rilievi --api-path /healthz --pdf-path /api/report.pdf"
echo "Connection Doctor: ge360-bridge doctor rilievi --device telefono-milan --api-path /healthz"
echo "Audit Log: ge360-bridge audit-list --limit 50"
echo "Metriche: ge360-bridge metrics --window 24h"
echo "Launcher device: http://10.88.0.1:8788/hub"
echo "Android SDK + VPN automatica: android-sdk/ge360-bridge-android"
echo "Backend discovery: ge360-bridge resource-discover"
echo "Linux Agent per host aggiuntivi: sudo ./install-agent.sh"
echo "Self-healing: ge360-bridge self-heal-status | sudo ge360-bridge self-heal-run --dry-run"
echo "Backup: sudo ge360-bridge backup-list | sudo ge360-bridge backup-create"
echo "Update Engine: sudo ge360-bridge update-status | sudo ge360-bridge update-run https://... --sha256 <SHA256>"
echo "NAT Discovery: ge360-bridge nat-discover"
echo "P2P Traversal: sudo ge360-bridge p2p-status"
echo "Relay opzionale: sudo ge360-bridge relay-status"
echo "Relay monitor è installato ma NON abilitato finché RELAY_ENABLED=false."
echo "I vecchi comandi service-* restano alias compatibili."
