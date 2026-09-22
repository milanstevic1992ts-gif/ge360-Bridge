#!/usr/bin/env bash
set -euo pipefail
RESOURCE_STATE=/etc/ge360-bridge/resources.json
LEGACY_STATE=/etc/ge360-bridge/services.json
STATE="$RESOURCE_STATE"
[[ -r "$STATE" ]] || STATE="$LEGACY_STATE"
HEALTH_PORT=8788
DASHBOARD_PORT=8789

ports="$HEALTH_PORT,$DASHBOARD_PORT"
if [[ -r "$STATE" ]]; then
  extra="$(python3 - "$STATE" <<'PY'
import json,sys
try:
    items=json.load(open(sys.argv[1], encoding='utf-8'))
except Exception:
    items=[]
ports=sorted({
    int(s.get('bridge_port', s.get('listen_port')))
    for s in items
    if s.get('enabled', True)
    and s.get('bridge_port', s.get('listen_port')) is not None
    and 1 <= int(s.get('bridge_port', s.get('listen_port'))) <= 65535
})
print(','.join(map(str, ports)))
PY
)"
  [[ -z "$extra" ]] || ports="$ports,$extra"
fi

nft delete table inet ge360_bridge 2>/dev/null || true
nft -f - <<NFT
table inet ge360_bridge {
  set service_ports {
    type inet_service
    elements = { $ports }
  }
  chain input_guard {
    type filter hook input priority -20; policy accept;
    iifname "wg0" ip daddr 10.88.0.1 ct state established,related accept
    iifname "wg0" ip daddr 10.88.0.1 tcp dport @service_ports accept
    iifname "wg0" drop
  }
  chain forward_guard {
    type filter hook forward priority -20; policy accept;
    iifname "wg0" drop
  }
}
NFT
