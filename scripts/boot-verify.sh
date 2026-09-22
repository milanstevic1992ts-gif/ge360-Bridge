#!/usr/bin/env bash
set -euo pipefail
fail=0
for u in wg-quick@wg0 ge360-bridge-firewall ge360-bridge ge360-bridge-dashboard; do
  if ! systemctl is-active --quiet "$u"; then
    echo "[FAIL] $u non attivo" >&2
    fail=1
  fi
done
if ! ip addr show wg0 | grep -q '10\.88\.0\.1/24'; then
  echo "[FAIL] wg0 senza 10.88.0.1/24" >&2
  fail=1
fi
if ! curl -fsS --max-time 2 http://127.0.0.1:8789/healthz >/dev/null 2>&1; then
  echo "[FAIL] dashboard health non raggiungibile" >&2
  fail=1
fi
exit "$fail"
