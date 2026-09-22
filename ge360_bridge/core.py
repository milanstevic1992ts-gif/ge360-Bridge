from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import subprocess
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge"))
SERVICES_FILE = STATE_DIR / "services.json"
DEVICES_FILE = STATE_DIR / "devices.json"
BRIDGE_ENV = STATE_DIR / "bridge.env"
WG_CONF = Path(os.environ.get("GE360_WG_CONF", "/etc/wireguard/wg0.conf"))

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")


class BridgeError(RuntimeError):
    pass


@dataclass
class Service:
    name: str
    listen_port: int
    target_host: str
    target_port: int
    allowed_devices: list[str]
    enabled: bool = True


@dataclass
class Device:
    name: str
    vpn_ip: str
    public_key: str
    preshared_key: str
    token: str
    enabled: bool = True


def _load(path: Path, default: Any) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return default


def _atomic_write(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, mode)
    tmp.replace(path)


def validate_name(name: str) -> str:
    if not SAFE_NAME.match(name):
        raise BridgeError("Nome non valido: usa lettere, numeri, punto, trattino o underscore (max 64).")
    return name


def validate_port(port: int) -> int:
    if not 1 <= int(port) <= 65535:
        raise BridgeError(f"Porta non valida: {port}")
    return int(port)


def list_services() -> list[dict[str, Any]]:
    return _load(SERVICES_FILE, [])


def save_services(items: list[dict[str, Any]]) -> None:
    _atomic_write(SERVICES_FILE, items)


def list_devices() -> list[dict[str, Any]]:
    return _load(DEVICES_FILE, [])


def save_devices(items: list[dict[str, Any]]) -> None:
    _atomic_write(DEVICES_FILE, items)


def next_device_ip(cidr: str = "10.88.0.0/24", server_ip: str = "10.88.0.1") -> str:
    network = ipaddress.ip_network(cidr, strict=False)
    used = {d.get("vpn_ip") for d in list_devices()}
    for ip in network.hosts():
        s = str(ip)
        if s == server_ip or s in used:
            continue
        return s
    raise BridgeError("Nessun IP VPN libero.")


def run(cmd: list[str], *, input_text: str | None = None, check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, input=input_text, text=True, capture_output=True, check=check)


def wg_keypair() -> tuple[str, str, str]:
    try:
        private = run(["wg", "genkey"]).stdout.strip()
        public = run(["wg", "pubkey"], input_text=private + "\n").stdout.strip()
        psk = run(["wg", "genpsk"]).stdout.strip()
    except (FileNotFoundError, subprocess.CalledProcessError) as exc:
        raise BridgeError("WireGuard non disponibile: installa il pacchetto wireguard-tools.") from exc
    return private, public, psk


def random_token() -> str:
    return secrets.token_urlsafe(32)


def register_service(name: str, listen_port: int, target_host: str, target_port: int, allowed_devices: list[str]) -> Service:
    validate_name(name)
    listen_port = validate_port(listen_port)
    target_port = validate_port(target_port)
    items = list_services()
    if any(s["name"] == name for s in items):
        raise BridgeError(f"Servizio già presente: {name}")
    if any(int(s["listen_port"]) == listen_port for s in items):
        raise BridgeError(f"Porta Bridge già usata: {listen_port}")
    known = {d["name"] for d in list_devices() if d.get("enabled", True)}
    unknown = sorted(set(allowed_devices) - known)
    if unknown:
        raise BridgeError("Dispositivi sconosciuti: " + ", ".join(unknown))
    service = Service(name, listen_port, target_host, target_port, sorted(set(allowed_devices)))
    items.append(asdict(service))
    save_services(items)
    return service


def remove_service(name: str) -> bool:
    items = list_services()
    new = [s for s in items if s.get("name") != name]
    if len(new) == len(items):
        return False
    save_services(new)
    return True


def revoke_device(name: str) -> Device | None:
    items = list_devices()
    found: Device | None = None
    for d in items:
        if d.get("name") == name:
            d["enabled"] = False
            found = Device(**d)
    save_devices(items)
    return found


def grant_device(service_name: str, device_name: str, grant: bool) -> dict[str, Any]:
    items = list_services()
    known = {d["name"] for d in list_devices() if d.get("enabled", True)}
    if device_name not in known:
        raise BridgeError(f"Dispositivo sconosciuto o revocato: {device_name}")
    for s in items:
        if s.get("name") == service_name:
            allowed = set(s.get("allowed_devices", []))
            if grant:
                allowed.add(device_name)
            else:
                allowed.discard(device_name)
            s["allowed_devices"] = sorted(allowed)
            save_services(items)
            return s
    raise BridgeError(f"Servizio non trovato: {service_name}")


def allowed_ips_for_service(service: dict[str, Any], devices: list[dict[str, Any]]) -> set[str]:
    by_name = {d["name"]: d for d in devices if d.get("enabled", True)}
    result: set[str] = set()
    for name in service.get("allowed_devices", []):
        if name in by_name:
            result.add(by_name[name]["vpn_ip"])
    return result
