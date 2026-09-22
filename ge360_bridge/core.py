from __future__ import annotations

import hashlib
import ipaddress
import json
import os
import re
import secrets
import subprocess
from dataclasses import asdict, dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge"))
SERVICES_FILE = STATE_DIR / "services.json"
DEVICES_FILE = STATE_DIR / "devices.json"
BRIDGE_ENV = STATE_DIR / "bridge.env"
WG_CONF = Path(os.environ.get("GE360_WG_CONF", "/etc/wireguard/wg0.conf"))

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
RESERVED_BRIDGE_PORTS = {8788, 8789}
LOOPBACK_TARGETS = {"127.0.0.1", "::1", "localhost"}
DEVICE_TYPES = {"android", "linux", "windows", "server", "tablet", "unknown"}
_UNSET = object()


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
    device_id: str
    name: str
    device_type: str
    owner: str
    vpn_ip: str
    public_key: str
    preshared_key: str
    token: str
    created_at: str
    expires_at: str | None = None
    notes: str = ""
    tags: list[str] = field(default_factory=list)
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


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def validate_name(name: str) -> str:
    if not SAFE_NAME.match(name):
        raise BridgeError("Nome non valido: usa lettere, numeri, punto, trattino o underscore (max 64).")
    return name


def validate_port(port: int) -> int:
    if not 1 <= int(port) <= 65535:
        raise BridgeError(f"Porta non valida: {port}")
    return int(port)


def validate_target_host(host: str) -> str:
    candidate = host.strip().lower()
    if candidate not in LOOPBACK_TARGETS:
        raise BridgeError("Target non consentito: GE360 Bridge accetta solo backend locali su 127.0.0.1, ::1 o localhost.")
    return candidate


def validate_device_type(device_type: str) -> str:
    value = (device_type or "unknown").strip().lower()
    if value not in DEVICE_TYPES:
        raise BridgeError("Tipo dispositivo non valido: android, linux, windows, server, tablet o unknown.")
    return value


def validate_expiry(value: str | None) -> str | None:
    if value in (None, ""):
        return None
    try:
        date.fromisoformat(value)
    except ValueError as exc:
        raise BridgeError("Scadenza non valida: usa YYYY-MM-DD.") from exc
    return value


def normalize_tags(tags: list[str] | tuple[str, ...] | None) -> list[str]:
    out: list[str] = []
    for raw in tags or []:
        tag = str(raw).strip().lower()
        if not tag:
            continue
        if not SAFE_TAG.match(tag):
            raise BridgeError(f"Tag non valido: {tag}")
        if tag not in out:
            out.append(tag)
    return sorted(out)


def new_device_id() -> str:
    return "dev_" + secrets.token_hex(6)


def legacy_device_id(device: dict[str, Any]) -> str:
    material = "|".join([
        str(device.get("public_key", "")),
        str(device.get("vpn_ip", "")),
        str(device.get("name", "")),
    ])
    return "dev_" + hashlib.sha256(material.encode("utf-8")).hexdigest()[:12]


def _normalize_device(device: dict[str, Any], created_at_default: str = "") -> dict[str, Any]:
    result = dict(device)
    result["device_id"] = str(result.get("device_id") or legacy_device_id(result))
    result["name"] = str(result.get("name") or "")
    result["device_type"] = str(result.get("device_type") or "unknown").lower()
    if result["device_type"] not in DEVICE_TYPES:
        result["device_type"] = "unknown"
    result["owner"] = str(result.get("owner") or "")
    result["created_at"] = str(result.get("created_at") or created_at_default)
    result["expires_at"] = result.get("expires_at") or None
    result["notes"] = str(result.get("notes") or "")
    try:
        result["tags"] = normalize_tags(list(result.get("tags") or []))
    except BridgeError:
        result["tags"] = []
    result["enabled"] = bool(result.get("enabled", True))
    return result


def list_services() -> list[dict[str, Any]]:
    return _load(SERVICES_FILE, [])


def save_services(items: list[dict[str, Any]]) -> None:
    _atomic_write(SERVICES_FILE, items)


def list_devices() -> list[dict[str, Any]]:
    items = _load(DEVICES_FILE, [])
    return [_normalize_device(d) for d in items]


def save_devices(items: list[dict[str, Any]]) -> None:
    now = utc_now_iso()
    normalized = [_normalize_device(d, now) for d in items]
    ids = [d["device_id"] for d in normalized]
    names = [d["name"] for d in normalized]
    if len(ids) != len(set(ids)):
        raise BridgeError("Device Registry non valido: device_id duplicato.")
    if len(names) != len(set(names)):
        raise BridgeError("Device Registry non valido: nome dispositivo duplicato.")
    _atomic_write(DEVICES_FILE, normalized)


def upgrade_device_registry() -> int:
    raw = _load(DEVICES_FILE, [])
    now = utc_now_iso()
    upgraded = [_normalize_device(d, now) for d in raw]
    changed = sum(1 for before, after in zip(raw, upgraded) if before != after)
    if upgraded != raw:
        save_devices(upgraded)
    return changed


def find_device(identifier: str) -> dict[str, Any] | None:
    for d in list_devices():
        if d.get("device_id") == identifier or d.get("name") == identifier:
            return d
    return None


def device_is_expired(device: dict[str, Any], today: date | None = None) -> bool:
    expiry = device.get("expires_at")
    if not expiry:
        return False
    try:
        expiry_date = date.fromisoformat(str(expiry))
    except ValueError:
        return False
    return expiry_date < (today or date.today())


def device_is_active(device: dict[str, Any], today: date | None = None) -> bool:
    return bool(device.get("enabled", True)) and not device_is_expired(device, today)


def next_device_ip(cidr: str = "10.88.0.0/24", server_ip: str = "10.88.0.1") -> str:
    network = ipaddress.ip_network(cidr, strict=False)
    used = {d.get("vpn_ip") for d in list_devices()}
    for ip in network.hosts():
        value = str(ip)
        if value == server_ip or value in used:
            continue
        return value
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
    target_host = validate_target_host(target_host)
    if listen_port in RESERVED_BRIDGE_PORTS:
        raise BridgeError(f"Porta Bridge riservata al sistema: {listen_port}")
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


def set_device_enabled(identifier: str, enabled: bool) -> dict[str, Any] | None:
    items = list_devices()
    found = None
    for d in items:
        if d.get("device_id") == identifier or d.get("name") == identifier:
            d["enabled"] = bool(enabled)
            found = d
            break
    if found is not None:
        save_devices(items)
    return found


def revoke_device(identifier: str) -> dict[str, Any] | None:
    return set_device_enabled(identifier, False)


def rename_device(identifier: str, new_name: str) -> dict[str, Any]:
    validate_name(new_name)
    items = list_devices()
    if any(d.get("name") == new_name and d.get("device_id") != identifier and d.get("name") != identifier for d in items):
        raise BridgeError(f"Nome dispositivo già usato: {new_name}")
    target = None
    old_name = ""
    for d in items:
        if d.get("device_id") == identifier or d.get("name") == identifier:
            target = d
            old_name = d["name"]
            break
    if target is None:
        raise BridgeError("Dispositivo non trovato.")
    if new_name == old_name:
        return target
    if any(d.get("name") == new_name and d is not target for d in items):
        raise BridgeError(f"Nome dispositivo già usato: {new_name}")
    target["name"] = new_name
    save_devices(items)

    services = list_services()
    changed = False
    for service in services:
        allowed = list(service.get("allowed_devices", []))
        if old_name in allowed:
            service["allowed_devices"] = sorted({new_name if x == old_name else x for x in allowed})
            changed = True
    if changed:
        save_services(services)
    return target


def update_device_metadata(
    identifier: str,
    *,
    device_type: str | None = None,
    owner: str | None = None,
    expires_at: str | None | object = _UNSET,
    notes: str | None = None,
    tags: list[str] | None = None,
) -> dict[str, Any]:
    items = list_devices()
    target = None
    for d in items:
        if d.get("device_id") == identifier or d.get("name") == identifier:
            target = d
            break
    if target is None:
        raise BridgeError("Dispositivo non trovato.")
    if device_type is not None:
        target["device_type"] = validate_device_type(device_type)
    if owner is not None:
        target["owner"] = owner.strip()[:120]
    if expires_at is not _UNSET:
        target["expires_at"] = validate_expiry(expires_at if isinstance(expires_at, str) else None)
    if notes is not None:
        target["notes"] = notes.strip()[:1000]
    if tags is not None:
        target["tags"] = normalize_tags(tags)
    save_devices(items)
    return target


def grant_device(service_name: str, device_name: str, grant: bool) -> dict[str, Any]:
    items = list_services()
    known = {d["name"] for d in list_devices() if d.get("enabled", True)}
    if device_name not in known:
        raise BridgeError(f"Dispositivo sconosciuto o disabilitato: {device_name}")
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
    by_name = {d["name"]: d for d in devices if device_is_active(d)}
    result: set[str] = set()
    for name in service.get("allowed_devices", []):
        if name in by_name:
            result.add(by_name[name]["vpn_ip"])
    return result
