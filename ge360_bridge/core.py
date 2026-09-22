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
GROUPS_FILE = STATE_DIR / "groups.json"
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
    denied_devices: list[str] = field(default_factory=list)
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


@dataclass
class Group:
    name: str
    description: str = ""
    device_ids: list[str] = field(default_factory=list)
    allowed_services: list[str] = field(default_factory=list)
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


def _normalize_service(service: dict[str, Any]) -> dict[str, Any]:
    result = dict(service)
    result["allowed_devices"] = sorted(set(result.get("allowed_devices") or []))
    result["denied_devices"] = sorted(set(result.get("denied_devices") or []))
    result["enabled"] = bool(result.get("enabled", True))
    return result


def _normalize_group(group: dict[str, Any]) -> dict[str, Any]:
    result = dict(group)
    result["name"] = str(result.get("name") or "")
    result["description"] = str(result.get("description") or "")[:500]
    result["device_ids"] = sorted(set(str(x) for x in (result.get("device_ids") or []) if x))
    result["allowed_services"] = sorted(set(str(x) for x in (result.get("allowed_services") or []) if x))
    result["enabled"] = bool(result.get("enabled", True))
    return result


def list_services() -> list[dict[str, Any]]:
    return [_normalize_service(s) for s in _load(SERVICES_FILE, [])]


def save_services(items: list[dict[str, Any]]) -> None:
    normalized = [_normalize_service(s) for s in items]
    _atomic_write(SERVICES_FILE, normalized)


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


def list_groups() -> list[dict[str, Any]]:
    return [_normalize_group(g) for g in _load(GROUPS_FILE, [])]


def save_groups(items: list[dict[str, Any]]) -> None:
    normalized = [_normalize_group(g) for g in items]
    names = [g["name"] for g in normalized]
    if len(names) != len(set(names)):
        raise BridgeError("Group Registry non valido: nome gruppo duplicato.")
    known_devices = {d["device_id"] for d in list_devices()}
    known_services = {s["name"] for s in list_services()}
    for group in normalized:
        validate_name(group["name"])
        unknown_devices = sorted(set(group["device_ids"]) - known_devices)
        if unknown_devices:
            raise BridgeError("Device sconosciuti nel gruppo: " + ", ".join(unknown_devices))
        unknown_services = sorted(set(group["allowed_services"]) - known_services)
        if unknown_services:
            raise BridgeError("Servizi sconosciuti nel gruppo: " + ", ".join(unknown_services))
    _atomic_write(GROUPS_FILE, normalized)


def upgrade_device_registry() -> int:
    raw = _load(DEVICES_FILE, [])
    now = utc_now_iso()
    upgraded = [_normalize_device(d, now) for d in raw]
    changed = sum(1 for before, after in zip(raw, upgraded) if before != after)
    if upgraded != raw:
        save_devices(upgraded)
    return changed


def upgrade_acl_registry() -> int:
    raw_services = _load(SERVICES_FILE, [])
    upgraded_services = [_normalize_service(s) for s in raw_services]
    changed = sum(1 for before, after in zip(raw_services, upgraded_services) if before != after)
    if upgraded_services != raw_services:
        save_services(upgraded_services)
    if not GROUPS_FILE.exists():
        _atomic_write(GROUPS_FILE, [])
    return changed


def find_device(identifier: str) -> dict[str, Any] | None:
    for d in list_devices():
        if d.get("device_id") == identifier or d.get("name") == identifier:
            return d
    return None


def find_group(name: str) -> dict[str, Any] | None:
    for group in list_groups():
        if group.get("name") == name:
            return group
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
    groups = list_groups()
    changed = False
    for group in groups:
        if name in group.get("allowed_services", []):
            group["allowed_services"] = [x for x in group["allowed_services"] if x != name]
            changed = True
    if changed:
        save_groups(groups)
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
    if any(d.get("name") == new_name for d in items if d is not target):
        raise BridgeError(f"Nome dispositivo già usato: {new_name}")
    target["name"] = new_name
    save_devices(items)

    services = list_services()
    changed = False
    for service in services:
        for field_name in ("allowed_devices", "denied_devices"):
            values = list(service.get(field_name, []))
            if old_name in values:
                service[field_name] = sorted({new_name if x == old_name else x for x in values})
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


def create_group(name: str, description: str = "") -> dict[str, Any]:
    validate_name(name)
    groups = list_groups()
    if any(g["name"] == name for g in groups):
        raise BridgeError(f"Gruppo già presente: {name}")
    group = asdict(Group(name=name, description=description.strip()[:500]))
    groups.append(group)
    save_groups(groups)
    return group


def remove_group(name: str) -> bool:
    groups = list_groups()
    new = [g for g in groups if g.get("name") != name]
    if len(new) == len(groups):
        return False
    save_groups(new)
    return True


def set_group_enabled(name: str, enabled: bool) -> dict[str, Any]:
    groups = list_groups()
    for group in groups:
        if group["name"] == name:
            group["enabled"] = bool(enabled)
            save_groups(groups)
            return group
    raise BridgeError(f"Gruppo non trovato: {name}")


def set_group_device(group_name: str, device_identifier: str, assigned: bool) -> dict[str, Any]:
    device = find_device(device_identifier)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    groups = list_groups()
    for group in groups:
        if group["name"] == group_name:
            members = set(group.get("device_ids", []))
            if assigned:
                members.add(device["device_id"])
            else:
                members.discard(device["device_id"])
            group["device_ids"] = sorted(members)
            save_groups(groups)
            return group
    raise BridgeError(f"Gruppo non trovato: {group_name}")


def set_group_service(group_name: str, service_name: str, allowed: bool) -> dict[str, Any]:
    if not any(s["name"] == service_name for s in list_services()):
        raise BridgeError(f"Servizio non trovato: {service_name}")
    groups = list_groups()
    for group in groups:
        if group["name"] == group_name:
            services = set(group.get("allowed_services", []))
            if allowed:
                services.add(service_name)
            else:
                services.discard(service_name)
            group["allowed_services"] = sorted(services)
            save_groups(groups)
            return group
    raise BridgeError(f"Gruppo non trovato: {group_name}")


def groups_for_device(device: dict[str, Any], groups: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    source = groups if groups is not None else list_groups()
    return [
        g for g in source
        if g.get("enabled", True) and device.get("device_id") in set(g.get("device_ids", []))
    ]


def set_device_access_override(service_name: str, device_identifier: str, decision: str) -> dict[str, Any]:
    device = find_device(device_identifier)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    if decision not in {"allow", "deny", "inherit"}:
        raise BridgeError("Override non valido: usa allow, deny o inherit.")
    services = list_services()
    for service in services:
        if service.get("name") != service_name:
            continue
        allowed = set(service.get("allowed_devices", []))
        denied = set(service.get("denied_devices", []))
        allowed.discard(device["name"])
        denied.discard(device["name"])
        if decision == "allow":
            allowed.add(device["name"])
        elif decision == "deny":
            denied.add(device["name"])
        service["allowed_devices"] = sorted(allowed)
        service["denied_devices"] = sorted(denied)
        save_services(services)
        return service
    raise BridgeError(f"Servizio non trovato: {service_name}")


def grant_device(service_name: str, device_name: str, grant: bool) -> dict[str, Any]:
    return set_device_access_override(service_name, device_name, "allow" if grant else "deny")


def service_access_source(
    service: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> str:
    if not device_is_active(device):
        return "inactive"
    name = device["name"]
    if name in set(service.get("denied_devices", [])):
        return "deny_override"
    if name in set(service.get("allowed_devices", [])):
        return "allow_override"
    for group in groups_for_device(device, groups):
        if service["name"] in set(group.get("allowed_services", [])):
            return f"group:{group['name']}"
    return "none"


def service_allows_device(
    service: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> bool:
    return service_access_source(service, device, groups) in {"allow_override"} or service_access_source(service, device, groups).startswith("group:")


def allowed_ips_for_service(
    service: dict[str, Any],
    devices: list[dict[str, Any]],
    groups: list[dict[str, Any]] | None = None,
) -> set[str]:
    source_groups = groups if groups is not None else list_groups()
    return {
        d["vpn_ip"]
        for d in devices
        if service_allows_device(service, d, source_groups)
    }


def effective_services_for_device(
    device: dict[str, Any],
    services: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    source_services = services if services is not None else list_services()
    source_groups = groups if groups is not None else list_groups()
    return [
        s for s in source_services
        if s.get("enabled", True) and service_allows_device(s, device, source_groups)
    ]
