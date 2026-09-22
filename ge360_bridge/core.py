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
from urllib.parse import urlsplit

STATE_DIR = Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge"))
SERVICES_FILE = STATE_DIR / "services.json"  # legacy compatibility mirror
RESOURCES_FILE = STATE_DIR / "resources.json"
DEVICES_FILE = STATE_DIR / "devices.json"
GROUPS_FILE = STATE_DIR / "groups.json"
BRIDGE_ENV = STATE_DIR / "bridge.env"
WG_CONF = Path(os.environ.get("GE360_WG_CONF", "/etc/wireguard/wg0.conf"))

SAFE_NAME = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SAFE_TAG = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,31}$")
RESERVED_BRIDGE_PORTS = {8788, 8789, 8790}
LOOPBACK_TARGETS = {"127.0.0.1", "::1", "localhost"}
DEVICE_TYPES = {"android", "linux", "windows", "server", "tablet", "unknown"}
RESOURCE_PROTOCOLS = {"tcp", "http", "https"}
_UNSET = object()


class BridgeError(RuntimeError):
    pass


@dataclass
class Resource:
    name: str
    bridge_port: int
    target_host: str
    target_port: int
    allowed_devices: list[str]
    icon: str = "server"
    description: str = ""
    protocol: str = "tcp"
    health_url: str = ""
    timeout_seconds: float = 2.0
    denied_devices: list[str] = field(default_factory=list)
    enabled: bool = True

    @property
    def listen_port(self) -> int:
        return self.bridge_port


# Python API compatibility for older GE360 Bridge modules.
Service = Resource


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


def validate_resource_protocol(protocol: str) -> str:
    value = (protocol or "tcp").strip().lower()
    if value not in RESOURCE_PROTOCOLS:
        raise BridgeError("Protocollo Resource non valido: usa tcp, http o https.")
    return value


def validate_resource_icon(icon: str) -> str:
    value = (icon or "server").strip()
    if not value:
        return "server"
    if len(value) > 64 or any(ord(ch) < 32 for ch in value):
        raise BridgeError("Icona Resource non valida.")
    return value


def validate_timeout_seconds(value: float | int | str) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise BridgeError("Timeout Resource non valido.") from exc
    if timeout < 0.1 or timeout > 30.0:
        raise BridgeError("Timeout Resource non valido: usa un valore tra 0.1 e 30 secondi.")
    return round(timeout, 3)


def validate_health_url(value: str | None, target_host: str, target_port: int) -> str:
    health = (value or "").strip()
    if not health:
        return ""
    if len(health) > 500:
        raise BridgeError("Health URL troppo lunga.")
    if health.startswith("/"):
        return health
    parsed = urlsplit(health)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise BridgeError("Health URL non valida: usa /percorso oppure http(s) su loopback.")
    if parsed.username or parsed.password or parsed.fragment:
        raise BridgeError("Health URL non valida.")
    if parsed.hostname.lower() not in LOOPBACK_TARGETS:
        raise BridgeError("Health URL deve puntare a un backend locale loopback.")
    try:
        explicit_port = parsed.port
    except ValueError as exc:
        raise BridgeError("Porta Health URL non valida.") from exc
    effective_port = explicit_port or (443 if parsed.scheme == "https" else 80)
    if effective_port != int(target_port):
        raise BridgeError("Health URL deve usare la stessa target port della Resource.")
    return health


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


def _normalize_resource(resource: dict[str, Any]) -> dict[str, Any]:
    result = dict(resource)
    result["name"] = str(result.get("name") or "")
    bridge_port = result.get("bridge_port", result.get("listen_port", 0))
    result["bridge_port"] = int(bridge_port)
    result["listen_port"] = int(bridge_port)  # compatibility alias persisted intentionally
    result["target_host"] = str(result.get("target_host") or "127.0.0.1").lower()
    result["target_port"] = int(result.get("target_port") or 0)
    protocol = str(result.get("protocol") or "tcp").lower()
    result["protocol"] = protocol if protocol in RESOURCE_PROTOCOLS else "tcp"
    result["icon"] = str(result.get("icon") or "server")[:64]
    result["description"] = str(result.get("description") or "")[:500]
    result["health_url"] = str(result.get("health_url") or "")[:500]
    try:
        result["timeout_seconds"] = validate_timeout_seconds(result.get("timeout_seconds", 2.0))
    except BridgeError:
        result["timeout_seconds"] = 2.0
    result["allowed_devices"] = sorted(set(result.get("allowed_devices") or []))
    result["denied_devices"] = sorted(set(result.get("denied_devices") or []))
    result["enabled"] = bool(result.get("enabled", True))
    return result


# Compatibility name used by older code/tests.
_normalize_service = _normalize_resource


def _normalize_group(group: dict[str, Any]) -> dict[str, Any]:
    result = dict(group)
    result["name"] = str(result.get("name") or "")
    result["description"] = str(result.get("description") or "")[:500]
    result["device_ids"] = sorted(set(str(x) for x in (result.get("device_ids") or []) if x))
    legacy = result.get("allowed_services") or result.get("allowed_resources") or []
    result["allowed_services"] = sorted(set(str(x) for x in legacy if x))
    result["allowed_resources"] = list(result["allowed_services"])
    result["enabled"] = bool(result.get("enabled", True))
    return result


def list_resources() -> list[dict[str, Any]]:
    raw_resources = _load(RESOURCES_FILE, [])
    if raw_resources:
        source = raw_resources
    else:
        source = _load(SERVICES_FILE, [])
    return [_normalize_resource(r) for r in source]


def save_resources(items: list[dict[str, Any]]) -> None:
    normalized = [_normalize_resource(r) for r in items]
    names = [r["name"] for r in normalized]
    ports = [int(r["bridge_port"]) for r in normalized]
    if len(names) != len(set(names)):
        raise BridgeError("Resource Registry non valido: nome duplicato.")
    if len(ports) != len(set(ports)):
        raise BridgeError("Resource Registry non valido: bridge port duplicata.")
    _atomic_write(RESOURCES_FILE, normalized)
    # Keep a compatibility mirror so older scripts/rollbacks do not lose service state.
    _atomic_write(SERVICES_FILE, normalized)


def list_services() -> list[dict[str, Any]]:
    return list_resources()


def save_services(items: list[dict[str, Any]]) -> None:
    save_resources(items)


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
    known_resources = {r["name"] for r in list_resources()}
    for group in normalized:
        validate_name(group["name"])
        unknown_devices = sorted(set(group["device_ids"]) - known_devices)
        if unknown_devices:
            raise BridgeError("Device sconosciuti nel gruppo: " + ", ".join(unknown_devices))
        unknown_resources = sorted(set(group["allowed_services"]) - known_resources)
        if unknown_resources:
            raise BridgeError("Resource sconosciute nel gruppo: " + ", ".join(unknown_resources))
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
    upgraded = [_normalize_resource(s) for s in raw_services]
    changed = sum(1 for before, after in zip(raw_services, upgraded) if before != after)
    if upgraded:
        save_resources(upgraded)
    if not GROUPS_FILE.exists():
        _atomic_write(GROUPS_FILE, [])
    return changed


def upgrade_resource_registry() -> int:
    raw_resources = _load(RESOURCES_FILE, [])
    legacy_services = _load(SERVICES_FILE, [])
    source = raw_resources if raw_resources else legacy_services
    upgraded = [_normalize_resource(r) for r in source]
    changed = sum(1 for before, after in zip(source, upgraded) if before != after)
    if source != upgraded or not RESOURCES_FILE.exists():
        save_resources(upgraded)
    elif upgraded:
        # Ensure compatibility mirror is synchronized as well.
        _atomic_write(SERVICES_FILE, upgraded)
    return changed + (1 if source and not raw_resources else 0)


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


def find_resource(name: str) -> dict[str, Any] | None:
    for resource in list_resources():
        if resource.get("name") == name:
            return resource
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


def _audit_acl(
    action: str,
    *,
    device: dict[str, Any] | None = None,
    resource: str | None = None,
    result: str | None = None,
) -> None:
    try:
        from .audit import write_event
        write_event(
            "ACL_CHANGED",
            device_id=device.get("device_id") if device else None,
            device_name=device.get("name") if device else None,
            resource=resource,
            action=action,
            result=result,
            ip=device.get("vpn_ip") if device else None,
        )
    except Exception:
        # L'audit non deve rendere fallibile una modifica ACL già applicata.
        pass


def register_resource(
    name: str,
    bridge_port: int,
    target_host: str,
    target_port: int,
    allowed_devices: list[str] | None = None,
    *,
    icon: str = "server",
    description: str = "",
    protocol: str = "tcp",
    health_url: str = "",
    timeout_seconds: float = 2.0,
) -> Resource:
    validate_name(name)
    bridge_port = validate_port(bridge_port)
    target_port = validate_port(target_port)
    target_host = validate_target_host(target_host)
    protocol = validate_resource_protocol(protocol)
    icon = validate_resource_icon(icon)
    timeout_seconds = validate_timeout_seconds(timeout_seconds)
    health_url = validate_health_url(health_url, target_host, target_port)
    if bridge_port in RESERVED_BRIDGE_PORTS:
        raise BridgeError(f"Porta Bridge riservata al sistema: {bridge_port}")
    items = list_resources()
    if any(r["name"] == name for r in items):
        raise BridgeError(f"Resource già presente: {name}")
    if any(int(r["bridge_port"]) == bridge_port for r in items):
        raise BridgeError(f"Porta Bridge già usata: {bridge_port}")
    known = {d["name"] for d in list_devices() if d.get("enabled", True)}
    requested = sorted(set(allowed_devices or []))
    unknown = sorted(set(requested) - known)
    if unknown:
        raise BridgeError("Dispositivi sconosciuti: " + ", ".join(unknown))
    resource = Resource(
        name=name,
        bridge_port=bridge_port,
        target_host=target_host,
        target_port=target_port,
        allowed_devices=requested,
        icon=icon,
        description=description.strip()[:500],
        protocol=protocol,
        health_url=health_url,
        timeout_seconds=timeout_seconds,
    )
    items.append(asdict(resource))
    save_resources(items)
    return resource


def register_service(name: str, listen_port: int, target_host: str, target_port: int, allowed_devices: list[str]) -> Resource:
    return register_resource(name, listen_port, target_host, target_port, allowed_devices)


def update_resource(
    name: str,
    *,
    icon: str | None = None,
    description: str | None = None,
    protocol: str | None = None,
    bridge_port: int | None = None,
    target_host: str | None = None,
    target_port: int | None = None,
    health_url: str | None = None,
    timeout_seconds: float | None = None,
    enabled: bool | None = None,
) -> dict[str, Any]:
    items = list_resources()
    target = next((r for r in items if r["name"] == name), None)
    if target is None:
        raise BridgeError(f"Resource non trovata: {name}")

    new_bridge_port = validate_port(bridge_port if bridge_port is not None else target["bridge_port"])
    if new_bridge_port in RESERVED_BRIDGE_PORTS:
        raise BridgeError(f"Porta Bridge riservata al sistema: {new_bridge_port}")
    if any(r["name"] != name and int(r["bridge_port"]) == new_bridge_port for r in items):
        raise BridgeError(f"Porta Bridge già usata: {new_bridge_port}")

    new_target_host = validate_target_host(target_host if target_host is not None else target["target_host"])
    new_target_port = validate_port(target_port if target_port is not None else target["target_port"])
    new_protocol = validate_resource_protocol(protocol if protocol is not None else target["protocol"])
    new_health = validate_health_url(
        health_url if health_url is not None else target.get("health_url", ""),
        new_target_host,
        new_target_port,
    )

    target["bridge_port"] = new_bridge_port
    target["listen_port"] = new_bridge_port
    target["target_host"] = new_target_host
    target["target_port"] = new_target_port
    target["protocol"] = new_protocol
    target["icon"] = validate_resource_icon(icon if icon is not None else target.get("icon", "server"))
    target["description"] = (description if description is not None else target.get("description", "")).strip()[:500]
    target["health_url"] = new_health
    target["timeout_seconds"] = validate_timeout_seconds(
        timeout_seconds if timeout_seconds is not None else target.get("timeout_seconds", 2.0)
    )
    if enabled is not None:
        target["enabled"] = bool(enabled)
    save_resources(items)
    return find_resource(name) or target


def remove_resource(name: str) -> bool:
    items = list_resources()
    new = [r for r in items if r.get("name") != name]
    if len(new) == len(items):
        return False
    save_resources(new)
    groups = list_groups()
    changed = False
    for group in groups:
        if name in group.get("allowed_services", []):
            group["allowed_services"] = [x for x in group["allowed_services"] if x != name]
            group["allowed_resources"] = list(group["allowed_services"])
            changed = True
    if changed:
        save_groups(groups)
    return True


def remove_service(name: str) -> bool:
    return remove_resource(name)


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
        _audit_acl("device_enable" if enabled else "device_disable", device=found, result="enabled" if enabled else "disabled")
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

    resources = list_resources()
    changed = False
    for resource in resources:
        for field_name in ("allowed_devices", "denied_devices"):
            values = list(resource.get(field_name, []))
            if old_name in values:
                resource[field_name] = sorted({new_name if x == old_name else x for x in values})
                changed = True
    if changed:
        save_resources(resources)
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
    group["allowed_resources"] = []
    groups.append(group)
    save_groups(groups)
    return group


def remove_group(name: str) -> bool:
    groups = list_groups()
    new = [g for g in groups if g.get("name") != name]
    if len(new) == len(groups):
        return False
    save_groups(new)
    _audit_acl("group_remove", result=name)
    return True


def set_group_enabled(name: str, enabled: bool) -> dict[str, Any]:
    groups = list_groups()
    for group in groups:
        if group["name"] == name:
            group["enabled"] = bool(enabled)
            save_groups(groups)
            _audit_acl("group_enable" if enabled else "group_disable", result=name)
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
            _audit_acl(
                "group_device_add" if assigned else "group_device_remove",
                device=device,
                result=group_name,
            )
            return group
    raise BridgeError(f"Gruppo non trovato: {group_name}")


def set_group_resource(group_name: str, resource_name: str, allowed: bool) -> dict[str, Any]:
    if not any(r["name"] == resource_name for r in list_resources()):
        raise BridgeError(f"Resource non trovata: {resource_name}")
    groups = list_groups()
    for group in groups:
        if group["name"] == group_name:
            resources = set(group.get("allowed_services", []))
            if allowed:
                resources.add(resource_name)
            else:
                resources.discard(resource_name)
            group["allowed_services"] = sorted(resources)
            group["allowed_resources"] = list(group["allowed_services"])
            save_groups(groups)
            _audit_acl(
                "group_resource_grant" if allowed else "group_resource_revoke",
                resource=resource_name,
                result=group_name,
            )
            return group
    raise BridgeError(f"Gruppo non trovato: {group_name}")


def set_group_service(group_name: str, service_name: str, allowed: bool) -> dict[str, Any]:
    return set_group_resource(group_name, service_name, allowed)


def groups_for_device(device: dict[str, Any], groups: list[dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    source = groups if groups is not None else list_groups()
    return [
        g for g in source
        if g.get("enabled", True) and device.get("device_id") in set(g.get("device_ids", []))
    ]


def set_device_access_override(resource_name: str, device_identifier: str, decision: str) -> dict[str, Any]:
    device = find_device(device_identifier)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    if decision not in {"allow", "deny", "inherit"}:
        raise BridgeError("Override non valido: usa allow, deny o inherit.")
    resources = list_resources()
    for resource in resources:
        if resource.get("name") != resource_name:
            continue
        allowed = set(resource.get("allowed_devices", []))
        denied = set(resource.get("denied_devices", []))
        allowed.discard(device["name"])
        denied.discard(device["name"])
        if decision == "allow":
            allowed.add(device["name"])
        elif decision == "deny":
            denied.add(device["name"])
        resource["allowed_devices"] = sorted(allowed)
        resource["denied_devices"] = sorted(denied)
        save_resources(resources)
        _audit_acl(
            f"device_override_{decision}",
            device=device,
            resource=resource_name,
            result=decision,
        )
        return resource
    raise BridgeError(f"Resource non trovata: {resource_name}")


def grant_device(service_name: str, device_name: str, grant: bool) -> dict[str, Any]:
    return set_device_access_override(service_name, device_name, "allow" if grant else "deny")


def resource_access_source(
    resource: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> str:
    if not device_is_active(device):
        return "inactive"
    name = device["name"]
    if name in set(resource.get("denied_devices", [])):
        return "deny_override"
    if name in set(resource.get("allowed_devices", [])):
        return "allow_override"
    for group in groups_for_device(device, groups):
        if resource["name"] in set(group.get("allowed_services", [])):
            return f"group:{group['name']}"
    return "none"


def service_access_source(
    service: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> str:
    return resource_access_source(service, device, groups)


def resource_allows_device(
    resource: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> bool:
    source = resource_access_source(resource, device, groups)
    return source == "allow_override" or source.startswith("group:")


def service_allows_device(
    service: dict[str, Any],
    device: dict[str, Any],
    groups: list[dict[str, Any]] | None = None,
) -> bool:
    return resource_allows_device(service, device, groups)


def allowed_ips_for_resource(
    resource: dict[str, Any],
    devices: list[dict[str, Any]],
    groups: list[dict[str, Any]] | None = None,
) -> set[str]:
    source_groups = groups if groups is not None else list_groups()
    return {
        d["vpn_ip"]
        for d in devices
        if resource_allows_device(resource, d, source_groups)
    }


def allowed_ips_for_service(
    service: dict[str, Any],
    devices: list[dict[str, Any]],
    groups: list[dict[str, Any]] | None = None,
) -> set[str]:
    return allowed_ips_for_resource(service, devices, groups)


def effective_resources_for_device(
    device: dict[str, Any],
    resources: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    source_resources = resources if resources is not None else list_resources()
    source_groups = groups if groups is not None else list_groups()
    return [
        r for r in source_resources
        if r.get("enabled", True) and resource_allows_device(r, device, source_groups)
    ]


def effective_services_for_device(
    device: dict[str, Any],
    services: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    return effective_resources_for_device(device, services, groups)
