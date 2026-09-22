from __future__ import annotations

import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import re
import secrets
import ssl
import tempfile
import threading
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import __version__
from . import core

SERVER_REGISTRY_SCHEMA = "ge360-multi-server-registry/v1"
CATALOG_SCHEMA = "ge360-multi-server-catalog/v1"
SERVER_STATE_DIR = Path(os.environ.get("GE360_SERVER_STATE_DIR", str(core.STATE_DIR / "servers")))
SERVER_REGISTRY_FILE = Path(os.environ.get("GE360_SERVER_REGISTRY_FILE", str(core.STATE_DIR / "servers.json")))
SERVER_ID_FILE = Path(os.environ.get("GE360_SERVER_ID_FILE", str(core.STATE_DIR / "server-id")))
SERVER_TOKEN_FILE = Path(os.environ.get("GE360_SERVER_TOKEN_FILE", str(core.STATE_DIR / "server.token")))
DEFAULT_CONTROL_PORT = int(os.environ.get("GE360_MULTI_SERVER_PORT", "8793"))
MAX_RESPONSE_BYTES = 1024 * 1024
MAX_SERVERS = 64
MAX_RESOURCES_PER_SERVER = 256
MAX_CLOCK_SKEW_SECONDS = 300
SERVER_ID_RE = re.compile(r"^srv_[a-z0-9][a-z0-9_-]{2,63}$")
SERVER_ALIAS_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
SERVER_TOKEN_RE = re.compile(r"^[A-Za-z0-9_-]{32,256}$")


@dataclass
class ServerRecord:
    server_id: str
    name: str
    control_url: str
    tls_cert_sha256: str
    token: str
    enabled: bool = True
    notes: str = ""
    created_at: str = ""


def _atomic_write(path: Path, payload: Any, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=".ge360-multi-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        tmp.replace(path)
        os.chmod(path, mode)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _atomic_text(path: Path, value: str, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path.parent, 0o700)
    except OSError:
        pass
    fd, tmp_name = tempfile.mkstemp(prefix=".ge360-multi-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(value.rstrip("\n") + "\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        tmp.replace(path)
        os.chmod(path, mode)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def local_server_id() -> str:
    try:
        value = SERVER_ID_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if SERVER_ID_RE.fullmatch(value):
        return value
    value = "srv_" + secrets.token_hex(8)
    _atomic_text(SERVER_ID_FILE, value)
    return value


def local_server_token() -> str:
    try:
        value = SERVER_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        value = ""
    if SERVER_TOKEN_RE.fullmatch(value):
        return value
    value = secrets.token_urlsafe(48)
    _atomic_text(SERVER_TOKEN_FILE, value)
    return value


def validate_server_id(value: str) -> str:
    server_id = (value or "").strip().lower()
    if not SERVER_ID_RE.fullmatch(server_id):
        raise core.BridgeError("server_id non valido: usa srv_ seguito da lettere, numeri, _ o -.")
    return server_id


def validate_server_name(value: str) -> str:
    name = (value or "").strip()
    if not SERVER_ALIAS_RE.fullmatch(name):
        raise core.BridgeError("Nome server non valido.")
    return name


def validate_control_url(value: str) -> str:
    url = (value or "").strip().rstrip("/")
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname or parsed.username or parsed.password or parsed.fragment:
        raise core.BridgeError("Control URL server deve essere HTTPS senza credenziali o fragment.")
    try:
        port = parsed.port
    except ValueError as exc:
        raise core.BridgeError("Porta control server non valida.") from exc
    if port is not None:
        core.validate_port(port)
    return url


def validate_fingerprint(value: str) -> str:
    digest = (value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise core.BridgeError("TLS certificate pin server non valido.")
    return digest


def validate_server_token(value: str) -> str:
    token = (value or "").strip()
    if not SERVER_TOKEN_RE.fullmatch(token):
        raise core.BridgeError("Token server non valido.")
    return token


def _normalize_server(raw: dict[str, Any]) -> dict[str, Any]:
    return asdict(ServerRecord(
        server_id=validate_server_id(str(raw.get("server_id") or "")),
        name=validate_server_name(str(raw.get("name") or "")),
        control_url=validate_control_url(str(raw.get("control_url") or "")),
        tls_cert_sha256=validate_fingerprint(str(raw.get("tls_cert_sha256") or "")),
        token=validate_server_token(str(raw.get("token") or "")),
        enabled=bool(raw.get("enabled", True)),
        notes=str(raw.get("notes") or "")[:500],
        created_at=str(raw.get("created_at") or core.utc_now_iso()),
    ))


def list_servers(*, include_secrets: bool = False) -> list[dict[str, Any]]:
    try:
        payload = json.loads(SERVER_REGISTRY_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        payload = []
    except (OSError, json.JSONDecodeError) as exc:
        raise core.BridgeError(f"Server Registry non leggibile: {exc}") from exc
    if not isinstance(payload, list):
        raise core.BridgeError("Server Registry non valido.")
    out = [_normalize_server(x) for x in payload if isinstance(x, dict)]
    if include_secrets:
        return out
    return [{
        "server_id": item["server_id"],
        "name": item["name"],
        "enabled": item["enabled"],
        "notes": item["notes"],
        "created_at": item["created_at"],
    } for item in out]


def save_servers(items: list[dict[str, Any]]) -> None:
    normalized = [_normalize_server(x) for x in items]
    if len(normalized) > MAX_SERVERS:
        raise core.BridgeError(f"Troppi server: massimo {MAX_SERVERS}.")
    ids = [x["server_id"] for x in normalized]
    names = [x["name"] for x in normalized]
    urls = [x["control_url"] for x in normalized]
    if len(ids) != len(set(ids)) or len(names) != len(set(names)) or len(urls) != len(set(urls)):
        raise core.BridgeError("Server Registry contiene server_id, nome o URL duplicati.")
    _atomic_write(SERVER_REGISTRY_FILE, normalized)


def find_server(identifier: str, *, include_secrets: bool = False) -> dict[str, Any] | None:
    for server in list_servers(include_secrets=True):
        if server["server_id"] == identifier or server["name"] == identifier:
            if include_secrets:
                return server
            return {
                "server_id": server["server_id"],
                "name": server["name"],
                "enabled": server["enabled"],
                "notes": server["notes"],
                "created_at": server["created_at"],
            }
    return None


def add_server(
    name: str,
    control_url: str,
    tls_cert_sha256: str,
    token: str,
    *,
    server_id: str | None = None,
    notes: str = "",
    enabled: bool = True,
) -> dict[str, Any]:
    items = list_servers(include_secrets=True)
    record = _normalize_server({
        "server_id": server_id or ("srv_" + secrets.token_hex(8)),
        "name": name,
        "control_url": control_url,
        "tls_cert_sha256": tls_cert_sha256,
        "token": token,
        "enabled": enabled,
        "notes": notes,
        "created_at": core.utc_now_iso(),
    })
    items.append(record)
    save_servers(items)
    return {
        "server_id": record["server_id"],
        "name": record["name"],
        "enabled": record["enabled"],
        "notes": record["notes"],
        "created_at": record["created_at"],
    }


def remove_server(identifier: str) -> bool:
    items = list_servers(include_secrets=True)
    new = [x for x in items if x["server_id"] != identifier and x["name"] != identifier]
    if len(new) == len(items):
        return False
    save_servers(new)
    return True


def set_server_enabled(identifier: str, enabled: bool) -> dict[str, Any]:
    items = list_servers(include_secrets=True)
    target = next((x for x in items if x["server_id"] == identifier or x["name"] == identifier), None)
    if target is None:
        raise core.BridgeError("Server non trovato.")
    target["enabled"] = bool(enabled)
    save_servers(items)
    return {
        "server_id": target["server_id"],
        "name": target["name"],
        "enabled": target["enabled"],
        "notes": target["notes"],
        "created_at": target["created_at"],
    }


def _peer_ip_allowed(value: str) -> bool:
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False
    return not (
        address.is_unspecified
        or address.is_multicast
        or address.is_loopback
        or address.is_link_local
    )


def sanitize_agent_snapshot(snapshot: dict[str, Any]) -> dict[str, Any]:
    if not isinstance(snapshot, dict):
        raise core.BridgeError("Snapshot server non valido.")
    resources = snapshot.get("resources")
    if not isinstance(resources, list) or len(resources) > MAX_RESOURCES_PER_SERVER:
        raise core.BridgeError("Resource remote non valide.")
    safe_resources: list[dict[str, Any]] = []
    names: set[str] = set()
    for raw in resources:
        if not isinstance(raw, dict):
            raise core.BridgeError("Resource remota non valida.")
        name = core.validate_name(str(raw.get("name") or ""))
        if name in names:
            raise core.BridgeError("Resource remota duplicata.")
        names.add(name)
        protocol = core.validate_resource_protocol(str(raw.get("protocol") or "tcp"))
        target_port = core.validate_port(int(raw.get("target_port") or 0))
        health_state = str(raw.get("health_state") or "UNKNOWN").upper()
        if health_state not in {"ONLINE", "DEGRADED", "OFFLINE", "TIMEOUT", "UNAUTHORIZED", "BAD_RESPONSE", "UNKNOWN"}:
            health_state = "UNKNOWN"
        latency = raw.get("latency_ms")
        safe_resources.append({
            "name": name,
            "display_name": str(raw.get("display_name") or name)[:120],
            "version": str(raw.get("version") or "")[:64],
            "icon": core.validate_resource_icon(str(raw.get("icon") or "server")),
            "description": str(raw.get("description") or "")[:500],
            "protocol": protocol,
            "target_port": target_port,
            "health_state": health_state,
            "latency_ms": latency if isinstance(latency, (int, float)) else None,
            "enabled": bool(raw.get("enabled", True)),
        })
    host = snapshot.get("host")
    if not isinstance(host, dict):
        host = {}
    addresses: list[str] = []
    for item in snapshot.get("ip_addresses") or []:
        if not isinstance(item, dict):
            continue
        value = str(item.get("address") or "")
        if _peer_ip_allowed(value):
            addresses.append(value)
    return {
        "agent": {
            "version": str((snapshot.get("agent") or {}).get("version") or "")[:64],
            "read_only": bool((snapshot.get("agent") or {}).get("read_only", True)),
        },
        "host": {
            "hostname": str(host.get("hostname") or "")[:255],
            "os": str(host.get("os") or "")[:255],
            "architecture": str(host.get("architecture") or "")[:64],
            "uptime_seconds": host.get("uptime_seconds") if isinstance(host.get("uptime_seconds"), (int, float)) else None,
        },
        "ip_addresses": sorted(set(addresses)),
        "resources": safe_resources,
        "generated_at": str(snapshot.get("generated_at") or ""),
    }


def _pinned_json_request(
    url: str,
    token: str,
    fingerprint: str,
    *,
    method: str = "GET",
    payload: dict[str, Any] | None = None,
    timeout: float = 5.0,
) -> dict[str, Any]:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise core.BridgeError("URL server deve essere HTTPS.")
    port = parsed.port or 443
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=timeout, context=context)
    try:
        conn.connect()
        cert = conn.sock.getpeercert(binary_form=True) if conn.sock else None
        if not cert or hashlib.sha256(cert).hexdigest() != fingerprint:
            raise core.BridgeError("TLS certificate pin server non corrisponde.")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + token,
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        conn.request(method, parsed.path or "/", body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(MAX_RESPONSE_BYTES + 1)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise core.BridgeError(f"Server remoto non raggiungibile: {exc.__class__.__name__}") from exc
    finally:
        conn.close()
    if len(raw) > MAX_RESPONSE_BYTES:
        raise core.BridgeError("Risposta server remota troppo grande.")
    try:
        result = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise core.BridgeError("Risposta server remota non JSON valida.") from exc
    if response.status < 200 or response.status >= 300 or not isinstance(result, dict):
        raise core.BridgeError(f"Server remoto HTTP {response.status}.")
    return result


def fetch_server_snapshot(server: dict[str, Any], *, timeout: float = 5.0) -> dict[str, Any]:
    if not server.get("enabled", True):
        raise core.BridgeError("Server disabilitato.")
    base = validate_control_url(str(server["control_url"]))
    root = _pinned_json_request(
        base + "/v1/control/snapshot",
        validate_server_token(str(server["token"])),
        validate_fingerprint(str(server["tls_cert_sha256"])),
        timeout=timeout,
    )
    return sanitize_agent_snapshot(root)


def fetch_agent_snapshot(
    control_url: str,
    token: str,
    fingerprint: str,
    *,
    timeout: float = 5.0,
) -> dict[str, Any]:
    base = validate_control_url(control_url)
    status = _pinned_json_request(
        base + "/v1/status",
        validate_server_token(token),
        validate_fingerprint(fingerprint),
        timeout=timeout,
    )
    resources_root = _pinned_json_request(
        base + "/v1/resources",
        validate_server_token(token),
        validate_fingerprint(fingerprint),
        timeout=timeout,
    )
    return sanitize_agent_snapshot({
        "agent": status.get("agent") or {},
        "host": status.get("host") or {},
        "ip_addresses": status.get("ip_addresses") or [],
        "resources": resources_root.get("resources") or [],
        "generated_at": resources_root.get("generated_at") or status.get("generated_at") or "",
    })


def _resource_id(server_id: str, resource_name: str) -> str:
    return f"{server_id}:{resource_name}"


def build_catalog(
    *,
    local_snapshot: dict[str, Any] | None = None,
    remote_snapshots: dict[str, dict[str, Any]] | None = None,
    fetcher=fetch_server_snapshot,
) -> dict[str, Any]:
    if local_snapshot is None:
        from .agent import build_snapshot
        local_snapshot = build_snapshot(use_cache=True)
    local = sanitize_agent_snapshot(local_snapshot)
    local_id = local_server_id()
    servers: list[dict[str, Any]] = [{
        "server_id": local_id,
        "name": "local",
        "local": True,
        "online": True,
        "host": local["host"],
        "ip_addresses": local["ip_addresses"],
        "resource_count": len(local["resources"]),
    }]
    resources: list[dict[str, Any]] = []
    local_registry = {item["name"]: item for item in core.list_resources()}
    for resource in local["resources"]:
        registered = local_registry.get(resource["name"], {})
        resources.append({
            **resource,
            "resource_id": _resource_id(local_id, resource["name"]),
            "server_id": local_id,
            "server_name": "local",
            "local": True,
            "bridge_port": int(registered["bridge_port"]) if registered.get("bridge_port") else None,
        })

    supplied = remote_snapshots or {}
    for server in list_servers(include_secrets=True):
        public = {
            "server_id": server["server_id"],
            "name": server["name"],
            "enabled": bool(server.get("enabled", True)),
            "notes": str(server.get("notes") or ""),
            "created_at": str(server.get("created_at") or ""),
        }
        if not server.get("enabled", True):
            servers.append({**public, "local": False, "online": False, "disabled": True, "resource_count": 0})
            continue
        try:
            snapshot = sanitize_agent_snapshot(supplied[server["server_id"]]) if server["server_id"] in supplied else fetcher(server)
            servers.append({
                **public,
                "local": False,
                "online": True,
                "disabled": False,
                "host": snapshot["host"],
                "ip_addresses": snapshot["ip_addresses"],
                "resource_count": len(snapshot["resources"]),
            })
            for resource in snapshot["resources"]:
                resources.append({
                    **resource,
                    "resource_id": _resource_id(server["server_id"], resource["name"]),
                    "server_id": server["server_id"],
                    "server_name": server["name"],
                    "local": False,
                })
        except core.BridgeError as exc:
            servers.append({
                **public,
                "local": False,
                "online": False,
                "disabled": False,
                "error": str(exc)[:300],
                "resource_count": 0,
            })
    return {
        "schema": CATALOG_SCHEMA,
        "control_server_id": local_id,
        "servers": servers,
        "resources": resources,
        "generated_at": core.utc_now_iso(),
        "remote_mutation": False,
        "remote_resource_proxy": False,
    }


def server_status() -> dict[str, Any]:
    catalog = build_catalog()
    return {
        "schema": "ge360-multi-server-status/v1",
        "control_server_id": catalog["control_server_id"],
        "server_count": len(catalog["servers"]),
        "online_servers": sum(1 for x in catalog["servers"] if x.get("online")),
        "resource_count": len(catalog["resources"]),
        "remote_mutation": False,
        "remote_resource_proxy": False,
        "servers": catalog["servers"],
    }


def _certificate_fingerprint(path: Path) -> str:
    try:
        pem = path.read_text(encoding="utf-8")
        der = ssl.PEM_cert_to_DER_cert(pem)
        return hashlib.sha256(der).hexdigest()
    except (OSError, ValueError, ssl.SSLError) as exc:
        raise core.BridgeError("Certificato multi-server non valido.") from exc


def server_export(*, public_host: str | None = None) -> dict[str, Any]:
    cert = core.STATE_DIR / "multi-server-tls.crt"
    host = (public_host or os.environ.get("GE360_MULTI_SERVER_PUBLIC_HOST", "")).strip()
    if not host:
        host = "CHANGE_ME"
    if "/" in host or any(ch.isspace() for ch in host):
        raise core.BridgeError("Host pubblico multi-server non valido.")
    rendered_host = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return {
        "schema": "ge360-server-invite/v1",
        "server_id": local_server_id(),
        "name": (os.uname().nodename or "ge360-server")[:64],
        "control_url": f"https://{rendered_host}:{DEFAULT_CONTROL_PORT}",
        "tls_cert_sha256": _certificate_fingerprint(cert),
        "token": local_server_token(),
    }
