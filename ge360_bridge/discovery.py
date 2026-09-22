from __future__ import annotations

import json
import re
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from .core import (
    BridgeError,
    RESERVED_BRIDGE_PORTS,
    list_resources,
    register_resource,
    validate_name,
    validate_port,
    validate_resource_icon,
    validate_target_host,
)

DISCOVERY_PATH = "/.well-known/ge360"
DISCOVERY_TIMEOUT_SECONDS = 0.6
MAX_DISCOVERY_PORTS = 64
MAX_MANIFEST_BYTES = 16 * 1024
ALLOWED_MANIFEST_KEYS = {"schema", "name", "type", "version", "health", "icon", "description"}
VERSION_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._+\-]{0,63}$")


def validate_discovery_timeout(value: float | int | str) -> float:
    try:
        timeout = float(value)
    except (TypeError, ValueError) as exc:
        raise BridgeError("Timeout discovery non valido.") from exc
    if timeout < 0.1 or timeout > 5.0:
        raise BridgeError("Timeout discovery non valido: usa un valore tra 0.1 e 5 secondi.")
    return timeout


def validate_manifest(payload: Any) -> dict[str, Any]:
    if not isinstance(payload, dict):
        raise BridgeError("Manifest GE360 non valido: atteso un oggetto JSON.")

    unknown = sorted(set(payload) - ALLOWED_MANIFEST_KEYS)
    if unknown:
        raise BridgeError("Manifest GE360 contiene campi non supportati: " + ", ".join(unknown))

    required = ("name", "type", "version", "health")
    missing = [key for key in required if key not in payload]
    if missing:
        raise BridgeError("Manifest GE360 incompleto: mancano " + ", ".join(missing))

    schema = payload.get("schema", 1)
    if type(schema) is not int or schema != 1:
        raise BridgeError("Schema manifest GE360 non supportato: usa schema=1.")

    name = payload["name"]
    if not isinstance(name, str):
        raise BridgeError("Manifest GE360: name deve essere una stringa.")
    name = name.strip()
    if not name or len(name) > 120 or any(ord(ch) < 32 for ch in name):
        raise BridgeError("Manifest GE360: name non valido.")

    resource_type = payload["type"]
    if not isinstance(resource_type, str):
        raise BridgeError("Manifest GE360: type deve essere una stringa.")
    resource_type = resource_type.strip().lower()
    validate_name(resource_type)

    version = payload["version"]
    if not isinstance(version, str):
        raise BridgeError("Manifest GE360: version deve essere una stringa.")
    version = version.strip()
    if not VERSION_RE.fullmatch(version):
        raise BridgeError("Manifest GE360: version non valida.")

    health = payload["health"]
    if not isinstance(health, str):
        raise BridgeError("Manifest GE360: health deve essere un percorso.")
    health = health.strip()
    parsed = urlsplit(health)
    if (
        not health.startswith("/")
        or health.startswith("//")
        or parsed.scheme
        or parsed.netloc
        or parsed.fragment
        or len(health) > 500
    ):
        raise BridgeError("Manifest GE360: health deve essere un percorso locale assoluto, es. /healthz.")

    icon = payload.get("icon", "server")
    if not isinstance(icon, str):
        raise BridgeError("Manifest GE360: icon deve essere una stringa.")
    icon = validate_resource_icon(icon)

    description = payload.get("description", "")
    if not isinstance(description, str):
        raise BridgeError("Manifest GE360: description deve essere una stringa.")
    description = description.strip()
    if len(description) > 500 or any(ord(ch) < 32 and ch not in "\t\n\r" for ch in description):
        raise BridgeError("Manifest GE360: description non valida.")

    return {
        "schema": 1,
        "name": name,
        "type": resource_type,
        "version": version,
        "health": health,
        "icon": icon,
        "description": description,
    }


def _endpoint_url(host: str, port: int, scheme: str) -> str:
    checked_host = validate_target_host(host)
    checked_port = validate_port(port)
    checked_scheme = (scheme or "http").strip().lower()
    if checked_scheme not in {"http", "https"}:
        raise BridgeError("Discovery GE360 supporta soltanto HTTP o HTTPS.")
    display_host = f"[{checked_host}]" if ":" in checked_host else checked_host
    return f"{checked_scheme}://{display_host}:{checked_port}{DISCOVERY_PATH}"


def probe_manifest(
    host: str,
    port: int,
    *,
    scheme: str = "http",
    timeout: float = DISCOVERY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    timeout = validate_discovery_timeout(timeout)
    url = _endpoint_url(host, port, scheme)
    request = Request(
        url,
        headers={
            "Accept": "application/json",
            "User-Agent": "GE360-Universal-Bridge/0.15",
        },
        method="GET",
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            status = int(getattr(response, "status", response.getcode()))
            if status != 200:
                raise BridgeError(f"Manifest GE360 non disponibile: HTTP {status}.")
            content_type = (response.headers.get("Content-Type") or "").split(";", 1)[0].strip().lower()
            if content_type != "application/json":
                raise BridgeError("Manifest GE360 non valido: Content-Type deve essere application/json.")
            raw = response.read(MAX_MANIFEST_BYTES + 1)
    except HTTPError as exc:
        raise BridgeError(f"Manifest GE360 non disponibile: HTTP {exc.code}.") from exc
    except (URLError, OSError, TimeoutError) as exc:
        raise BridgeError("Manifest GE360 non raggiungibile.") from exc

    if len(raw) > MAX_MANIFEST_BYTES:
        raise BridgeError("Manifest GE360 troppo grande.")
    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError("Manifest GE360 non contiene JSON UTF-8 valido.") from exc
    return validate_manifest(payload)


def _proc_ipv4_loopback_ports(path: Path = Path("/proc/net/tcp")) -> list[int]:
    try:
        lines = path.read_text(encoding="ascii").splitlines()[1:]
    except (FileNotFoundError, PermissionError, OSError):
        return []

    ports: set[int] = set()
    for line in lines:
        fields = line.split()
        if len(fields) < 4 or fields[3] != "0A":
            continue
        local = fields[1]
        if ":" not in local:
            continue
        address_hex, port_hex = local.rsplit(":", 1)
        if address_hex.upper() != "0100007F":
            continue
        try:
            ports.add(validate_port(int(port_hex, 16)))
        except (ValueError, BridgeError):
            continue
    return sorted(ports)


def loopback_listener_ports() -> list[int]:
    return _proc_ipv4_loopback_ports()


def _proposal(manifest: dict[str, Any], host: str, port: int, scheme: str) -> dict[str, Any]:
    resources = list_resources()
    resource_name = manifest["type"]
    same_name = next((r for r in resources if r.get("name") == resource_name), None)
    same_target = next(
        (
            r
            for r in resources
            if r.get("target_host") in {"127.0.0.1", "localhost"}
            and int(r.get("target_port", 0)) == int(port)
        ),
        None,
    )
    used_bridge_ports = {int(r.get("bridge_port", 0)) for r in resources}
    suggested_bridge_port = (
        int(port)
        if int(port) not in RESERVED_BRIDGE_PORTS and int(port) not in used_bridge_ports
        else None
    )

    status = "new"
    reason = ""
    if same_name:
        status = "registered" if int(same_name.get("target_port", 0)) == int(port) else "name_conflict"
        reason = f"Resource {resource_name} già registrata."
    elif same_target:
        status = "target_registered"
        reason = f"Target già registrato come {same_target.get('name')}."
    elif suggested_bridge_port is None:
        status = "bridge_port_required"
        reason = "La target port non può essere riutilizzata come bridge port; scegline una libera."

    return {
        "manifest": manifest,
        "resource_name": resource_name,
        "target_host": validate_target_host(host),
        "target_port": int(port),
        "protocol": scheme,
        "discovery_url": _endpoint_url(host, port, scheme),
        "suggested_bridge_port": suggested_bridge_port,
        "status": status,
        "reason": reason,
    }


def discover_backends(
    ports: list[int] | tuple[int, ...] | None = None,
    *,
    host: str = "127.0.0.1",
    scheme: str = "http",
    timeout: float = DISCOVERY_TIMEOUT_SECONDS,
) -> dict[str, Any]:
    host = validate_target_host(host)
    scheme = (scheme or "http").strip().lower()
    if scheme not in {"http", "https"}:
        raise BridgeError("Discovery GE360 supporta soltanto HTTP o HTTPS.")
    timeout = validate_discovery_timeout(timeout)

    selected = loopback_listener_ports() if ports is None else [validate_port(p) for p in ports]
    selected = sorted(set(int(p) for p in selected if int(p) not in RESERVED_BRIDGE_PORTS))
    if len(selected) > MAX_DISCOVERY_PORTS:
        raise BridgeError(f"Discovery GE360 limitata a massimo {MAX_DISCOVERY_PORTS} porte per esecuzione.")

    proposals: list[dict[str, Any]] = []
    errors: list[dict[str, Any]] = []

    def one(port: int) -> tuple[int, dict[str, Any] | None, str | None]:
        try:
            manifest = probe_manifest(host, port, scheme=scheme, timeout=timeout)
            return port, _proposal(manifest, host, port, scheme), None
        except BridgeError as exc:
            return port, None, str(exc)[:200]

    workers = max(1, min(8, len(selected)))
    if selected:
        with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ge360-discovery") as pool:
            futures = [pool.submit(one, port) for port in selected]
            for future in as_completed(futures):
                port, proposal, error = future.result()
                if proposal is not None:
                    proposals.append(proposal)
                elif error:
                    errors.append({"port": port, "error": error})

    proposals.sort(key=lambda item: (item["target_port"], item["resource_name"]))
    errors.sort(key=lambda item: item["port"])
    return {
        "host": host,
        "scheme": scheme,
        "scanned_ports": selected,
        "proposals": proposals,
        "errors": errors,
    }


def import_discovered_backend(
    *,
    host: str,
    target_port: int,
    scheme: str = "http",
    bridge_port: int | None = None,
    timeout: float = 1.0,
):
    host = validate_target_host(host)
    target_port = validate_port(target_port)
    scheme = (scheme or "http").strip().lower()
    manifest = probe_manifest(host, target_port, scheme=scheme, timeout=timeout)
    proposal = _proposal(manifest, host, target_port, scheme)
    if proposal["status"] in {"registered", "name_conflict", "target_registered"}:
        raise BridgeError(proposal["reason"])

    selected_bridge_port = bridge_port if bridge_port is not None else proposal["suggested_bridge_port"]
    if selected_bridge_port is None:
        raise BridgeError("Specifica una bridge port libera per importare questo backend.")

    description = manifest["description"] or f"{manifest['name']} v{manifest['version']}"
    return register_resource(
        manifest["type"],
        validate_port(selected_bridge_port),
        host,
        target_port,
        [],
        icon=manifest["icon"],
        description=description,
        protocol=scheme,
        health_url=manifest["health"],
        timeout_seconds=2.0,
    )
