from __future__ import annotations

import ipaddress
import json
import os
import re
import secrets
import socket
import struct
import subprocess
import time
from typing import Any, Callable

from .core import BRIDGE_ENV, BridgeError

STUN_MAGIC_COOKIE = 0x2112A442
STUN_BINDING_REQUEST = 0x0001
STUN_BINDING_SUCCESS = 0x0101
ATTR_MAPPED_ADDRESS = 0x0001
ATTR_CHANGE_REQUEST = 0x0003
ATTR_XOR_MAPPED_ADDRESS = 0x0020
ATTR_RESPONSE_ORIGIN = 0x802B
ATTR_OTHER_ADDRESS = 0x802C
DEFAULT_STUN_SERVERS = (
    "stun.cloudflare.com:3478",
    "stun.cloudflare.com:53",
)
MAX_STUN_SERVERS = 6
CACHE_SECONDS = 30.0
_CACHE: tuple[float, dict[str, Any]] | None = None
HOST_RE = re.compile(r"^[A-Za-z0-9.-]{1,253}$")


def parse_stun_server(value: str) -> tuple[str, int]:
    raw = (value or "").strip()
    if not raw:
        raise BridgeError("Server STUN vuoto.")
    if raw.startswith("["):
        raise BridgeError("La Fase 18 usa STUN IPv4 per classificare NAT; usa hostname/IPv4 senza parentesi.")
    if ":" not in raw:
        host, port_text = raw, "3478"
    else:
        host, port_text = raw.rsplit(":", 1)
    host = host.strip().lower()
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not HOST_RE.fullmatch(host) or ".." in host or host.startswith(".") or host.endswith("."):
            raise BridgeError(f"Hostname STUN non valido: {host}")
    try:
        port = int(port_text)
    except ValueError as exc:
        raise BridgeError("Porta STUN non valida.") from exc
    if port < 1 or port > 65535:
        raise BridgeError("Porta STUN non valida.")
    return host, port


def _bridge_env_stun_servers() -> str:
    try:
        lines = BRIDGE_ENV.read_text(encoding="utf-8").splitlines()
    except (FileNotFoundError, OSError, UnicodeDecodeError):
        return ""
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key.strip() == "STUN_SERVERS":
            return value.strip().strip('"').strip("'")
    return ""


def configured_stun_servers(values: list[str] | tuple[str, ...] | None = None) -> list[tuple[str, int]]:
    raw_values: list[str]
    if values:
        raw_values = list(values)
    else:
        env = os.environ.get("GE360_STUN_SERVERS", "").strip() or _bridge_env_stun_servers()
        raw_values = [x.strip() for x in env.split(",") if x.strip()] if env else list(DEFAULT_STUN_SERVERS)
    if len(raw_values) > MAX_STUN_SERVERS:
        raise BridgeError(f"Troppi server STUN: massimo {MAX_STUN_SERVERS}.")
    out: list[tuple[str, int]] = []
    for raw in raw_values:
        server = parse_stun_server(raw)
        if server not in out:
            out.append(server)
    if not out:
        raise BridgeError("Nessun server STUN configurato.")
    return out


def _stun_request(transaction_id: bytes, *, change_request: int | None = None) -> bytes:
    if len(transaction_id) != 12:
        raise BridgeError("Transaction ID STUN non valido.")
    attrs = b""
    if change_request is not None:
        attrs += struct.pack("!HHI", ATTR_CHANGE_REQUEST, 4, int(change_request))
    return struct.pack("!HHI12s", STUN_BINDING_REQUEST, len(attrs), STUN_MAGIC_COOKIE, transaction_id) + attrs


def _decode_address(value: bytes, *, xor: bool, transaction_id: bytes) -> tuple[str, int]:
    if len(value) < 4:
        raise BridgeError("Attributo indirizzo STUN troppo corto.")
    _zero, family, port = struct.unpack("!BBH", value[:4])
    if xor:
        port ^= STUN_MAGIC_COOKIE >> 16
    if family == 0x01:
        if len(value) != 8:
            raise BridgeError("Attributo STUN IPv4 non valido.")
        packed = bytearray(value[4:8])
        if xor:
            cookie = struct.pack("!I", STUN_MAGIC_COOKIE)
            packed = bytearray(a ^ b for a, b in zip(packed, cookie))
        return str(ipaddress.IPv4Address(bytes(packed))), int(port)
    if family == 0x02:
        if len(value) != 20:
            raise BridgeError("Attributo STUN IPv6 non valido.")
        packed = bytearray(value[4:20])
        if xor:
            mask = struct.pack("!I", STUN_MAGIC_COOKIE) + transaction_id
            packed = bytearray(a ^ b for a, b in zip(packed, mask))
        return str(ipaddress.IPv6Address(bytes(packed))), int(port)
    raise BridgeError("Famiglia indirizzo STUN sconosciuta.")


def parse_stun_response(data: bytes, expected_transaction_id: bytes) -> dict[str, Any]:
    if len(data) < 20:
        raise BridgeError("Risposta STUN troppo corta.")
    msg_type, length, cookie, transaction_id = struct.unpack("!HHI12s", data[:20])
    if cookie != STUN_MAGIC_COOKIE:
        raise BridgeError("Magic cookie STUN non valida.")
    if transaction_id != expected_transaction_id:
        raise BridgeError("Transaction ID STUN non corrisponde.")
    if msg_type != STUN_BINDING_SUCCESS:
        raise BridgeError(f"Risposta STUN non-success: 0x{msg_type:04x}.")
    if length != len(data) - 20:
        raise BridgeError("Lunghezza risposta STUN non valida.")

    attrs: dict[int, list[bytes]] = {}
    offset = 20
    end = 20 + length
    while offset < end:
        if offset + 4 > end:
            raise BridgeError("Header attributo STUN troncato.")
        attr_type, attr_len = struct.unpack("!HH", data[offset:offset + 4])
        start = offset + 4
        stop = start + attr_len
        if stop > end:
            raise BridgeError("Attributo STUN troncato.")
        attrs.setdefault(attr_type, []).append(data[start:stop])
        offset = start + ((attr_len + 3) // 4) * 4

    mapped = None
    if ATTR_XOR_MAPPED_ADDRESS in attrs:
        mapped = _decode_address(attrs[ATTR_XOR_MAPPED_ADDRESS][0], xor=True, transaction_id=transaction_id)
    elif ATTR_MAPPED_ADDRESS in attrs:
        mapped = _decode_address(attrs[ATTR_MAPPED_ADDRESS][0], xor=False, transaction_id=transaction_id)
    if mapped is None:
        raise BridgeError("Risposta STUN senza MAPPED-ADDRESS.")

    def addr(attr_type: int) -> tuple[str, int] | None:
        values = attrs.get(attr_type)
        if not values:
            return None
        return _decode_address(values[0], xor=False, transaction_id=transaction_id)

    return {
        "mapped_ip": mapped[0],
        "mapped_port": mapped[1],
        "response_origin": addr(ATTR_RESPONSE_ORIGIN),
        "other_address": addr(ATTR_OTHER_ADDRESS),
    }


def _resolve_ipv4(
    host: str,
    port: int,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
) -> list[tuple[str, int]]:
    try:
        rows = resolver(host, port, socket.AF_INET, socket.SOCK_DGRAM)
    except OSError as exc:
        raise BridgeError(f"DNS STUN fallito per {host}: {exc.__class__.__name__}") from exc
    out: list[tuple[str, int]] = []
    for row in rows:
        sockaddr = row[4]
        remote = (str(sockaddr[0]), int(sockaddr[1]))
        if remote not in out:
            out.append(remote)
    if not out:
        raise BridgeError(f"Nessun IPv4 risolto per server STUN {host}.")
    return out


def _exchange(
    sock: socket.socket,
    remote: tuple[str, int],
    *,
    timeout: float,
    change_request: int | None = None,
) -> tuple[dict[str, Any], tuple[str, int]]:
    txid = secrets.token_bytes(12)
    request = _stun_request(txid, change_request=change_request)
    sock.settimeout(timeout)
    try:
        sock.sendto(request, remote)
        data, source = sock.recvfrom(4096)
    except socket.timeout as exc:
        raise BridgeError("STUN timeout.") from exc
    except OSError as exc:
        raise BridgeError(f"STUN socket error: {exc.__class__.__name__}") from exc
    parsed = parse_stun_response(data, txid)
    return parsed, (str(source[0]), int(source[1]))


def probe_stun_servers(
    servers: list[tuple[str, int]],
    *,
    timeout: float = 1.2,
    resolver: Callable[..., list[tuple[Any, ...]]] = socket.getaddrinfo,
    socket_factory: Callable[..., socket.socket] = socket.socket,
) -> dict[str, Any]:
    if timeout < 0.2 or timeout > 5.0:
        raise BridgeError("Timeout STUN non valido: usa 0.2..5.0 secondi.")
    observations: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    filtering_behavior = "UNKNOWN"
    filtering_reason = "server_rfc5780_not_observed"

    with socket_factory(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", 0))
        local_port = int(sock.getsockname()[1])
        seen_remotes: set[tuple[str, int]] = set()
        first_other: tuple[str, int] | None = None
        first_remote: tuple[str, int] | None = None

        for host, port in servers:
            try:
                remotes = _resolve_ipv4(host, port, resolver)
            except BridgeError as exc:
                errors.append({"server": f"{host}:{port}", "error": str(exc)})
                continue
            success = False
            for remote in remotes[:2]:
                if remote in seen_remotes:
                    continue
                seen_remotes.add(remote)
                try:
                    parsed, source = _exchange(sock, remote, timeout=timeout)
                except BridgeError as exc:
                    errors.append({"server": f"{host}:{port}", "remote": f"{remote[0]}:{remote[1]}", "error": str(exc)})
                    continue
                observations.append({
                    "server": f"{host}:{port}",
                    "remote_ip": remote[0],
                    "remote_port": remote[1],
                    "response_source_ip": source[0],
                    "response_source_port": source[1],
                    "mapped_ip": parsed["mapped_ip"],
                    "mapped_port": parsed["mapped_port"],
                    "other_address": None if not parsed.get("other_address") else {
                        "ip": parsed["other_address"][0],
                        "port": parsed["other_address"][1],
                    },
                })
                if first_remote is None:
                    first_remote = remote
                    first_other = parsed.get("other_address")
                success = True
                break
            if not success and not remotes:
                errors.append({"server": f"{host}:{port}", "error": "no_remote_endpoint"})

        if first_remote and first_other and first_other != first_remote:
            try:
                _parsed, source = _exchange(sock, first_remote, timeout=timeout, change_request=0x00000006)
                if source != first_remote:
                    filtering_behavior = "ENDPOINT_INDEPENDENT"
                    filtering_reason = "rfc5780_change_ip_port_response_received"
                else:
                    filtering_reason = "rfc5780_change_request_ignored"
            except BridgeError:
                filtering_reason = "rfc5780_change_request_no_response_or_unsupported"

    return {
        "local_udp_port": local_port,
        "observations": observations,
        "errors": errors,
        "filtering_behavior": filtering_behavior,
        "filtering_reason": filtering_reason,
    }


def local_ipv4() -> str | None:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("1.1.1.1", 53))
            ip = str(sock.getsockname()[0])
    except OSError:
        return None
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return None
    return ip if isinstance(address, ipaddress.IPv4Address) and not address.is_loopback else None


def global_ipv6_addresses() -> list[str]:
    try:
        proc = subprocess.run(
            ["ip", "-6", "-j", "address", "show", "scope", "global"],
            text=True,
            capture_output=True,
            timeout=3,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        rows = json.loads(proc.stdout or "[]")
    except json.JSONDecodeError:
        return []
    out: list[str] = []
    for iface in rows if isinstance(rows, list) else []:
        for info in iface.get("addr_info", []) if isinstance(iface, dict) else []:
            if info.get("family") != "inet6":
                continue
            raw = str(info.get("local") or "")
            try:
                ip = ipaddress.IPv6Address(raw)
            except ValueError:
                continue
            if ip.is_global and str(ip) not in out:
                out.append(str(ip))
    return out


def upnp_external_ipv4() -> dict[str, Any]:
    try:
        proc = subprocess.run(
            ["upnpc", "-s"],
            text=True,
            capture_output=True,
            timeout=5,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"available": False, "ip": None, "error": exc.__class__.__name__}
    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    match = re.search(r"ExternalIPAddress\s*=\s*([^\s]+)", text)
    if not match:
        return {"available": False, "ip": None, "error": "external_ip_not_reported"}
    raw = match.group(1).strip()
    try:
        ip = ipaddress.IPv4Address(raw)
    except ValueError:
        return {"available": False, "ip": None, "error": "invalid_external_ip"}
    return {"available": True, "ip": str(ip), "global": ip.is_global, "shared_cgnat": ip in ipaddress.IPv4Network("100.64.0.0/10")}


def classify_cgnat(stun_ip: str | None, upnp: dict[str, Any]) -> dict[str, Any]:
    stun = None
    if stun_ip:
        try:
            parsed = ipaddress.ip_address(stun_ip)
            stun = parsed if isinstance(parsed, ipaddress.IPv4Address) else None
        except ValueError:
            stun = None

    wan = None
    if upnp.get("ip"):
        try:
            parsed = ipaddress.ip_address(str(upnp["ip"]))
            wan = parsed if isinstance(parsed, ipaddress.IPv4Address) else None
        except ValueError:
            wan = None

    shared = ipaddress.IPv4Network("100.64.0.0/10")
    if wan in shared if wan else False:
        return {"status": "YES", "confidence": "HIGH", "reason": "router_wan_in_rfc6598_shared_space"}
    if stun in shared if stun else False:
        return {"status": "YES", "confidence": "HIGH", "reason": "stun_mapped_ip_in_rfc6598_shared_space"}
    if wan is not None and not wan.is_global and stun is not None and stun.is_global:
        return {"status": "LIKELY", "confidence": "MEDIUM", "reason": "router_wan_non_global_but_stun_public"}
    if wan is not None and wan.is_global and stun is not None and stun.is_global:
        if wan == stun:
            return {"status": "NO_EVIDENCE", "confidence": "HIGH", "reason": "router_wan_matches_stun_public_ip"}
        return {"status": "POSSIBLE", "confidence": "LOW", "reason": "router_wan_and_stun_public_ip_differ"}
    if stun is not None and not stun.is_global:
        return {"status": "POSSIBLE", "confidence": "MEDIUM", "reason": "stun_mapping_not_globally_routable"}
    return {"status": "UNKNOWN", "confidence": "LOW", "reason": "insufficient_router_wan_evidence"}


def classify_nat(
    observations: list[dict[str, Any]],
    *,
    local_ip: str | None,
    local_port: int | None,
    filtering_behavior: str = "UNKNOWN",
) -> dict[str, Any]:
    if not observations:
        return {
            "type": "UNKNOWN",
            "mapping_behavior": "UNKNOWN",
            "filtering_behavior": filtering_behavior,
            "port_preservation": None,
            "reason": "no_stun_observation",
        }

    mapped = [(str(x["mapped_ip"]), int(x["mapped_port"])) for x in observations]
    distinct_remote = {(str(x["remote_ip"]), int(x["remote_port"])) for x in observations}
    port_preservation = None if local_port is None else all(port == int(local_port) for _, port in mapped)

    if local_ip and local_port is not None:
        try:
            lip = ipaddress.IPv4Address(local_ip)
        except ValueError:
            lip = None
        if lip is not None and lip.is_global and all(ip == local_ip and port == int(local_port) for ip, port in mapped):
            return {
                "type": "NO_NAT",
                "mapping_behavior": "DIRECT",
                "filtering_behavior": filtering_behavior,
                "port_preservation": True,
                "reason": "global_local_endpoint_matches_stun_mapping",
            }

    if len(distinct_remote) < 2:
        return {
            "type": "UNKNOWN",
            "mapping_behavior": "UNKNOWN",
            "filtering_behavior": filtering_behavior,
            "port_preservation": port_preservation,
            "reason": "single_stun_destination",
        }

    if len(set(mapped)) == 1:
        mapping = "ENDPOINT_INDEPENDENT"
        nat_type = "ENDPOINT_INDEPENDENT_MAPPING"
        reason = "same_mapping_across_distinct_stun_destinations"
    else:
        mapping = "DESTINATION_DEPENDENT"
        nat_type = "SYMMETRIC_LIKE_MAPPING"
        reason = "mapping_changes_across_stun_destinations"

    return {
        "type": nat_type,
        "mapping_behavior": mapping,
        "filtering_behavior": filtering_behavior,
        "port_preservation": port_preservation,
        "reason": reason,
    }


def discover_nat(
    server_values: list[str] | tuple[str, ...] | None = None,
    *,
    timeout: float = 1.2,
    use_cache: bool = False,
    probe: Callable[..., dict[str, Any]] = probe_stun_servers,
    local_ipv4_getter: Callable[[], str | None] = local_ipv4,
    ipv6_getter: Callable[[], list[str]] = global_ipv6_addresses,
    upnp_getter: Callable[[], dict[str, Any]] = upnp_external_ipv4,
) -> dict[str, Any]:
    global _CACHE
    now = time.monotonic()
    if use_cache and not server_values and _CACHE and now - _CACHE[0] <= CACHE_SECONDS:
        return dict(_CACHE[1])

    servers = configured_stun_servers(server_values)
    stun = probe(servers, timeout=timeout)
    observations = list(stun.get("observations") or [])
    local_ip = local_ipv4_getter()
    ipv6 = ipv6_getter()
    upnp = upnp_getter()
    mapped_ip = str(observations[0]["mapped_ip"]) if observations else None
    mapped_port = int(observations[0]["mapped_port"]) if observations else None
    cgnat = classify_cgnat(mapped_ip, upnp)
    nat = classify_nat(
        observations,
        local_ip=local_ip,
        local_port=stun.get("local_udp_port"),
        filtering_behavior=str(stun.get("filtering_behavior") or "UNKNOWN"),
    )

    direct = {
        "global_ipv6_available": bool(ipv6),
        "global_ipv6": ipv6,
        "public_ipv4_observed": mapped_ip,
        "stun_mapped_udp_port": mapped_port,
        "wireguard_port_inferred": False,
        "note": "STUN misura la socket diagnostica e non dimostra che la porta WireGuard sia raggiungibile.",
    }
    report = {
        "schema": "ge360-nat-discovery/v1",
        "generated_at": time.time(),
        "servers": [f"{h}:{p}" for h, p in servers],
        "local_ipv4": local_ip,
        "stun": stun,
        "upnp_status_read_only": upnp,
        "cgnat": cgnat,
        "nat": nat,
        "public_endpoint_observation": direct,
        "phase19_traversal_attempted": False,
        "port_mapping_changed": False,
    }
    if use_cache and not server_values:
        _CACHE = (now, dict(report))
    return report
