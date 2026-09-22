from __future__ import annotations

import argparse
import hmac
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import threading
import time
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .core import BridgeError, validate_port
from .discovery import discover_backends
from .health import check_resources, health_summary

AGENT_STATE_DIR = Path(os.environ.get("GE360_AGENT_STATE_DIR", "/etc/ge360-agent"))
AGENT_TOKEN_FILE = Path(os.environ.get("GE360_AGENT_TOKEN_FILE", str(AGENT_STATE_DIR / "token")))
DEFAULT_BIND = os.environ.get("GE360_AGENT_BIND", "127.0.0.1")
DEFAULT_PORT = int(os.environ.get("GE360_AGENT_PORT", "8791"))
DEFAULT_DISCOVERY_TIMEOUT = float(os.environ.get("GE360_AGENT_DISCOVERY_TIMEOUT", "0.6"))
SNAPSHOT_CACHE_SECONDS = 5.0

_snapshot_lock = threading.Lock()
_snapshot_cache: tuple[float, dict[str, Any]] | None = None


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _read_text(path: Path) -> str:
    try:
        return path.read_text(encoding="utf-8")
    except OSError:
        return ""


def _parse_os_release(path: Path = Path("/etc/os-release")) -> dict[str, str]:
    out: dict[str, str] = {}
    for raw in _read_text(path).splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key] = value.strip().strip('"').strip("'")
    return out


def system_uptime_seconds(path: Path = Path("/proc/uptime")) -> float | None:
    try:
        return round(float(path.read_text(encoding="utf-8").split()[0]), 2)
    except (OSError, ValueError, IndexError):
        return None


def memory_metrics(path: Path = Path("/proc/meminfo")) -> dict[str, int | None]:
    values: dict[str, int] = {}
    for raw in _read_text(path).splitlines():
        if ":" not in raw:
            continue
        key, rest = raw.split(":", 1)
        parts = rest.strip().split()
        if not parts:
            continue
        try:
            value = int(parts[0])
        except ValueError:
            continue
        if len(parts) > 1 and parts[1].lower() == "kb":
            value *= 1024
        values[key] = value

    total = values.get("MemTotal")
    available = values.get("MemAvailable")
    used = None
    if total is not None and available is not None:
        used = max(0, total - available)
    return {
        "total_bytes": total,
        "available_bytes": available,
        "used_bytes": used,
        "swap_total_bytes": values.get("SwapTotal"),
        "swap_free_bytes": values.get("SwapFree"),
    }


def network_metrics(path: Path = Path("/proc/net/dev")) -> dict[str, Any]:
    interfaces: list[dict[str, Any]] = []
    total_rx = 0
    total_tx = 0
    for raw in _read_text(path).splitlines()[2:]:
        if ":" not in raw:
            continue
        name, data = raw.split(":", 1)
        interface = name.strip()
        fields = data.split()
        if len(fields) < 16 or interface == "lo":
            continue
        try:
            rx = max(0, int(fields[0]))
            tx = max(0, int(fields[8]))
        except ValueError:
            continue
        total_rx += rx
        total_tx += tx
        interfaces.append({"name": interface, "rx_bytes": rx, "tx_bytes": tx})
    interfaces.sort(key=lambda item: item["name"])
    return {"rx_bytes": total_rx, "tx_bytes": total_tx, "interfaces": interfaces}


def disk_metrics(path: str = "/") -> dict[str, int]:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return {"total_bytes": 0, "used_bytes": 0, "free_bytes": 0}
    return {
        "total_bytes": int(usage.total),
        "used_bytes": int(usage.used),
        "free_bytes": int(usage.free),
    }


def load_metrics() -> dict[str, Any]:
    try:
        load1, load5, load15 = os.getloadavg()
    except (AttributeError, OSError):
        load1 = load5 = load15 = None
    return {
        "cpu_count": os.cpu_count(),
        "load_1m": None if load1 is None else round(float(load1), 3),
        "load_5m": None if load5 is None else round(float(load5), 3),
        "load_15m": None if load15 is None else round(float(load15), 3),
    }


def ip_addresses() -> list[dict[str, Any]]:
    try:
        proc = subprocess.run(
            ["ip", "-j", "address", "show"],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    if proc.returncode != 0:
        return []
    try:
        payload = json.loads(proc.stdout)
    except json.JSONDecodeError:
        return []

    out: list[dict[str, Any]] = []
    for iface in payload if isinstance(payload, list) else []:
        ifname = str(iface.get("ifname") or "")
        if ifname == "lo":
            continue
        for info in iface.get("addr_info") or []:
            family = str(info.get("family") or "")
            local = str(info.get("local") or "")
            if family not in {"inet", "inet6"} or not local:
                continue
            try:
                ip = ipaddress.ip_address(local)
            except ValueError:
                continue
            if ip.is_loopback:
                continue
            out.append({
                "interface": ifname,
                "family": family,
                "address": local,
                "prefixlen": info.get("prefixlen"),
                "scope": info.get("scope"),
            })
    out.sort(key=lambda item: (item["interface"], item["family"], item["address"]))
    return out


def host_status() -> dict[str, Any]:
    os_release = _parse_os_release()
    uname = platform.uname()
    return {
        "hostname": socket.gethostname(),
        "os": os_release.get("PRETTY_NAME") or platform.platform(),
        "os_id": os_release.get("ID", ""),
        "os_version": os_release.get("VERSION_ID", ""),
        "kernel": uname.release,
        "architecture": uname.machine,
        "uptime_seconds": system_uptime_seconds(),
    }


def _resource_from_proposal(proposal: dict[str, Any]) -> dict[str, Any]:
    manifest = proposal["manifest"]
    return {
        "name": proposal["resource_name"],
        "display_name": manifest["name"],
        "version": manifest["version"],
        "icon": manifest.get("icon", "server"),
        "description": manifest.get("description", ""),
        "protocol": proposal["protocol"],
        "target_host": proposal["target_host"],
        "target_port": int(proposal["target_port"]),
        "health_url": manifest["health"],
        "timeout_seconds": 2.0,
        "enabled": True,
    }


def local_resources(*, discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT) -> list[dict[str, Any]]:
    report = discover_backends(timeout=discovery_timeout)
    return [_resource_from_proposal(item) for item in report.get("proposals", [])]


def host_metrics() -> dict[str, Any]:
    return {
        "load": load_metrics(),
        "memory": memory_metrics(),
        "disk_root": disk_metrics("/"),
        "network": network_metrics(),
        "uptime_seconds": system_uptime_seconds(),
    }


def build_snapshot(
    *,
    use_cache: bool = True,
    discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
) -> dict[str, Any]:
    global _snapshot_cache
    now = time.monotonic()
    if use_cache:
        with _snapshot_lock:
            if _snapshot_cache is not None and now - _snapshot_cache[0] <= SNAPSHOT_CACHE_SECONDS:
                return json.loads(json.dumps(_snapshot_cache[1]))

    discovery_error = None
    try:
        resources = local_resources(discovery_timeout=discovery_timeout)
    except BridgeError as exc:
        resources = []
        discovery_error = str(exc)
    health = check_resources(resources, use_cache=use_cache)
    health_by_name = {item["name"]: item for item in health}
    resource_rows = [
        {
            **resource,
            "health_state": health_by_name.get(resource["name"], {}).get("state", "OFFLINE"),
            "latency_ms": health_by_name.get(resource["name"], {}).get("latency_ms"),
        }
        for resource in resources
    ]
    snapshot = {
        "agent": {
            "name": "GE360 Linux Agent",
            "version": __version__,
            "api_version": 1,
            "read_only": True,
        },
        "host": host_status(),
        "ip_addresses": ip_addresses(),
        "resources": resource_rows,
        "resource_discovery": {
            "ok": discovery_error is None,
            "error": discovery_error,
        },
        "health": {
            "summary": health_summary(health),
            "resources": health,
        },
        "metrics": host_metrics(),
        "generated_at": utc_now_iso(),
    }
    with _snapshot_lock:
        _snapshot_cache = (now, snapshot)
    return json.loads(json.dumps(snapshot))


def clear_snapshot_cache() -> None:
    global _snapshot_cache
    with _snapshot_lock:
        _snapshot_cache = None


def load_agent_token(path: Path = AGENT_TOKEN_FILE) -> str:
    try:
        token = path.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise BridgeError(f"Token Agent non leggibile: {path}") from exc
    if len(token) < 32 or any(ch.isspace() for ch in token):
        raise BridgeError("Token Agent non valido: deve contenere almeno 32 caratteri senza spazi.")
    return token


def validate_bind(value: str) -> str:
    bind = (value or "").strip()
    if bind == "localhost":
        return bind
    try:
        ipaddress.ip_address(bind)
    except ValueError as exc:
        raise BridgeError("Bind Agent non valido: usa localhost o un indirizzo IP letterale.") from exc
    return bind


class AgentServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, server_address, handler_class, *, agent_token: str, discovery_timeout: float):
        super().__init__(server_address, handler_class)
        self.agent_token = agent_token
        self.discovery_timeout = discovery_timeout


class AgentHandler(BaseHTTPRequestHandler):
    server_version = "GE360LinuxAgent/0.16"

    def log_message(self, format: str, *args: Any) -> None:
        return

    def _json(self, payload: Any, status: int = 200) -> None:
        raw = json.dumps(payload, sort_keys=True).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(raw)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(raw)

    def _authorized(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if not auth.startswith("Bearer "):
            return False
        candidate = auth[7:].strip()
        return bool(candidate and hmac.compare_digest(candidate, self.server.agent_token))

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json({"ok": True, "agent": "ge360-linux-agent", "version": __version__})
            return
        if path == "/.well-known/ge360-agent":
            self._json({
                "schema": 1,
                "name": "GE360 Linux Agent",
                "type": "ge360-agent",
                "version": __version__,
                "api": "/v1/status",
                "auth": "bearer",
            })
            return
        if path not in {"/v1/status", "/v1/resources", "/v1/health", "/v1/metrics"}:
            self._json({"error": "not_found"}, HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return

        snapshot = build_snapshot(
            use_cache=True,
            discovery_timeout=self.server.discovery_timeout,
        )
        if path == "/v1/status":
            self._json({
                "agent": snapshot["agent"],
                "host": snapshot["host"],
                "ip_addresses": snapshot["ip_addresses"],
                "resource_count": len(snapshot["resources"]),
                "resource_discovery": snapshot["resource_discovery"],
                "generated_at": snapshot["generated_at"],
            })
        elif path == "/v1/resources":
            self._json({
                "resources": snapshot["resources"],
                "resource_discovery": snapshot["resource_discovery"],
                "generated_at": snapshot["generated_at"],
            })
        elif path == "/v1/health":
            self._json({**snapshot["health"], "generated_at": snapshot["generated_at"]})
        else:
            self._json({"metrics": snapshot["metrics"], "generated_at": snapshot["generated_at"]})


def serve(
    *,
    bind: str = DEFAULT_BIND,
    port: int = DEFAULT_PORT,
    token_file: Path = AGENT_TOKEN_FILE,
    discovery_timeout: float = DEFAULT_DISCOVERY_TIMEOUT,
) -> None:
    bind = validate_bind(bind)
    port = validate_port(port)
    token = load_agent_token(token_file)
    server_class = AgentServer
    if ":" in bind:
        class IPv6AgentServer(AgentServer):
            address_family = socket.AF_INET6
        server_class = IPv6AgentServer
    server = server_class(
        (bind, port),
        AgentHandler,
        agent_token=token,
        discovery_timeout=float(discovery_timeout),
    )
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ge360-agent", description="GE360 Linux Agent read-only")
    sub = p.add_subparsers(dest="cmd", required=True)

    snapshot = sub.add_parser("snapshot", help="Mostra stato, Resource, health, IP e metriche locali")
    snapshot.add_argument("--no-cache", action="store_true")
    snapshot.add_argument("--timeout", type=float, default=DEFAULT_DISCOVERY_TIMEOUT)

    server = sub.add_parser("serve", help="Avvia API HTTP read-only del Linux Agent")
    server.add_argument("--bind", default=DEFAULT_BIND)
    server.add_argument("--port", type=int, default=DEFAULT_PORT)
    server.add_argument("--token-file", default=str(AGENT_TOKEN_FILE))
    server.add_argument("--timeout", type=float, default=DEFAULT_DISCOVERY_TIMEOUT)
    return p


def main() -> None:
    try:
        args = parser().parse_args()
        if args.cmd == "snapshot":
            print(json.dumps(build_snapshot(use_cache=not args.no_cache, discovery_timeout=args.timeout), indent=2))
            return
        serve(
            bind=args.bind,
            port=args.port,
            token_file=Path(args.token_file),
            discovery_timeout=args.timeout,
        )
    except BridgeError as exc:
        raise SystemExit(f"[GE360 Agent] ERRORE: {exc}") from exc


if __name__ == "__main__":
    main()
