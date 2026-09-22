from __future__ import annotations

import hashlib
import hmac
import ipaddress
import json
import os
import secrets
import socket
import ssl
import threading
import time
from dataclasses import dataclass
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

STATE_DIR = Path(os.environ.get("GE360_RELAY_STATE_DIR", "/etc/ge360-relay"))
REGISTRY_FILE = STATE_DIR / "devices.json"
TOKEN_FILE = STATE_DIR / "admin.token"
TLS_CERT_FILE = STATE_DIR / "tls.crt"
TLS_KEY_FILE = STATE_DIR / "tls.key"

CONTROL_BIND = os.environ.get("GE360_RELAY_BIND", "0.0.0.0")
CONTROL_PORT = int(os.environ.get("GE360_RELAY_CONTROL_PORT", "8792"))
PUBLIC_HOST = os.environ.get("GE360_RELAY_PUBLIC_HOST", "").strip()
UDP_BIND = os.environ.get("GE360_RELAY_UDP_BIND", "0.0.0.0")
UDP_START = int(os.environ.get("GE360_RELAY_UDP_START", "40000"))
UDP_END = int(os.environ.get("GE360_RELAY_UDP_END", "40199"))
MAX_SESSIONS = int(os.environ.get("GE360_RELAY_MAX_SESSIONS", "50"))
SESSION_IDLE_SECONDS = int(os.environ.get("GE360_RELAY_IDLE_SECONDS", "90"))
SESSION_MAX_SECONDS = int(os.environ.get("GE360_RELAY_MAX_SECONDS", "86400"))
MAX_BODY = 32 * 1024
MAX_DATAGRAM = 65535

_registry_lock = threading.RLock()
_sessions_lock = threading.RLock()
_sessions: dict[str, "RelaySession"] = {}


def utc_now() -> float:
    return time.time()


def token_hash(token: str) -> str:
    return hashlib.sha256(str(token).encode("utf-8")).hexdigest()


def _load_admin_token() -> str:
    try:
        token = TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError:
        return ""
    return token


def _safe_device_id(value: str) -> str:
    text = str(value or "").strip()
    if not text or len(text) > 128:
        raise ValueError("device_id non valido")
    if any(ch not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-." for ch in text):
        raise ValueError("device_id non valido")
    return text


def _global_or_none(value: str | None) -> str | None:
    if not value:
        return None
    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return None
    return str(address) if isinstance(address, ipaddress.IPv4Address) and address.is_global else None


def _load_registry() -> dict[str, dict[str, Any]]:
    try:
        data = json.loads(REGISTRY_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return {}
    if not isinstance(data, dict):
        return {}
    out: dict[str, dict[str, Any]] = {}
    for key, value in data.items():
        if not isinstance(value, dict):
            continue
        digest = str(value.get("token_sha256") or "").lower()
        if len(digest) != 64:
            continue
        out[str(key)] = {
            "token_sha256": digest,
            "enabled": bool(value.get("enabled", True)),
            "updated_at": float(value.get("updated_at", 0)),
        }
    return out


def _save_registry(items: dict[str, dict[str, Any]]) -> None:
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(STATE_DIR, 0o700)
    tmp = REGISTRY_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.chmod(tmp, 0o600)
    tmp.replace(REGISTRY_FILE)
    os.chmod(REGISTRY_FILE, 0o600)


def sync_devices(items: list[dict[str, Any]]) -> dict[str, Any]:
    now = utc_now()
    clean: dict[str, dict[str, Any]] = {}
    for item in items:
        if not isinstance(item, dict):
            raise ValueError("registry relay non valido")
        device_id = _safe_device_id(str(item.get("device_id") or ""))
        digest = str(item.get("token_sha256") or "").strip().lower()
        if len(digest) != 64 or any(ch not in "0123456789abcdef" for ch in digest):
            raise ValueError("token_sha256 relay non valido")
        clean[device_id] = {
            "token_sha256": digest,
            "enabled": bool(item.get("enabled", True)),
            "updated_at": now,
        }
    with _registry_lock:
        _save_registry(clean)
    return {"ok": True, "devices": len(clean)}


def authenticate_device(device_id: str, token: str) -> bool:
    try:
        key = _safe_device_id(device_id)
    except ValueError:
        return False
    with _registry_lock:
        item = _load_registry().get(key)
    if not item or not item.get("enabled", True):
        return False
    supplied = token_hash(token)
    return hmac.compare_digest(str(item.get("token_sha256") or ""), supplied)


@dataclass
class RelayStats:
    bytes_bridge_to_client: int = 0
    bytes_client_to_bridge: int = 0
    packets_bridge_to_client: int = 0
    packets_client_to_bridge: int = 0


class RelaySession:
    def __init__(
        self,
        *,
        session_id: str,
        device_id: str,
        public_host: str,
        bridge_socket: socket.socket,
        client_socket: socket.socket,
        expected_client_ip: str | None,
        expected_bridge_ip: str | None = None,
    ):
        self.session_id = session_id
        self.device_id = device_id
        self.public_host = public_host
        self.bridge_socket = bridge_socket
        self.client_socket = client_socket
        self.expected_client_ip = expected_client_ip
        self.expected_bridge_ip = expected_bridge_ip
        self.bridge_peer: tuple[str, int] | None = None
        self.client_peer: tuple[str, int] | None = None
        self.created_at = utc_now()
        self.last_activity = self.created_at
        self.status = "WAITING_BRIDGE"
        self.stats = RelayStats()
        self._stop = threading.Event()
        self._threads: list[threading.Thread] = []

    @property
    def bridge_port(self) -> int:
        return int(self.bridge_socket.getsockname()[1])

    @property
    def client_port(self) -> int:
        return int(self.client_socket.getsockname()[1])

    @property
    def bridge_endpoint(self) -> str:
        return f"{self.public_host}:{self.bridge_port}"

    @property
    def client_endpoint(self) -> str:
        return f"{self.public_host}:{self.client_port}"

    def start(self) -> None:
        for role in ("bridge", "client"):
            thread = threading.Thread(
                target=self._pump,
                args=(role,),
                name=f"ge360-relay-{self.session_id}-{role}",
                daemon=True,
            )
            thread.start()
            self._threads.append(thread)

    def stop(self) -> None:
        self._stop.set()
        for sock in (self.bridge_socket, self.client_socket):
            try:
                sock.close()
            except OSError:
                pass

    def activate_bridge(self, expected_bridge_ip: str | None) -> None:
        self.expected_bridge_ip = expected_bridge_ip
        self.status = "ACTIVE"

    def _allowed(self, role: str, source_ip: str) -> bool:
        expected = self.expected_bridge_ip if role == "bridge" else self.expected_client_ip
        return expected is None or source_ip == expected

    def _pump(self, role: str) -> None:
        incoming = self.bridge_socket if role == "bridge" else self.client_socket
        outgoing = self.client_socket if role == "bridge" else self.bridge_socket
        incoming.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, peer = incoming.recvfrom(MAX_DATAGRAM)
            except socket.timeout:
                continue
            except OSError:
                break
            source = (str(peer[0]), int(peer[1]))
            if not self._allowed(role, source[0]):
                continue
            self.last_activity = utc_now()
            if role == "bridge":
                self.bridge_peer = source
                target = self.client_peer
                if target:
                    try:
                        outgoing.sendto(data, target)
                        self.stats.bytes_bridge_to_client += len(data)
                        self.stats.packets_bridge_to_client += 1
                    except OSError:
                        pass
            else:
                self.client_peer = source
                target = self.bridge_peer
                if target:
                    try:
                        outgoing.sendto(data, target)
                        self.stats.bytes_client_to_bridge += len(data)
                        self.stats.packets_client_to_bridge += 1
                    except OSError:
                        pass

    def expired(self, now: float | None = None) -> bool:
        current = float(now or utc_now())
        if current - self.created_at > SESSION_MAX_SECONDS:
            return True
        if current - self.last_activity > SESSION_IDLE_SECONDS and self.status == "ACTIVE":
            return True
        if current - self.created_at > 120 and self.status == "WAITING_BRIDGE":
            return True
        return False

    def public(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "device_id": self.device_id,
            "status": self.status,
            "bridge_endpoint": self.bridge_endpoint,
            "client_endpoint": self.client_endpoint,
            "expected_client_ip": self.expected_client_ip,
            "expected_bridge_ip": self.expected_bridge_ip,
            "bridge_peer_seen": self.bridge_peer is not None,
            "client_peer_seen": self.client_peer is not None,
            "created_at": self.created_at,
            "last_activity": self.last_activity,
            "stats": self.stats.__dict__.copy(),
        }


def _bind_udp_pair() -> tuple[socket.socket, socket.socket]:
    if UDP_START < 1024 or UDP_END > 65535 or UDP_END - UDP_START < 3:
        raise RuntimeError("Range UDP relay non valido")
    attempts = min(200, max(20, UDP_END - UDP_START + 1))
    for _ in range(attempts):
        first = secrets.randbelow(UDP_END - UDP_START + 1) + UDP_START
        second = secrets.randbelow(UDP_END - UDP_START + 1) + UDP_START
        if first == second:
            continue
        a = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        b = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            a.bind((UDP_BIND, first))
            b.bind((UDP_BIND, second))
            return a, b
        except OSError:
            a.close()
            b.close()
    raise RuntimeError("Nessuna coppia di porte UDP relay disponibile")


def create_session(device_id: str, client_ip: str) -> RelaySession:
    if not PUBLIC_HOST:
        raise RuntimeError("GE360_RELAY_PUBLIC_HOST non configurato")
    expected_client = _global_or_none(client_ip)
    if expected_client is None:
        # In test/LAN il client HTTP può essere loopback; in produzione la restrizione IP
        # resta best-effort e il ruolo è comunque separato da due porte casuali.
        expected_client = str(client_ip) if client_ip else None
    with _sessions_lock:
        cleanup_sessions()
        if len(_sessions) >= MAX_SESSIONS:
            raise RuntimeError("Capacità relay esaurita")
        existing = next(
            (x for x in _sessions.values() if x.device_id == device_id and not x.expired()),
            None,
        )
        if existing:
            return existing
        bridge_sock, client_sock = _bind_udp_pair()
        session = RelaySession(
            session_id="relay_" + secrets.token_hex(12),
            device_id=device_id,
            public_host=PUBLIC_HOST,
            bridge_socket=bridge_sock,
            client_socket=client_sock,
            expected_client_ip=expected_client,
        )
        _sessions[session.session_id] = session
        session.start()
        return session


def cleanup_sessions() -> None:
    now = utc_now()
    stale = [key for key, value in _sessions.items() if value.expired(now)]
    for key in stale:
        session = _sessions.pop(key, None)
        if session:
            session.stop()


def relay_status() -> dict[str, Any]:
    with _sessions_lock:
        cleanup_sessions()
        return {
            "schema": "ge360-relay-status/v1",
            "public_host": PUBLIC_HOST,
            "control_port": CONTROL_PORT,
            "udp_range": [UDP_START, UDP_END],
            "max_sessions": MAX_SESSIONS,
            "active_sessions": len(_sessions),
            "sessions": [x.public() for x in _sessions.values()],
            "payload_decryption": False,
            "resource_catalog": False,
            "multi_server_control_plane": False,
        }


def _admin_authorized(header: str | None) -> bool:
    token = _load_admin_token()
    if not token:
        return False
    value = str(header or "")
    if not value.startswith("Bearer "):
        return False
    return hmac.compare_digest(token, value[7:].strip())


class RelayHandler(BaseHTTPRequestHandler):
    server_version = "GE360Relay/0.22"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[ge360-relay] {self.client_address[0]} {fmt % args}")

    def send_json(self, payload: dict[str, Any], status: int = 200) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(data)

    def _body(self) -> dict[str, Any]:
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size <= 0 or size > MAX_BODY:
            raise ValueError("invalid_body")
        data = json.loads(self.rfile.read(size).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("invalid_body")
        return data

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json({"ok": True, "schema": "ge360-relay/v1"})
            return
        if self.path == "/v1/admin/status":
            if not _admin_authorized(self.headers.get("Authorization")):
                self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            self.send_json({"ok": True, "result": relay_status()})
            return
        self.send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        try:
            body = self._body()
        except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
            self.send_json({"ok": False, "error": "invalid_request"}, HTTPStatus.BAD_REQUEST)
            return

        if self.path.startswith("/v1/admin/"):
            if not _admin_authorized(self.headers.get("Authorization")):
                self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            try:
                if self.path == "/v1/admin/sync":
                    result = sync_devices(body.get("devices") or [])
                elif self.path == "/v1/admin/requests":
                    with _sessions_lock:
                        cleanup_sessions()
                        result = {
                            "requests": [
                                x.public()
                                for x in _sessions.values()
                                if x.status == "WAITING_BRIDGE"
                            ]
                        }
                elif self.path == "/v1/admin/activate":
                    session_id = str(body.get("session_id") or "")
                    with _sessions_lock:
                        session = _sessions.get(session_id)
                        if not session:
                            raise ValueError("session_not_found")
                        session.activate_bridge(_global_or_none(self.client_address[0]) or self.client_address[0])
                        result = session.public()
                else:
                    self.send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)
                    return
            except (ValueError, RuntimeError) as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self.send_json({"ok": True, "result": result})
            return

        if self.path in {"/v1/device/request", "/v1/device/status"}:
            device_id = str(body.get("device_id") or "")
            token = str(body.get("device_token") or "")
            if not authenticate_device(device_id, token):
                self.send_json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
                return
            try:
                if self.path == "/v1/device/request":
                    reason = str(body.get("reason") or "")
                    if reason not in {"direct_failed", "p2p_failed", "control_unreachable"}:
                        raise ValueError("fallback_reason_invalid")
                    with _sessions_lock:
                        session = create_session(device_id, self.client_address[0])
                    result = session.public() | {"fallback_reason": reason}
                else:
                    session_id = str(body.get("session_id") or "")
                    with _sessions_lock:
                        cleanup_sessions()
                        session = _sessions.get(session_id)
                        if not session or session.device_id != device_id:
                            raise ValueError("session_not_found")
                        result = session.public()
            except (ValueError, RuntimeError) as exc:
                self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.BAD_REQUEST)
                return
            self.send_json({"ok": True, "result": result})
            return

        self.send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)


def _wrap_tls(server: ThreadingHTTPServer) -> None:
    if not TLS_CERT_FILE.exists() or not TLS_KEY_FILE.exists():
        raise SystemExit("Certificato TLS relay mancante: esegui install-relay.sh")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(TLS_CERT_FILE), keyfile=str(TLS_KEY_FILE))
    server.socket = context.wrap_socket(server.socket, server_side=True)


def serve() -> None:
    if not PUBLIC_HOST:
        raise SystemExit("GE360_RELAY_PUBLIC_HOST non configurato")
    try:
        server = ThreadingHTTPServer((CONTROL_BIND, CONTROL_PORT), RelayHandler)
        _wrap_tls(server)
    except OSError as exc:
        raise SystemExit(f"Bind relay {CONTROL_BIND}:{CONTROL_PORT} fallito: {exc}") from exc
    threading.Thread(target=server.serve_forever, daemon=True).start()

    try:
        while True:
            with _sessions_lock:
                cleanup_sessions()
            time.sleep(5)
    except KeyboardInterrupt:
        pass
    finally:
        server.shutdown()
        server.server_close()
        with _sessions_lock:
            for session in list(_sessions.values()):
                session.stop()
            _sessions.clear()


if __name__ == "__main__":
    serve()
