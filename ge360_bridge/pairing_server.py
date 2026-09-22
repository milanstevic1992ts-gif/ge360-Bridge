from __future__ import annotations

import json
import socket
import ssl
import subprocess
import threading
import time
from collections import defaultdict, deque
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from . import core
from .pairing import PAIRING_PORT, TLS_CERT_FILE, consume_enrollment
from .p2p import prepare_traversal, traversal_status

MAX_BODY = 8192
RATE_LIMIT = 20
RATE_WINDOW_SECONDS = 60
_attempts: dict[str, deque[float]] = defaultdict(deque)
_rate_lock = threading.Lock()


def allowed_request(ip: str) -> bool:
    now = time.time()
    with _rate_lock:
        q = _attempts[ip]
        while q and now - q[0] > RATE_WINDOW_SECONDS:
            q.popleft()
        if len(q) >= RATE_LIMIT:
            return False
        q.append(now)
        return True


class EnrollmentHandler(BaseHTTPRequestHandler):
    server_version = "GE360BridgeEnrollment/0.21"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[pairing-v2] {self.client_address[0]} {fmt % args}")

    def send_json(self, payload: dict, status: int = 200) -> None:
        data = json.dumps(payload, separators=(",", ":")).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("X-Frame-Options", "DENY")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        if self.path == "/healthz":
            self.send_json({"ok": True, "schema": "ge360-bridge-pairing/v2"})
        else:
            self.send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if self.path not in {"/v2/enroll", "/v3/traversal/prepare", "/v3/traversal/status"}:
            self.send_json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)
            return
        ip = self.client_address[0]
        if not allowed_request(ip):
            self.send_json({"ok": False, "error": "rate_limited"}, HTTPStatus.TOO_MANY_REQUESTS)
            return
        try:
            size = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            size = 0
        if size <= 0 or size > MAX_BODY:
            self.send_json({"ok": False, "error": "invalid_request"}, HTTPStatus.BAD_REQUEST)
            return
        try:
            body = json.loads(self.rfile.read(size).decode("utf-8"))
            if not isinstance(body, dict):
                raise ValueError("body_not_object")
        except (json.JSONDecodeError, UnicodeDecodeError, ValueError):
            self.send_json({"ok": False, "error": "invalid_json"}, HTTPStatus.BAD_REQUEST)
            return

        if self.path == "/v2/enroll":
            try:
                enrollment_id = str(body.get("enrollment_id", ""))
                token = str(body.get("token", ""))
                public_key = str(body.get("public_key", ""))
                result = consume_enrollment(enrollment_id, token, public_key)
            except core.BridgeError as exc:
                message = str(exc)
                status = HTTPStatus.BAD_REQUEST if "Public key" in message else HTTPStatus.FORBIDDEN
                self.send_json({"ok": False, "error": message}, status)
                return

            try:
                sync = subprocess.run(
                    ["/usr/local/sbin/ge360-bridge", "device-sync"],
                    text=True,
                    capture_output=True,
                    timeout=15,
                    check=False,
                )
                result["runtime_sync"] = sync.returncode == 0
            except (OSError, subprocess.TimeoutExpired):
                result["runtime_sync"] = False
            self.send_json({"ok": True, "result": result}, HTTPStatus.OK)
            return

        try:
            device_id = str(body.get("device_id", ""))
            device_token = str(body.get("device_token", ""))
            if self.path == "/v3/traversal/prepare":
                candidate = body.get("candidate")
                if not isinstance(candidate, dict):
                    raise core.BridgeError("Candidato P2P mancante.")
                result = prepare_traversal(
                    device_id,
                    device_token,
                    candidate_ip=str(candidate.get("ip", "")),
                    candidate_port=int(candidate.get("port", 0)),
                    candidate_local_port=(
                        int(candidate["local_port"])
                        if candidate.get("local_port") is not None
                        else None
                    ),
                    candidate_source=str(candidate.get("source", "stun")),
                )
            else:
                result = traversal_status(
                    device_id,
                    device_token,
                    str(body.get("session_id", "")),
                )
        except (core.BridgeError, TypeError, ValueError) as exc:
            self.send_json({"ok": False, "error": str(exc)}, HTTPStatus.FORBIDDEN)
            return
        self.send_json({"ok": True, "result": result}, HTTPStatus.OK)


class V6ThreadingHTTPServer(ThreadingHTTPServer):
    address_family = socket.AF_INET6
    def server_bind(self) -> None:
        self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
        super().server_bind()


def wrap_tls(server: ThreadingHTTPServer) -> None:
    key_file = core.STATE_DIR / "pairing-tls.key"
    if not TLS_CERT_FILE.exists() or not key_file.exists():
        raise SystemExit("Certificato TLS pairing mancante: esegui install.sh")
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(TLS_CERT_FILE), keyfile=str(key_file))
    server.socket = context.wrap_socket(server.socket, server_side=True)


def serve() -> None:
    servers: list[ThreadingHTTPServer] = []
    for cls, address in (
        (ThreadingHTTPServer, ("0.0.0.0", PAIRING_PORT)),
        (V6ThreadingHTTPServer, ("::", PAIRING_PORT)),
    ):
        try:
            server = cls(address, EnrollmentHandler)
            wrap_tls(server)
        except OSError as exc:
            print(f"[pairing-v2] bind {address[0]}:{PAIRING_PORT} fallito: {exc}")
            continue
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[pairing-v2] HTTPS {address[0]}:{PAIRING_PORT}")
    if not servers:
        raise SystemExit("Nessun bind disponibile per pairing v2")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    serve()
