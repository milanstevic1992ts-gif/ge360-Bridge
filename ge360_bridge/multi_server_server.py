from __future__ import annotations

import hmac
import json
import os
import ssl
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

from . import __version__
from .agent import build_snapshot
from .multi_server import DEFAULT_CONTROL_PORT, local_server_id, local_server_token

BIND = os.environ.get("GE360_MULTI_SERVER_BIND", "0.0.0.0")
PORT = int(os.environ.get("GE360_MULTI_SERVER_PORT", str(DEFAULT_CONTROL_PORT)))
CERT_FILE = Path(os.environ.get("GE360_MULTI_SERVER_TLS_CERT", "/etc/ge360-bridge/multi-server-tls.crt"))
KEY_FILE = Path(os.environ.get("GE360_MULTI_SERVER_TLS_KEY", "/etc/ge360-bridge/multi-server-tls.key"))


class ControlHandler(BaseHTTPRequestHandler):
    server_version = "GE360MultiServer/0.23"

    def log_message(self, fmt: str, *args: Any) -> None:
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
        candidate = auth[7:].strip() if auth.startswith("Bearer ") else ""
        expected = self.server.control_token
        return bool(candidate and expected and hmac.compare_digest(candidate, expected))

    def do_GET(self) -> None:
        path = self.path.split("?", 1)[0]
        if path == "/healthz":
            self._json({
                "ok": True,
                "schema": "ge360-multi-server-control/v1",
                "server_id": self.server.server_id,
                "version": __version__,
            })
            return
        if path != "/v1/control/snapshot":
            self._json({"ok": False, "error": "not_found"}, HTTPStatus.NOT_FOUND)
            return
        if not self._authorized():
            self._json({"ok": False, "error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        snapshot = build_snapshot(use_cache=True)
        self._json(snapshot)


class ControlServer(ThreadingHTTPServer):
    daemon_threads = True

    def __init__(self, address, handler, *, token: str, server_id: str):
        super().__init__(address, handler)
        self.control_token = token
        self.server_id = server_id


def serve() -> None:
    token = local_server_token()
    server_id = local_server_id()
    if not CERT_FILE.is_file() or not KEY_FILE.is_file():
        raise SystemExit("Certificato multi-server mancante: esegui install.sh")
    server = ControlServer((BIND, PORT), ControlHandler, token=token, server_id=server_id)
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    context.load_cert_chain(certfile=str(CERT_FILE), keyfile=str(KEY_FILE))
    server.socket = context.wrap_socket(server.socket, server_side=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()


if __name__ == "__main__":
    serve()
