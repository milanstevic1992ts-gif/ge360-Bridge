from __future__ import annotations

import hashlib
import http.client
import json
import os
import ssl
import subprocess
import tempfile
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

from . import core

RELAY_TOKEN_FILE = Path(os.environ.get("GE360_RELAY_TOKEN_FILE", "/etc/ge360-bridge/relay.token"))
RELAY_RUNTIME_DIR = Path(os.environ.get("GE360_RELAY_RUNTIME_DIR", "/run/ge360-bridge"))
RELAY_STATUS_FILE = RELAY_RUNTIME_DIR / "relay-status.json"
POLL_SECONDS = 2.0
SYNC_SECONDS = 60.0


def _bridge_env() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = core.BRIDGE_ENV.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def relay_config() -> dict[str, Any]:
    env = _bridge_env()
    enabled = env.get("RELAY_ENABLED", "false").strip().lower() in {"1", "true", "yes", "on"}
    url = env.get("RELAY_URL", "").strip().rstrip("/")
    fingerprint = env.get("RELAY_CERT_SHA256", "").strip().lower()
    fingerprint_valid = len(fingerprint) == 64 and all(ch in "0123456789abcdef" for ch in fingerprint)
    configured = (
        enabled
        and url.startswith("https://")
        and fingerprint_valid
        and RELAY_TOKEN_FILE.is_file()
    )
    return {
        "enabled": enabled,
        "configured": configured,
        "url": url,
        "tls_cert_sha256": fingerprint,
    }


def relay_public_config() -> dict[str, Any]:
    config = relay_config()
    if not config["configured"]:
        return {"enabled": False}
    return {
        "enabled": True,
        "url": config["url"],
        "tls_cert_sha256": config["tls_cert_sha256"],
    }


def _admin_token() -> str:
    try:
        token = RELAY_TOKEN_FILE.read_text(encoding="utf-8").strip()
    except OSError as exc:
        raise core.BridgeError("Token relay admin mancante.") from exc
    if len(token) < 24:
        raise core.BridgeError("Token relay admin non valido.")
    return token


def _relay_request(path: str, payload: dict[str, Any] | None = None, *, method: str = "POST") -> dict[str, Any]:
    config = relay_config()
    if not config["configured"]:
        raise core.BridgeError("Relay non configurato o disabilitato.")
    parsed = urlsplit(config["url"])
    if parsed.scheme != "https" or not parsed.hostname:
        raise core.BridgeError("RELAY_URL deve essere HTTPS.")
    port = parsed.port or 443
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE
    conn = http.client.HTTPSConnection(parsed.hostname, port, timeout=8, context=context)
    try:
        conn.connect()
        cert = conn.sock.getpeercert(binary_form=True) if conn.sock else None
        if not cert:
            raise core.BridgeError("Certificato TLS relay mancante.")
        actual = hashlib.sha256(cert).hexdigest()
        if actual != config["tls_cert_sha256"]:
            raise core.BridgeError("TLS certificate pin relay non corrisponde.")
        body = None if payload is None else json.dumps(payload, separators=(",", ":")).encode("utf-8")
        headers = {
            "Accept": "application/json",
            "Authorization": "Bearer " + _admin_token(),
        }
        if body is not None:
            headers["Content-Type"] = "application/json"
        base = parsed.path.rstrip("/")
        conn.request(method, base + path, body=body, headers=headers)
        response = conn.getresponse()
        raw = response.read(64 * 1024)
    except (OSError, ssl.SSLError, http.client.HTTPException) as exc:
        raise core.BridgeError(f"Connessione relay fallita: {exc.__class__.__name__}") from exc
    finally:
        conn.close()
    try:
        root = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise core.BridgeError("Risposta relay non JSON valida.") from exc
    if response.status < 200 or response.status >= 300 or not root.get("ok", False):
        raise core.BridgeError(str(root.get("error") or f"Relay HTTP {response.status}"))
    result = root.get("result")
    return result if isinstance(result, dict) else {}


def device_sync_payload() -> dict[str, Any]:
    devices = []
    for device in core.list_devices():
        token = str(device.get("token") or "")
        if not token:
            continue
        devices.append({
            "device_id": str(device["device_id"]),
            "token_sha256": hashlib.sha256(token.encode("utf-8")).hexdigest(),
            "enabled": core.device_is_active(device),
        })
    return {"devices": devices}


def sync_relay_devices() -> dict[str, Any]:
    return _relay_request("/v1/admin/sync", device_sync_payload())


def relay_remote_status() -> dict[str, Any]:
    return _relay_request("/v1/admin/status", None, method="GET")


def relay_requests() -> list[dict[str, Any]]:
    result = _relay_request("/v1/admin/requests", {})
    items = result.get("requests")
    return [dict(x) for x in items] if isinstance(items, list) else []


def _run(command: list[str], timeout: float = 4.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            command,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(command, 1, "", exc.__class__.__name__)


def _audit_relay(event: str, *, device: dict[str, Any] | None = None, result: str = "", error: str | None = None) -> None:
    try:
        from .audit import write_event
        write_event(
            event,
            device_id=device.get("device_id") if device else None,
            device_name=device.get("name") if device else None,
            action="relay_fallback",
            result=result,
            ip=None,
            error=error,
        )
    except Exception:
        pass


def activate_request(
    request: dict[str, Any],
    *,
    runner=_run,
) -> dict[str, Any]:
    session_id = str(request.get("session_id") or "")
    device_id = str(request.get("device_id") or "")
    endpoint = str(request.get("bridge_endpoint") or "")
    if not session_id or not device_id or not endpoint:
        raise core.BridgeError("Richiesta relay incompleta.")
    device = core.find_device(device_id)
    if not device or not core.device_is_active(device):
        raise core.BridgeError("Device relay non trovato o disabilitato.")
    peer_key = str(device.get("public_key") or "")
    if not peer_key:
        raise core.BridgeError("Public key WireGuard device mancante.")
    set_result = runner(
        [
            "wg", "set", "wg0",
            "peer", peer_key,
            "endpoint", endpoint,
            "persistent-keepalive", "25",
        ],
        4.0,
    )
    if set_result.returncode != 0:
        raise core.BridgeError("Impossibile impostare endpoint relay WireGuard runtime.")
    runner(["ping", "-c", "1", "-W", "1", str(device["vpn_ip"])], 3.0)
    activated = _relay_request("/v1/admin/activate", {"session_id": session_id})
    _audit_relay("RELAY_ACTIVE", device=device, result=str(activated.get("status", "ACTIVE")))
    return {
        "session_id": session_id,
        "device_id": device_id,
        "device_name": device.get("name"),
        "bridge_endpoint": endpoint,
        "client_endpoint": request.get("client_endpoint"),
        "status": activated.get("status", "ACTIVE"),
        "activated_at": time.time(),
        "runtime_only": True,
    }


def _write_local_status(payload: dict[str, Any]) -> None:
    try:
        RELAY_RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(RELAY_RUNTIME_DIR, 0o700)
        fd, tmp_name = tempfile.mkstemp(prefix=".relay-status-", dir=str(RELAY_RUNTIME_DIR))
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            tmp.replace(RELAY_STATUS_FILE)
            os.chmod(RELAY_STATUS_FILE, 0o600)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
    except OSError:
        pass


def local_relay_status() -> dict[str, Any]:
    config = relay_config()
    try:
        runtime = json.loads(RELAY_STATUS_FILE.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        runtime = {}
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "schema": "ge360-bridge-relay-status/v1",
        "enabled": config["enabled"],
        "configured": config["configured"],
        "url": config["url"],
        "runtime": runtime,
        "multi_server_control_plane": False,
    }


def relay_visible() -> bool:
    status = local_relay_status()
    runtime = status.get("runtime") or {}
    if runtime.get("active_sessions"):
        return True
    try:
        from .p2p import list_sessions
        return any(x.get("status") in {"FAILED", "ERROR"} for x in list_sessions())
    except Exception:
        return False


def monitor_once(*, runner=_run) -> dict[str, Any]:
    if not relay_config()["configured"]:
        result = {"configured": False, "active_sessions": [], "errors": []}
        _write_local_status(result)
        return result
    sync = sync_relay_devices()
    requests = relay_requests()
    active: list[dict[str, Any]] = []
    errors: list[dict[str, str]] = []
    for item in requests:
        try:
            active.append(activate_request(item, runner=runner))
        except Exception as exc:
            device = core.find_device(str(item.get("device_id") or ""))
            _audit_relay("RELAY_FAILED", device=device, result="ERROR", error=str(exc)[:300])
            errors.append({
                "session_id": str(item.get("session_id") or ""),
                "device_id": str(item.get("device_id") or ""),
                "error": str(exc)[:300],
            })
    try:
        remote = relay_remote_status()
        remote_sessions = remote.get("sessions") if isinstance(remote.get("sessions"), list) else []
    except Exception as exc:
        remote_sessions = active
        errors.append({"error": "remote_status: " + str(exc)[:250]})
    result = {
        "configured": True,
        "last_sync": time.time(),
        "synced_devices": sync.get("devices"),
        "active_sessions": remote_sessions,
        "errors": errors,
    }
    _write_local_status(result)
    return result


def monitor_forever() -> None:
    last_sync = 0.0
    while True:
        config = relay_config()
        if not config["configured"]:
            _write_local_status({"configured": False, "active_sessions": [], "errors": []})
            time.sleep(10)
            continue
        now = time.time()
        try:
            if now - last_sync >= SYNC_SECONDS:
                sync_relay_devices()
                last_sync = now
            requests = relay_requests()
            active = []
            errors = []
            for item in requests:
                try:
                    active.append(activate_request(item))
                except Exception as exc:
                    errors.append({
                        "session_id": str(item.get("session_id") or ""),
                        "error": str(exc)[:300],
                    })
            try:
                remote = relay_remote_status()
                remote_sessions = remote.get("sessions") if isinstance(remote.get("sessions"), list) else active
            except Exception as exc:
                remote_sessions = active
                errors.append({"error": "remote_status: " + str(exc)[:250]})
            _write_local_status({
                "configured": True,
                "last_poll": now,
                "active_sessions": remote_sessions,
                "errors": errors,
            })
        except Exception as exc:
            _write_local_status({
                "configured": True,
                "last_poll": now,
                "active_sessions": [],
                "errors": [{"error": str(exc)[:300]}],
            })
        time.sleep(POLL_SECONDS)
