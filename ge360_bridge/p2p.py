from __future__ import annotations

import hmac
import ipaddress
import json
import os
import secrets
import subprocess
import tempfile
import threading
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlsplit

from . import core
from .nat_discovery import global_ipv6_addresses
from .pairing import load_bridge_env

SESSION_TTL_SECONDS = 90
START_DELAY_SECONDS = 0.35
PUNCH_ATTEMPTS = 5
PUNCH_INTERVAL_SECONDS = 0.8
RATE_WINDOW_SECONDS = 60
RATE_LIMIT_PER_DEVICE = 6

_LOCK = threading.RLock()
_SESSIONS: dict[str, dict[str, Any]] = {}
_DEVICE_ATTEMPTS: dict[str, list[float]] = {}
RUNTIME_DIR = Path(os.environ.get("GE360_P2P_RUNTIME_DIR", "/run/ge360-bridge"))
SESSION_MIRROR = RUNTIME_DIR / "p2p-sessions.json"


@dataclass(frozen=True)
class PeerCandidate:
    ip: str
    port: int
    local_port: int | None = None
    source: str = "stun"

    @property
    def endpoint(self) -> str:
        address = ipaddress.ip_address(self.ip)
        if isinstance(address, ipaddress.IPv6Address):
            return f"[{address}]:{self.port}"
        return f"{address}:{self.port}"


def traversal_enabled() -> bool:
    value = load_bridge_env().get("TRAVERSAL_ENABLED", "true").strip().lower()
    return value not in {"0", "false", "no", "off", "disabled"}


def _now() -> float:
    return time.time()


def _write_session_mirror_unlocked() -> None:
    try:
        RUNTIME_DIR.mkdir(parents=True, exist_ok=True)
        os.chmod(RUNTIME_DIR, 0o700)
        payload = [
            _safe_session(dict(session))
            for session in sorted(
                _SESSIONS.values(),
                key=lambda item: float(item.get("created_at", 0)),
                reverse=True,
            )
        ]
        fd, tmp_name = tempfile.mkstemp(prefix=".p2p-", dir=str(RUNTIME_DIR))
        tmp = Path(tmp_name)
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as handle:
                json.dump(payload, handle, indent=2, sort_keys=True)
                handle.write("\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.chmod(tmp, 0o600)
            tmp.replace(SESSION_MIRROR)
            os.chmod(SESSION_MIRROR, 0o600)
        finally:
            if tmp.exists():
                tmp.unlink(missing_ok=True)
    except OSError:
        pass


def _read_session_mirror() -> list[dict[str, Any]]:
    try:
        data = json.loads(SESSION_MIRROR.read_text(encoding="utf-8"))
    except (FileNotFoundError, OSError, json.JSONDecodeError):
        return []
    if not isinstance(data, list):
        return []
    now = _now()
    return [
        dict(item)
        for item in data
        if isinstance(item, dict) and float(item.get("expires_at", 0)) > now
    ]


def _cleanup(now: float | None = None) -> None:
    current = float(now or _now())
    expired = [
        session_id
        for session_id, session in _SESSIONS.items()
        if float(session.get("expires_at", 0)) <= current
    ]
    changed = bool(expired)
    for session_id in expired:
        _SESSIONS.pop(session_id, None)
    for device_id, values in list(_DEVICE_ATTEMPTS.items()):
        fresh = [x for x in values if current - x < RATE_WINDOW_SECONDS]
        if fresh:
            _DEVICE_ATTEMPTS[device_id] = fresh
        else:
            _DEVICE_ATTEMPTS.pop(device_id, None)
    if changed:
        _write_session_mirror_unlocked()


def _rate_limit(device_id: str, now: float | None = None) -> None:
    current = float(now or _now())
    with _LOCK:
        _cleanup(current)
        values = _DEVICE_ATTEMPTS.setdefault(device_id, [])
        if len(values) >= RATE_LIMIT_PER_DEVICE:
            raise core.BridgeError("Troppi tentativi P2P per questo device; riprova tra poco.")
        values.append(current)


def authenticate_device(device_id: str, token: str) -> dict[str, Any]:
    device = core.find_device(device_id)
    if not device or not core.device_is_active(device):
        raise core.BridgeError("Device P2P non valido o disabilitato.")
    stored = str(device.get("token") or "")
    supplied = str(token or "")
    if not stored or not supplied or not hmac.compare_digest(stored, supplied):
        raise core.BridgeError("Autenticazione P2P non valida.")
    return device


def validate_candidate(ip: str, port: int, local_port: int | None = None, source: str = "stun") -> PeerCandidate:
    try:
        address = ipaddress.ip_address(str(ip).strip())
    except ValueError as exc:
        raise core.BridgeError("IP candidato P2P non valido.") from exc
    if not address.is_global:
        raise core.BridgeError("Il candidato P2P deve essere un indirizzo IP globale.")
    try:
        port_value = int(port)
    except (TypeError, ValueError) as exc:
        raise core.BridgeError("Porta candidata P2P non valida.") from exc
    if port_value < 1 or port_value > 65535:
        raise core.BridgeError("Porta candidata P2P non valida.")
    local_value = None
    if local_port is not None:
        try:
            local_value = int(local_port)
        except (TypeError, ValueError) as exc:
            raise core.BridgeError("Porta locale candidata P2P non valida.") from exc
        if local_value < 1 or local_value > 65535:
            raise core.BridgeError("Porta locale candidata P2P non valida.")
    source_value = str(source or "stun").strip().lower()
    if source_value not in {"stun", "ipv6", "manual"}:
        raise core.BridgeError("Sorgente candidato P2P non valida.")
    return PeerCandidate(str(address), port_value, local_value, source_value)


def _public_endpoint_candidate() -> dict[str, Any] | None:
    env = load_bridge_env()
    raw = str(env.get("PUBLIC_ENDPOINT") or "").strip()
    if not raw or raw.upper().startswith("CHANGE_ME"):
        return None
    try:
        if raw.startswith("["):
            parsed = urlsplit("udp://" + raw)
            host = parsed.hostname
            port = parsed.port
        else:
            host_text, port_text = raw.rsplit(":", 1)
            host = host_text.strip()
            port = int(port_text)
    except (ValueError, TypeError):
        return None
    if not host or not port or port < 1 or port > 65535:
        return None
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        # Hostname configurato esplicitamente dall'operatore: il client lo risolverà.
        return {
            "endpoint": raw,
            "kind": "configured_public_endpoint",
            "priority": 100,
        }
    if not address.is_global:
        return None
    endpoint = f"[{address}]:{port}" if isinstance(address, ipaddress.IPv6Address) else f"{address}:{port}"
    return {
        "endpoint": endpoint,
        "kind": "configured_public_endpoint",
        "priority": 100,
    }


def server_candidates() -> list[dict[str, Any]]:
    env = load_bridge_env()
    try:
        wg_port = int(env.get("WG_PORT", "51820"))
    except ValueError:
        wg_port = 51820
    out: list[dict[str, Any]] = []
    configured = _public_endpoint_candidate()
    if configured:
        out.append(configured)
    for address in global_ipv6_addresses():
        endpoint = f"[{address}]:{wg_port}"
        if not any(item["endpoint"] == endpoint for item in out):
            out.append({
                "endpoint": endpoint,
                "kind": "global_ipv6",
                "priority": 90,
            })
    return sorted(out, key=lambda x: int(x.get("priority", 0)), reverse=True)


def _safe_session(session: dict[str, Any]) -> dict[str, Any]:
    return {
        key: value
        for key, value in session.items()
        if key not in {"peer_public_key", "device_token"}
    }


def prepare_traversal(
    device_id: str,
    token: str,
    *,
    candidate_ip: str,
    candidate_port: int,
    candidate_local_port: int | None = None,
    candidate_source: str = "stun",
    start_worker: bool = True,
) -> dict[str, Any]:
    if not traversal_enabled():
        raise core.BridgeError("NAT Traversal P2P disabilitato in bridge.env.")
    device = authenticate_device(device_id, token)
    candidate = validate_candidate(candidate_ip, candidate_port, candidate_local_port, candidate_source)
    candidates = server_candidates()
    if not candidates:
        raise core.BridgeError(
            "Nessun candidato server P2P disponibile: configura PUBLIC_ENDPOINT o IPv6 globale."
        )
    _rate_limit(device["device_id"])
    now = _now()
    session_id = "p2p_" + secrets.token_hex(12)
    session = {
        "schema": "ge360-p2p-traversal-session/v1",
        "session_id": session_id,
        "device_id": device["device_id"],
        "device_name": device["name"],
        "vpn_ip": device["vpn_ip"],
        "peer_public_key": device["public_key"],
        "client_candidate": asdict(candidate) | {"endpoint": candidate.endpoint},
        "server_candidates": candidates,
        "recommended_endpoint": candidates[0]["endpoint"],
        "fallback_endpoint": str(load_bridge_env().get("PUBLIC_ENDPOINT") or ""),
        "created_at": now,
        "expires_at": now + SESSION_TTL_SECONDS,
        "status": "PREPARED",
        "attempts": 0,
        "latest_handshake": 0,
        "error": None,
        "relay_used": False,
        "runtime_only": True,
    }
    with _LOCK:
        _cleanup(now)
        _SESSIONS[session_id] = session
        _write_session_mirror_unlocked()
    _audit("P2P_PREPARED", session, "PREPARED")
    if start_worker:
        thread = threading.Thread(
            target=_delayed_attempt,
            args=(session_id,),
            name=f"ge360-{session_id}",
            daemon=True,
        )
        thread.start()
    return _safe_session(dict(session))


def traversal_status(device_id: str, token: str, session_id: str) -> dict[str, Any]:
    device = authenticate_device(device_id, token)
    with _LOCK:
        _cleanup()
        session = _SESSIONS.get(str(session_id))
        if not session or session.get("device_id") != device["device_id"]:
            raise core.BridgeError("Sessione P2P non trovata o scaduta.")
        return _safe_session(dict(session))


def list_sessions() -> list[dict[str, Any]]:
    with _LOCK:
        _cleanup()
        if _SESSIONS:
            return [_safe_session(dict(x)) for x in sorted(
                _SESSIONS.values(),
                key=lambda item: float(item.get("created_at", 0)),
                reverse=True,
            )]
    return _read_session_mirror()


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


def _latest_handshake(public_key: str, runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run) -> int:
    proc = runner(["wg", "show", "wg0", "latest-handshakes"], 3.0)
    if proc.returncode != 0:
        return 0
    for raw in proc.stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == public_key:
            try:
                return int(parts[1])
            except ValueError:
                return 0
    return 0


def _current_endpoint(public_key: str, runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run) -> str | None:
    proc = runner(["wg", "show", "wg0", "endpoints"], 3.0)
    if proc.returncode != 0:
        return None
    for raw in proc.stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == public_key:
            value = parts[1].strip()
            return None if value in {"(none)", "off"} else value
    return None


def _current_keepalive(
    public_key: str,
    runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run,
) -> int:
    proc = runner(["wg", "show", "wg0", "persistent-keepalive"], 3.0)
    if proc.returncode != 0:
        return 0
    for raw in proc.stdout.splitlines():
        parts = raw.split()
        if len(parts) >= 2 and parts[0] == public_key:
            value = parts[1].strip().lower()
            if value in {"off", "0"}:
                return 0
            try:
                return int(value)
            except ValueError:
                return 0
    return 0


def _set_peer_endpoint(
    public_key: str,
    endpoint: str,
    keepalive: int,
    runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run,
) -> None:
    proc = runner(
        [
            "wg", "set", "wg0",
            "peer", public_key,
            "endpoint", endpoint,
            "persistent-keepalive", str(int(keepalive)),
        ],
        4.0,
    )
    if proc.returncode != 0:
        raise core.BridgeError("Impossibile impostare endpoint WireGuard runtime per P2P.")


def _trigger_wireguard(
    vpn_ip: str,
    runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run,
) -> None:
    # Il ping non trasporta dati applicativi: serve soltanto a far emettere traffico WireGuard.
    runner(["ping", "-c", "1", "-W", "1", vpn_ip], 3.0)


def _update_session(session_id: str, **changes: Any) -> dict[str, Any] | None:
    with _LOCK:
        session = _SESSIONS.get(session_id)
        if not session:
            return None
        session.update(changes)
        _write_session_mirror_unlocked()
        return dict(session)


def attempt_traversal(
    session_id: str,
    *,
    runner: Callable[[list[str], float], subprocess.CompletedProcess[str]] = _run,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    with _LOCK:
        _cleanup()
        session = _SESSIONS.get(session_id)
        if not session:
            raise core.BridgeError("Sessione P2P non trovata o scaduta.")
        session = dict(session)
    if session.get("status") not in {"PREPARED", "PUNCHING"}:
        return _safe_session(session)

    public_key = str(session["peer_public_key"])
    candidate_endpoint = str(session["client_candidate"]["endpoint"])
    previous_endpoint = _current_endpoint(public_key, runner)
    previous_keepalive = _current_keepalive(public_key, runner)
    baseline = _latest_handshake(public_key, runner)
    started = int(_now())
    _update_session(
        session_id,
        status="PUNCHING",
        previous_endpoint=previous_endpoint,
        previous_keepalive=previous_keepalive,
        baseline_handshake=baseline,
    )

    try:
        _set_peer_endpoint(public_key, candidate_endpoint, 5, runner)
        for attempt in range(1, PUNCH_ATTEMPTS + 1):
            _update_session(session_id, attempts=attempt)
            _trigger_wireguard(str(session["vpn_ip"]), runner)
            sleeper(PUNCH_INTERVAL_SECONDS)
            latest = _latest_handshake(public_key, runner)
            _update_session(session_id, latest_handshake=latest)
            if latest > max(baseline, started - 1):
                _set_peer_endpoint(public_key, candidate_endpoint, 25, runner)
                completed = _update_session(
                    session_id,
                    status="SUCCEEDED",
                    error=None,
                    completed_at=_now(),
                    endpoint_active=candidate_endpoint,
                ) or session
                _audit("P2P_SUCCEEDED", completed, "SUCCEEDED")
                return _safe_session(completed)

        if previous_endpoint:
            try:
                _set_peer_endpoint(public_key, previous_endpoint, previous_keepalive, runner)
                restore = "previous_endpoint_restored"
            except core.BridgeError:
                restore = "previous_endpoint_restore_failed"
        else:
            # WireGuard non espone un comando sicuro per rimuovere solo l'endpoint mantenendo il peer.
            # Lasciamo il candidato runtime: un pacchetto WireGuard autenticato successivo lo aggiornerà via roaming.
            try:
                _set_peer_endpoint(public_key, candidate_endpoint, 0, runner)
            except core.BridgeError:
                pass
            restore = "no_previous_endpoint_candidate_left_runtime_only"
        completed = _update_session(
            session_id,
            status="FAILED",
            error="wireguard_handshake_not_observed",
            completed_at=_now(),
            endpoint_restore=restore,
        ) or session
        _audit("P2P_FAILED", completed, "FAILED", error="wireguard_handshake_not_observed")
        return _safe_session(completed)
    except Exception as exc:
        if previous_endpoint:
            try:
                _set_peer_endpoint(public_key, previous_endpoint, previous_keepalive, runner)
            except Exception:
                pass
        completed = _update_session(
            session_id,
            status="ERROR",
            error=exc.__class__.__name__,
            completed_at=_now(),
        ) or session
        _audit("P2P_FAILED", completed, "ERROR", error=exc.__class__.__name__)
        return _safe_session(completed)


def _delayed_attempt(session_id: str) -> None:
    time.sleep(START_DELAY_SECONDS)
    try:
        attempt_traversal(session_id)
    except Exception:
        _update_session(
            session_id,
            status="ERROR",
            error="worker_error",
            completed_at=_now(),
        )


def _audit(event: str, session: dict[str, Any], result: str, error: str | None = None) -> None:
    try:
        from .audit import write_event
        write_event(
            event,
            device_id=session.get("device_id"),
            device_name=session.get("device_name"),
            action="nat_traversal",
            result=result,
            ip=(session.get("client_candidate") or {}).get("ip"),
            error=error,
        )
    except Exception:
        pass


def p2p_status() -> dict[str, Any]:
    candidates = server_candidates()
    try:
        from .relay_client import local_relay_status
        relay = local_relay_status()
        relay_runtime = relay.get("runtime") or {}
        relay_sessions = relay_runtime.get("active_sessions") or []
        relay_available = bool(relay.get("configured"))
        relay_used = bool(relay_sessions)
    except Exception:
        relay_available = False
        relay_used = False
    return {
        "schema": "ge360-p2p-traversal-status/v1",
        "enabled": traversal_enabled(),
        "session_ttl_seconds": SESSION_TTL_SECONDS,
        "rate_limit_per_device_per_minute": RATE_LIMIT_PER_DEVICE,
        "server_candidates": candidates,
        "sessions": list_sessions(),
        "relay_available": relay_available,
        "relay_used": relay_used,
        "phase20_started": True,
        "limitations": [
            "P2P diretto richiede un control path raggiungibile per lo scambio candidati",
            "STUN non garantisce hole punching attraverso CGNAT o NAT destination-dependent",
            "relay Fase 20 è opzionale e viene usato soltanto come fallback",
        ],
    }
