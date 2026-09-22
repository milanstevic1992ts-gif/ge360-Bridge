from __future__ import annotations

import base64
import binascii
import fcntl
import hashlib
import hmac
import json
import os
import secrets
import ssl
import time
from contextlib import contextmanager
from pathlib import Path
from typing import Any

from . import core
from .relay_client import relay_public_config

PAIRING_PORT = 8790
ENROLLMENTS_FILE = core.STATE_DIR / "enrollments.json"
ENROLLMENT_SECRET_FILE = core.STATE_DIR / "enrollment.key"
ENROLLMENT_LOCK_FILE = core.STATE_DIR / "enrollments.lock"
TLS_CERT_FILE = core.STATE_DIR / "pairing-tls.crt"
USED_RETENTION_SECONDS = 7 * 24 * 3600
MIN_TTL_SECONDS = 60
MAX_TTL_SECONDS = 24 * 3600
DEFAULT_TTL_SECONDS = 600


@contextmanager
def enrollment_lock():
    ENROLLMENT_LOCK_FILE.parent.mkdir(parents=True, exist_ok=True)
    with ENROLLMENT_LOCK_FILE.open("a+", encoding="utf-8") as lock:
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def _load_enrollments() -> list[dict[str, Any]]:
    try:
        return json.loads(ENROLLMENTS_FILE.read_text(encoding="utf-8"))
    except FileNotFoundError:
        return []


def _save_enrollments(items: list[dict[str, Any]]) -> None:
    core._atomic_write(ENROLLMENTS_FILE, items)


def _secret() -> bytes:
    try:
        raw = ENROLLMENT_SECRET_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        ENROLLMENT_SECRET_FILE.parent.mkdir(parents=True, exist_ok=True)
        raw = secrets.token_hex(32)
        ENROLLMENT_SECRET_FILE.write_text(raw + "\n", encoding="utf-8")
        os.chmod(ENROLLMENT_SECRET_FILE, 0o600)
    try:
        return bytes.fromhex(raw)
    except ValueError as exc:
        raise core.BridgeError("enrollment.key non valido.") from exc


def token_digest(token: str) -> str:
    return hmac.new(_secret(), token.encode("utf-8"), hashlib.sha256).hexdigest()


def cleanup_enrollments(items: list[dict[str, Any]], now: int | None = None) -> list[dict[str, Any]]:
    now = int(now or time.time())
    out = []
    for item in items:
        record = dict(item)
        if record.get("status") == "pending" and int(record.get("expires_at", 0)) <= now:
            record["status"] = "expired"
            record["expired_at"] = now
        terminal_at = int(record.get("used_at") or record.get("expired_at") or 0)
        if record.get("status") in {"used", "expired"} and terminal_at and now - terminal_at > USED_RETENTION_SECONDS:
            continue
        out.append(record)
    return out


def _validate_ttl(ttl_seconds: int) -> int:
    ttl = int(ttl_seconds)
    if ttl < MIN_TTL_SECONDS or ttl > MAX_TTL_SECONDS:
        raise core.BridgeError("TTL pairing non valido: minimo 60 secondi, massimo 86400.")
    return ttl


def validate_wireguard_public_key(value: str) -> str:
    key = (value or "").strip()
    try:
        decoded = base64.b64decode(key, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise core.BridgeError("Public key WireGuard non valida.") from exc
    if len(decoded) != 32:
        raise core.BridgeError("Public key WireGuard non valida.")
    return key


def generate_psk() -> str:
    try:
        return core.run(["wg", "genpsk"]).stdout.strip()
    except Exception as exc:
        raise core.BridgeError("Impossibile generare la PSK WireGuard.") from exc


def load_bridge_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if not core.BRIDGE_ENV.exists():
        return out
    for raw in core.BRIDGE_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def server_public_key() -> str:
    path = core.STATE_DIR / "server.pub"
    try:
        return path.read_text(encoding="utf-8").strip()
    except FileNotFoundError as exc:
        raise core.BridgeError("Chiave pubblica server mancante.") from exc


def tls_cert_fingerprint() -> str:
    try:
        pem = TLS_CERT_FILE.read_text(encoding="utf-8")
        der = ssl.PEM_cert_to_DER_cert(pem)
    except (FileNotFoundError, ValueError) as exc:
        raise core.BridgeError("Certificato TLS pairing mancante o non valido.") from exc
    return hashlib.sha256(der).hexdigest()


def public_enrollment_url() -> str:
    env = load_bridge_env()
    endpoint = env.get("PUBLIC_ENDPOINT", "CHANGE_ME:51820")
    port = int(env.get("PAIRING_PORT", str(PAIRING_PORT)))
    if endpoint.startswith("[") and "]" in endpoint:
        host = endpoint[1:endpoint.index("]")]
        return f"https://[{host}]:{port}/v2/enroll"
    host = endpoint.rsplit(":", 1)[0] if ":" in endpoint else endpoint
    return f"https://{host}:{port}/v2/enroll"


def create_enrollment(
    name: str,
    *,
    device_type: str = "unknown",
    owner: str = "",
    expires_at: str | None = None,
    notes: str = "",
    tags: list[str] | None = None,
    group_names: list[str] | None = None,
    ttl_seconds: int = DEFAULT_TTL_SECONDS,
) -> tuple[dict[str, Any], str]:
    core.validate_name(name)
    device_type = core.validate_device_type(device_type)
    expires_at = core.validate_expiry(expires_at)
    tags = core.normalize_tags(tags or [])
    ttl = _validate_ttl(ttl_seconds)
    groups = sorted(set(group_names or []))
    known_groups = {g["name"] for g in core.list_groups()}
    unknown_groups = sorted(set(groups) - known_groups)
    if unknown_groups:
        raise core.BridgeError("Gruppi sconosciuti: " + ", ".join(unknown_groups))
    if core.find_device(name):
        raise core.BridgeError(f"Dispositivo già presente: {name}")

    now = int(time.time())
    token = secrets.token_urlsafe(32)
    with enrollment_lock():
        items = cleanup_enrollments(_load_enrollments(), now)
        if any(x.get("status") == "pending" and x.get("device_name") == name for x in items):
            raise core.BridgeError(f"Esiste già un pairing v2 attivo per: {name}")
        record = {
            "enrollment_id": "enr_" + secrets.token_hex(8),
            "device_name": name,
            "device_type": device_type,
            "owner": owner.strip()[:120],
            "device_expires_at": expires_at,
            "notes": notes.strip()[:1000],
            "tags": tags,
            "groups": groups,
            "token_hash": token_digest(token),
            "created_at": now,
            "expires_at": now + ttl,
            "status": "pending",
        }
        items.append(record)
        _save_enrollments(items)
    return record, token


def invitation_payload(record: dict[str, Any], token: str) -> dict[str, Any]:
    env = load_bridge_env()
    return {
        "schema": "ge360-bridge-pairing/v2",
        "enrollment_id": record["enrollment_id"],
        "device": record["device_name"],
        "enrollment_url": public_enrollment_url(),
        "token": token,
        "expires_at": int(record["expires_at"]),
        "tls_cert_sha256": tls_cert_fingerprint(),
        "wireguard": {
            "server_public_key": server_public_key(),
            "endpoint": env.get("PUBLIC_ENDPOINT", "CHANGE_ME:51820"),
            "allowed_ips": "10.88.0.1/32",
            "persistent_keepalive": 25,
        },
        "relay": relay_public_config(),
    }


def create_pairing_payload(**kwargs) -> dict[str, Any]:
    record, token = create_enrollment(**kwargs)
    return invitation_payload(record, token)


def list_enrollments() -> list[dict[str, Any]]:
    with enrollment_lock():
        items = cleanup_enrollments(_load_enrollments())
        _save_enrollments(items)
        return [{k: v for k, v in x.items() if k != "token_hash"} for x in items]


def consume_enrollment(enrollment_id: str, token: str, public_key: str) -> dict[str, Any]:
    public_key = validate_wireguard_public_key(public_key)
    now = int(time.time())
    with enrollment_lock():
        items = cleanup_enrollments(_load_enrollments(), now)
        record = next((x for x in items if x.get("enrollment_id") == enrollment_id), None)
        if not record:
            _save_enrollments(items)
            raise core.BridgeError("Pairing non valido.")
        if record.get("status") != "pending":
            _save_enrollments(items)
            raise core.BridgeError("Pairing già utilizzato, scaduto o non valido.")
        if not hmac.compare_digest(str(record.get("token_hash", "")), token_digest(token)):
            _save_enrollments(items)
            raise core.BridgeError("Pairing non valido.")
        if int(record.get("expires_at", 0)) <= now:
            record["status"] = "expired"
            record["expired_at"] = now
            _save_enrollments(items)
            raise core.BridgeError("Pairing scaduto.")
        if core.find_device(record["device_name"]):
            record["status"] = "used"
            record["used_at"] = now
            _save_enrollments(items)
            raise core.BridgeError("Pairing già utilizzato.")

        groups = core.list_groups()
        by_group = {g["name"]: g for g in groups}
        missing = [name for name in record.get("groups", []) if name not in by_group]
        if missing:
            raise core.BridgeError("Gruppo pairing non più disponibile: " + ", ".join(missing))

        psk = generate_psk()
        app_token = core.random_token()
        device = core.Device(
            device_id=core.new_device_id(),
            name=record["device_name"],
            device_type=record.get("device_type", "unknown"),
            owner=record.get("owner", ""),
            vpn_ip=core.next_device_ip(),
            public_key=public_key,
            preshared_key=psk,
            token=app_token,
            created_at=core.utc_now_iso(),
            expires_at=record.get("device_expires_at"),
            notes=record.get("notes", ""),
            tags=list(record.get("tags", [])),
            enabled=True,
        )
        before_devices = core.list_devices()
        new_devices = before_devices + [device.__dict__]
        core.save_devices(new_devices)
        try:
            if record.get("groups"):
                for group in groups:
                    if group["name"] in set(record["groups"]):
                        group["device_ids"] = sorted(set(group.get("device_ids", [])) | {device.device_id})
                core.save_groups(groups)
        except Exception:
            core.save_devices(before_devices)
            raise

        record["status"] = "used"
        record["used_at"] = now
        record["device_id"] = device.device_id
        _save_enrollments(items)

    effective = core.effective_resources_for_device(device.__dict__)
    env = load_bridge_env()
    return {
        "schema": "ge360-bridge-enrollment-response/v2",
        "device_id": device.device_id,
        "device": device.name,
        "vpn_ip": device.vpn_ip,
        "preshared_key": psk,
        "device_token": app_token,
        "bridge_ip": "10.88.0.1",
        "health_url": "http://10.88.0.1:8788/v1/status",
        "launcher_url": "http://10.88.0.1:8788/hub",
        "wireguard": {
            "server_public_key": server_public_key(),
            "endpoint": env.get("PUBLIC_ENDPOINT", "CHANGE_ME:51820"),
            "allowed_ips": "10.88.0.1/32",
            "persistent_keepalive": 25,
        },
        "relay": relay_public_config(),
        "groups": list(record.get("groups", [])),
        "resources": [
            {
                "name": r["name"],
                "icon": r.get("icon","server"),
                "description": r.get("description",""),
                "protocol": r.get("protocol","tcp"),
                "bridge_port": r["bridge_port"],
                "url": f"http://10.88.0.1:{r['bridge_port']}",
            }
            for r in effective
        ],
        "services": [
            {"name": r["name"], "url": f"http://10.88.0.1:{r['bridge_port']}"}
            for r in effective
        ],
    }
