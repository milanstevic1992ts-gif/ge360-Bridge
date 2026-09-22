from __future__ import annotations

import hashlib
import io
import json
import os
import tarfile
import tempfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from . import __version__
from . import core
from .core import BridgeError

BACKUP_DIR = Path(os.environ.get("GE360_BACKUP_DIR", str(core.STATE_DIR / "backups")))
BACKUP_SCHEMA = "ge360-bridge-config-backup/v1"
DEFAULT_RETENTION = 10
MAX_RETENTION = 100
MAX_ARCHIVE_BYTES = 8 * 1024 * 1024
MAX_FILE_BYTES = 2 * 1024 * 1024

SOURCE_MAP: dict[str, Path] = {
    "state/devices.json": core.STATE_DIR / "devices.json",
    "state/resources.json": core.STATE_DIR / "resources.json",
    "state/services.json": core.STATE_DIR / "services.json",
    "state/groups.json": core.STATE_DIR / "groups.json",
    "state/bridge.env": core.STATE_DIR / "bridge.env",
    "state/server.key": core.STATE_DIR / "server.key",
    "state/server.pub": core.STATE_DIR / "server.pub",
    "state/dashboard.token": core.STATE_DIR / "dashboard.token",
    "state/enrollment.key": core.STATE_DIR / "enrollment.key",
    "state/pairing-tls.key": core.STATE_DIR / "pairing-tls.key",
    "state/pairing-tls.crt": core.STATE_DIR / "pairing-tls.crt",
    "wireguard/wg0.conf": core.WG_CONF,
}

OPTIONAL_SOURCE_MAP: dict[str, Path] = {
    "state/relay.token": core.STATE_DIR / "relay.token",
    "state/servers.json": core.STATE_DIR / "servers.json",
    "state/server-id": core.STATE_DIR / "server-id",
    "state/server.token": core.STATE_DIR / "server.token",
    "state/multi-server-tls.key": core.STATE_DIR / "multi-server-tls.key",
    "state/multi-server-tls.crt": core.STATE_DIR / "multi-server-tls.crt",
}
ALL_SOURCE_MAP: dict[str, Path] = {**SOURCE_MAP, **OPTIONAL_SOURCE_MAP}
REQUIRED_ARCHIVE_FILES = frozenset(SOURCE_MAP)
ALLOWED_ARCHIVE_FILES = frozenset(ALL_SOURCE_MAP)
FORBIDDEN_CLIENT_PRIVATE_KEYS = {
    "private_key",
    "client_private_key",
    "wireguard_private_key",
    "client_private",
}


def _utc_now(now: datetime | None = None) -> datetime:
    value = now or datetime.now(timezone.utc)
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.astimezone(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _validate_retention(value: int) -> int:
    try:
        keep = int(value)
    except (TypeError, ValueError) as exc:
        raise BridgeError("Retention backup non valida.") from exc
    if keep < 1 or keep > MAX_RETENTION:
        raise BridgeError(f"Retention backup non valida: usa 1..{MAX_RETENTION}.")
    return keep


def _ensure_backup_dir() -> Path:
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(BACKUP_DIR, 0o700)
    except OSError:
        pass
    return BACKUP_DIR


def _scan_for_client_private_keys(value: Any, path: str = "$") -> None:
    if isinstance(value, dict):
        for key, child in value.items():
            normalized = str(key).strip().lower().replace("-", "_")
            if normalized in FORBIDDEN_CLIENT_PRIVATE_KEYS:
                raise BridgeError(f"Backup bloccato: possibile private key client rilevata in {path}.{key}.")
            _scan_for_client_private_keys(child, f"{path}.{key}")
    elif isinstance(value, list):
        for index, child in enumerate(value):
            _scan_for_client_private_keys(child, f"{path}[{index}]")


def _json_bytes(data: bytes, name: str) -> Any:
    try:
        return json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError(f"JSON non valido nel backup: {name}") from exc


def _validate_device_registry(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not all(isinstance(x, dict) for x in payload):
        raise BridgeError("devices.json non valido.")
    _scan_for_client_private_keys(payload, "devices")
    normalized = [core._normalize_device(x) for x in payload]
    ids = [str(x.get("device_id") or "") for x in normalized]
    names = [str(x.get("name") or "") for x in normalized]
    if any(not x for x in ids + names) or len(ids) != len(set(ids)) or len(names) != len(set(names)):
        raise BridgeError("devices.json contiene device_id o nomi non validi/duplicati.")
    return normalized


def _validate_resource_registry(payload: Any) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not all(isinstance(x, dict) for x in payload):
        raise BridgeError("resources.json non valido.")
    normalized: list[dict[str, Any]] = []
    for raw in payload:
        item = core._normalize_resource(raw)
        core.validate_name(item["name"])
        core.validate_port(item["bridge_port"])
        core.validate_port(item["target_port"])
        core.validate_target_host(item["target_host"])
        core.validate_resource_protocol(item["protocol"])
        core.validate_timeout_seconds(item["timeout_seconds"])
        core.validate_health_url(item.get("health_url", ""), item["target_host"], item["target_port"])
        unit = core.validate_systemd_unit(item.get("systemd_unit", ""))
        if item.get("self_heal_enabled") and not unit:
            raise BridgeError(f"Resource {item['name']}: self-healing senza systemd_unit.")
        normalized.append(item)
    names = [x["name"] for x in normalized]
    ports = [int(x["bridge_port"]) for x in normalized]
    if len(names) != len(set(names)) or len(ports) != len(set(ports)):
        raise BridgeError("resources.json contiene nomi o bridge port duplicati.")
    return normalized


def _validate_group_registry(
    payload: Any,
    *,
    device_ids: set[str],
    resource_names: set[str],
) -> list[dict[str, Any]]:
    if not isinstance(payload, list) or not all(isinstance(x, dict) for x in payload):
        raise BridgeError("groups.json non valido.")
    normalized = [core._normalize_group(x) for x in payload]
    names = [x["name"] for x in normalized]
    if len(names) != len(set(names)):
        raise BridgeError("groups.json contiene nomi duplicati.")
    for group in normalized:
        core.validate_name(group["name"])
        unknown_devices = sorted(set(group.get("device_ids", [])) - device_ids)
        unknown_resources = sorted(set(group.get("allowed_services", [])) - resource_names)
        if unknown_devices:
            raise BridgeError("groups.json contiene device sconosciuti: " + ", ".join(unknown_devices))
        if unknown_resources:
            raise BridgeError("groups.json contiene Resource sconosciute: " + ", ".join(unknown_resources))
    return normalized


def _validate_bridge_env(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeError("bridge.env non è UTF-8 valido.") from exc
    if "\x00" in text or len(text) > 65536:
        raise BridgeError("bridge.env non valido.")
    for raw in text.splitlines():
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        if "=" not in line:
            raise BridgeError("bridge.env contiene una riga non valida.")


def _validate_wireguard_conf(data: bytes) -> None:
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeError("wg0.conf non è UTF-8 valido.") from exc
    if "\x00" in text or "[Interface]" not in text or "PrivateKey =" not in text or "Address =" not in text:
        raise BridgeError("wg0.conf non valido.")


def validate_snapshot(files: dict[str, bytes]) -> dict[str, Any]:
    missing = sorted(REQUIRED_ARCHIVE_FILES - set(files))
    if missing:
        raise BridgeError("Backup incompleto, file mancanti: " + ", ".join(missing))
    unexpected = sorted(set(files) - ALLOWED_ARCHIVE_FILES)
    if unexpected:
        raise BridgeError("Backup contiene file non previsti: " + ", ".join(unexpected))

    devices = _validate_device_registry(_json_bytes(files["state/devices.json"], "devices.json"))
    resources = _validate_resource_registry(_json_bytes(files["state/resources.json"], "resources.json"))
    services = _validate_resource_registry(_json_bytes(files["state/services.json"], "services.json"))
    if resources != services:
        raise BridgeError("services.json non corrisponde al mirror resources.json.")

    groups = _validate_group_registry(
        _json_bytes(files["state/groups.json"], "groups.json"),
        device_ids={x["device_id"] for x in devices},
        resource_names={x["name"] for x in resources},
    )
    _validate_bridge_env(files["state/bridge.env"])
    _validate_wireguard_conf(files["wireguard/wg0.conf"])

    for name in (
        "state/server.key",
        "state/server.pub",
        "state/dashboard.token",
        "state/enrollment.key",
        "state/pairing-tls.key",
        "state/pairing-tls.crt",
    ):
        if not files[name].strip():
            raise BridgeError(f"Backup contiene un segreto/config vuoto: {name}")
    if "state/relay.token" in files and not files["state/relay.token"].strip():
        raise BridgeError("Backup contiene relay.token vuoto.")
    for name in ("state/server-id", "state/server.token", "state/multi-server-tls.key", "state/multi-server-tls.crt"):
        if name in files and not files[name].strip():
            raise BridgeError(f"Backup contiene segreto/config multi-server vuoto: {name}")
    if "state/servers.json" in files:
        try:
            servers = json.loads(files["state/servers.json"].decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise BridgeError("servers.json non valido nel backup.") from exc
        if not isinstance(servers, list):
            raise BridgeError("servers.json non valido nel backup.")
        try:
            from .multi_server import _normalize_server
            normalized_servers = [_normalize_server(x) for x in servers if isinstance(x, dict)]
        except Exception as exc:
            raise BridgeError("servers.json non valido nel backup.") from exc
        if len(normalized_servers) != len(servers):
            raise BridgeError("servers.json non valido nel backup.")
        ids = [x["server_id"] for x in normalized_servers]
        names = [x["name"] for x in normalized_servers]
        if len(ids) != len(set(ids)) or len(names) != len(set(names)):
            raise BridgeError("servers.json contiene server duplicati.")

    return {
        "devices": len(devices),
        "resources": len(resources),
        "groups": len(groups),
        "client_private_keys": False,
    }


def _snapshot_sources() -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    missing: list[str] = []
    for archive_name, source in SOURCE_MAP.items():
        try:
            data = source.read_bytes()
        except FileNotFoundError:
            missing.append(str(source))
            continue
        except OSError as exc:
            raise BridgeError(f"Impossibile leggere {source}: {exc}") from exc
        if len(data) > MAX_FILE_BYTES:
            raise BridgeError(f"File troppo grande per backup configurazione: {source}")
        files[archive_name] = data
    if missing:
        raise BridgeError("Configurazione incompleta, file mancanti: " + ", ".join(missing))
    for archive_name, source in OPTIONAL_SOURCE_MAP.items():
        try:
            data = source.read_bytes()
        except FileNotFoundError:
            continue
        except OSError as exc:
            raise BridgeError(f"Impossibile leggere {source}: {exc}") from exc
        if len(data) > MAX_FILE_BYTES:
            raise BridgeError(f"File troppo grande per backup configurazione: {source}")
        files[archive_name] = data
    validate_snapshot(files)
    return files


def _tar_add_bytes(tf: tarfile.TarFile, name: str, data: bytes, mtime: int) -> None:
    info = tarfile.TarInfo(name=name)
    info.size = len(data)
    info.mode = 0o600
    info.uid = 0
    info.gid = 0
    info.uname = "root"
    info.gname = "root"
    info.mtime = int(mtime)
    tf.addfile(info, io.BytesIO(data))


def _backup_name(now: datetime, reason: str) -> str:
    safe_reason = reason if reason in {"manual", "daily", "pre-restore", "pre-update"} else "manual"
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    return f"ge360-config-{stamp}-{safe_reason}.tar.gz"


def _same_day_scheduled(now: datetime) -> Path | None:
    prefix = f"ge360-config-{now.strftime('%Y%m%d')}T"
    for path in sorted(_ensure_backup_dir().glob(prefix + "*-daily.tar.gz")):
        if path.is_file():
            return path
    return None


def prune_backups(keep: int = DEFAULT_RETENTION) -> list[str]:
    keep = _validate_retention(keep)
    backup_dir = _ensure_backup_dir()
    backups = sorted(
        (p for p in backup_dir.glob("ge360-config-*.tar.gz") if p.is_file()),
        key=lambda p: (p.stat().st_mtime_ns, p.name),
        reverse=True,
    )
    removed: list[str] = []
    for path in backups[keep:]:
        try:
            path.unlink()
            removed.append(path.name)
        except OSError as exc:
            raise BridgeError(f"Impossibile eliminare backup vecchio {path.name}: {exc}") from exc
    return removed


def create_backup(
    *,
    scheduled: bool = False,
    keep: int = DEFAULT_RETENTION,
    now: datetime | None = None,
    reason: str | None = None,
) -> dict[str, Any]:
    keep = _validate_retention(keep)
    when = _utc_now(now)
    if scheduled:
        existing = _same_day_scheduled(when)
        if existing is not None:
            return {
                "created": False,
                "skipped": True,
                "reason": "daily_backup_already_exists",
                "backup": existing.name,
                "retention": keep,
                "removed": prune_backups(keep),
            }

    backup_reason = reason or ("daily" if scheduled else "manual")
    files = _snapshot_sources()
    validation = validate_snapshot(files)
    manifest = {
        "schema": BACKUP_SCHEMA,
        "bridge_version": __version__,
        "created_at": when.isoformat(),
        "reason": backup_reason,
        "sensitive": True,
        "contains_server_secrets": True,
        "contains_client_private_keys": False,
        "files": [
            {
                "name": name,
                "size": len(data),
                "sha256": _sha256(data),
            }
            for name, data in sorted(files.items())
        ],
        "summary": validation,
    }
    manifest_bytes = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")

    backup_dir = _ensure_backup_dir()
    final_path = backup_dir / _backup_name(when, backup_reason)
    if final_path.exists():
        raise BridgeError(f"Backup già esistente: {final_path.name}")

    fd, tmp_name = tempfile.mkstemp(prefix=".ge360-backup-", suffix=".tmp", dir=str(backup_dir))
    os.close(fd)
    tmp_path = Path(tmp_name)
    try:
        with tarfile.open(tmp_path, mode="w:gz", format=tarfile.PAX_FORMAT) as tf:
            _tar_add_bytes(tf, "manifest.json", manifest_bytes, int(when.timestamp()))
            for name, data in sorted(files.items()):
                _tar_add_bytes(tf, name, data, int(when.timestamp()))
        os.chmod(tmp_path, 0o600)
        if tmp_path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise BridgeError("Archivio backup troppo grande.")
        tmp_path.replace(final_path)
        os.chmod(final_path, 0o600)
    finally:
        if tmp_path.exists():
            tmp_path.unlink(missing_ok=True)

    removed = prune_backups(keep)
    return {
        "created": True,
        "skipped": False,
        "backup": final_path.name,
        "path": str(final_path),
        "size": final_path.stat().st_size,
        "retention": keep,
        "removed": removed,
        "summary": validation,
    }


def _resolve_backup(identifier: str) -> Path:
    name = Path(identifier).name
    if not name or name != identifier or not name.endswith(".tar.gz"):
        raise BridgeError("Nome backup non valido.")
    path = _ensure_backup_dir() / name
    if not path.is_file():
        raise BridgeError(f"Backup non trovato: {name}")
    return path


def _read_archive(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    try:
        if path.stat().st_size > MAX_ARCHIVE_BYTES:
            raise BridgeError("Archivio backup troppo grande.")
    except OSError as exc:
        raise BridgeError(f"Impossibile leggere backup: {exc}") from exc

    members: dict[str, bytes] = {}
    try:
        with tarfile.open(path, mode="r:gz") as tf:
            for member in tf.getmembers():
                if not member.isfile():
                    raise BridgeError(f"Backup contiene un membro non regolare: {member.name}")
                if member.name in members:
                    raise BridgeError(f"Backup contiene un file duplicato: {member.name}")
                if member.name != "manifest.json" and member.name not in ALLOWED_ARCHIVE_FILES:
                    raise BridgeError(f"Backup contiene un percorso non consentito: {member.name}")
                if member.size < 0 or member.size > MAX_FILE_BYTES:
                    raise BridgeError(f"File backup troppo grande: {member.name}")
                stream = tf.extractfile(member)
                if stream is None:
                    raise BridgeError(f"Impossibile leggere {member.name} dal backup.")
                data = stream.read(MAX_FILE_BYTES + 1)
                if len(data) != member.size or len(data) > MAX_FILE_BYTES:
                    raise BridgeError(f"Dimensione non valida per {member.name}.")
                members[member.name] = data
    except (tarfile.TarError, OSError) as exc:
        raise BridgeError(f"Archivio backup non valido: {exc}") from exc

    manifest_raw = members.pop("manifest.json", None)
    if manifest_raw is None:
        raise BridgeError("manifest.json mancante dal backup.")
    manifest = _json_bytes(manifest_raw, "manifest.json")
    if not isinstance(manifest, dict) or manifest.get("schema") != BACKUP_SCHEMA:
        raise BridgeError("Schema backup GE360 non supportato.")
    if manifest.get("contains_client_private_keys") is not False:
        raise BridgeError("Backup rifiutato: garanzia private key client assente.")

    declared = manifest.get("files")
    if not isinstance(declared, list):
        raise BridgeError("Manifest backup non valido.")
    declared_names: set[str] = set()
    for item in declared:
        if not isinstance(item, dict):
            raise BridgeError("Manifest backup non valido.")
        name = str(item.get("name") or "")
        if name in declared_names or name not in ALLOWED_ARCHIVE_FILES:
            raise BridgeError("Manifest backup contiene file duplicati/non consentiti.")
        declared_names.add(name)
        data = members.get(name)
        if data is None:
            raise BridgeError(f"File dichiarato ma assente: {name}")
        if int(item.get("size", -1)) != len(data):
            raise BridgeError(f"Size mismatch nel backup: {name}")
        if str(item.get("sha256") or "") != _sha256(data):
            raise BridgeError(f"Checksum mismatch nel backup: {name}")
    if declared_names != set(members):
        raise BridgeError("Manifest e contenuto archivio non corrispondono.")

    validate_snapshot(members)
    return manifest, members


def verify_backup(identifier: str) -> dict[str, Any]:
    path = _resolve_backup(identifier)
    manifest, files = _read_archive(path)
    return {
        "valid": True,
        "backup": path.name,
        "size": path.stat().st_size,
        "schema": manifest["schema"],
        "bridge_version": manifest.get("bridge_version"),
        "created_at": manifest.get("created_at"),
        "reason": manifest.get("reason"),
        "contains_server_secrets": bool(manifest.get("contains_server_secrets")),
        "contains_client_private_keys": False,
        "files": len(files),
        "summary": manifest.get("summary") or validate_snapshot(files),
    }


def list_backups() -> list[dict[str, Any]]:
    rows: list[dict[str, Any]] = []
    for path in sorted(
        _ensure_backup_dir().glob("ge360-config-*.tar.gz"),
        key=lambda p: (p.stat().st_mtime_ns, p.name),
        reverse=True,
    ):
        try:
            info = verify_backup(path.name)
            rows.append(info)
        except BridgeError as exc:
            rows.append({
                "valid": False,
                "backup": path.name,
                "size": path.stat().st_size,
                "error": str(exc),
            })
    return rows


def _atomic_restore_file(target: Path, data: bytes) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".ge360-restore-", dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        tmp.replace(target)
        os.chmod(target, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def restore_backup(
    identifier: str,
    *,
    apply: bool = False,
    keep: int = DEFAULT_RETENTION,
    create_safety_backup: bool = True,
) -> dict[str, Any]:
    keep = _validate_retention(keep)
    path = _resolve_backup(identifier)
    manifest, files = _read_archive(path)
    validation = validate_snapshot(files)

    plan = {
        "backup": path.name,
        "verified": True,
        "apply": bool(apply),
        "target_files": [str(ALL_SOURCE_MAP[name]) for name in sorted(files)],
        "summary": validation,
    }
    if not apply:
        return plan

    safety: dict[str, Any] | None = None
    safety_error: str | None = None
    if create_safety_backup:
        try:
            safety = create_backup(keep=keep, reason="pre-restore")
        except BridgeError as exc:
            safety_error = str(exc)

    restored: list[str] = []
    for name, data in sorted(files.items()):
        target = ALL_SOURCE_MAP[name]
        _atomic_restore_file(target, data)
        restored.append(str(target))

    return {
        **plan,
        "restored": restored,
        "safety_backup": None if safety is None else safety.get("backup"),
        "safety_backup_error": safety_error,
        "source_created_at": manifest.get("created_at"),
    }
