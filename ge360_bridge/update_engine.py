from __future__ import annotations

import compileall
import fcntl
import hashlib
import io
import json
import os
import re
import shutil
import ssl
import subprocess
import tarfile
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath
from typing import Any, Callable
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen

from . import __version__
from .backup import create_backup, restore_backup
from .core import BridgeError

UPDATE_SCHEMA = "ge360-bridge-update/v1"
ROLLBACK_SCHEMA = "ge360-bridge-software-rollback/v1"
UPDATE_STATE_DIR = Path(os.environ.get("GE360_UPDATE_STATE_DIR", "/var/lib/ge360-bridge/updates"))
SOFTWARE_ROOT = Path(os.environ.get("GE360_SOFTWARE_ROOT", "/opt/ge360-bridge"))
LOCAL_SBIN = Path(os.environ.get("GE360_LOCAL_SBIN", "/usr/local/sbin"))
SYSTEMD_DIR = Path(os.environ.get("GE360_SYSTEMD_DIR", "/etc/systemd/system"))
MAX_PACKAGE_BYTES = 32 * 1024 * 1024
MAX_MEMBER_BYTES = 4 * 1024 * 1024
MAX_PACKAGE_FILES = 256
MAX_UNPACKED_BYTES = 32 * 1024 * 1024
ROLLBACK_RETENTION = 3
VERSION_RE = re.compile(r"^[0-9]+(?:\.[0-9]+){1,3}(?:[-+][A-Za-z0-9._-]+)?$")
INIT_VERSION_RE = re.compile(r'^__version__\s*=\s*["\']([^"\']+)["\']\s*$', re.MULTILINE)

REQUIRED_RUNTIME_PATHS = {
    "ge360_bridge/__init__.py",
    "ge360_bridge/cli.py",
    "ge360_bridge/core.py",
    "ge360_bridge/daemon.py",
    "ge360_bridge/dashboard.py",
    "ge360_bridge/pairing_server.py",
    "ge360-bridge",
}
FIXED_SCRIPT_TARGETS = {
    "ge360-bridge": LOCAL_SBIN / "ge360-bridge",
    "scripts/apply-firewall.sh": LOCAL_SBIN / "ge360-bridge-firewall",
    "scripts/boot-verify.sh": LOCAL_SBIN / "ge360-bridge-boot-verify",
}
CORE_SERVICES = (
    "wg-quick@wg0.service",
    "ge360-bridge-firewall.service",
    "ge360-bridge.service",
    "ge360-bridge-dashboard.service",
    "ge360-bridge-enrollment.service",
)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _version_tuple(value: str) -> tuple[int, ...]:
    base = value.split("-", 1)[0].split("+", 1)[0]
    try:
        return tuple(int(x) for x in base.split("."))
    except ValueError as exc:
        raise BridgeError(f"Versione update non valida: {value}") from exc


def _validate_version(value: Any) -> str:
    version = str(value or "").strip()
    if not VERSION_RE.fullmatch(version):
        raise BridgeError("Versione update non valida.")
    return version


def _safe_logical_path(value: str) -> str:
    if not isinstance(value, str) or not value:
        raise BridgeError("Percorso update non valido.")
    path = PurePosixPath(value)
    if path.is_absolute() or ".." in path.parts or "." in path.parts or "\\" in value:
        raise BridgeError(f"Percorso update non consentito: {value}")
    normalized = path.as_posix()
    if normalized.startswith("ge360_bridge/"):
        if not normalized.endswith(".py"):
            raise BridgeError(f"Solo moduli Python sono consentiti sotto ge360_bridge/: {value}")
        for part in path.parts[1:]:
            if not re.fullmatch(r"[A-Za-z0-9_]+(?:\.py)?", part):
                raise BridgeError(f"Nome modulo update non valido: {value}")
        return normalized
    if normalized in FIXED_SCRIPT_TARGETS:
        return normalized
    if normalized.startswith("systemd/"):
        name = path.name
        if not re.fullmatch(r"ge360-bridge(?:-[A-Za-z0-9_.@-]+)?\.(?:service|timer)", name):
            raise BridgeError(f"Unit systemd update non consentita: {value}")
        if len(path.parts) != 2:
            raise BridgeError(f"Percorso systemd update non valido: {value}")
        return normalized
    raise BridgeError(f"File update non gestito: {value}")


def target_for(logical_path: str) -> Path:
    logical = _safe_logical_path(logical_path)
    if logical.startswith("ge360_bridge/"):
        return SOFTWARE_ROOT / logical
    if logical in FIXED_SCRIPT_TARGETS:
        return FIXED_SCRIPT_TARGETS[logical]
    return SYSTEMD_DIR / PurePosixPath(logical).name


def mode_for(logical_path: str) -> int:
    logical = _safe_logical_path(logical_path)
    if logical in FIXED_SCRIPT_TARGETS:
        return 0o755
    return 0o644


def _ensure_update_dir() -> Path:
    UPDATE_STATE_DIR.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(UPDATE_STATE_DIR, 0o700)
    except OSError:
        pass
    return UPDATE_STATE_DIR


def _read_regular_file(path: Path, max_bytes: int = MAX_PACKAGE_BYTES) -> bytes:
    if path.is_symlink() or not path.is_file():
        raise BridgeError(f"File update non valido: {path}")
    try:
        size = path.stat().st_size
    except OSError as exc:
        raise BridgeError(f"Impossibile leggere file update: {exc}") from exc
    if size <= 0 or size > max_bytes:
        raise BridgeError("Dimensione pacchetto update non valida.")
    data = path.read_bytes()
    if len(data) != size:
        raise BridgeError("Lettura pacchetto update incompleta.")
    return data


def _validate_sha256_hex(value: str) -> str:
    digest = (value or "").strip().lower()
    if not re.fullmatch(r"[0-9a-f]{64}", digest):
        raise BridgeError("SHA-256 update non valido: servono 64 caratteri esadecimali.")
    return digest


def download_update(url: str, expected_sha256: str) -> dict[str, Any]:
    expected = _validate_sha256_hex(expected_sha256)
    parsed = urlsplit((url or "").strip())
    if parsed.scheme.lower() != "https" or not parsed.hostname:
        raise BridgeError("Download update consentito soltanto tramite URL HTTPS.")
    if parsed.username or parsed.password or parsed.fragment:
        raise BridgeError("URL update non valido.")

    request = Request(
        url,
        headers={"User-Agent": f"GE360-Universal-Bridge/{__version__}", "Accept": "application/gzip, application/octet-stream"},
        method="GET",
    )
    try:
        with urlopen(request, timeout=30) as response:
            final = urlsplit(response.geturl())
            if final.scheme.lower() != "https":
                raise BridgeError("Redirect update verso protocollo non HTTPS rifiutato.")
            length = response.headers.get("Content-Length")
            if length and int(length) > MAX_PACKAGE_BYTES:
                raise BridgeError("Pacchetto update troppo grande.")
            data = response.read(MAX_PACKAGE_BYTES + 1)
    except BridgeError:
        raise
    except (HTTPError, URLError, OSError, TimeoutError, ValueError) as exc:
        raise BridgeError(f"Download update fallito: {exc.__class__.__name__}") from exc

    if not data or len(data) > MAX_PACKAGE_BYTES:
        raise BridgeError("Pacchetto update vuoto o troppo grande.")
    actual = _sha256(data)
    if actual != expected:
        raise BridgeError(f"SHA-256 update non corrisponde: atteso {expected}, ottenuto {actual}.")

    update_dir = _ensure_update_dir()
    name = f"download-{actual[:16]}.tar.gz"
    target = update_dir / name
    fd, tmp_name = tempfile.mkstemp(prefix=".download-", dir=str(update_dir))
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
    return {"path": str(target), "package": target.name, "sha256": actual, "size": len(data)}


def _read_package(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    _read_regular_file(path)
    members: dict[str, bytes] = {}
    manifest_raw: bytes | None = None
    try:
        with tarfile.open(path, "r:gz") as tf:
            all_members = tf.getmembers()
            if len(all_members) > MAX_PACKAGE_FILES + 1:
                raise BridgeError("Pacchetto update contiene troppi file.")
            unpacked = 0
            for member in all_members:
                unpacked += max(0, int(member.size))
                if unpacked > MAX_UNPACKED_BYTES:
                    raise BridgeError("Pacchetto update supera il limite decompressed.")
                if not member.isfile():
                    raise BridgeError(f"Pacchetto update contiene membro non regolare: {member.name}")
                if member.size < 0 or member.size > MAX_MEMBER_BYTES:
                    raise BridgeError(f"File update troppo grande: {member.name}")
                if member.name == "manifest.json":
                    key = member.name
                elif member.name.startswith("payload/"):
                    logical = _safe_logical_path(member.name[len("payload/"):])
                    key = "payload/" + logical
                else:
                    raise BridgeError(f"Percorso pacchetto update non consentito: {member.name}")
                if key in members or (key == "manifest.json" and manifest_raw is not None):
                    raise BridgeError(f"Membro update duplicato: {member.name}")
                stream = tf.extractfile(member)
                if stream is None:
                    raise BridgeError(f"Impossibile leggere membro update: {member.name}")
                data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
                    raise BridgeError(f"Dimensione membro update non valida: {member.name}")
                if key == "manifest.json":
                    manifest_raw = data
                else:
                    members[key] = data
    except (tarfile.TarError, OSError) as exc:
        raise BridgeError(f"Pacchetto update non valido: {exc}") from exc

    if manifest_raw is None:
        raise BridgeError("manifest.json mancante dal pacchetto update.")
    try:
        manifest = json.loads(manifest_raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise BridgeError("Manifest update non contiene JSON UTF-8 valido.") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != UPDATE_SCHEMA:
        raise BridgeError("Schema update GE360 non supportato.")
    version = _validate_version(manifest.get("version"))
    declared = manifest.get("files")
    if not isinstance(declared, list) or not declared:
        raise BridgeError("Manifest update senza file.")

    seen: set[str] = set()
    for item in declared:
        if not isinstance(item, dict):
            raise BridgeError("Manifest update non valido.")
        logical = _safe_logical_path(str(item.get("path") or ""))
        if logical in seen:
            raise BridgeError(f"File update duplicato nel manifest: {logical}")
        seen.add(logical)
        expected_mode = mode_for(logical)
        if int(item.get("mode", -1)) != expected_mode:
            raise BridgeError(f"Mode update non valido per {logical}.")
        key = "payload/" + logical
        data = members.get(key)
        if data is None:
            raise BridgeError(f"Payload mancante: {logical}")
        if int(item.get("size", -1)) != len(data):
            raise BridgeError(f"Size mismatch update: {logical}")
        digest = _validate_sha256_hex(str(item.get("sha256") or ""))
        if digest != _sha256(data):
            raise BridgeError(f"Checksum mismatch update: {logical}")
    if {"payload/" + x for x in seen} != set(members):
        raise BridgeError("Manifest update e payload non corrispondono.")
    missing = sorted(REQUIRED_RUNTIME_PATHS - seen)
    if missing:
        raise BridgeError("Pacchetto update incompleto, file runtime mancanti: " + ", ".join(missing))

    init_data = members["payload/ge360_bridge/__init__.py"]
    try:
        init_text = init_data.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise BridgeError("__init__.py update non UTF-8.") from exc
    match = INIT_VERSION_RE.search(init_text)
    if not match or match.group(1) != version:
        raise BridgeError("Versione manifest e ge360_bridge.__version__ non corrispondono.")
    return manifest, {"payload/" + _safe_logical_path(k[len("payload/"):]): v for k, v in members.items()}


def verify_update(path: str | Path, *, require_newer: bool = True) -> dict[str, Any]:
    package = Path(path)
    manifest, members = _read_package(package)
    version = _validate_version(manifest["version"])
    if require_newer and _version_tuple(version) <= _version_tuple(__version__):
        raise BridgeError(f"Update {version} non è più recente della versione installata {__version__}.")
    return {
        "valid": True,
        "package": str(package),
        "version": version,
        "current_version": __version__,
        "files": len(members),
        "size": package.stat().st_size,
        "sha256": _sha256(package.read_bytes()),
    }


def _stage_package(path: Path) -> tuple[tempfile.TemporaryDirectory[str], Path, dict[str, Any], list[str]]:
    manifest, members = _read_package(path)
    temp = tempfile.TemporaryDirectory(prefix="ge360-update-stage-")
    root = Path(temp.name)
    logical_files: list[str] = []
    for key, data in members.items():
        logical = key[len("payload/"):]
        target = root / logical
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        os.chmod(target, mode_for(logical))
        logical_files.append(logical)
    return temp, root, manifest, sorted(logical_files)


def preflight_update(path: str | Path, *, require_newer: bool = True) -> dict[str, Any]:
    package = Path(path)
    verify = verify_update(package, require_newer=require_newer)
    temp, root, manifest, logical_files = _stage_package(package)
    try:
        if not compileall.compile_dir(str(root / "ge360_bridge"), quiet=1, force=True):
            raise BridgeError("Preflight update fallito: compileall Python.")
        shell_files = [x for x in logical_files if x == "ge360-bridge" or x.startswith("scripts/")]
        for logical in shell_files:
            proc = subprocess.run(
                ["/bin/bash", "-n", str(root / logical)],
                text=True,
                capture_output=True,
                timeout=10,
                check=False,
            )
            if proc.returncode != 0:
                raise BridgeError(f"Preflight update fallito: bash -n {logical}: {(proc.stderr or '').strip()[:200]}")
        for logical in (x for x in logical_files if x.startswith("systemd/")):
            text = (root / logical).read_text(encoding="utf-8")
            if "[Unit]" not in text or ("[Service]" not in text and "[Timer]" not in text):
                raise BridgeError(f"Unit systemd update non valida: {logical}")
    finally:
        temp.cleanup()
    return {**verify, "preflight": "ok", "logical_files": logical_files, "target_version": manifest["version"]}


def _rollback_path(version: str) -> Path:
    stamp = _utc_now().strftime("%Y%m%dT%H%M%S%fZ")
    return _ensure_update_dir() / f"rollback-{stamp}-from-{version}.tar.gz"


def _create_software_rollback(logical_files: list[str], current_version: str) -> Path:
    path = _rollback_path(current_version)
    manifest: dict[str, Any] = {
        "schema": ROLLBACK_SCHEMA,
        "created_at": _utc_now().isoformat(),
        "version": current_version,
        "files": [],
    }
    payload: dict[str, bytes] = {}
    for logical in logical_files:
        target = target_for(logical)
        existed = target.is_file() and not target.is_symlink()
        data = target.read_bytes() if existed else b""
        if len(data) > MAX_MEMBER_BYTES:
            raise BridgeError(f"File installato troppo grande per rollback: {target}")
        manifest["files"].append({
            "path": logical,
            "existed": existed,
            "size": len(data),
            "sha256": _sha256(data),
            "mode": mode_for(logical),
        })
        if existed:
            payload["payload/" + logical] = data

    fd, tmp_name = tempfile.mkstemp(prefix=".rollback-", dir=str(_ensure_update_dir()))
    os.close(fd)
    tmp = Path(tmp_name)
    try:
        with tarfile.open(tmp, "w:gz") as tf:
            manifest_data = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
            info = tarfile.TarInfo("manifest.json")
            info.size = len(manifest_data)
            info.mode = 0o600
            tf.addfile(info, io.BytesIO(manifest_data))
            for name, data in sorted(payload.items()):
                info = tarfile.TarInfo(name)
                info.size = len(data)
                info.mode = 0o600
                tf.addfile(info, io.BytesIO(data))
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)
    _prune_rollbacks()
    return path


def _prune_rollbacks() -> None:
    paths = sorted(
        _ensure_update_dir().glob("rollback-*.tar.gz"),
        key=lambda p: (p.stat().st_mtime_ns, p.name),
        reverse=True,
    )
    for path in paths[ROLLBACK_RETENTION:]:
        path.unlink(missing_ok=True)


def _atomic_install(target: Path, data: bytes, mode: int) -> None:
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(prefix=".ge360-update-", dir=str(target.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "wb") as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, mode)
        tmp.replace(target)
        os.chmod(target, mode)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def _install_payload(root: Path, logical_files: list[str]) -> None:
    for logical in logical_files:
        _atomic_install(target_for(logical), (root / logical).read_bytes(), mode_for(logical))


def _read_rollback(path: Path) -> tuple[dict[str, Any], dict[str, bytes]]:
    if path.is_symlink() or not path.is_file():
        raise BridgeError("Snapshot rollback non valido.")
    payload: dict[str, bytes] = {}
    manifest: dict[str, Any] | None = None
    try:
        with tarfile.open(path, "r:gz") as tf:
            all_members = tf.getmembers()
            if len(all_members) > MAX_PACKAGE_FILES + 1:
                raise BridgeError("Rollback contiene troppi file.")
            unpacked = 0
            for member in all_members:
                unpacked += max(0, int(member.size))
                if unpacked > MAX_UNPACKED_BYTES:
                    raise BridgeError("Rollback supera il limite decompressed.")
                if not member.isfile():
                    raise BridgeError("Rollback contiene membro non regolare.")
                stream = tf.extractfile(member)
                if stream is None:
                    raise BridgeError("Rollback non leggibile.")
                data = stream.read(MAX_MEMBER_BYTES + 1)
                if len(data) != member.size or len(data) > MAX_MEMBER_BYTES:
                    raise BridgeError("Rollback contiene file troppo grande.")
                if member.name == "manifest.json":
                    manifest = json.loads(data.decode("utf-8"))
                elif member.name.startswith("payload/"):
                    logical = _safe_logical_path(member.name[len("payload/"):])
                    payload[logical] = data
                else:
                    raise BridgeError("Rollback contiene path non consentito.")
    except (tarfile.TarError, OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise BridgeError(f"Snapshot rollback non valido: {exc}") from exc
    if not isinstance(manifest, dict) or manifest.get("schema") != ROLLBACK_SCHEMA:
        raise BridgeError("Schema rollback non valido.")
    return manifest, payload


def _restore_software_rollback(path: Path) -> None:
    manifest, payload = _read_rollback(path)
    files = manifest.get("files")
    if not isinstance(files, list):
        raise BridgeError("Manifest rollback non valido.")
    for item in files:
        if not isinstance(item, dict):
            raise BridgeError("Manifest rollback non valido.")
        logical = _safe_logical_path(str(item.get("path") or ""))
        target = target_for(logical)
        existed = bool(item.get("existed"))
        data = payload.get(logical, b"")
        if existed:
            if int(item.get("size", -1)) != len(data) or str(item.get("sha256") or "") != _sha256(data):
                raise BridgeError(f"Checksum rollback non valido: {logical}")
            _atomic_install(target, data, mode_for(logical))
        else:
            if logical in payload:
                raise BridgeError(f"Payload rollback inatteso: {logical}")
            target.unlink(missing_ok=True)


def _run_systemctl(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["systemctl", *args],
            text=True,
            capture_output=True,
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(["systemctl", *args], 1, "", exc.__class__.__name__)


def restart_runtime(runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl) -> dict[str, Any]:
    commands = [
        ["daemon-reload"],
        ["restart", "wg-quick@wg0.service"],
        ["restart", "ge360-bridge-firewall.service"],
        ["restart", "ge360-bridge.service"],
        ["restart", "ge360-bridge-dashboard.service"],
        ["restart", "ge360-bridge-enrollment.service"],
    ]
    results = []
    for args in commands:
        proc = runner(args)
        results.append({"args": args, "returncode": proc.returncode, "error": (proc.stderr or "").strip()[:300]})
        if proc.returncode != 0:
            raise BridgeError("Restart runtime update fallito: systemctl " + " ".join(args))
    return {"commands": results}


def _http_ok(url: str, *, insecure_tls: bool = False) -> bool:
    context = ssl._create_unverified_context() if insecure_tls else None
    try:
        with urlopen(url, timeout=2, context=context) as response:
            return int(getattr(response, "status", response.getcode())) == 200
    except Exception:
        return False


def health_check_runtime(
    *,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl,
    http_checker: Callable[..., bool] = _http_ok,
    attempts: int = 10,
    sleeper: Callable[[float], None] = time.sleep,
) -> dict[str, Any]:
    last: dict[str, Any] = {}
    for _ in range(max(1, attempts)):
        services: dict[str, bool] = {}
        for unit in CORE_SERVICES:
            proc = runner(["is-active", "--quiet", unit])
            services[unit] = proc.returncode == 0
        dashboard = http_checker("http://127.0.0.1:8789/healthz")
        pairing = http_checker("https://127.0.0.1:8790/healthz", insecure_tls=True)
        last = {"services": services, "dashboard_health": dashboard, "pairing_health": pairing}
        if all(services.values()) and dashboard and pairing:
            return {"ok": True, **last}
        sleeper(1.0)
    return {"ok": False, **last}


def _history_path() -> Path:
    return _ensure_update_dir() / "last-update.json"


def _write_history(payload: dict[str, Any]) -> None:
    path = _history_path()
    fd, tmp_name = tempfile.mkstemp(prefix=".history-", dir=str(path.parent))
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2, sort_keys=True)
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.chmod(tmp, 0o600)
        tmp.replace(path)
        os.chmod(path, 0o600)
    finally:
        if tmp.exists():
            tmp.unlink(missing_ok=True)


def update_status() -> dict[str, Any]:
    path = _history_path()
    try:
        history = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        history = None
    return {
        "current_version": __version__,
        "last_update": history,
        "rollback_snapshots": [p.name for p in sorted(_ensure_update_dir().glob("rollback-*.tar.gz"), reverse=True)],
    }


def apply_update(
    path: str | Path,
    *,
    config_backup_keep: int = 10,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl,
    health_checker: Callable[..., dict[str, Any]] = health_check_runtime,
) -> dict[str, Any]:
    package = Path(path)
    lock_path = _ensure_update_dir() / "update.lock"
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            preflight = preflight_update(package, require_newer=True)
            temp, root, manifest, logical_files = _stage_package(package)
            config_backup = None
            rollback_path = None
            try:
                config_backup_result = create_backup(keep=config_backup_keep, reason="pre-update")
                config_backup = config_backup_result.get("backup")
                if not config_backup:
                    raise BridgeError("Backup configurazione pre-update non creato.")
                rollback_path = _create_software_rollback(logical_files, __version__)
                _install_payload(root, logical_files)
                restart_runtime(runner)
                health = health_checker(runner=runner)
                if not health.get("ok"):
                    raise BridgeError("Health check post-update fallito.")
                result = {
                    "ok": True,
                    "rolled_back": False,
                    "from_version": __version__,
                    "to_version": manifest["version"],
                    "config_backup": config_backup,
                    "software_rollback": rollback_path.name,
                    "preflight": preflight,
                    "health": health,
                    "completed_at": _utc_now().isoformat(),
                }
                _write_history(result)
                return result
            except Exception as update_exc:
                rollback_error = None
                rollback_health = None
                if rollback_path is not None:
                    try:
                        _restore_software_rollback(rollback_path)
                        if config_backup:
                            restore_backup(config_backup, apply=True, create_safety_backup=False)
                        restart_runtime(runner)
                        rollback_health = health_checker(runner=runner)
                        if not rollback_health.get("ok"):
                            raise BridgeError("Health check dopo rollback fallito.")
                    except Exception as rb_exc:
                        rollback_error = str(rb_exc)
                result = {
                    "ok": False,
                    "rolled_back": rollback_path is not None and rollback_error is None,
                    "from_version": __version__,
                    "to_version": manifest["version"],
                    "config_backup": config_backup,
                    "software_rollback": None if rollback_path is None else rollback_path.name,
                    "error": str(update_exc),
                    "rollback_error": rollback_error,
                    "rollback_health": rollback_health,
                    "completed_at": _utc_now().isoformat(),
                }
                _write_history(result)
                if rollback_error:
                    raise BridgeError(f"Update fallito e rollback NON riuscito: {update_exc}; rollback: {rollback_error}") from update_exc
                if rollback_path is not None:
                    raise BridgeError(f"Update fallito; rollback eseguito: {update_exc}") from update_exc
                raise BridgeError(f"Update abortito prima dell'installazione: {update_exc}") from update_exc
            finally:
                temp.cleanup()
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)


def run_update(
    url: str,
    expected_sha256: str,
    *,
    config_backup_keep: int = 10,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _run_systemctl,
    health_checker: Callable[..., dict[str, Any]] = health_check_runtime,
) -> dict[str, Any]:
    download = download_update(url, expected_sha256)
    result = apply_update(
        download["path"],
        config_backup_keep=config_backup_keep,
        runner=runner,
        health_checker=health_checker,
    )
    result["download"] = download
    return result


def _source_files(source_root: Path) -> list[str]:
    paths = []
    package = source_root / "ge360_bridge"
    if not package.is_dir():
        raise BridgeError("Sorgente update senza ge360_bridge/.")
    for path in package.rglob("*.py"):
        rel = path.relative_to(source_root).as_posix()
        paths.append(_safe_logical_path(rel))
    for fixed in ("ge360-bridge", "scripts/apply-firewall.sh", "scripts/boot-verify.sh"):
        if (source_root / fixed).is_file():
            paths.append(_safe_logical_path(fixed))
    systemd = source_root / "systemd"
    if systemd.is_dir():
        for path in systemd.iterdir():
            if path.is_file() and path.name.startswith("ge360-bridge") and path.suffix in {".service", ".timer"}:
                paths.append(_safe_logical_path(path.relative_to(source_root).as_posix()))
    return sorted(set(paths))


def build_update_package(source_root: str | Path, output: str | Path) -> dict[str, Any]:
    source = Path(source_root)
    files = _source_files(source)
    missing = sorted(REQUIRED_RUNTIME_PATHS - set(files))
    if missing:
        raise BridgeError("Sorgente update incompleta: " + ", ".join(missing))
    init = (source / "ge360_bridge/__init__.py").read_text(encoding="utf-8")
    match = INIT_VERSION_RE.search(init)
    if not match:
        raise BridgeError("Impossibile leggere __version__ dal sorgente.")
    version = _validate_version(match.group(1))
    manifest_files = []
    payload: dict[str, bytes] = {}
    for logical in files:
        data = (source / logical).read_bytes()
        if len(data) > MAX_MEMBER_BYTES:
            raise BridgeError(f"File sorgente troppo grande: {logical}")
        payload[logical] = data
        manifest_files.append({
            "path": logical,
            "size": len(data),
            "sha256": _sha256(data),
            "mode": mode_for(logical),
        })
    manifest = {
        "schema": UPDATE_SCHEMA,
        "version": version,
        "created_at": _utc_now().isoformat(),
        "files": manifest_files,
    }
    output_path = Path(output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with tarfile.open(output_path, "w:gz") as tf:
        raw = (json.dumps(manifest, indent=2, sort_keys=True) + "\n").encode("utf-8")
        info = tarfile.TarInfo("manifest.json")
        info.size = len(raw)
        info.mode = 0o644
        tf.addfile(info, io.BytesIO(raw))
        for logical, data in sorted(payload.items()):
            info = tarfile.TarInfo("payload/" + logical)
            info.size = len(data)
            info.mode = mode_for(logical)
            tf.addfile(info, io.BytesIO(data))
    os.chmod(output_path, 0o644)
    digest = _sha256(output_path.read_bytes())
    return {"package": str(output_path), "version": version, "files": len(files), "sha256": digest}
