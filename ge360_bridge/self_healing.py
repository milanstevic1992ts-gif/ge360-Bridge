from __future__ import annotations

import fcntl
import os
import subprocess
import time
from pathlib import Path
from typing import Any, Callable

from .audit import write_event
from .core import (
    STATE_DIR,
    BridgeError,
    _atomic_write,
    list_resources,
    validate_systemd_unit,
)
from .health import check_resource

SELF_HEAL_STATE_FILE = STATE_DIR / "self_heal_state.json"
RESTART_LIMIT = 3
RESTART_WINDOW_SECONDS = 10 * 60
RECOVERY_CHECK_ATTEMPTS = 10
RECOVERY_CHECK_INTERVAL_SECONDS = 1.0
TRIGGER_STATES = {"OFFLINE", "TIMEOUT"}


def _load_state(path: Path = SELF_HEAL_STATE_FILE) -> dict[str, list[float]]:
    try:
        raw = __import__("json").loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, ValueError, OSError):
        return {}
    if not isinstance(raw, dict):
        return {}
    out: dict[str, list[float]] = {}
    for name, values in raw.items():
        if not isinstance(name, str) or not isinstance(values, list):
            continue
        clean: list[float] = []
        for value in values:
            try:
                clean.append(float(value))
            except (TypeError, ValueError):
                continue
        out[name] = clean
    return out


def _save_state(state: dict[str, list[float]], path: Path = SELF_HEAL_STATE_FILE) -> None:
    _atomic_write(path, state, mode=0o600)


def _prune_attempts(values: list[float], now_epoch: float) -> list[float]:
    cutoff = float(now_epoch) - RESTART_WINDOW_SECONDS
    ceiling = float(now_epoch) + 60.0
    return sorted(ts for ts in values if cutoff < float(ts) <= ceiling)


def _prune_state(state: dict[str, list[float]], now_epoch: float) -> dict[str, list[float]]:
    out: dict[str, list[float]] = {}
    for name, values in state.items():
        clean = _prune_attempts(values, now_epoch)
        if clean:
            out[name] = clean
    return out


def _audit(
    event: str,
    *,
    resource: str,
    action: str,
    result: str,
    error: str | None = None,
) -> None:
    try:
        write_event(
            event,
            resource=resource,
            action=action,
            result=result,
            error=error,
        )
    except Exception:
        pass


def _systemctl(args: list[str]) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["systemctl", *args],
            text=True,
            capture_output=True,
            timeout=20,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return subprocess.CompletedProcess(["systemctl", *args], 1, "", exc.__class__.__name__)


def _unit_is_loaded(unit: str, runner: Callable[[list[str]], subprocess.CompletedProcess[str]]) -> tuple[bool, str]:
    proc = runner(["show", unit, "--property=LoadState", "--value"])
    value = (proc.stdout or "").strip().lower()
    if proc.returncode != 0:
        return False, (proc.stderr or "systemctl_show_failed").strip()[:300]
    if value != "loaded":
        return False, value or "not_loaded"
    return True, ""


def _restart_unit(unit: str, runner: Callable[[list[str]], subprocess.CompletedProcess[str]]) -> tuple[bool, str]:
    proc = runner(["restart", unit])
    if proc.returncode == 0:
        return True, ""
    return False, (proc.stderr or proc.stdout or "systemctl_restart_failed").strip()[:300]


def _health_state(
    resource: dict[str, Any],
    checker: Callable[..., dict[str, Any]],
) -> dict[str, Any]:
    try:
        return checker(resource, use_cache=False)
    except Exception as exc:
        return {
            "name": resource.get("name", ""),
            "state": "OFFLINE",
            "latency_ms": None,
            "error": f"health_exception:{exc.__class__.__name__}",
            "checks": {},
        }


def self_heal_status(now_epoch: float | None = None) -> dict[str, Any]:
    now = float(time.time() if now_epoch is None else now_epoch)
    state = _prune_state(_load_state(), now)
    rows = []
    for resource in list_resources():
        attempts = state.get(resource["name"], [])
        oldest = min(attempts) if attempts else None
        retry_after = 0
        if len(attempts) >= RESTART_LIMIT and oldest is not None:
            retry_after = max(0, int(oldest + RESTART_WINDOW_SECONDS - now))
        rows.append({
            "resource": resource["name"],
            "self_heal_enabled": bool(resource.get("self_heal_enabled", False)),
            "systemd_unit": resource.get("systemd_unit", ""),
            "attempts_in_window": len(attempts),
            "restart_limit": RESTART_LIMIT,
            "window_seconds": RESTART_WINDOW_SECONDS,
            "rate_limited": len(attempts) >= RESTART_LIMIT,
            "retry_after_seconds": retry_after,
        })
    return {
        "restart_limit": RESTART_LIMIT,
        "window_seconds": RESTART_WINDOW_SECONDS,
        "resources": rows,
    }


def heal_resource(
    resource: dict[str, Any],
    state: dict[str, list[float]],
    *,
    now_epoch: float,
    dry_run: bool,
    checker: Callable[..., dict[str, Any]] = check_resource,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _systemctl,
    sleeper: Callable[[float], None] = time.sleep,
    state_path: Path = SELF_HEAL_STATE_FILE,
) -> dict[str, Any]:
    name = str(resource.get("name") or "")

    if not resource.get("enabled", True):
        return {"resource": name, "result": "SKIPPED", "reason": "resource_disabled"}

    if not resource.get("self_heal_enabled", False):
        return {"resource": name, "result": "SKIPPED", "reason": "self_heal_disabled"}

    unit = validate_systemd_unit(resource.get("systemd_unit", ""))
    if not unit:
        return {"resource": name, "result": "CONFIG_ERROR", "reason": "systemd_unit_missing"}

    health_before = _health_state(resource, checker)
    state_before = str(health_before.get("state") or "OFFLINE").upper()
    if state_before not in TRIGGER_STATES:
        return {
            "resource": name,
            "result": "NO_ACTION",
            "reason": "health_state_not_restartable",
            "health_before": state_before,
        }

    attempts = _prune_attempts(state.get(name, []), now_epoch)
    state[name] = attempts
    if len(attempts) >= RESTART_LIMIT:
        retry_after = max(0, int(attempts[0] + RESTART_WINDOW_SECONDS - now_epoch))
        _audit(
            "SELF_HEAL_BLOCKED",
            resource=name,
            action="restart",
            result="RATE_LIMITED",
            error=f"retry_after_seconds={retry_after}",
        )
        return {
            "resource": name,
            "result": "RATE_LIMITED",
            "health_before": state_before,
            "attempts_in_window": len(attempts),
            "restart_limit": RESTART_LIMIT,
            "retry_after_seconds": retry_after,
        }

    loaded, unit_error = _unit_is_loaded(unit, runner)
    if not loaded:
        _audit(
            "SELF_HEAL_BLOCKED",
            resource=name,
            action="unit_validation",
            result="UNIT_NOT_LOADED",
            error=unit_error,
        )
        return {
            "resource": name,
            "result": "UNIT_NOT_LOADED",
            "health_before": state_before,
            "systemd_unit": unit,
            "error": unit_error,
        }

    if dry_run:
        return {
            "resource": name,
            "result": "WOULD_RESTART",
            "health_before": state_before,
            "systemd_unit": unit,
            "attempts_in_window": len(attempts),
        }

    attempts.append(float(now_epoch))
    state[name] = attempts
    _save_state(_prune_state(state, now_epoch), state_path)
    _audit(
        "SELF_HEAL_RESTART",
        resource=name,
        action="restart",
        result="ATTEMPT",
        error=f"unit={unit}",
    )

    restarted, restart_error = _restart_unit(unit, runner)
    if not restarted:
        _audit(
            "SELF_HEAL_RESTART",
            resource=name,
            action="restart",
            result="FAILED",
            error=restart_error,
        )
        return {
            "resource": name,
            "result": "RESTART_FAILED",
            "health_before": state_before,
            "systemd_unit": unit,
            "attempts_in_window": len(attempts),
            "error": restart_error,
        }

    last_health = health_before
    for _ in range(RECOVERY_CHECK_ATTEMPTS):
        sleeper(RECOVERY_CHECK_INTERVAL_SECONDS)
        last_health = _health_state(resource, checker)
        if str(last_health.get("state") or "").upper() == "ONLINE":
            _audit(
                "SELF_HEAL_RECOVERED",
                resource=name,
                action="restart",
                result="ONLINE",
            )
            return {
                "resource": name,
                "result": "RECOVERED",
                "health_before": state_before,
                "health_after": "ONLINE",
                "systemd_unit": unit,
                "attempts_in_window": len(attempts),
                "latency_ms": last_health.get("latency_ms"),
            }

    final_state = str(last_health.get("state") or "OFFLINE").upper()
    _audit(
        "SELF_HEAL_RESTART",
        resource=name,
        action="post_restart_health",
        result="STILL_UNHEALTHY",
        error=final_state,
    )
    return {
        "resource": name,
        "result": "STILL_UNHEALTHY",
        "health_before": state_before,
        "health_after": final_state,
        "systemd_unit": unit,
        "attempts_in_window": len(attempts),
        "error": last_health.get("error"),
    }


def _run_self_heal_locked(
    resource_name: str | None = None,
    *,
    dry_run: bool = False,
    now_epoch: float | None = None,
    checker: Callable[..., dict[str, Any]] = check_resource,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _systemctl,
    sleeper: Callable[[float], None] = time.sleep,
    state_path: Path = SELF_HEAL_STATE_FILE,
) -> dict[str, Any]:
    now = float(time.time() if now_epoch is None else now_epoch)
    resources = list_resources()
    if resource_name is not None:
        resources = [r for r in resources if r.get("name") == resource_name]
        if not resources:
            raise BridgeError(f"Resource non trovata: {resource_name}")

    state = _prune_state(_load_state(state_path), now)
    results = []
    for resource in resources:
        result = heal_resource(
            resource,
            state,
            now_epoch=now,
            dry_run=dry_run,
            checker=checker,
            runner=runner,
            sleeper=sleeper,
            state_path=state_path,
        )
        results.append(result)

    _save_state(_prune_state(state, now), state_path)
    summary: dict[str, int] = {}
    for item in results:
        key = str(item.get("result") or "UNKNOWN")
        summary[key] = summary.get(key, 0) + 1
    return {
        "dry_run": bool(dry_run),
        "restart_limit": RESTART_LIMIT,
        "window_seconds": RESTART_WINDOW_SECONDS,
        "summary": summary,
        "results": results,
    }



def run_self_heal(
    resource_name: str | None = None,
    *,
    dry_run: bool = False,
    now_epoch: float | None = None,
    checker: Callable[..., dict[str, Any]] = check_resource,
    runner: Callable[[list[str]], subprocess.CompletedProcess[str]] = _systemctl,
    sleeper: Callable[[float], None] = time.sleep,
    state_path: Path = SELF_HEAL_STATE_FILE,
) -> dict[str, Any]:
    lock_path = state_path.with_name("self_heal.lock")
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    with lock_path.open("a+", encoding="utf-8") as lock:
        try:
            os.chmod(lock_path, 0o600)
        except OSError:
            pass
        fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
        try:
            return _run_self_heal_locked(
                resource_name,
                dry_run=dry_run,
                now_epoch=now_epoch,
                checker=checker,
                runner=runner,
                sleeper=sleeper,
                state_path=state_path,
            )
        finally:
            fcntl.flock(lock.fileno(), fcntl.LOCK_UN)
