from __future__ import annotations

import copy
import http.client
import json
import socket
import ssl
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

HEALTH_STATES = {
    "ONLINE",
    "DEGRADED",
    "OFFLINE",
    "TIMEOUT",
    "UNAUTHORIZED",
    "BAD_RESPONSE",
}
MAX_BODY_BYTES = 65536
CACHE_TTL_SECONDS = 5.0
_cache_lock = threading.Lock()
_cache: dict[str, tuple[tuple[Any, ...], float, dict[str, Any]]] = {}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _round_ms(seconds: float) -> float:
    return round(max(0.0, seconds) * 1000.0, 2)


def _signature(resource: dict[str, Any]) -> tuple[Any, ...]:
    return (
        resource.get("name"),
        resource.get("protocol", "tcp"),
        resource.get("target_host"),
        int(resource.get("target_port", 0)),
        resource.get("health_url", ""),
        float(resource.get("timeout_seconds", 2.0)),
        bool(resource.get("enabled", True)),
    )


def _cached(resource: dict[str, Any]) -> dict[str, Any] | None:
    name = str(resource.get("name", ""))
    sig = _signature(resource)
    now = time.monotonic()
    with _cache_lock:
        item = _cache.get(name)
        if not item:
            return None
        old_sig, ts, result = item
        if old_sig != sig or now - ts > CACHE_TTL_SECONDS:
            _cache.pop(name, None)
            return None
        return copy.deepcopy(result)


def _store_cache(resource: dict[str, Any], result: dict[str, Any]) -> None:
    with _cache_lock:
        _cache[str(resource.get("name", ""))] = (
            _signature(resource),
            time.monotonic(),
            copy.deepcopy(result),
        )


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


def _base_result(resource: dict[str, Any]) -> dict[str, Any]:
    return {
        "name": str(resource.get("name", "")),
        "state": "OFFLINE",
        "checked_at": _now_iso(),
        "latency_ms": None,
        "protocol": str(resource.get("protocol", "tcp")).lower(),
        "target": f"{resource.get('target_host')}:{resource.get('target_port')}",
        "health_url": str(resource.get("health_url") or ""),
        "error": None,
        "checks": {
            "tcp": {"ok": False, "latency_ms": None, "error": None},
            "http": {"performed": False, "ok": None, "status_code": None, "latency_ms": None, "content_type": None, "error": None},
            "json": {"performed": False, "ok": None, "type": None, "error": None},
            "tls": {"performed": False, "ok": None, "version": None, "cipher": None, "error": None},
        },
    }


def _health_request(resource: dict[str, Any]) -> tuple[str, str, int, str]:
    protocol = str(resource.get("protocol", "tcp")).lower()
    target_host = str(resource["target_host"])
    target_port = int(resource["target_port"])
    health_url = str(resource.get("health_url") or "")
    if health_url.startswith("/"):
        return protocol, target_host, target_port, health_url
    parsed = urlsplit(health_url)
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme.lower(), str(parsed.hostname), int(parsed.port or (443 if parsed.scheme == "https" else 80)), path


def _finish(result: dict[str, Any], state: str, *, error: str | None = None, started: float | None = None) -> dict[str, Any]:
    if state not in HEALTH_STATES:
        state = "BAD_RESPONSE"
    result["state"] = state
    result["error"] = error
    if started is not None:
        result["latency_ms"] = _round_ms(time.monotonic() - started)
    return result


def check_resource(resource: dict[str, Any], *, use_cache: bool = True) -> dict[str, Any]:
    if use_cache:
        cached = _cached(resource)
        if cached is not None:
            return cached

    result = _base_result(resource)
    started = time.monotonic()

    if not resource.get("enabled", True):
        result = _finish(result, "OFFLINE", error="resource_disabled", started=started)
        _store_cache(resource, result)
        return result

    host = str(resource.get("target_host", "127.0.0.1"))
    port = int(resource.get("target_port", 0))
    timeout = float(resource.get("timeout_seconds", 2.0))

    tcp_started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.close()
        result["checks"]["tcp"] = {
            "ok": True,
            "latency_ms": _round_ms(time.monotonic() - tcp_started),
            "error": None,
        }
    except (socket.timeout, TimeoutError):
        result["checks"]["tcp"]["error"] = "timeout"
        result = _finish(result, "TIMEOUT", error="tcp_timeout", started=started)
        _store_cache(resource, result)
        return result
    except OSError as exc:
        result["checks"]["tcp"]["error"] = exc.__class__.__name__
        result = _finish(result, "OFFLINE", error="tcp_unreachable", started=started)
        _store_cache(resource, result)
        return result

    protocol = str(resource.get("protocol", "tcp")).lower()
    health_url = str(resource.get("health_url") or "")
    if protocol == "tcp":
        result = _finish(result, "ONLINE", started=started)
        _store_cache(resource, result)
        return result

    if protocol not in {"http", "https"}:
        result = _finish(result, "BAD_RESPONSE", error="unsupported_protocol", started=started)
        _store_cache(resource, result)
        return result

    if not health_url:
        result = _finish(result, "DEGRADED", error="health_url_not_configured", started=started)
        _store_cache(resource, result)
        return result

    scheme, req_host, req_port, path = _health_request(resource)
    if scheme not in {"http", "https"}:
        result = _finish(result, "BAD_RESPONSE", error="health_scheme_invalid", started=started)
        _store_cache(resource, result)
        return result

    http_started = time.monotonic()
    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(req_host, req_port, timeout=timeout, context=context)
            result["checks"]["tls"]["performed"] = True
        else:
            connection = http.client.HTTPConnection(req_host, req_port, timeout=timeout)

        connection.request("GET", path, headers={"Accept": "application/json", "User-Agent": "GE360-Bridge-Health/0.7"})
        response = connection.getresponse()

        if scheme == "https":
            tls_sock = getattr(connection, "sock", None)
            result["checks"]["tls"]["ok"] = True
            if tls_sock is not None:
                try:
                    result["checks"]["tls"]["version"] = tls_sock.version()
                    cipher = tls_sock.cipher()
                    result["checks"]["tls"]["cipher"] = cipher[0] if cipher else None
                except Exception:
                    pass

        body = response.read(MAX_BODY_BYTES + 1)
        http_latency = _round_ms(time.monotonic() - http_started)
        content_type = response.getheader("Content-Type", "")
        result["checks"]["http"] = {
            "performed": True,
            "ok": 200 <= response.status < 300,
            "status_code": int(response.status),
            "latency_ms": http_latency,
            "content_type": content_type,
            "error": None,
        }

        if len(body) > MAX_BODY_BYTES:
            result["checks"]["http"]["ok"] = False
            result["checks"]["http"]["error"] = "body_too_large"
            result = _finish(result, "BAD_RESPONSE", error="body_too_large", started=started)
            _store_cache(resource, result)
            return result

        if response.status in {401, 403}:
            result = _finish(result, "UNAUTHORIZED", error=f"http_{response.status}", started=started)
            _store_cache(resource, result)
            return result

        if not 200 <= response.status < 300:
            result = _finish(result, "BAD_RESPONSE", error=f"http_{response.status}", started=started)
            _store_cache(resource, result)
            return result

        stripped = body.strip()
        claims_json = "json" in content_type.lower()
        looks_json = bool(stripped[:1] in {b"{", b"["})
        if not stripped:
            result["checks"]["json"] = {
                "performed": True,
                "ok": False,
                "type": None,
                "error": "empty_body",
            }
            result = _finish(result, "DEGRADED", error="empty_health_body", started=started)
            _store_cache(resource, result)
            return result

        if claims_json or looks_json:
            result["checks"]["json"]["performed"] = True
            try:
                payload = json.loads(stripped.decode("utf-8"))
                result["checks"]["json"] = {
                    "performed": True,
                    "ok": True,
                    "type": type(payload).__name__,
                    "error": None,
                }
            except (UnicodeDecodeError, json.JSONDecodeError):
                result["checks"]["json"] = {
                    "performed": True,
                    "ok": False,
                    "type": None,
                    "error": "invalid_json",
                }
                result = _finish(result, "BAD_RESPONSE", error="invalid_json", started=started)
                _store_cache(resource, result)
                return result
            result = _finish(result, "ONLINE", started=started)
            _store_cache(resource, result)
            return result

        result["checks"]["json"] = {
            "performed": True,
            "ok": False,
            "type": None,
            "error": "non_json_response",
        }
        result = _finish(result, "DEGRADED", error="non_json_health_response", started=started)
        _store_cache(resource, result)
        return result

    except ssl.SSLCertVerificationError:
        result["checks"]["tls"] = {
            "performed": True,
            "ok": False,
            "version": None,
            "cipher": None,
            "error": "certificate_verification_failed",
        }
        result = _finish(result, "BAD_RESPONSE", error="tls_certificate_invalid", started=started)
    except ssl.SSLError as exc:
        result["checks"]["tls"] = {
            "performed": True,
            "ok": False,
            "version": None,
            "cipher": None,
            "error": exc.__class__.__name__,
        }
        result = _finish(result, "BAD_RESPONSE", error="tls_error", started=started)
    except (socket.timeout, TimeoutError):
        result["checks"]["http"]["performed"] = True
        result["checks"]["http"]["error"] = "timeout"
        result = _finish(result, "TIMEOUT", error="http_timeout", started=started)
    except (ConnectionError, OSError, http.client.HTTPException) as exc:
        result["checks"]["http"]["performed"] = True
        result["checks"]["http"]["error"] = exc.__class__.__name__
        result = _finish(result, "OFFLINE", error="http_unreachable", started=started)
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass

    _store_cache(resource, result)
    return result


def check_resources(
    resources: list[dict[str, Any]],
    *,
    use_cache: bool = True,
    max_workers: int = 8,
) -> list[dict[str, Any]]:
    if not resources:
        return []
    workers = max(1, min(int(max_workers), len(resources), 16))
    indexed: dict[str, int] = {str(r.get("name", "")): i for i, r in enumerate(resources)}
    out: list[dict[str, Any] | None] = [None] * len(resources)
    with ThreadPoolExecutor(max_workers=workers, thread_name_prefix="ge360-health") as pool:
        futures = {pool.submit(check_resource, r, use_cache=use_cache): r for r in resources}
        for future in as_completed(futures):
            resource = futures[future]
            name = str(resource.get("name", ""))
            try:
                result = future.result()
            except Exception as exc:
                result = _finish(_base_result(resource), "BAD_RESPONSE", error=f"health_engine_error:{exc.__class__.__name__}")
            out[indexed[name]] = result
    return [x for x in out if x is not None]


def health_summary(results: list[dict[str, Any]]) -> dict[str, int]:
    counts = {state: 0 for state in sorted(HEALTH_STATES)}
    for item in results:
        state = str(item.get("state", "BAD_RESPONSE"))
        counts[state if state in counts else "BAD_RESPONSE"] += 1
    counts["TOTAL"] = len(results)
    return counts
