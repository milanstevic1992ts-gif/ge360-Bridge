from __future__ import annotations

import http.client
import ipaddress
import json
import re
import socket
import ssl
import subprocess
import time
from datetime import datetime, timezone
from typing import Any
from urllib.parse import urlsplit

BRIDGE_IP = "10.88.0.1"
MAX_PREVIEW_BYTES = 4096
MAX_TRACE_LINES = 40
ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "::1", "localhost"}


class DiagnosticError(RuntimeError):
    pass


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def _ms(started: float) -> float:
    return round(max(0.0, time.monotonic() - started) * 1000.0, 2)


def _run(cmd: list[str], timeout: float) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            cmd,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
    except FileNotFoundError as exc:
        raise DiagnosticError(f"comando_non_disponibile:{cmd[0]}") from exc
    except subprocess.TimeoutExpired as exc:
        raise DiagnosticError(f"comando_timeout:{cmd[0]}") from exc


def dns_lookup(host: str) -> dict[str, Any]:
    started = time.monotonic()
    result = {
        "check": "dns",
        "host": host,
        "ok": False,
        "addresses": [],
        "latency_ms": None,
        "error": None,
    }
    try:
        infos = socket.getaddrinfo(host, None, type=socket.SOCK_STREAM)
        addresses: list[dict[str, str]] = []
        seen: set[tuple[str, str]] = set()
        for family, _socktype, _proto, _canon, sockaddr in infos:
            address = str(sockaddr[0])
            family_name = "IPv6" if family == socket.AF_INET6 else "IPv4" if family == socket.AF_INET else str(family)
            key = (family_name, address)
            if key not in seen:
                seen.add(key)
                addresses.append({"family": family_name, "address": address})
        result["addresses"] = addresses
        result["ok"] = bool(addresses)
        if not addresses:
            result["error"] = "nessun_indirizzo"
    except socket.gaierror as exc:
        result["error"] = f"dns_error:{exc.__class__.__name__}"
    result["latency_ms"] = _ms(started)
    return result


def ping_host(host: str, *, count: int = 2, timeout_seconds: float = 3.0) -> dict[str, Any]:
    started = time.monotonic()
    result = {
        "check": "ping",
        "host": host,
        "ok": False,
        "packets_transmitted": count,
        "packets_received": 0,
        "packet_loss_percent": None,
        "rtt_avg_ms": None,
        "latency_ms": None,
        "error": None,
    }
    try:
        proc = _run(
            ["ping", "-n", "-c", str(max(1, min(count, 4))), "-W", "1", host],
            max(2.0, timeout_seconds),
        )
    except DiagnosticError as exc:
        result["error"] = str(exc)
        result["latency_ms"] = _ms(started)
        return result

    text = (proc.stdout or "") + "\n" + (proc.stderr or "")
    packet = re.search(r"(\d+)\s+packets transmitted,\s+(\d+)\s+(?:packets )?received,\s+([\d.]+)%\s+packet loss", text)
    if packet:
        result["packets_transmitted"] = int(packet.group(1))
        result["packets_received"] = int(packet.group(2))
        result["packet_loss_percent"] = float(packet.group(3))
    rtt = re.search(r"(?:rtt|round-trip).*?=\s*[\d.]+/([\d.]+)/", text)
    if rtt:
        result["rtt_avg_ms"] = float(rtt.group(1))
    result["ok"] = proc.returncode == 0 and int(result["packets_received"]) > 0
    if not result["ok"]:
        result["error"] = "ping_failed"
    result["latency_ms"] = _ms(started)
    return result


def tcp_test(host: str, port: int, *, timeout_seconds: float = 2.0, label: str = "tcp") -> dict[str, Any]:
    started = time.monotonic()
    result = {
        "check": label,
        "host": host,
        "port": int(port),
        "ok": False,
        "latency_ms": None,
        "error": None,
    }
    try:
        with socket.create_connection((host, int(port)), timeout=timeout_seconds):
            result["ok"] = True
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except OSError as exc:
        result["error"] = exc.__class__.__name__
    result["latency_ms"] = _ms(started)
    return result


def traceroute_host(host: str, *, max_hops: int = 12, timeout_seconds: float = 15.0) -> dict[str, Any]:
    started = time.monotonic()
    result = {
        "check": "traceroute",
        "host": host,
        "ok": False,
        "hops": [],
        "latency_ms": None,
        "error": None,
    }
    try:
        proc = _run(
            ["traceroute", "-n", "-m", str(max(1, min(max_hops, 30))), "-w", "1", "-q", "1", host],
            timeout_seconds,
        )
    except DiagnosticError as exc:
        result["error"] = str(exc)
        result["latency_ms"] = _ms(started)
        return result

    lines = [line.strip() for line in (proc.stdout or "").splitlines() if line.strip()]
    hop_lines = [line for line in lines if re.match(r"^\d+\s+", line)][:MAX_TRACE_LINES]
    result["hops"] = hop_lines
    result["ok"] = proc.returncode == 0 and bool(hop_lines)
    if not result["ok"]:
        result["error"] = "traceroute_failed"
    result["latency_ms"] = _ms(started)
    return result


def _resource_request(resource: dict[str, Any], path_or_url: str, *, timeout_seconds: float | None = None) -> tuple[str, str, int, str]:
    raw = (path_or_url or "").strip()
    if not raw:
        raise DiagnosticError("percorso_mancante")

    target_host = str(resource.get("target_host", "127.0.0.1")).lower()
    target_port = int(resource.get("target_port", 0))
    protocol = str(resource.get("protocol", "http")).lower()
    if protocol not in {"http", "https"}:
        raise DiagnosticError("resource_non_http")

    if raw.startswith("/"):
        return protocol, target_host, target_port, raw

    parsed = urlsplit(raw)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise DiagnosticError("url_non_valida")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise DiagnosticError("porta_url_non_valida") from exc
    if parsed.hostname.lower() != target_host or int(port) != target_port:
        raise DiagnosticError("url_fuori_resource")
    path = parsed.path or "/"
    if parsed.query:
        path += "?" + parsed.query
    return parsed.scheme.lower(), parsed.hostname.lower(), int(port), path


def _http_get(
    resource: dict[str, Any],
    path_or_url: str,
    *,
    accept: str,
    max_bytes: int,
    timeout_seconds: float | None = None,
    allow_truncated: bool = False,
) -> dict[str, Any]:
    started = time.monotonic()
    scheme, host, port, path = _resource_request(resource, path_or_url, timeout_seconds=timeout_seconds)
    timeout = float(timeout_seconds or resource.get("timeout_seconds", 2.0))
    connection: http.client.HTTPConnection | http.client.HTTPSConnection | None = None
    result: dict[str, Any] = {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "ok": False,
        "status_code": None,
        "content_type": None,
        "content_length": None,
        "latency_ms": None,
        "tls": None,
        "body": b"",
        "error": None,
    }
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            connection = http.client.HTTPSConnection(host, port, timeout=timeout, context=context)
        else:
            connection = http.client.HTTPConnection(host, port, timeout=timeout)

        connection.request("GET", path, headers={"Accept": accept, "User-Agent": "GE360-Bridge-Diagnostics/0.8"})
        response = connection.getresponse()
        body = response.read(max_bytes + 1)
        result["status_code"] = int(response.status)
        result["content_type"] = response.getheader("Content-Type", "")
        result["content_length"] = response.getheader("Content-Length")
        if scheme == "https":
            tls_sock = getattr(connection, "sock", None)
            if tls_sock is not None:
                try:
                    cipher = tls_sock.cipher()
                    result["tls"] = {
                        "version": tls_sock.version(),
                        "cipher": cipher[0] if cipher else None,
                    }
                except Exception:
                    result["tls"] = {"version": None, "cipher": None}
        if len(body) > max_bytes:
            if not allow_truncated:
                result["error"] = "body_too_large_for_diagnostic"
            body = body[:max_bytes]
        result["body"] = body
        result["ok"] = 200 <= response.status < 300
    except ssl.SSLCertVerificationError:
        result["error"] = "tls_certificate_invalid"
    except ssl.SSLError:
        result["error"] = "tls_error"
    except (socket.timeout, TimeoutError):
        result["error"] = "timeout"
    except (OSError, ConnectionError, http.client.HTTPException) as exc:
        result["error"] = exc.__class__.__name__
    finally:
        if connection is not None:
            try:
                connection.close()
            except Exception:
                pass
    result["latency_ms"] = _ms(started)
    return result


def api_test(resource: dict[str, Any], path_or_url: str | None = None) -> dict[str, Any]:
    requested = (path_or_url or resource.get("health_url") or "/").strip()
    result = {
        "check": "api",
        "resource": resource.get("name"),
        "request": requested,
        "ok": False,
        "status_code": None,
        "content_type": None,
        "latency_ms": None,
        "json_valid": None,
        "json_type": None,
        "preview": None,
        "error": None,
    }
    try:
        raw = _http_get(resource, requested, accept="application/json,*/*;q=0.5", max_bytes=65536)
    except DiagnosticError as exc:
        result["error"] = str(exc)
        return result

    result["status_code"] = raw["status_code"]
    result["content_type"] = raw["content_type"]
    result["latency_ms"] = raw["latency_ms"]
    result["error"] = raw["error"]
    body = raw["body"]
    result["preview"] = body.decode("utf-8", "replace")[:1000] if body else ""
    if body:
        try:
            payload = json.loads(body.decode("utf-8"))
            result["json_valid"] = True
            result["json_type"] = type(payload).__name__
        except (UnicodeDecodeError, json.JSONDecodeError):
            result["json_valid"] = False
    result["ok"] = bool(raw["ok"]) and result["json_valid"] is not False
    if not result["ok"] and not result["error"]:
        if raw["status_code"] is not None and not 200 <= int(raw["status_code"]) < 300:
            result["error"] = f"http_{raw['status_code']}"
        elif result["json_valid"] is False:
            result["error"] = "invalid_json"
    return result


def pdf_test(resource: dict[str, Any], path_or_url: str) -> dict[str, Any]:
    result = {
        "check": "pdf",
        "resource": resource.get("name"),
        "request": path_or_url,
        "ok": False,
        "status_code": None,
        "content_type": None,
        "content_length": None,
        "latency_ms": None,
        "pdf_magic": False,
        "error": None,
    }
    try:
        raw = _http_get(resource, path_or_url, accept="application/pdf,*/*;q=0.2", max_bytes=MAX_PREVIEW_BYTES, allow_truncated=True)
    except DiagnosticError as exc:
        result["error"] = str(exc)
        return result

    body = raw["body"]
    content_type = (raw["content_type"] or "").lower()
    result["status_code"] = raw["status_code"]
    result["content_type"] = raw["content_type"]
    result["content_length"] = raw["content_length"]
    result["latency_ms"] = raw["latency_ms"]
    result["pdf_magic"] = body.startswith(b"%PDF-")
    result["error"] = raw["error"]
    result["ok"] = bool(raw["ok"]) and result["pdf_magic"]
    if not result["ok"] and not result["error"]:
        if raw["status_code"] is not None and not 200 <= int(raw["status_code"]) < 300:
            result["error"] = f"http_{raw['status_code']}"
        elif not result["pdf_magic"]:
            result["error"] = "not_a_pdf"
    return result


def diagnose_resource(
    resource: dict[str, Any],
    *,
    api_path: str | None = None,
    pdf_path: str | None = None,
    include_traceroute: bool = True,
) -> dict[str, Any]:
    target_host = str(resource.get("target_host", "127.0.0.1"))
    timeout = float(resource.get("timeout_seconds", 2.0))
    report: dict[str, Any] = {
        "schema": "ge360-bridge-diagnostics/v1",
        "resource": resource.get("name"),
        "checked_at": _now_iso(),
        "checks": {},
    }
    report["checks"]["bridge_ping"] = ping_host(BRIDGE_IP, timeout_seconds=timeout)
    report["checks"]["backend_ping"] = ping_host(target_host, timeout_seconds=timeout)
    report["checks"]["target_tcp"] = tcp_test(target_host, int(resource["target_port"]), timeout_seconds=timeout, label="target_tcp")
    report["checks"]["dns"] = dns_lookup(target_host)

    if str(resource.get("protocol", "tcp")).lower() in {"http", "https"}:
        report["checks"]["api"] = api_test(resource, api_path)
    else:
        report["checks"]["api"] = {
            "check": "api",
            "resource": resource.get("name"),
            "ok": False,
            "skipped": True,
            "error": "resource_non_http",
        }

    if pdf_path:
        report["checks"]["pdf"] = pdf_test(resource, pdf_path)
    else:
        report["checks"]["pdf"] = {
            "check": "pdf",
            "resource": resource.get("name"),
            "ok": False,
            "skipped": True,
            "error": "pdf_path_non_fornito",
        }

    if include_traceroute:
        report["checks"]["traceroute"] = traceroute_host(target_host)
    else:
        report["checks"]["traceroute"] = {
            "check": "traceroute",
            "host": target_host,
            "ok": False,
            "skipped": True,
            "error": "traceroute_disabilitato",
        }

    performed = [x for x in report["checks"].values() if not x.get("skipped")]
    report["summary"] = {
        "performed": len(performed),
        "ok": sum(1 for x in performed if x.get("ok")),
        "failed": sum(1 for x in performed if not x.get("ok")),
    }
    return report
