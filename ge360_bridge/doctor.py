from __future__ import annotations

import ipaddress
import re
import subprocess
import time
from pathlib import Path
from typing import Any

from .core import (
    BRIDGE_ENV,
    device_is_active,
    find_device,
    resource_allows_device,
)

PROBLEM_CATEGORIES = {
    "VPN_DOWN",
    "BRIDGE_DOWN",
    "DEVICE_NOT_AUTHORIZED",
    "SERVICE_NOT_ALLOWED",
    "BACKEND_DOWN",
    "HTTP_ERROR",
    "PDF_URL_INVALID",
    "TIMEOUT",
    "PORT_CONFLICT",
    "ENDPOINT_INVALID",
}
OK_CATEGORY = "OK"
HANDSHAKE_FRESH_SECONDS = 180


def _run(cmd: list[str], timeout: float = 2.0) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(cmd, text=True, capture_output=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return subprocess.CompletedProcess(cmd, 127, "", "")


def _load_env() -> dict[str, str]:
    out: dict[str, str] = {}
    try:
        lines = BRIDGE_ENV.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        out[key.strip()] = value.strip().strip('"').strip("'")
    return out


def validate_public_endpoint(value: str | None) -> tuple[bool, str | None]:
    endpoint = (value or "").strip()
    if not endpoint or endpoint.upper().startswith("CHANGE_ME"):
        return False, "public_endpoint_non_configurato"

    host = ""
    port_text = ""
    if endpoint.startswith("["):
        match = re.fullmatch(r"\[([^\]]+)\]:(\d+)", endpoint)
        if not match:
            return False, "public_endpoint_formato_non_valido"
        host, port_text = match.groups()
        try:
            ip = ipaddress.ip_address(host)
            if ip.version != 6:
                return False, "public_endpoint_ipv6_non_valido"
        except ValueError:
            return False, "public_endpoint_ipv6_non_valido"
    else:
        if endpoint.count(":") != 1:
            return False, "public_endpoint_formato_non_valido"
        host, port_text = endpoint.rsplit(":", 1)
        if not host:
            return False, "public_endpoint_host_mancante"

    try:
        port = int(port_text)
    except ValueError:
        return False, "public_endpoint_porta_non_valida"
    if not 1 <= port <= 65535:
        return False, "public_endpoint_porta_non_valida"
    return True, None


def bridge_runtime(resource: dict[str, Any]) -> dict[str, Any]:
    port = int(resource.get("bridge_port", 0))
    service = _run(["systemctl", "is-active", "ge360-bridge.service"])
    wg = _run(["ip", "link", "show", "wg0"])
    listeners = _run(["ss", "-H", "-ltn"])
    listener_lines = [x.strip() for x in listeners.stdout.splitlines() if x.strip()]
    port_marker = f":{port}"
    matching = [line for line in listener_lines if port_marker in line]
    expected = any(
        ("10.88.0.1:" + str(port)) in line
        or ("[10.88.0.1]:" + str(port)) in line
        for line in matching
    )
    conflicting = bool(matching) and not expected

    env = _load_env()
    endpoint = env.get("PUBLIC_ENDPOINT")
    endpoint_ok, endpoint_error = validate_public_endpoint(endpoint)
    return {
        "bridge_service_active": service.returncode == 0 and service.stdout.strip() == "active",
        "wg0_present": wg.returncode == 0,
        "bridge_port": port,
        "bridge_port_listening": expected,
        "port_conflict": conflicting,
        "listeners": matching[:5],
        "public_endpoint": endpoint,
        "public_endpoint_valid": endpoint_ok,
        "public_endpoint_error": endpoint_error,
    }


def device_runtime(device_identifier: str | None, resource: dict[str, Any]) -> dict[str, Any]:
    if not device_identifier:
        return {
            "requested": False,
            "found": None,
            "active": None,
            "allowed": None,
            "handshake_age_seconds": None,
            "vpn_up": None,
        }

    device = find_device(device_identifier)
    if not device:
        return {
            "requested": True,
            "found": False,
            "active": False,
            "allowed": False,
            "handshake_age_seconds": None,
            "vpn_up": False,
        }

    dump = _run(["wg", "show", "wg0", "dump"])
    latest = 0
    if dump.returncode == 0:
        lines = [x for x in dump.stdout.splitlines() if x.strip()]
        for raw in lines[1:]:
            parts = raw.split("\t")
            if len(parts) >= 5 and parts[0] == device.get("public_key"):
                try:
                    latest = int(parts[4])
                except ValueError:
                    latest = 0
                break
    age = None if latest <= 0 else max(0, int(time.time()) - latest)
    vpn_up = age is not None and age <= HANDSHAKE_FRESH_SECONDS
    return {
        "requested": True,
        "found": True,
        "device_id": device.get("device_id"),
        "name": device.get("name"),
        "active": device_is_active(device),
        "allowed": resource_allows_device(resource, device),
        "handshake_age_seconds": age,
        "vpn_up": vpn_up,
    }


def classify(
    resource: dict[str, Any],
    diagnostics: dict[str, Any],
    health: dict[str, Any],
    *,
    bridge: dict[str, Any],
    device: dict[str, Any],
) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []

    def add(category: str, reason: str, evidence: dict[str, Any] | None = None) -> None:
        findings.append({
            "category": category,
            "reason": reason,
            "evidence": evidence or {},
        })

    if not bridge.get("wg0_present") or not bridge.get("bridge_service_active"):
        add("BRIDGE_DOWN", "WireGuard wg0 o servizio ge360-bridge non risulta attivo.", {
            "wg0_present": bridge.get("wg0_present"),
            "bridge_service_active": bridge.get("bridge_service_active"),
        })

    if bridge.get("port_conflict"):
        add("PORT_CONFLICT", "La bridge port della Resource risulta occupata da un listener non atteso.", {
            "bridge_port": bridge.get("bridge_port"),
            "listeners": bridge.get("listeners", []),
        })

    if not bridge.get("public_endpoint_valid"):
        add("ENDPOINT_INVALID", "PUBLIC_ENDPOINT non è configurato o non ha un formato valido.", {
            "public_endpoint": bridge.get("public_endpoint"),
            "error": bridge.get("public_endpoint_error"),
        })

    if device.get("requested"):
        if not device.get("found") or not device.get("active"):
            add("DEVICE_NOT_AUTHORIZED", "Il device richiesto non esiste, è disabilitato o è scaduto.", {
                "found": device.get("found"),
                "active": device.get("active"),
            })
        elif not device.get("allowed"):
            add("SERVICE_NOT_ALLOWED", "Il device non ha accesso effettivo alla Resource secondo ACL/gruppi.", {
                "device": device.get("name"),
                "resource": resource.get("name"),
            })
        elif not device.get("vpn_up"):
            add("VPN_DOWN", "Il peer WireGuard del device non ha un handshake recente.", {
                "handshake_age_seconds": device.get("handshake_age_seconds"),
                "fresh_threshold_seconds": HANDSHAKE_FRESH_SECONDS,
            })

    checks = diagnostics.get("checks", {})
    primary_checks = [checks.get("target_tcp", {}), checks.get("api", {}), checks.get("pdf", {})]
    if health.get("state") == "TIMEOUT" or any(x.get("error") == "timeout" for x in primary_checks):
        add("TIMEOUT", "Un controllo backend/API/PDF ha superato il timeout configurato.", {
            "health_state": health.get("state"),
        })

    target_tcp = checks.get("target_tcp", {})
    if target_tcp and not target_tcp.get("ok") and target_tcp.get("error") != "timeout":
        add("BACKEND_DOWN", "La porta TCP del backend registrato non è raggiungibile.", {
            "target": f"{target_tcp.get('host')}:{target_tcp.get('port')}",
            "error": target_tcp.get("error"),
        })

    pdf = checks.get("pdf", {})
    if pdf and not pdf.get("skipped") and not pdf.get("ok"):
        pdf_error = str(pdf.get("error") or "")
        if pdf_error in {
            "url_fuori_resource",
            "url_non_valida",
            "porta_url_non_valida",
            "percorso_mancante",
            "not_a_pdf",
        }:
            add("PDF_URL_INVALID", "Il percorso PDF non identifica un PDF valido della Resource.", {
                "request": pdf.get("request"),
                "status_code": pdf.get("status_code"),
                "content_type": pdf.get("content_type"),
                "pdf_magic": pdf.get("pdf_magic"),
                "error": pdf.get("error"),
            })

    api = checks.get("api", {})
    http_error = False
    http_evidence: dict[str, Any] = {}
    if api and not api.get("skipped") and not api.get("ok"):
        error = str(api.get("error") or "")
        status = api.get("status_code")
        if error != "timeout" and not (target_tcp and not target_tcp.get("ok")):
            http_error = True
            http_evidence = {
                "status_code": status,
                "content_type": api.get("content_type"),
                "error": api.get("error"),
            }
    elif health.get("state") in {"UNAUTHORIZED", "BAD_RESPONSE"}:
        http_error = True
        http_evidence = {
            "health_state": health.get("state"),
            "error": health.get("error"),
        }
    if http_error:
        add("HTTP_ERROR", "Il backend risponde a livello TCP ma il controllo HTTP/API non è valido.", http_evidence)

    precedence = [
        "BRIDGE_DOWN",
        "PORT_CONFLICT",
        "ENDPOINT_INVALID",
        "DEVICE_NOT_AUTHORIZED",
        "SERVICE_NOT_ALLOWED",
        "VPN_DOWN",
        "TIMEOUT",
        "BACKEND_DOWN",
        "PDF_URL_INVALID",
        "HTTP_ERROR",
    ]
    categories = [f["category"] for f in findings]
    primary = next((x for x in precedence if x in categories), OK_CATEGORY)

    return {
        "category": primary,
        "ok": primary == OK_CATEGORY,
        "findings": findings,
    }


def connection_doctor(
    resource: dict[str, Any],
    diagnostics: dict[str, Any],
    health: dict[str, Any],
    *,
    device_identifier: str | None = None,
    bridge_snapshot: dict[str, Any] | None = None,
    device_snapshot: dict[str, Any] | None = None,
) -> dict[str, Any]:
    bridge = bridge_snapshot if bridge_snapshot is not None else bridge_runtime(resource)
    device = device_snapshot if device_snapshot is not None else device_runtime(device_identifier, resource)
    diagnosis = classify(resource, diagnostics, health, bridge=bridge, device=device)
    return {
        "schema": "ge360-bridge-connection-doctor/v1",
        "resource": resource.get("name"),
        "device": device.get("name") if device.get("found") else device_identifier,
        "category": diagnosis["category"],
        "ok": diagnosis["ok"],
        "findings": diagnosis["findings"],
        "runtime": {
            "bridge": bridge,
            "device": device,
        },
        "source": {
            "health_state": health.get("state"),
            "diagnostics_schema": diagnostics.get("schema"),
        },
    }
