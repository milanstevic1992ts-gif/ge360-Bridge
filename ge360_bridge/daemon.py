from __future__ import annotations

import asyncio
import json
import signal
import subprocess
import time
from typing import Any

from .core import (
    allowed_ips_for_resource,
    device_is_active,
    effective_resources_for_device,
    list_devices,
    list_groups,
    list_resources,
)
from .health import check_resources
from .audit import init_db, write_event
from .metrics import collect_snapshot, init_db as init_metrics_db
from .launcher import launcher_payload, multi_server_catalog_payload, render_hub, resources_for_launcher

BIND_HOST = "10.88.0.1"
HEALTH_PORT = 8788


async def pipe(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    try:
        while data := await reader.read(65536):
            writer.write(data)
            await writer.drain()
    except (ConnectionError, asyncio.CancelledError):
        pass
    finally:
        writer.close()
        try:
            await writer.wait_closed()
        except Exception:
            pass


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, resource: dict[str, Any], allowed: set[str]) -> None:
    started = time.monotonic()
    peer = client_writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    device = next((d for d in list_devices() if d.get("vpn_ip") == peer_ip), None)
    audit_common = {
        "device_id": device.get("device_id") if device else None,
        "device_name": device.get("name") if device else None,
        "resource": resource.get("name"),
        "action": "tcp_connect",
        "ip": peer_ip or None,
    }
    if peer_ip not in allowed:
        await asyncio.to_thread(write_event, "RESOURCE_ACCESS", **audit_common, result="DENY", error="acl_denied")
        client_writer.close()
        await client_writer.wait_closed()
        return
    try:
        target_reader, target_writer = await asyncio.open_connection(resource["target_host"], int(resource["target_port"]))
    except OSError as exc:
        await asyncio.to_thread(
            write_event,
            "RESOURCE_ACCESS",
            **audit_common,
            result="ERROR",
            latency_ms=(time.monotonic() - started) * 1000.0,
            error=exc.__class__.__name__,
        )
        client_writer.close()
        await client_writer.wait_closed()
        return
    await asyncio.to_thread(
        write_event,
        "RESOURCE_ACCESS",
        **audit_common,
        result="ALLOW",
        latency_ms=(time.monotonic() - started) * 1000.0,
    )
    await asyncio.gather(pipe(client_reader, target_writer), pipe(target_reader, client_writer))


async def handle_health(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    devices = list_devices()
    groups = list_groups()
    resources_all = list_resources()
    active_devices = {d["vpn_ip"]: d for d in devices if device_is_active(d)}
    if peer_ip not in active_devices:
        writer.close()
        await writer.wait_closed()
        return

    try:
        request = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=2)
    except Exception:
        writer.close()
        await writer.wait_closed()
        return

    first = request.split(b"\r\n", 1)[0].decode("ascii", "replace")
    parts = first.split()
    request_target = parts[1] if len(parts) >= 2 else "/"
    path = request_target.split("?", 1)[0]
    content_type = "application/json"
    if path not in ("/", "/healthz", "/v1/status", "/v1/resources", "/v1/catalog", "/hub"):
        body = json.dumps({"ok": False, "error": "not_found"}).encode()
        status = "404 Not Found"
    else:
        device = active_devices[peer_ip]
        effective = effective_resources_for_device(device, resources_all, groups)
        health_results = await asyncio.to_thread(check_resources, effective)
        resources = resources_for_launcher(
            device,
            resources=resources_all,
            groups=groups,
            health_results=health_results,
        )
        memberships = [
            g["name"] for g in groups
            if g.get("enabled", True) and device["device_id"] in g.get("device_ids", [])
        ]
        if path == "/hub":
            body = render_hub(device, resources).encode()
            content_type = "text/html; charset=utf-8"
        elif path == "/v1/resources":
            body = json.dumps(launcher_payload(device, resources)).encode()
        elif path == "/v1/catalog":
            try:
                from .multi_server import build_catalog
                catalog = await asyncio.to_thread(build_catalog)
                body = json.dumps(multi_server_catalog_payload(device, resources, catalog)).encode()
            except Exception as exc:
                body = json.dumps({
                    "ok": False,
                    "error": "multi_server_catalog_unavailable",
                    "detail": str(exc)[:200],
                }).encode()
                status = "503 Service Unavailable"
        else:
            body = json.dumps({
                "ok": True,
                "bridge": "GE360 Universal Bridge",
                "schema": "ge360-bridge-status/v1",
                "device": device["name"],
                "device_id": device["device_id"],
                "vpn_ip": peer_ip,
                "groups": memberships,
                "resources": resources,
                "services": [{"name": r["name"], "url": r["url"]} for r in resources],
                "launcher_url": f"http://{BIND_HOST}:{HEALTH_PORT}/hub",
            }).encode()
        if path != "/v1/catalog" or not body.startswith(b'{"ok": false'):
            status = "200 OK"

    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Type: {content_type}\r\nContent-Length: {len(body)}\r\nCache-Control: no-store\r\nX-Content-Type-Options: nosniff\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    await writer.drain()
    writer.close()
    await writer.wait_closed()


def _wireguard_connected(devices: list[dict[str, Any]]) -> dict[str, bool]:
    try:
        proc = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return {d["device_id"]: False for d in devices}
    latest_by_key: dict[str, int] = {}
    if proc.returncode == 0:
        lines = [x for x in proc.stdout.splitlines() if x.strip()]
        for raw in lines[1:]:
            parts = raw.split("\t")
            if len(parts) >= 5:
                try:
                    latest_by_key[parts[0]] = int(parts[4])
                except ValueError:
                    latest_by_key[parts[0]] = 0
    now = int(time.time())
    return {
        d["device_id"]: bool(
            latest_by_key.get(d.get("public_key",""), 0)
            and now - latest_by_key.get(d.get("public_key",""), 0) <= 180
            and device_is_active(d)
        )
        for d in devices
    }


async def audit_monitor(stop: asyncio.Event) -> None:
    previous_devices: dict[str, bool] | None = None
    previous_resources: dict[str, bool] | None = None
    while not stop.is_set():
        devices = list_devices()
        current_devices = await asyncio.to_thread(_wireguard_connected, devices)
        resources = list_resources()
        health = await asyncio.to_thread(check_resources, resources)
        current_resources = {h["name"]: h.get("state") == "ONLINE" for h in health}
        health_by_name = {h["name"]: h for h in health}

        if previous_devices is not None:
            by_id = {d["device_id"]: d for d in devices}
            for device_id, connected in current_devices.items():
                before = previous_devices.get(device_id, False)
                if connected == before:
                    continue
                d = by_id.get(device_id, {})
                await asyncio.to_thread(
                    write_event,
                    "DEVICE_CONNECTED" if connected else "DEVICE_DISCONNECTED",
                    device_id=device_id,
                    device_name=d.get("name"),
                    action="wireguard_handshake",
                    result="CONNECTED" if connected else "DISCONNECTED",
                    ip=d.get("vpn_ip"),
                )

        if previous_resources is not None:
            for name, online in current_resources.items():
                if name not in previous_resources or previous_resources[name] == online:
                    continue
                h = health_by_name.get(name, {})
                await asyncio.to_thread(
                    write_event,
                    "RESOURCE_ONLINE" if online else "RESOURCE_OFFLINE",
                    resource=name,
                    action="health_transition",
                    result=h.get("state"),
                    latency_ms=h.get("latency_ms"),
                    error=h.get("error"),
                )

        previous_devices = current_devices
        previous_resources = current_resources
        try:
            await asyncio.wait_for(stop.wait(), timeout=15.0)
        except asyncio.TimeoutError:
            pass


async def metrics_monitor(stop: asyncio.Event) -> None:
    while not stop.is_set():
        await asyncio.to_thread(collect_snapshot)
        try:
            await asyncio.wait_for(stop.wait(), timeout=60.0)
        except asyncio.TimeoutError:
            pass


async def main() -> None:
    init_db()
    init_metrics_db()
    devices = list_devices()
    groups = list_groups()
    servers: list[asyncio.AbstractServer] = []

    health = await asyncio.start_server(handle_health, BIND_HOST, HEALTH_PORT)
    servers.append(health)

    for resource in list_resources():
        if not resource.get("enabled", True):
            continue
        allowed = allowed_ips_for_resource(resource, devices, groups)
        server = await asyncio.start_server(
            lambda r, w, s=resource, a=allowed: handle_client(r, w, s, a),
            BIND_HOST,
            int(resource["listen_port"]),
        )
        servers.append(server)

    stop = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            loop.add_signal_handler(sig, stop.set)
        except NotImplementedError:
            pass

    tasks = [asyncio.create_task(s.serve_forever()) for s in servers]
    monitor_task = asyncio.create_task(audit_monitor(stop))
    metrics_task = asyncio.create_task(metrics_monitor(stop))
    await stop.wait()
    for s in servers:
        s.close()
    await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
    monitor_task.cancel()
    metrics_task.cancel()
    await asyncio.gather(monitor_task, metrics_task, return_exceptions=True)
    for t in tasks:
        t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
