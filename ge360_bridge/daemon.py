from __future__ import annotations

import asyncio
import json
import signal
from typing import Any

from .core import (
    allowed_ips_for_resource,
    device_is_active,
    effective_resources_for_device,
    list_devices,
    list_groups,
    list_resources,
)

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
    peer = client_writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    if peer_ip not in allowed:
        client_writer.close()
        await client_writer.wait_closed()
        return
    try:
        target_reader, target_writer = await asyncio.open_connection(resource["target_host"], int(resource["target_port"]))
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return
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
    path = parts[1] if len(parts) >= 2 else "/"
    if path not in ("/", "/healthz", "/v1/status"):
        body = json.dumps({"ok": False, "error": "not_found"}).encode()
        status = "404 Not Found"
    else:
        device = active_devices[peer_ip]
        resources = [
            {
                "name": r["name"],
                "icon": r.get("icon","server"),
                "description": r.get("description",""),
                "protocol": r.get("protocol","tcp"),
                "bridge_port": r["bridge_port"],
                "url": f"http://{BIND_HOST}:{r['bridge_port']}",
            }
            for r in effective_resources_for_device(device, resources_all, groups)
        ]
        memberships = [
            g["name"] for g in groups
            if g.get("enabled", True) and device["device_id"] in g.get("device_ids", [])
        ]
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
        }).encode()
        status = "200 OK"

    writer.write(
        f"HTTP/1.1 {status}\r\nContent-Type: application/json\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode()
        + body
    )
    await writer.drain()
    writer.close()
    await writer.wait_closed()


async def main() -> None:
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
    await stop.wait()
    for s in servers:
        s.close()
    await asyncio.gather(*(s.wait_closed() for s in servers), return_exceptions=True)
    for t in tasks:
        t.cancel()


if __name__ == "__main__":
    asyncio.run(main())
