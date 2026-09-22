from __future__ import annotations

import asyncio
import json
import signal
from typing import Any

from .core import allowed_ips_for_service, list_devices, list_services

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


async def handle_client(client_reader: asyncio.StreamReader, client_writer: asyncio.StreamWriter, service: dict[str, Any], allowed: set[str]) -> None:
    peer = client_writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    if peer_ip not in allowed:
        client_writer.close()
        await client_writer.wait_closed()
        return
    try:
        target_reader, target_writer = await asyncio.open_connection(service["target_host"], int(service["target_port"]))
    except OSError:
        client_writer.close()
        await client_writer.wait_closed()
        return
    await asyncio.gather(pipe(client_reader, target_writer), pipe(target_reader, client_writer))


async def handle_health(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
    peer = writer.get_extra_info("peername")
    peer_ip = peer[0] if peer else ""
    enabled_devices = {d["vpn_ip"]: d["name"] for d in list_devices() if d.get("enabled", True)}
    if peer_ip not in enabled_devices:
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
        device_name = enabled_devices[peer_ip]
        services = []
        for s in list_services():
            if s.get("enabled", True) and device_name in s.get("allowed_devices", []):
                services.append({"name": s["name"], "url": f"http://{BIND_HOST}:{s['listen_port']}"})
        body = json.dumps({
            "ok": True,
            "bridge": "GE360 Universal Bridge",
            "schema": "ge360-bridge-status/v1",
            "device": device_name,
            "vpn_ip": peer_ip,
            "services": services,
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
    servers: list[asyncio.AbstractServer] = []

    health = await asyncio.start_server(handle_health, BIND_HOST, HEALTH_PORT)
    servers.append(health)

    for service in list_services():
        if not service.get("enabled", True):
            continue
        allowed = allowed_ips_for_service(service, devices)
        server = await asyncio.start_server(
            lambda r, w, s=service, a=allowed: handle_client(r, w, s, a),
            BIND_HOST,
            int(service["listen_port"]),
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
