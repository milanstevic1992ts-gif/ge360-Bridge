from __future__ import annotations

import argparse
import base64
import json
import os
import socket
import subprocess
import sys
from pathlib import Path

from .core import (
    BRIDGE_ENV,
    SERVICES_FILE,
    WG_CONF,
    BridgeError,
    Device,
    create_group,
    device_is_active,
    effective_services_for_device,
    find_device,
    list_devices,
    list_groups,
    list_resources,
    list_services,
    new_device_id,
    next_device_ip,
    normalize_tags,
    random_token,
    register_resource,
    register_service,
    remove_group,
    remove_resource,
    remove_service,
    rename_device,
    revoke_device,
    save_devices,
    set_device_access_override,
    set_device_enabled,
    set_group_device,
    set_group_enabled,
    set_group_service,
    update_device_metadata,
    update_resource,
    utc_now_iso,
    validate_device_type,
    validate_expiry,
    wg_keypair,
)
from .pairing import create_pairing_payload, list_enrollments
from .health import check_resource, check_resources, health_summary
from .diagnostics import diagnose_resource
from .doctor import connection_doctor
from .audit import list_events
from .metrics import collect_snapshot, query_series
from .discovery import discover_backends, import_discovered_backend
from .self_healing import run_self_heal, self_heal_status
from .backup import create_backup, list_backups, restore_backup, verify_backup
from .update_engine import apply_update, download_update, preflight_update, run_update, update_status, verify_update
from .nat_discovery import discover_nat
from .p2p import p2p_status
from .relay_client import local_relay_status, monitor_forever, monitor_once, relay_config, relay_remote_status, sync_relay_devices

DEFAULT_WG_PORT = 51820
DEFAULT_SERVER_VPN_IP = "10.88.0.1"
HEALTH_PORT = 8788


def must_root() -> None:
    if os.geteuid() != 0:
        raise BridgeError("Questo comando richiede root (usa sudo).")


def sh(cmd: list[str], check: bool = True) -> subprocess.CompletedProcess[str]:
    return subprocess.run(cmd, text=True, capture_output=True, check=check)


def load_env() -> dict[str, str]:
    out: dict[str, str] = {}
    if not BRIDGE_ENV.exists():
        return out
    for raw in BRIDGE_ENV.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        k, v = line.split("=", 1)
        out[k.strip()] = v.strip().strip('"').strip("'")
    return out


def endpoint() -> str:
    env = load_env()
    return env.get("PUBLIC_ENDPOINT") or f"CHANGE_ME:{env.get('WG_PORT', str(DEFAULT_WG_PORT))}"


def server_public_key() -> str:
    p = Path("/etc/ge360-bridge/server.pub")
    if not p.exists():
        raise BridgeError("Chiave pubblica server mancante. Esegui install.sh.")
    return p.read_text(encoding="utf-8").strip()


def render_wg_config() -> None:
    env = load_env()
    key_path = Path("/etc/ge360-bridge/server.key")
    if not key_path.exists():
        raise BridgeError("Chiave server mancante. Esegui install.sh.")
    lines = [
        "[Interface]",
        f"Address = {env.get('WG_ADDRESS', '10.88.0.1/24')}",
        f"ListenPort = {env.get('WG_PORT', str(DEFAULT_WG_PORT))}",
        f"PrivateKey = {key_path.read_text(encoding='utf-8').strip()}",
        "SaveConfig = false",
    ]
    for d in list_devices():
        if not device_is_active(d):
            continue
        lines.extend([
            "",
            "[Peer]",
            f"# GE360 device: {d['name']} ({d['device_id']})",
            f"PublicKey = {d['public_key']}",
            f"PresharedKey = {d['preshared_key']}",
            f"AllowedIPs = {d['vpn_ip']}/32",
        ])
    WG_CONF.parent.mkdir(parents=True, exist_ok=True)
    WG_CONF.write_text("\n".join(lines) + "\n", encoding="utf-8")
    os.chmod(WG_CONF, 0o600)
    sh(["systemctl", "restart", "wg-quick@wg0"], check=False)


def make_client_conf(private_key: str, psk: str, vpn_ip: str) -> str:
    env = load_env()
    dns_line = f"DNS = {env['CLIENT_DNS']}\n" if env.get("CLIENT_DNS") else ""
    return (
        "[Interface]\n"
        f"PrivateKey = {private_key}\n"
        f"Address = {vpn_ip}/32\n"
        f"{dns_line}"
        "\n[Peer]\n"
        f"PublicKey = {server_public_key()}\n"
        f"PresharedKey = {psk}\n"
        f"Endpoint = {endpoint()}\n"
        f"AllowedIPs = {DEFAULT_SERVER_VPN_IP}/32\n"
        "PersistentKeepalive = 25\n"
    )


def bundle_for(name: str, conf: str, token: str) -> str:
    device = find_device(name)
    services = []
    if device:
        services = [
            {"name": s["name"], "url": f"http://{DEFAULT_SERVER_VPN_IP}:{s['listen_port']}"}
            for s in effective_services_for_device(device)
        ]
    payload = {
        "schema": "ge360-bridge-pairing/v1",
        "device": name,
        "wireguard_config_b64": base64.b64encode(conf.encode()).decode(),
        "bridge_ip": DEFAULT_SERVER_VPN_IP,
        "health_url": f"http://{DEFAULT_SERVER_VPN_IP}:{HEALTH_PORT}/v1/status",
        "services": services,
        "device_token": token,
    }
    return json.dumps(payload, separators=(",", ":"))


def which(name: str) -> str | None:
    for p in os.environ.get("PATH", "").split(os.pathsep):
        candidate = Path(p) / name
        if candidate.is_file() and os.access(candidate, os.X_OK):
            return str(candidate)
    return None


def qr_print(payload: str) -> None:
    if not which("qrencode"):
        print(payload)
        return
    subprocess.run(["qrencode", "-t", "ANSIUTF8"], input=payload, text=True, check=False)


def reload_runtime() -> None:
    sh(["systemctl", "restart", "ge360-bridge.service"], check=False)
    sh(["/usr/local/sbin/ge360-bridge-firewall"], check=False)


def parse_tags_csv(value: str) -> list[str]:
    return normalize_tags([x for x in (value or "").split(",") if x.strip()])


def cmd_device_add(args: argparse.Namespace) -> None:
    must_root()
    payload = create_pairing_payload(
        name=args.name,
        device_type=args.type,
        owner=args.owner or "",
        expires_at=args.expires,
        notes=args.notes or "",
        tags=parse_tags_csv(args.tags),
        group_names=[x.strip() for x in (args.groups or "").split(",") if x.strip()],
        ttl_seconds=args.ttl,
    )
    raw = json.dumps(payload, separators=(",", ":"))
    print(f"Pairing v2 creato per: {args.name}")
    print(f"Enrollment ID: {payload['enrollment_id']}")
    print(f"Scadenza token: {payload['expires_at']}")
    print(f"Endpoint enrollment: {payload['enrollment_url']}\n")
    if args.raw:
        print(raw)
    else:
        qr_print(raw)
        print("\nLa private key WireGuard deve essere generata dal client e non viene mai inviata nel QR.")


def cmd_pairing_list(_: argparse.Namespace) -> None:
    print(json.dumps({"enrollments": list_enrollments()}, indent=2))


def cmd_device_state(args: argparse.Namespace, enabled: bool) -> None:
    must_root()
    device = set_device_enabled(args.device, enabled)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    render_wg_config()
    reload_runtime()
    print(f"{'Abilitato' if enabled else 'Disabilitato'}: {device['name']} ({device['device_id']})")


def cmd_device_rename(args: argparse.Namespace) -> None:
    must_root()
    device = rename_device(args.device, args.new_name)
    render_wg_config()
    reload_runtime()
    print(f"Rinominato: {device['name']} ({device['device_id']})")


def cmd_device_update(args: argparse.Namespace) -> None:
    must_root()
    current = find_device(args.device)
    if not current:
        raise BridgeError("Dispositivo non trovato.")
    expires = current.get("expires_at")
    if args.clear_expiry:
        expires = None
    elif args.expires is not None:
        expires = args.expires
    tags = current.get("tags", []) if args.tags is None else parse_tags_csv(args.tags)
    device = update_device_metadata(
        args.device,
        device_type=args.type if args.type is not None else current.get("device_type", "unknown"),
        owner=args.owner if args.owner is not None else current.get("owner", ""),
        expires_at=expires,
        notes=args.notes if args.notes is not None else current.get("notes", ""),
        tags=tags,
    )
    render_wg_config()
    reload_runtime()
    print(json.dumps({k: v for k, v in device.items() if k not in ("preshared_key", "token", "public_key")}, indent=2))


def cmd_device_show(args: argparse.Namespace) -> None:
    device = find_device(args.device)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    safe = {k: v for k, v in device.items() if k not in ("preshared_key", "token")}
    safe["groups"] = [g["name"] for g in list_groups() if device["device_id"] in g.get("device_ids", [])]
    safe["effective_services"] = [s["name"] for s in effective_services_for_device(device)]
    print(json.dumps(safe, indent=2))


def cmd_device_sync(_: argparse.Namespace) -> None:
    must_root()
    render_wg_config()
    reload_runtime()
    print("Device Registry sincronizzato con WireGuard.")


def cmd_group_create(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(create_group(args.name, args.description or ""), indent=2))


def cmd_group_remove(args: argparse.Namespace) -> None:
    must_root()
    if not remove_group(args.name):
        raise BridgeError("Gruppo non trovato.")
    reload_runtime()
    print(f"Gruppo rimosso: {args.name}")


def cmd_group_state(args: argparse.Namespace, enabled: bool) -> None:
    must_root()
    group = set_group_enabled(args.name, enabled)
    reload_runtime()
    print(json.dumps(group, indent=2))


def cmd_group_device(args: argparse.Namespace, assigned: bool) -> None:
    must_root()
    group = set_group_device(args.group, args.device, assigned)
    reload_runtime()
    print(json.dumps(group, indent=2))


def cmd_group_service(args: argparse.Namespace, allowed: bool) -> None:
    must_root()
    group = set_group_service(args.group, args.service, allowed)
    reload_runtime()
    print(json.dumps(group, indent=2))


def cmd_service_override(args: argparse.Namespace, decision: str) -> None:
    must_root()
    service = set_device_access_override(args.service, args.device, decision)
    reload_runtime()
    print(json.dumps(service, indent=2))


def cmd_service_add(args: argparse.Namespace) -> None:
    must_root()
    allowed = [x for x in (args.allow or "").split(",") if x]
    service = register_service(args.name, args.port, args.target_host, args.target_port, allowed)
    reload_runtime()
    print(json.dumps(service.__dict__, indent=2))


def cmd_service_remove(args: argparse.Namespace) -> None:
    must_root()
    if not remove_service(args.name):
        raise BridgeError("Servizio non trovato.")
    reload_runtime()
    print(f"Rimosso: {args.name}")


def cmd_resource_add(args: argparse.Namespace) -> None:
    must_root()
    allowed = [x for x in (args.allow or "").split(",") if x]
    resource = register_resource(
        args.name,
        args.port,
        args.target_host,
        args.target_port,
        allowed,
        icon=args.icon,
        description=args.description,
        protocol=args.protocol,
        health_url=args.health_url,
        timeout_seconds=args.timeout,
        systemd_unit=args.systemd_unit,
        self_heal_enabled=args.self_heal == "true",
    )
    reload_runtime()
    print(json.dumps(resource.__dict__, indent=2))


def cmd_resource_update(args: argparse.Namespace) -> None:
    must_root()
    resource = update_resource(
        args.name,
        icon=args.icon,
        description=args.description,
        protocol=args.protocol,
        bridge_port=args.port,
        target_host=args.target_host,
        target_port=args.target_port,
        health_url=args.health_url,
        timeout_seconds=args.timeout,
        enabled=None if args.enabled is None else args.enabled == "true",
        systemd_unit=args.systemd_unit,
        self_heal_enabled=None if args.self_heal is None else args.self_heal == "true",
    )
    reload_runtime()
    print(json.dumps(resource, indent=2))


def cmd_resource_remove(args: argparse.Namespace) -> None:
    must_root()
    if not remove_resource(args.name):
        raise BridgeError("Resource non trovata.")
    reload_runtime()
    print(f"Resource rimossa: {args.name}")


def cmd_resource_list(_: argparse.Namespace) -> None:
    print(json.dumps({"resources": list_resources()}, indent=2))


def cmd_resource_discover(args: argparse.Namespace) -> None:
    report = discover_backends(
        ports=args.port or None,
        host=args.host,
        scheme=args.scheme,
        timeout=args.timeout,
    )
    print(json.dumps(report, indent=2))


def cmd_resource_import(args: argparse.Namespace) -> None:
    must_root()
    resource = import_discovered_backend(
        host=args.host,
        target_port=args.target_port,
        scheme=args.scheme,
        bridge_port=args.bridge_port,
        timeout=args.timeout,
    )
    reload_runtime()
    print(json.dumps(resource.__dict__, indent=2))


def cmd_self_heal_run(args: argparse.Namespace) -> None:
    must_root()
    report = run_self_heal(args.resource, dry_run=args.dry_run)
    print(json.dumps(report, indent=2))


def cmd_self_heal_status(_: argparse.Namespace) -> None:
    print(json.dumps(self_heal_status(), indent=2))


def cmd_backup_create(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(create_backup(scheduled=args.scheduled, keep=args.keep), indent=2))


def cmd_backup_list(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps({"backups": list_backups()}, indent=2))


def cmd_backup_verify(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(verify_backup(args.backup), indent=2))


def cmd_backup_restore(args: argparse.Namespace) -> None:
    must_root()
    report = restore_backup(args.backup, apply=args.apply, keep=args.keep)
    if args.apply:
        render_wg_config()
        reload_runtime()
        sh(["systemctl", "restart", "ge360-bridge-dashboard.service"], check=False)
        sh(["systemctl", "restart", "ge360-bridge-enrollment.service"], check=False)
    print(json.dumps(report, indent=2))


def cmd_update_download(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(download_update(args.url, args.sha256), indent=2))


def cmd_update_verify(args: argparse.Namespace) -> None:
    must_root()
    report = preflight_update(args.package, require_newer=not args.allow_not_newer)
    print(json.dumps(report, indent=2))


def cmd_update_apply(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(apply_update(args.package, config_backup_keep=args.keep), indent=2))


def cmd_update_run(args: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(run_update(args.url, args.sha256, config_backup_keep=args.keep), indent=2))


def cmd_update_status(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(update_status(), indent=2))


def cmd_nat_discover(args: argparse.Namespace) -> None:
    report = discover_nat(args.server or None, timeout=args.timeout, use_cache=False)
    print(json.dumps(report, indent=2))


def cmd_p2p_status(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(p2p_status(), indent=2))


def cmd_relay_status(args: argparse.Namespace) -> None:
    result = local_relay_status()
    if args.remote and relay_config().get("configured"):
        try:
            result["remote"] = relay_remote_status()
        except BridgeError as exc:
            result["remote_error"] = str(exc)
    print(json.dumps(result, indent=2))


def cmd_relay_sync(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(sync_relay_devices(), indent=2))


def cmd_relay_run_once(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(monitor_once(), indent=2))


def cmd_relay_monitor(_: argparse.Namespace) -> None:
    must_root()
    monitor_forever()


def cmd_health_check(args: argparse.Namespace) -> None:
    resources = list_resources()
    if args.resource:
        resources = [r for r in resources if r.get("name") == args.resource]
        if not resources:
            raise BridgeError(f"Resource non trovata: {args.resource}")
    results = check_resources(resources, use_cache=not args.no_cache)
    print(json.dumps({"summary": health_summary(results), "resources": results}, indent=2))


def cmd_diagnose_resource(args: argparse.Namespace) -> None:
    resource = next((r for r in list_resources() if r.get("name") == args.resource), None)
    if not resource:
        raise BridgeError(f"Resource non trovata: {args.resource}")
    report = diagnose_resource(
        resource,
        api_path=args.api_path,
        pdf_path=args.pdf_path,
        include_traceroute=not args.no_traceroute,
    )
    print(json.dumps(report, indent=2))


def cmd_connection_doctor(args: argparse.Namespace) -> None:
    resource = next((r for r in list_resources() if r.get("name") == args.resource), None)
    if not resource:
        raise BridgeError(f"Resource non trovata: {args.resource}")
    diagnostics = diagnose_resource(
        resource,
        api_path=args.api_path,
        pdf_path=args.pdf_path,
        include_traceroute=not args.no_traceroute,
    )
    health = check_resource(resource, use_cache=False)
    result = connection_doctor(
        resource,
        diagnostics,
        health,
        device_identifier=args.device,
    )
    result["diagnostics"] = diagnostics
    result["health"] = health
    print(json.dumps(result, indent=2))


def cmd_audit_list(args: argparse.Namespace) -> None:
    print(json.dumps({
        "events": list_events(
            limit=args.limit,
            event=args.event,
            device=args.device,
            resource=args.resource,
        )
    }, indent=2))


def cmd_metrics_show(args: argparse.Namespace) -> None:
    try:
        data = query_series(args.window, resource=args.resource, device=args.device)
    except ValueError as exc:
        raise BridgeError(str(exc)) from exc
    print(json.dumps(data, indent=2))


def cmd_metrics_sample(_: argparse.Namespace) -> None:
    must_root()
    print(json.dumps(collect_snapshot(), indent=2))


def cmd_list(_: argparse.Namespace) -> None:
    safe_devices = [{k: v for k, v in d.items() if k not in ("preshared_key", "token")} for d in list_devices()]
    print(json.dumps({"devices": safe_devices, "groups": list_groups(), "resources": list_resources(), "services": list_services()}, indent=2))


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False


def cmd_status(_: argparse.Namespace) -> None:
    env = load_env()
    resources = list_resources()
    health_results = check_resources(resources)
    health_by_name = {h["name"]: h for h in health_results}
    status = {
        "wireguard_config": WG_CONF.exists(),
        "services_file": SERVICES_FILE.exists(),
        "resource_registry": True,
        "health_engine": True,
        "endpoint": endpoint(),
        "health_url": f"http://{DEFAULT_SERVER_VPN_IP}:{HEALTH_PORT}/v1/status",
        "groups": len(list_groups()),
        "health_summary": health_summary(health_results),
        "resources": [],
        "services": [],
    }
    for resource in resources:
        item = {
            "name": resource["name"],
            "protocol": resource.get("protocol","tcp"),
            "target": f"{resource['target_host']}:{resource['target_port']}",
            "bridge_port": resource["bridge_port"],
            "allowed_devices": resource.get("allowed_devices", []),
            "denied_devices": resource.get("denied_devices", []),
            "health": health_by_name.get(resource["name"]),
        }
        status["resources"].append(item)
        status["services"].append(item)
    status["wg_port"] = int(env.get("WG_PORT", DEFAULT_WG_PORT))
    print(json.dumps(status, indent=2))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ge360-bridge", description="GE360 Universal Bridge")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("device-add", help="Crea un pairing sicuro v2; il device nasce dopo l'enrollment del client")
    d.add_argument("name")
    d.add_argument("--type", default="unknown", choices=["android", "linux", "windows", "server", "tablet", "unknown"])
    d.add_argument("--owner", default="")
    d.add_argument("--expires", default=None, help="Scadenza del device YYYY-MM-DD")
    d.add_argument("--notes", default="")
    d.add_argument("--tags", default="")
    d.add_argument("--groups", default="", help="Gruppi iniziali separati da virgola")
    d.add_argument("--ttl", type=int, default=600, help="TTL token pairing in secondi (60..86400)")
    d.add_argument("--raw", action="store_true")
    d.set_defaults(func=cmd_device_add)

    d = sub.add_parser("pairing-create")
    d.add_argument("name")
    d.add_argument("--type", default="unknown", choices=["android", "linux", "windows", "server", "tablet", "unknown"])
    d.add_argument("--owner", default="")
    d.add_argument("--expires", default=None)
    d.add_argument("--notes", default="")
    d.add_argument("--tags", default="")
    d.add_argument("--groups", default="")
    d.add_argument("--ttl", type=int, default=600)
    d.add_argument("--raw", action="store_true")
    d.set_defaults(func=cmd_device_add)
    d = sub.add_parser("pairing-list"); d.set_defaults(func=cmd_pairing_list)

    d = sub.add_parser("device-show"); d.add_argument("device"); d.set_defaults(func=cmd_device_show)
    d = sub.add_parser("device-rename"); d.add_argument("device"); d.add_argument("new_name"); d.set_defaults(func=cmd_device_rename)
    d = sub.add_parser("device-update")
    d.add_argument("device"); d.add_argument("--type", choices=["android","linux","windows","server","tablet","unknown"])
    d.add_argument("--owner"); d.add_argument("--expires"); d.add_argument("--clear-expiry", action="store_true"); d.add_argument("--notes"); d.add_argument("--tags")
    d.set_defaults(func=cmd_device_update)
    d = sub.add_parser("device-enable"); d.add_argument("device"); d.set_defaults(func=lambda a: cmd_device_state(a, True))
    d = sub.add_parser("device-disable"); d.add_argument("device"); d.set_defaults(func=lambda a: cmd_device_state(a, False))
    d = sub.add_parser("device-revoke"); d.add_argument("device"); d.set_defaults(func=lambda a: cmd_device_state(a, False))
    d = sub.add_parser("device-sync"); d.set_defaults(func=cmd_device_sync)

    g = sub.add_parser("group-create"); g.add_argument("name"); g.add_argument("--description", default=""); g.set_defaults(func=cmd_group_create)
    g = sub.add_parser("group-remove"); g.add_argument("name"); g.set_defaults(func=cmd_group_remove)
    g = sub.add_parser("group-enable"); g.add_argument("name"); g.set_defaults(func=lambda a: cmd_group_state(a, True))
    g = sub.add_parser("group-disable"); g.add_argument("name"); g.set_defaults(func=lambda a: cmd_group_state(a, False))
    g = sub.add_parser("group-device-add"); g.add_argument("group"); g.add_argument("device"); g.set_defaults(func=lambda a: cmd_group_device(a, True))
    g = sub.add_parser("group-device-remove"); g.add_argument("group"); g.add_argument("device"); g.set_defaults(func=lambda a: cmd_group_device(a, False))
    g = sub.add_parser("group-service-grant"); g.add_argument("group"); g.add_argument("service"); g.set_defaults(func=lambda a: cmd_group_service(a, True))
    g = sub.add_parser("group-service-revoke"); g.add_argument("group"); g.add_argument("service"); g.set_defaults(func=lambda a: cmd_group_service(a, False))

    s = sub.add_parser("service-add")
    s.add_argument("name"); s.add_argument("--port", type=int, required=True); s.add_argument("--target-host", default="127.0.0.1"); s.add_argument("--target-port", type=int, required=True); s.add_argument("--allow", default="")
    s.set_defaults(func=cmd_service_add)
    s = sub.add_parser("service-remove"); s.add_argument("name"); s.set_defaults(func=cmd_service_remove)
    s = sub.add_parser("service-grant"); s.add_argument("service"); s.add_argument("device"); s.set_defaults(func=lambda a: cmd_service_override(a, "allow"))
    s = sub.add_parser("service-revoke"); s.add_argument("service"); s.add_argument("device"); s.set_defaults(func=lambda a: cmd_service_override(a, "deny"))
    s = sub.add_parser("service-inherit"); s.add_argument("service"); s.add_argument("device"); s.set_defaults(func=lambda a: cmd_service_override(a, "inherit"))

    r = sub.add_parser("resource-add")
    r.add_argument("name")
    r.add_argument("--port", type=int, required=True, help="Bridge port")
    r.add_argument("--target-host", default="127.0.0.1")
    r.add_argument("--target-port", type=int, required=True)
    r.add_argument("--protocol", default="tcp", choices=["tcp","http","https"])
    r.add_argument("--icon", default="server")
    r.add_argument("--description", default="")
    r.add_argument("--health-url", default="")
    r.add_argument("--timeout", type=float, default=2.0)
    r.add_argument("--systemd-unit", default="")
    r.add_argument("--self-heal", choices=["true","false"], default="false")
    r.add_argument("--allow", default="")
    r.set_defaults(func=cmd_resource_add)

    r = sub.add_parser("resource-update")
    r.add_argument("name")
    r.add_argument("--port", type=int)
    r.add_argument("--target-host")
    r.add_argument("--target-port", type=int)
    r.add_argument("--protocol", choices=["tcp","http","https"])
    r.add_argument("--icon")
    r.add_argument("--description")
    r.add_argument("--health-url")
    r.add_argument("--timeout", type=float)
    r.add_argument("--enabled", choices=["true","false"])
    r.add_argument("--systemd-unit")
    r.add_argument("--self-heal", choices=["true","false"])
    r.set_defaults(func=cmd_resource_update)

    r = sub.add_parser("resource-remove"); r.add_argument("name"); r.set_defaults(func=cmd_resource_remove)
    r = sub.add_parser("resource-list"); r.set_defaults(func=cmd_resource_list)

    r = sub.add_parser("resource-discover", help="Rileva backend GE360 locali tramite /.well-known/ge360")
    r.add_argument("--port", type=int, action="append", default=[], help="Porta loopback da verificare; ripetibile")
    r.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1","localhost","::1"])
    r.add_argument("--scheme", default="http", choices=["http","https"])
    r.add_argument("--timeout", type=float, default=0.6)
    r.set_defaults(func=cmd_resource_discover)

    r = sub.add_parser("resource-import", help="Importa una proposta discovery nel Resource Registry")
    r.add_argument("target_port", type=int)
    r.add_argument("--bridge-port", type=int)
    r.add_argument("--host", default="127.0.0.1", choices=["127.0.0.1","localhost","::1"])
    r.add_argument("--scheme", default="http", choices=["http","https"])
    r.add_argument("--timeout", type=float, default=1.0)
    r.set_defaults(func=cmd_resource_import)

    sh = sub.add_parser("self-heal-run", help="Esegue un ciclo self-healing controllato")
    sh.add_argument("resource", nargs="?", help="Resource opzionale; senza nome controlla tutte")
    sh.add_argument("--dry-run", action="store_true", help="Mostra cosa verrebbe riavviato senza eseguire restart")
    sh.set_defaults(func=cmd_self_heal_run)

    sh = sub.add_parser("self-heal-status", help="Mostra configurazione e rate limit del self-healing")
    sh.set_defaults(func=cmd_self_heal_status)

    b = sub.add_parser("backup-create", help="Crea backup configurazione GE360 e applica retention")
    b.add_argument("--scheduled", action="store_true", help="Modalità timer: massimo un backup giornaliero")
    b.add_argument("--keep", type=int, default=10, help="Numero backup da conservare (default 10)")
    b.set_defaults(func=cmd_backup_create)

    b = sub.add_parser("backup-list", help="Elenca e verifica i backup configurazione")
    b.set_defaults(func=cmd_backup_list)

    b = sub.add_parser("backup-verify", help="Verifica manifest, checksum e contenuto di un backup")
    b.add_argument("backup")
    b.set_defaults(func=cmd_backup_verify)

    b = sub.add_parser("backup-restore", help="Verifica o ripristina un backup configurazione")
    b.add_argument("backup")
    b.add_argument("--apply", action="store_true", help="Applica realmente il restore; senza flag mostra solo il piano")
    b.add_argument("--keep", type=int, default=10, help="Retention usata per il safety backup pre-restore")
    b.set_defaults(func=cmd_backup_restore)

    u = sub.add_parser("update-download", help="Scarica un pacchetto update solo via HTTPS e verifica SHA-256")
    u.add_argument("url")
    u.add_argument("--sha256", required=True)
    u.set_defaults(func=cmd_update_download)

    u = sub.add_parser("update-verify", help="Verifica pacchetto e preflight senza installare")
    u.add_argument("package")
    u.add_argument("--allow-not-newer", action="store_true", help="Solo diagnostica: consente verifica di una versione non più recente")
    u.set_defaults(func=cmd_update_verify)

    u = sub.add_parser("update-apply", help="Installa un pacchetto locale verificato con rollback automatico")
    u.add_argument("package")
    u.add_argument("--keep", type=int, default=10, help="Retention backup configurazione pre-update")
    u.set_defaults(func=cmd_update_apply)

    u = sub.add_parser("update-run", help="Download HTTPS + verifica + backup + install + health + rollback")
    u.add_argument("url")
    u.add_argument("--sha256", required=True)
    u.add_argument("--keep", type=int, default=10)
    u.set_defaults(func=cmd_update_run)

    u = sub.add_parser("update-status", help="Mostra ultimo aggiornamento e snapshot rollback disponibili")
    u.set_defaults(func=cmd_update_status)

    n = sub.add_parser("nat-discover", help="Fase 18: STUN, endpoint pubblico, CGNAT e comportamento NAT")
    n.add_argument("--server", action="append", default=[], help="Server STUN host:port; ripetibile")
    n.add_argument("--timeout", type=float, default=1.2)
    n.set_defaults(func=cmd_nat_discover)

    p2p = sub.add_parser("p2p-status", help="Fase 19: stato NAT Traversal P2P e sessioni runtime")
    p2p.set_defaults(func=cmd_p2p_status)

    relay = sub.add_parser("relay-status", help="Fase 20: stato relay opzionale")
    relay.add_argument("--remote", action="store_true", help="Interroga anche il nodo relay configurato")
    relay.set_defaults(func=cmd_relay_status)

    relay = sub.add_parser("relay-sync", help="Sincronizza hash device verso il relay configurato")
    relay.set_defaults(func=cmd_relay_sync)

    relay = sub.add_parser("relay-run-once", help="Esegue un singolo ciclo monitor relay")
    relay.set_defaults(func=cmd_relay_run_once)

    relay = sub.add_parser("relay-monitor", help=argparse.SUPPRESS)
    relay.set_defaults(func=cmd_relay_monitor)

    h = sub.add_parser("health-check")
    h.add_argument("resource", nargs="?", help="Nome Resource; senza nome controlla tutte")
    h.add_argument("--no-cache", action="store_true")
    h.set_defaults(func=cmd_health_check)

    x = sub.add_parser("diagnose-resource", help="Diagnostica avanzata Fase 6 su una Resource")
    x.add_argument("resource")
    x.add_argument("--api-path", help="Percorso API locale della Resource; default health_url o /")
    x.add_argument("--pdf-path", help="Percorso PDF locale della Resource, es. /api/report/123.pdf")
    x.add_argument("--no-traceroute", action="store_true")
    x.set_defaults(func=cmd_diagnose_resource)

    x = sub.add_parser("doctor", help="Connection Doctor Fase 7")
    x.add_argument("resource")
    x.add_argument("--device", help="Nome o device_id opzionale per verificare VPN e ACL")
    x.add_argument("--api-path")
    x.add_argument("--pdf-path")
    x.add_argument("--no-traceroute", action="store_true")
    x.set_defaults(func=cmd_connection_doctor)

    a = sub.add_parser("audit-list", help="Audit Log Fase 8")
    a.add_argument("--limit", type=int, default=100)
    a.add_argument("--event")
    a.add_argument("--device")
    a.add_argument("--resource")
    a.set_defaults(func=cmd_audit_list)

    m = sub.add_parser("metrics", help="Metriche Fase 9")
    m.add_argument("--window", default="24h", choices=["1h","24h","7d","30d"])
    m.add_argument("--resource")
    m.add_argument("--device")
    m.set_defaults(func=cmd_metrics_show)
    m = sub.add_parser("metrics-sample", help="Forza un campione metriche")
    m.set_defaults(func=cmd_metrics_sample)

    l = sub.add_parser("list"); l.set_defaults(func=cmd_list)
    st = sub.add_parser("status"); st.set_defaults(func=cmd_status)
    return p


def main() -> None:
    try:
        args = parser().parse_args()
        args.func(args)
    except BridgeError as exc:
        print(f"[GE360 Bridge] ERRORE: {exc}", file=sys.stderr)
        raise SystemExit(2)


if __name__ == "__main__":
    main()
