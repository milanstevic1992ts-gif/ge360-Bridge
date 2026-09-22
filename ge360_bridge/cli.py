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
    grant_device,
    list_devices,
    list_services,
    next_device_ip,
    random_token,
    register_service,
    remove_service,
    revoke_device,
    save_devices,
    wg_keypair,
)

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
    if env.get("PUBLIC_ENDPOINT"):
        return env["PUBLIC_ENDPOINT"]
    return f"CHANGE_ME:{env.get('WG_PORT', str(DEFAULT_WG_PORT))}"


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
        if not d.get("enabled", True):
            continue
        lines.extend([
            "",
            "[Peer]",
            f"# GE360 device: {d['name']}",
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
    dns = env.get("CLIENT_DNS", "")
    dns_line = f"DNS = {dns}\n" if dns else ""
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
    services = [
        {"name": s["name"], "url": f"http://{DEFAULT_SERVER_VPN_IP}:{s['listen_port']}"}
        for s in list_services()
        if s.get("enabled", True) and name in s.get("allowed_devices", [])
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


def cmd_device_add(args: argparse.Namespace) -> None:
    must_root()
    if any(d["name"] == args.name for d in list_devices()):
        raise BridgeError(f"Dispositivo già presente: {args.name}")
    private, public, psk = wg_keypair()
    vpn_ip = next_device_ip()
    token = random_token()
    items = list_devices()
    device = Device(args.name, vpn_ip, public, psk, token, True)
    items.append(device.__dict__)
    save_devices(items)
    render_wg_config()
    conf = make_client_conf(private, psk, vpn_ip)
    payload = bundle_for(args.name, conf, token)
    print(f"Dispositivo: {args.name}\nVPN IP: {vpn_ip}\n")
    if args.raw:
        print(payload)
    else:
        qr_print(payload)
        print("\nIl QR contiene una chiave privata: scansionalo in un luogo sicuro e non pubblicarlo.")


def cmd_device_revoke(args: argparse.Namespace) -> None:
    must_root()
    device = revoke_device(args.name)
    if not device:
        raise BridgeError("Dispositivo non trovato.")
    render_wg_config()
    reload_runtime()
    print(f"Revocato: {args.name}")


def cmd_service_add(args: argparse.Namespace) -> None:
    must_root()
    allowed = [x for x in (args.allow or "").split(",") if x]
    s = register_service(args.name, args.port, args.target_host, args.target_port, allowed)
    reload_runtime()
    print(json.dumps(s.__dict__, indent=2))


def cmd_service_remove(args: argparse.Namespace) -> None:
    must_root()
    if not remove_service(args.name):
        raise BridgeError("Servizio non trovato.")
    reload_runtime()
    print(f"Rimosso: {args.name}")


def cmd_service_acl(args: argparse.Namespace, grant: bool) -> None:
    must_root()
    s = grant_device(args.service, args.device, grant)
    reload_runtime()
    print(json.dumps(s, indent=2))


def cmd_list(_: argparse.Namespace) -> None:
    safe_devices = []
    for d in list_devices():
        safe_devices.append({k: v for k, v in d.items() if k not in ("preshared_key", "token")})
    print(json.dumps({"devices": safe_devices, "services": list_services()}, indent=2))


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, port), timeout=0.8):
            return True
    except OSError:
        return False


def cmd_status(_: argparse.Namespace) -> None:
    env = load_env()
    status = {
        "wireguard_config": WG_CONF.exists(),
        "services_file": SERVICES_FILE.exists(),
        "endpoint": endpoint(),
        "health_url": f"http://{DEFAULT_SERVER_VPN_IP}:{HEALTH_PORT}/v1/status",
        "services": [],
    }
    for s in list_services():
        status["services"].append({
            "name": s["name"],
            "target": f"{s['target_host']}:{s['target_port']}",
            "target_reachable": port_open(s["target_host"], int(s["target_port"])),
            "bridge_port": s["listen_port"],
            "allowed_devices": s.get("allowed_devices", []),
        })
    status["wg_port"] = int(env.get("WG_PORT", DEFAULT_WG_PORT))
    print(json.dumps(status, indent=2))


def parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="ge360-bridge", description="GE360 Universal Bridge")
    sub = p.add_subparsers(dest="cmd", required=True)

    d = sub.add_parser("device-add")
    d.add_argument("name")
    d.add_argument("--raw", action="store_true", help="Stampa JSON invece del QR")
    d.set_defaults(func=cmd_device_add)

    d = sub.add_parser("device-revoke")
    d.add_argument("name")
    d.set_defaults(func=cmd_device_revoke)

    s = sub.add_parser("service-add")
    s.add_argument("name")
    s.add_argument("--port", type=int, required=True, help="Porta esposta solo su WireGuard")
    s.add_argument("--target-host", default="127.0.0.1")
    s.add_argument("--target-port", type=int, required=True)
    s.add_argument("--allow", default="", help="Nomi dispositivi separati da virgola")
    s.set_defaults(func=cmd_service_add)

    s = sub.add_parser("service-remove")
    s.add_argument("name")
    s.set_defaults(func=cmd_service_remove)

    g = sub.add_parser("service-grant")
    g.add_argument("service")
    g.add_argument("device")
    g.set_defaults(func=lambda a: cmd_service_acl(a, True))

    g = sub.add_parser("service-revoke")
    g.add_argument("service")
    g.add_argument("device")
    g.set_defaults(func=lambda a: cmd_service_acl(a, False))

    l = sub.add_parser("list")
    l.set_defaults(func=cmd_list)

    st = sub.add_parser("status")
    st.set_defaults(func=cmd_status)
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
