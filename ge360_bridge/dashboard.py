from __future__ import annotations

import hmac
import html
import json
import os
import socket
import subprocess
import threading
import time
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from .cli import DEFAULT_SERVER_VPN_IP, bundle_for, endpoint, load_env, make_client_conf, reload_runtime, render_wg_config
from .core import (
    BridgeError, Device, grant_device, list_devices, list_services, next_device_ip,
    random_token, register_service, remove_service, revoke_device, save_devices,
    validate_name, wg_keypair,
)

PORT = 8789
STATE_DIR = Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge"))
TOKEN_FILE = STATE_DIR / "dashboard.token"
PAIRINGS_DIR = STATE_DIR / "pairings"
PAIRING_TTL = 1800


def port_open(host: str, port: int) -> bool:
    try:
        with socket.create_connection((host, int(port)), timeout=0.6):
            return True
    except OSError:
        return False


def parse_wg_dump(text: str) -> dict[str, dict]:
    lines = [x for x in text.splitlines() if x.strip()]
    if not lines:
        return {}
    now = int(time.time())
    peers = {}
    for raw in lines[1:]:
        p = raw.split("\t")
        if len(p) < 8:
            continue
        pub, _psk, peer_endpoint, allowed, handshake, rx, tx, keepalive = p[:8]
        try:
            hs = int(handshake)
        except ValueError:
            hs = 0
        age = None if hs <= 0 else max(0, now - hs)
        peers[pub] = {
            "endpoint": "" if peer_endpoint == "(none)" else peer_endpoint,
            "allowed_ips": allowed,
            "handshake_age_seconds": age,
            "online": age is not None and age <= 180,
            "rx_bytes": int(rx) if rx.isdigit() else 0,
            "tx_bytes": int(tx) if tx.isdigit() else 0,
            "keepalive": keepalive,
        }
    return peers


def wg_state() -> dict[str, dict]:
    try:
        p = subprocess.run(["wg", "show", "wg0", "dump"], text=True, capture_output=True, timeout=2, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return {}
    return parse_wg_dump(p.stdout) if p.returncode == 0 else {}


def human_age(value: int | None) -> str:
    if value is None:
        return "mai"
    if value < 60:
        return f"{value}s fa"
    if value < 3600:
        return f"{value // 60} min fa"
    if value < 86400:
        return f"{value // 3600} h fa"
    return f"{value // 86400} g fa"


def human_bytes(value: int) -> str:
    n = float(max(0, value))
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f} {unit}" if unit == "B" else f"{n:.1f} {unit}"
        n /= 1024
    return "0 B"


def status_data() -> dict:
    peers = wg_state()
    devices = []
    for d in list_devices():
        peer = peers.get(d.get("public_key", ""), {})
        devices.append({
            "name": d.get("name", ""),
            "vpn_ip": d.get("vpn_ip", ""),
            "enabled": bool(d.get("enabled", True)),
            "online": bool(peer.get("online", False)),
            "handshake_age_seconds": peer.get("handshake_age_seconds"),
            "endpoint": peer.get("endpoint", ""),
            "rx_bytes": peer.get("rx_bytes", 0),
            "tx_bytes": peer.get("tx_bytes", 0),
        })
    services = []
    for s in list_services():
        services.append({
            "name": s["name"],
            "enabled": bool(s.get("enabled", True)),
            "bridge_port": int(s["listen_port"]),
            "bridge_url": f"http://{DEFAULT_SERVER_VPN_IP}:{int(s['listen_port'])}",
            "target": f"{s['target_host']}:{s['target_port']}",
            "target_reachable": port_open(str(s["target_host"]), int(s["target_port"])),
            "allowed_devices": list(s.get("allowed_devices", [])),
        })
    env = load_env()
    return {
        "bridge": {
            "vpn_ip": DEFAULT_SERVER_VPN_IP,
            "wg_port": int(env.get("WG_PORT", "51820")),
            "public_endpoint": endpoint(),
            "dashboard_url": f"http://{DEFAULT_SERVER_VPN_IP}:{PORT}",
        },
        "devices": devices,
        "services": services,
        "counts": {
            "devices": len(devices),
            "online_devices": sum(1 for d in devices if d["enabled"] and d["online"]),
            "services": len(services),
            "healthy_services": sum(1 for s in services if s["enabled"] and s["target_reachable"]),
        },
        "generated_at": int(time.time()),
    }


def admin_token() -> str:
    try:
        return TOKEN_FILE.read_text(encoding="utf-8").strip()
    except FileNotFoundError:
        return ""


def valid_token(candidate: str) -> bool:
    expected = admin_token()
    return bool(expected and candidate and hmac.compare_digest(candidate, expected))


def cookie_token(value: str | None) -> str:
    if not value:
        return ""
    c = SimpleCookie()
    try:
        c.load(value)
    except Exception:
        return ""
    m = c.get("ge360_admin")
    return m.value if m else ""


def cleanup_pairings() -> None:
    PAIRINGS_DIR.mkdir(parents=True, exist_ok=True)
    now = time.time()
    for p in PAIRINGS_DIR.glob("*.json"):
        try:
            if now - p.stat().st_mtime > PAIRING_TTL:
                p.unlink(missing_ok=True)
        except OSError:
            pass


def save_pairing(name: str, payload: str) -> None:
    cleanup_pairings()
    PAIRINGS_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(PAIRINGS_DIR, 0o700)
    p = PAIRINGS_DIR / f"{name}.json"
    p.write_text(json.dumps({"payload": payload, "created_at": int(time.time())}), encoding="utf-8")
    os.chmod(p, 0o600)


def load_pairing(name: str) -> str | None:
    cleanup_pairings()
    try:
        return json.loads((PAIRINGS_DIR / f"{name}.json").read_text(encoding="utf-8")).get("payload") or None
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None


def qr_svg(payload: str) -> str:
    try:
        p = subprocess.run(["qrencode", "-t", "SVG", "-o", "-", "-m", "2"], input=payload, text=True, capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout if p.returncode == 0 and "<svg" in p.stdout else ""


def create_device(name: str, services: list[str]) -> str:
    validate_name(name)
    if any(d.get("name") == name for d in list_devices()):
        raise BridgeError(f"Dispositivo già presente: {name}")
    known = {s.get("name") for s in list_services()}
    unknown = sorted(set(services) - known)
    if unknown:
        raise BridgeError("Servizi sconosciuti: " + ", ".join(unknown))
    private, public, psk = wg_keypair()
    vpn_ip = next_device_ip()
    token = random_token()
    items = list_devices()
    items.append(Device(name, vpn_ip, public, psk, token, True).__dict__)
    save_devices(items)
    for service in services:
        grant_device(service, name, True)
    render_wg_config()
    reload_runtime()
    payload = bundle_for(name, make_client_conf(private, psk, vpn_ip), token)
    save_pairing(name, payload)
    return payload


def revoke_named_device(name: str) -> None:
    validate_name(name)
    if not revoke_device(name):
        raise BridgeError("Dispositivo non trovato.")
    render_wg_config()
    reload_runtime()


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


CSS = """
:root{color-scheme:dark;--bg:#07111f;--p:#0d1b2a;--b:#203b58;--t:#eef6ff;--m:#91a7bd;--ok:#3ddc97;--bad:#ff6b6b;--a:#2d8bd0}*{box-sizing:border-box}body{margin:0;background:#07111f;color:var(--t);font:14px system-ui}.w{max-width:1180px;margin:auto;padding:22px}h1,h2,h3{margin-top:0}.top,.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel,.box{background:var(--p);border:1px solid var(--b);border-radius:14px;padding:16px}.panel{margin-top:14px}.n{font-size:28px;font-weight:800}.m{color:var(--m)}table{width:100%;border-collapse:collapse}th,td{padding:10px 7px;text-align:left;border-bottom:1px solid #19324b;vertical-align:middle}th{color:var(--m);font-size:11px;text-transform:uppercase}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--bad);margin-right:6px}.dot.ok{background:var(--ok)}button,.btn,input{border:1px solid var(--b);background:#091828;color:var(--t);padding:8px 10px;border-radius:9px;text-decoration:none}button,.btn{cursor:pointer}.primary{background:#116aa9}.danger{color:#ffbaba;border-color:#7b3037}.small{padding:5px 7px;font-size:12px}.forms{display:grid;grid-template-columns:1fr 1fr;gap:12px}.box label{display:block;color:var(--m);font-size:12px;margin:8px 0 4px}.box input{width:100%}.checks{display:flex;gap:8px;flex-wrap:wrap}.checks label{color:var(--t);display:flex;gap:5px}.checks input{width:auto}.pill{border:1px solid var(--b);border-radius:999px;padding:7px 10px}.msg{padding:10px;border:1px solid #31577c;border-radius:10px;margin-bottom:12px}.err{border-color:#7b3037}.qr{background:white;padding:12px;border-radius:12px;max-width:360px}.qr svg{width:100%;height:auto}.mono{font-family:monospace;word-break:break-all}.login{max-width:420px;margin:12vh auto}.tw{overflow:auto}@media(max-width:820px){.grid{grid-template-columns:1fr 1fr}.forms{grid-template-columns:1fr}}@media(max-width:500px){.grid{grid-template-columns:1fr}.w{padding:12px}}
"""


def shell(body: str, title: str = "GE360 Bridge", refresh: bool = False) -> str:
    r = "<meta http-equiv='refresh' content='15'>" if refresh else ""
    return f"<!doctype html><html lang='it'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>{r}<title>{esc(title)}</title><style>{CSS}</style></head><body>{body}</body></html>"


def login_page(error: str = "") -> str:
    msg = f"<div class='msg err'>{esc(error)}</div>" if error else ""
    return shell(f"<div class='login panel'><h1>GE360 Bridge</h1><p class='m'>Dashboard amministratore</p>{msg}<form method='post' action='/login'><input type='password' name='token' placeholder='Token amministratore' required><p><button class='primary'>Accedi</button></p></form><p class='m mono'>sudo cat /etc/ge360-bridge/dashboard.token</p></div>")


def dashboard_page(error: str = "") -> str:
    s = status_data()
    devices, services, counts, bridge = s["devices"], s["services"], s["counts"], s["bridge"]
    banner = f"<div class='msg err'>{esc(error)}</div>" if error else ""
    dr = []
    for d in devices:
        live = d["enabled"] and d["online"]
        state = "Online" if live else ("Revocato" if not d["enabled"] else "Offline")
        pair = load_pairing(d["name"]) if d["enabled"] else None
        qr = f"<a class='btn small' href='/pairing/{esc(d['name'])}'>QR</a>" if pair else ""
        revoke = "" if not d["enabled"] else f"<form method='post' action='/device/revoke' style='display:inline'><input type='hidden' name='name' value='{esc(d['name'])}'><button class='small danger'>Revoca</button></form>"
        dr.append(f"<tr><td><b>{esc(d['name'])}</b><div class='m mono'>{esc(d['vpn_ip'])}</div></td><td><span class='dot {'ok' if live else ''}'></span>{state}</td><td>{esc(human_age(d['handshake_age_seconds']))}</td><td>{esc(d['endpoint'] or '—')}</td><td>{esc(human_bytes(d['rx_bytes']))} / {esc(human_bytes(d['tx_bytes']))}</td><td>{qr} {revoke}</td></tr>")
    sr = []
    active = [d for d in devices if d["enabled"]]
    for service in services:
        acl = []
        for d in active:
            allowed = d["name"] in service["allowed_devices"]
            acl.append(f"<form method='post' action='/acl' style='display:inline'><input type='hidden' name='service' value='{esc(service['name'])}'><input type='hidden' name='device' value='{esc(d['name'])}'><input type='hidden' name='grant' value='{'0' if allowed else '1'}'><button class='small'>{'Togli' if allowed else 'Consenti'} {esc(d['name'])}</button></form>")
        sr.append(f"<tr><td><b>{esc(service['name'])}</b><div class='m mono'>{esc(service['bridge_url'])}</div></td><td><span class='dot {'ok' if service['target_reachable'] else ''}'></span>{'Raggiungibile' if service['target_reachable'] else 'Non risponde'}<div class='m mono'>{esc(service['target'])}</div></td><td>{' '.join(acl) or '—'}</td><td><form method='post' action='/service/remove'><input type='hidden' name='name' value='{esc(service['name'])}'><button class='small danger'>Rimuovi</button></form></td></tr>")
    service_checks = "".join(f"<label><input type='checkbox' name='service' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in services if x["enabled"]) or "<span class='m'>Nessun servizio</span>"
    device_checks = "".join(f"<label><input type='checkbox' name='allow' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in active) or "<span class='m'>Nessun dispositivo</span>"
    body = f"""<div class='w'><div class='top'><div><h1>GE360 Universal Bridge</h1><div class='m'>Hub privato frontend ↔ backend</div></div><span class='pill mono'>{esc(bridge['public_endpoint'])}</span></div>{banner}
<div class='grid'><div class='card'><div class='n'>{counts['online_devices']}/{counts['devices']}</div><div class='m'>device online</div></div><div class='card'><div class='n'>{counts['healthy_services']}/{counts['services']}</div><div class='m'>backend attivi</div></div><div class='card'><div class='n'>wg0</div><div class='m'>10.88.0.1 · UDP {bridge['wg_port']}</div></div><div class='card'><div class='n'>8789</div><div class='m'>dashboard privata</div></div></div>
<div class='panel'><div class='row'><h2>Dispositivi</h2><span class='m'>refresh 15s</span></div><div class='tw'><table><tr><th>Device</th><th>Stato</th><th>Handshake</th><th>Endpoint</th><th>RX / TX</th><th>Azioni</th></tr>{''.join(dr) or '<tr><td colspan=6>Nessun dispositivo</td></tr>'}</table></div></div>
<div class='panel'><h2>Servizi / backend</h2><div class='tw'><table><tr><th>Servizio</th><th>Backend</th><th>ACL</th><th></th></tr>{''.join(sr) or '<tr><td colspan=4>Nessun servizio</td></tr>'}</table></div></div>
<div class='panel'><h2>Gestione</h2><div class='forms'><div class='box'><h3>Aggiungi dispositivo</h3><form method='post' action='/device/add'><label>Nome</label><input name='name' placeholder='telefono-milan' pattern='[A-Za-z0-9][A-Za-z0-9_.-]{{0,63}}' required><label>Accessi iniziali</label><div class='checks'>{service_checks}</div><p><button class='primary'>Genera QR pairing</button></p></form></div><div class='box'><h3>Aggiungi backend</h3><form method='post' action='/service/add'><label>Nome</label><input name='name' placeholder='rilievi' required><label>Porta Bridge</label><input type='number' name='bridge_port' min='1' max='65535' placeholder='9888' required><label>Target locale</label><input name='target_host' value='127.0.0.1' required><label>Target porta</label><input type='number' name='target_port' min='1' max='65535' placeholder='9888' required><label>Dispositivi</label><div class='checks'>{device_checks}</div><p><button class='primary'>Registra backend</button></p></form></div></div></div>
<div class='panel row'><span class='pill mono'>Health app 10.88.0.1:8788</span><span class='pill mono'>Dashboard 10.88.0.1:8789</span><a class='btn' href='/api/status'>JSON</a><a class='btn' href='/logout'>Esci</a></div></div>"""
    return shell(body, refresh=True)


def pairing_page(name: str, payload: str) -> str:
    svg = qr_svg(payload)
    qr = f"<div class='qr'>{svg}</div>" if svg else "<div class='msg err'>QR non disponibile: usa il JSON.</div>"
    return shell(f"<div class='w'><div class='top'><div><h1>Pairing {esc(name)}</h1><div class='m'>Scansiona dal frontend GE360</div></div><a class='btn' href='/'>Dashboard</a></div><div class='panel row' style='align-items:flex-start'>{qr}<div style='flex:1;min-width:280px'><h2>Credenziale sensibile</h2><p>Il QR contiene la chiave privata WireGuard. Non condividerlo.</p><p class='m'>Rimane recuperabile per 30 minuti, poi viene eliminato.</p><details><summary>JSON pairing</summary><pre class='mono'>{esc(payload)}</pre></details></div></div></div>", f"Pairing {name}")


class Handler(BaseHTTPRequestHandler):
    server_version = "GE360BridgeDashboard/0.2"

    def log_message(self, fmt: str, *args) -> None:
        print(f"[dashboard] {self.client_address[0]} {fmt % args}")

    def send_body(self, body: str | bytes, status=200, content_type="text/html; charset=utf-8", headers=None) -> None:
        data = body.encode() if isinstance(body, str) else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def redirect(self, location: str, headers=None) -> None:
        h = {"Location": location}
        h.update(headers or {})
        self.send_body(b"", HTTPStatus.SEE_OTHER, "text/plain", h)

    def authenticated(self) -> bool:
        auth = self.headers.get("Authorization", "")
        if auth.startswith("Bearer ") and valid_token(auth[7:].strip()):
            return True
        return valid_token(cookie_token(self.headers.get("Cookie")))

    def form(self) -> dict[str, list[str]]:
        n = min(int(self.headers.get("Content-Length", "0") or 0), 65536)
        return parse_qs(self.rfile.read(n).decode("utf-8", "replace"), keep_blank_values=True)

    def require_auth(self) -> bool:
        if self.authenticated():
            return True
        self.send_body(login_page(), HTTPStatus.UNAUTHORIZED)
        return False

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/healthz":
            self.send_body('{"ok":true}', 200, "application/json")
            return
        if path == "/logout":
            self.redirect("/", {"Set-Cookie": "ge360_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"})
            return
        if not self.require_auth():
            return
        if path == "/":
            self.send_body(dashboard_page())
        elif path == "/api/status":
            self.send_body(json.dumps(status_data(), indent=2), 200, "application/json")
        elif path.startswith("/pairing/"):
            name = path.split("/", 2)[2]
            try:
                validate_name(name)
            except BridgeError as exc:
                self.send_body(dashboard_page(str(exc)), 400)
                return
            payload = load_pairing(name)
            self.send_body(pairing_page(name, payload), 200) if payload else self.send_body(dashboard_page("Pairing scaduto o non disponibile."), 404)
        else:
            self.send_body("Not found", 404, "text/plain")

    def do_POST(self) -> None:
        path = urlparse(self.path).path
        if path == "/login":
            token = (self.form().get("token") or [""])[0]
            if not valid_token(token):
                self.send_body(login_page("Token non valido."), HTTPStatus.UNAUTHORIZED)
                return
            self.redirect("/", {"Set-Cookie": f"ge360_admin={token}; Path=/; HttpOnly; SameSite=Strict"})
            return
        if not self.require_auth():
            return
        f = self.form()
        try:
            if path == "/device/add":
                name = (f.get("name") or [""])[0].strip()
                create_device(name, [x for x in f.get("service", []) if x])
                self.redirect(f"/pairing/{name}")
                return
            if path == "/device/revoke":
                name = (f.get("name") or [""])[0].strip()
                revoke_named_device(name)
                self.redirect("/")
                return
            if path == "/acl":
                grant_device((f.get("service") or [""])[0], (f.get("device") or [""])[0], (f.get("grant") or ["0"])[0] == "1")
                reload_runtime()
                self.redirect("/")
                return
            if path == "/service/add":
                register_service(
                    (f.get("name") or [""])[0].strip(),
                    int((f.get("bridge_port") or ["0"])[0]),
                    (f.get("target_host") or ["127.0.0.1"])[0].strip(),
                    int((f.get("target_port") or ["0"])[0]),
                    [x for x in f.get("allow", []) if x],
                )
                reload_runtime()
                self.redirect("/")
                return
            if path == "/service/remove":
                name = (f.get("name") or [""])[0].strip()
                validate_name(name)
                if not remove_service(name):
                    raise BridgeError("Servizio non trovato.")
                reload_runtime()
                self.redirect("/")
                return
        except (BridgeError, ValueError) as exc:
            self.send_body(dashboard_page(str(exc)), 400)
            return
        self.send_body("Not found", 404, "text/plain")


def serve() -> None:
    if not admin_token():
        raise SystemExit("Token dashboard mancante: esegui install.sh")
    servers = []
    for host in ("127.0.0.1", DEFAULT_SERVER_VPN_IP):
        try:
            server = ThreadingHTTPServer((host, PORT), Handler)
        except OSError as exc:
            print(f"[dashboard] {host}:{PORT} non disponibile: {exc}")
            continue
        servers.append(server)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        print(f"[dashboard] http://{host}:{PORT}")
    if not servers:
        raise SystemExit("Nessun bind dashboard disponibile")
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        pass
    finally:
        for server in servers:
            server.shutdown()
            server.server_close()


if __name__ == "__main__":
    serve()
