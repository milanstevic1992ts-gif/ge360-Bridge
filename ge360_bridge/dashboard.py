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
    BridgeError, Device, create_group, device_is_expired, effective_services_for_device,
    find_device, find_group, list_devices, list_groups, list_services, new_device_id,
    next_device_ip, normalize_tags, random_token, register_service, remove_group,
    remove_service, rename_device, save_devices, service_access_source,
    set_device_access_override, set_device_enabled, set_group_device, set_group_enabled,
    set_group_service, update_device_metadata, utc_now_iso, validate_device_type,
    validate_expiry, validate_name, wg_keypair,
)
from .pairing import create_pairing_payload, list_enrollments

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
    groups = list_groups()
    services = list_services()
    devices = []
    for d in list_devices():
        peer = peers.get(d.get("public_key", ""), {})
        expired = device_is_expired(d)
        memberships = [g["name"] for g in groups if d["device_id"] in g.get("device_ids", [])]
        effective = [s["name"] for s in effective_services_for_device(d, services, groups)]
        devices.append({
            **{k: d.get(k) for k in ("device_id","name","device_type","owner","vpn_ip","created_at","expires_at","notes","tags","enabled")},
            "expired": expired,
            "online": bool(peer.get("online")) and bool(d.get("enabled", True)) and not expired,
            "handshake_age_seconds": peer.get("handshake_age_seconds"),
            "endpoint": peer.get("endpoint", ""),
            "rx_bytes": peer.get("rx_bytes", 0),
            "tx_bytes": peer.get("tx_bytes", 0),
            "groups": memberships,
            "effective_services": effective,
        })
    service_rows = [{
        **s,
        "bridge_url": f"http://{DEFAULT_SERVER_VPN_IP}:{int(s['listen_port'])}",
        "target": f"{s['target_host']}:{s['target_port']}",
        "target_reachable": port_open(str(s["target_host"]), int(s["target_port"])),
    } for s in services]
    env = load_env()
    return {
        "bridge": {"vpn_ip":DEFAULT_SERVER_VPN_IP,"wg_port":int(env.get("WG_PORT","51820")),"public_endpoint":endpoint()},
        "devices": devices,
        "groups": groups,
        "services": service_rows,
        "counts": {
            "devices": len(devices),
            "online_devices": sum(1 for d in devices if d["online"]),
            "groups": len(groups),
            "services": len(service_rows),
            "healthy_services": sum(1 for s in service_rows if s.get("enabled",True) and s["target_reachable"]),
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


def drop_pairing(name: str) -> None:
    try:
        (PAIRINGS_DIR / f"{name}.json").unlink(missing_ok=True)
    except OSError:
        pass


def qr_svg(payload: str) -> str:
    try:
        p = subprocess.run(["qrencode","-t","SVG","-o","-","-m","2"], input=payload, text=True, capture_output=True, timeout=3, check=False)
    except (OSError, subprocess.TimeoutExpired):
        return ""
    return p.stdout if p.returncode == 0 and "<svg" in p.stdout else ""


def create_device(name: str, services: list[str], **meta) -> str:
    validate_name(name)
    if any(d["name"] == name for d in list_devices()):
        raise BridgeError(f"Dispositivo già presente: {name}")
    known = {s["name"] for s in list_services()}
    unknown = sorted(set(services) - known)
    if unknown:
        raise BridgeError("Servizi sconosciuti: " + ", ".join(unknown))
    private, public, psk = wg_keypair()
    device = Device(
        device_id=new_device_id(), name=name,
        device_type=validate_device_type(meta.get("device_type","unknown")),
        owner=str(meta.get("owner","")).strip()[:120], vpn_ip=next_device_ip(),
        public_key=public, preshared_key=psk, token=random_token(), created_at=utc_now_iso(),
        expires_at=validate_expiry(meta.get("expires_at")), notes=str(meta.get("notes","")).strip()[:1000],
        tags=normalize_tags(meta.get("tags") or []), enabled=True,
    )
    items=list_devices(); items.append(device.__dict__); save_devices(items)
    for service in services:
        set_device_access_override(service, name, "allow")
    render_wg_config(); reload_runtime()
    payload=bundle_for(name, make_client_conf(private,psk,device.vpn_ip), device.token)
    save_pairing(name,payload)
    return payload


def esc(value: object) -> str:
    return html.escape(str(value), quote=True)


CSS="""
:root{color-scheme:dark;--bg:#07111f;--p:#0d1b2a;--b:#203b58;--t:#eef6ff;--m:#91a7bd;--ok:#3ddc97;--bad:#ff6b6b;--warn:#ffc857}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px system-ui}.w{max-width:1220px;margin:auto;padding:22px}h1,h2,h3{margin-top:0}.top,.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel,.box{background:var(--p);border:1px solid var(--b);border-radius:14px;padding:16px}.panel{margin-top:14px}.n{font-size:28px;font-weight:800}.m{color:var(--m)}table{width:100%;border-collapse:collapse}th,td{padding:9px 7px;text-align:left;border-bottom:1px solid #19324b;vertical-align:middle}th{color:var(--m);font-size:11px;text-transform:uppercase}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--bad);margin-right:6px}.ok{background:var(--ok)}.warn{background:var(--warn)}button,.btn,input,select,textarea{border:1px solid var(--b);background:#091828;color:var(--t);padding:8px 10px;border-radius:9px;text-decoration:none}button,.btn{cursor:pointer}.primary{background:#116aa9}.danger{color:#ffbaba;border-color:#7b3037}.small{padding:5px 7px;font-size:12px}.forms,.detail{display:grid;grid-template-columns:1fr 1fr;gap:12px}.box label{display:block;color:var(--m);font-size:12px;margin:8px 0 4px}.box input,.box select,.box textarea{width:100%}.checks{display:flex;gap:8px;flex-wrap:wrap}.checks label{display:flex;gap:5px}.checks input{width:auto}.pill,.tag{display:inline-block;border:1px solid var(--b);border-radius:999px;padding:5px 8px;margin:2px}.tag{font-size:11px}.msg{padding:10px;border:1px solid #31577c;border-radius:10px;margin-bottom:12px}.err{border-color:#7b3037}.qr{background:white;padding:12px;border-radius:12px;max-width:360px}.qr svg{width:100%;height:auto}.mono{font-family:monospace;word-break:break-all}.login{max-width:420px;margin:12vh auto}.tw{overflow:auto}@media(max-width:820px){.grid{grid-template-columns:1fr 1fr}.forms,.detail{grid-template-columns:1fr}}@media(max-width:500px){.grid{grid-template-columns:1fr}.w{padding:12px}}
"""


def shell(body:str,title:str="GE360 Bridge",refresh:bool=False)->str:
    r="<meta http-equiv='refresh' content='15'>" if refresh else ""
    return f"<!doctype html><html lang='it'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>{r}<title>{esc(title)}</title><style>{CSS}</style></head><body>{body}</body></html>"


def login_page(error:str="")->str:
    msg=f"<div class='msg err'>{esc(error)}</div>" if error else ""
    return shell(f"<div class='login panel'><h1>GE360 Bridge</h1><p class='m'>Dashboard amministratore</p>{msg}<form method='post' action='/login'><input type='password' name='token' placeholder='Token amministratore' required><p><button class='primary'>Accedi</button></p></form></div>")


def dashboard_page(error:str="")->str:
    s=status_data(); devices=s["devices"]; groups=s["groups"]; services=s["services"]; c=s["counts"]
    banner=f"<div class='msg err'>{esc(error)}</div>" if error else ""
    dr=[]
    for d in devices:
        state="Disabilitato" if not d["enabled"] else ("Scaduto" if d["expired"] else ("Online" if d["online"] else "Offline"))
        gtags="".join(f"<span class='tag'>{esc(g)}</span>" for g in d["groups"]) or "—"
        srvs="".join(f"<span class='tag'>{esc(x)}</span>" for x in d["effective_services"]) or "—"
        dr.append(f"<tr><td><b>{esc(d['name'])}</b><div class='m mono'>{esc(d['device_id'])}</div></td><td>{esc(state)}<div class='m'>{esc(d['vpn_ip'])}</div></td><td>{gtags}</td><td>{srvs}</td><td>{esc(human_age(d['handshake_age_seconds']))}</td><td><a class='btn small' href='/device/{esc(d['device_id'])}'>Gestisci</a></td></tr>")
    gr=[]
    for g in groups:
        gr.append(f"<tr><td><b>{esc(g['name'])}</b><div class='m'>{esc(g.get('description',''))}</div></td><td>{len(g.get('device_ids',[]))}</td><td>{' '.join(f'<span class=\"tag\">{esc(x)}</span>' for x in g.get('allowed_services',[])) or '—'}</td><td>{'Attivo' if g.get('enabled',True) else 'Disabilitato'}</td><td><a class='btn small' href='/group/{esc(g['name'])}'>Gestisci</a></td></tr>")
    sv=[]
    all_groups=list_groups()
    all_devices=list_devices()
    for service in services:
        access=[]
        for d in all_devices:
            src=service_access_source(service,d,all_groups)
            if src!="none" and src!="inactive":
                access.append(f"{d['name']}={src}")
        sv.append(f"<tr><td><b>{esc(service['name'])}</b><div class='m mono'>{esc(service['bridge_url'])}</div></td><td><span class='dot {'ok' if service['target_reachable'] else ''}'></span>{'OK' if service['target_reachable'] else 'Down'}<div class='m mono'>{esc(service['target'])}</div></td><td>{'<br>'.join(esc(x) for x in access) or '—'}</td></tr>")
    service_checks="".join(f"<label><input type='checkbox' name='service' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in services) or "—"
    group_checks="".join(f"<label><input type='checkbox' name='group' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in groups if x.get("enabled",True)) or "—"
    body=f"""<div class='w'><div class='top'><div><h1>GE360 Universal Bridge</h1><div class='m'>FASE 3 · Pairing sicuro v2</div></div><span class='pill mono'>{esc(s['bridge']['public_endpoint'])}</span></div>{banner}
<div class='grid'><div class='card'><div class='n'>{c['online_devices']}/{c['devices']}</div><div class='m'>device online</div></div><div class='card'><div class='n'>{c['groups']}</div><div class='m'>gruppi</div></div><div class='card'><div class='n'>{c['healthy_services']}/{c['services']}</div><div class='m'>backend attivi</div></div><div class='card'><div class='n'>v0.5</div><div class='m'>Pairing v2</div></div></div>
<div class='panel'><h2>Dispositivi</h2><div class='tw'><table><tr><th>Device</th><th>Stato</th><th>Gruppi</th><th>Accesso effettivo</th><th>Handshake</th><th></th></tr>{''.join(dr) or '<tr><td colspan=6>Nessun device</td></tr>'}</table></div></div>
<div class='panel'><h2>Gruppi</h2><div class='tw'><table><tr><th>Gruppo</th><th>Device</th><th>Servizi</th><th>Stato</th><th></th></tr>{''.join(gr) or '<tr><td colspan=5>Nessun gruppo</td></tr>'}</table></div></div>
<div class='panel'><h2>Servizi e ACL effettive</h2><div class='tw'><table><tr><th>Servizio</th><th>Backend</th><th>Sorgente accesso</th></tr>{''.join(sv) or '<tr><td colspan=3>Nessun servizio</td></tr>'}</table></div></div>
<div class='panel forms'><div class='box'><h3>Crea gruppo</h3><form method='post' action='/group/create'><label>Nome</label><input name='name' placeholder='amministratori' required><label>Descrizione</label><textarea name='description'></textarea><p><button class='primary'>Crea gruppo</button></p></form></div>
<div class='box'><h3>Pairing sicuro v2</h3><form method='post' action='/device/add'><label>Nome device</label><input name='name' required><label>Tipo</label><select name='device_type'><option>android</option><option>tablet</option><option>linux</option><option>windows</option><option>server</option><option selected>unknown</option></select><label>Proprietario</label><input name='owner'><label>Tag</label><input name='tags'><label>Scadenza device</label><input type='date' name='expires_at'><label>Gruppi iniziali</label><div class='checks'>{group_checks}</div><label>TTL token</label><select name='ttl'><option value='300'>5 minuti</option><option value='600' selected>10 minuti</option><option value='1800'>30 minuti</option><option value='86400'>24 ore</option></select><p><button class='primary'>Genera QR v2 monouso</button></p></form></div></div>
<div class='panel row'><a class='btn' href='/api/status'>JSON</a><a class='btn' href='/logout'>Esci</a></div></div>"""
    return shell(body,refresh=True)


def device_page(identifier:str,error:str="")->str:
    d=find_device(identifier)
    if not d: return shell("<div class='w panel'>Device non trovato</div>")
    groups=list_groups(); services=list_services()
    memberships={g["name"] for g in groups if d["device_id"] in g.get("device_ids",[])}
    banner=f"<div class='msg err'>{esc(error)}</div>" if error else ""
    group_controls="".join(f"<form method='post' action='/group/device' style='display:inline'><input type='hidden' name='group' value='{esc(g['name'])}'><input type='hidden' name='device' value='{esc(d['device_id'])}'><input type='hidden' name='assigned' value='{'0' if g['name'] in memberships else '1'}'><button class='small'>{'Togli da' if g['name'] in memberships else 'Aggiungi a'} {esc(g['name'])}</button></form>" for g in groups) or "Nessun gruppo"
    acl=[]
    for s in services:
        src=service_access_source(s,d,groups)
        acl.append(f"<tr><td>{esc(s['name'])}</td><td>{esc(src)}</td><td><form method='post' action='/acl' style='display:inline'><input type='hidden' name='service' value='{esc(s['name'])}'><input type='hidden' name='device' value='{esc(d['device_id'])}'><button class='small' name='decision' value='allow'>Allow</button><button class='small danger' name='decision' value='deny'>Deny</button><button class='small' name='decision' value='inherit'>Eredita</button></form></td></tr>")
    tags=",".join(d.get("tags",[])); selected=lambda x:" selected" if d.get("device_type")==x else ""
    body=f"""<div class='w'><div class='top'><div><h1>{esc(d['name'])}</h1><div class='m mono'>{esc(d['device_id'])}</div></div><a class='btn' href='/'>← Dashboard</a></div>{banner}
<div class='panel'><h2>Gruppi</h2>{group_controls}</div>
<div class='panel'><h2>ACL effettive e override</h2><table><tr><th>Servizio</th><th>Sorgente</th><th>Override device</th></tr>{''.join(acl)}</table></div>
<div class='panel detail'><div><h2>Metadati</h2><form method='post' action='/device/update'><input type='hidden' name='device_id' value='{esc(d['device_id'])}'><label>Nome</label><input name='name' value='{esc(d['name'])}'><label>Tipo</label><select name='device_type'><option{selected('android')}>android</option><option{selected('tablet')}>tablet</option><option{selected('linux')}>linux</option><option{selected('windows')}>windows</option><option{selected('server')}>server</option><option{selected('unknown')}>unknown</option></select><label>Proprietario</label><input name='owner' value='{esc(d.get('owner',''))}'><label>Scadenza</label><input type='date' name='expires_at' value='{esc(d.get('expires_at') or '')}'><label>Tag</label><input name='tags' value='{esc(tags)}'><label>Note</label><textarea name='notes'>{esc(d.get('notes',''))}</textarea><p><button class='primary'>Salva</button></p></form></div>
<div><h2>Stato</h2><p>{'Abilitato' if d.get('enabled',True) else 'Disabilitato'}</p><form method='post' action='/device/toggle'><input type='hidden' name='device_id' value='{esc(d['device_id'])}'><input type='hidden' name='enabled' value='{'0' if d.get('enabled',True) else '1'}'><button class='{'danger' if d.get('enabled',True) else 'primary'}'>{'Disabilita' if d.get('enabled',True) else 'Abilita'}</button></form></div></div></div>"""
    return shell(body,d["name"])


def group_page(name:str,error:str="")->str:
    g=find_group(name)
    if not g: return shell("<div class='w panel'>Gruppo non trovato</div>")
    devices=list_devices(); services=list_services()
    banner=f"<div class='msg err'>{esc(error)}</div>" if error else ""
    members=set(g.get("device_ids",[])); allowed=set(g.get("allowed_services",[]))
    dev_rows="".join(f"<tr><td>{esc(d['name'])}<div class='m mono'>{esc(d['device_id'])}</div></td><td>{'Membro' if d['device_id'] in members else '—'}</td><td><form method='post' action='/group/device'><input type='hidden' name='group' value='{esc(g['name'])}'><input type='hidden' name='device' value='{esc(d['device_id'])}'><button class='small' name='assigned' value='{'0' if d['device_id'] in members else '1'}'>{'Rimuovi' if d['device_id'] in members else 'Aggiungi'}</button></form></td></tr>" for d in devices)
    svc_rows="".join(f"<tr><td>{esc(s['name'])}</td><td>{'Consentito' if s['name'] in allowed else '—'}</td><td><form method='post' action='/group/service'><input type='hidden' name='group' value='{esc(g['name'])}'><input type='hidden' name='service' value='{esc(s['name'])}'><button class='small' name='allowed' value='{'0' if s['name'] in allowed else '1'}'>{'Revoca' if s['name'] in allowed else 'Consenti'}</button></form></td></tr>" for s in services)
    body=f"""<div class='w'><div class='top'><div><h1>Gruppo {esc(g['name'])}</h1><div class='m'>{esc(g.get('description',''))}</div></div><a class='btn' href='/'>← Dashboard</a></div>{banner}
<div class='panel'><h2>Dispositivi</h2><table><tr><th>Device</th><th>Stato</th><th></th></tr>{dev_rows}</table></div>
<div class='panel'><h2>Servizi del gruppo</h2><table><tr><th>Servizio</th><th>Accesso</th><th></th></tr>{svc_rows}</table></div>
<div class='panel row'><form method='post' action='/group/toggle'><input type='hidden' name='group' value='{esc(g['name'])}'><input type='hidden' name='enabled' value='{'0' if g.get('enabled',True) else '1'}'><button>{'Disabilita gruppo' if g.get('enabled',True) else 'Abilita gruppo'}</button></form><form method='post' action='/group/remove'><input type='hidden' name='group' value='{esc(g['name'])}'><button class='danger'>Elimina gruppo</button></form></div></div>"""
    return shell(body,g["name"])


def pairing_page(name:str,payload)->str:
    raw = json.dumps(payload,separators=(",",":")) if isinstance(payload,dict) else str(payload)
    svg=qr_svg(raw); qr=f"<div class='qr'>{svg}</div>" if svg else "QR non disponibile"
    if isinstance(payload,dict):
        info=f"<p><b>Enrollment:</b> <span class='mono'>{esc(payload.get('enrollment_id',''))}</span></p><p><b>HTTPS:</b> <span class='mono'>{esc(payload.get('enrollment_url',''))}</span></p><p><b>Scadenza token:</b> {esc(payload.get('expires_at',''))}</p><p class='m'>Il QR non contiene alcuna private key. Il client genera localmente la chiave WireGuard e invia solo la public key.</p>"
    else:
        info="<p class='m'>Pairing legacy v1 temporaneo.</p>"
    return shell(f"<div class='w'><div class='top'><h1>Pairing {esc(name)}</h1><a class='btn' href='/'>Dashboard</a></div><div class='panel row' style='align-items:flex-start'>{qr}<div style='flex:1;min-width:280px'>{info}<details><summary>Payload</summary><pre class='mono'>{esc(raw)}</pre></details></div></div></div>")


class Handler(BaseHTTPRequestHandler):
    server_version="GE360BridgeDashboard/0.5"
    def log_message(self,fmt,*args): print(f"[dashboard] {self.client_address[0]} {fmt % args}")
    def send_body(self,body,status=200,content_type="text/html; charset=utf-8",headers=None):
        data=body.encode() if isinstance(body,str) else body
        self.send_response(status); self.send_header("Content-Type",content_type); self.send_header("Content-Length",str(len(data)))
        self.send_header("Cache-Control","no-store"); self.send_header("X-Frame-Options","DENY"); self.send_header("X-Content-Type-Options","nosniff")
        self.send_header("Content-Security-Policy","default-src 'self'; style-src 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'; form-action 'self'")
        for k,v in (headers or {}).items(): self.send_header(k,v)
        self.end_headers(); self.wfile.write(data)
    def redirect(self,location,headers=None):
        h={"Location":location}; h.update(headers or {}); self.send_body(b"",HTTPStatus.SEE_OTHER,"text/plain",h)
    def authenticated(self):
        auth=self.headers.get("Authorization","")
        return (auth.startswith("Bearer ") and valid_token(auth[7:].strip())) or valid_token(cookie_token(self.headers.get("Cookie")))
    def form(self):
        n=min(int(self.headers.get("Content-Length","0") or 0),65536)
        return parse_qs(self.rfile.read(n).decode("utf-8","replace"),keep_blank_values=True)
    def require_auth(self):
        if self.authenticated(): return True
        self.send_body(login_page(),HTTPStatus.UNAUTHORIZED); return False

    def do_GET(self):
        path=urlparse(self.path).path
        if path=="/healthz": self.send_body('{"ok":true}',200,"application/json"); return
        if path=="/logout": self.redirect("/",{"Set-Cookie":"ge360_admin=; Path=/; Max-Age=0; HttpOnly; SameSite=Strict"}); return
        if not self.require_auth(): return
        if path=="/": self.send_body(dashboard_page())
        elif path=="/api/status": self.send_body(json.dumps(status_data(),indent=2),200,"application/json")
        elif path.startswith("/device/"): self.send_body(device_page(path.split("/",2)[2]))
        elif path.startswith("/group/"): self.send_body(group_page(path.split("/",2)[2]))
        elif path.startswith("/pairing/"):
            name=path.split("/",2)[2]; payload=load_pairing(name)
            self.send_body(pairing_page(name,payload),200) if payload else self.send_body(dashboard_page("Pairing scaduto."),404)
        else: self.send_body("Not found",404,"text/plain")

    def do_POST(self):
        path=urlparse(self.path).path
        if path=="/login":
            token=(self.form().get("token") or [""])[0]
            if not valid_token(token): self.send_body(login_page("Token non valido."),HTTPStatus.UNAUTHORIZED); return
            self.redirect("/",{"Set-Cookie":f"ge360_admin={token}; Path=/; HttpOnly; SameSite=Strict"}); return
        if not self.require_auth(): return
        f=self.form()
        try:
            if path=="/group/create":
                create_group((f.get("name") or [""])[0].strip(),(f.get("description") or [""])[0]); reload_runtime(); self.redirect("/"); return
            if path=="/group/device":
                group=(f.get("group") or [""])[0]; set_group_device(group,(f.get("device") or [""])[0],(f.get("assigned") or ["0"])[0]=="1"); reload_runtime(); self.redirect(f"/group/{group}"); return
            if path=="/group/service":
                group=(f.get("group") or [""])[0]; set_group_service(group,(f.get("service") or [""])[0],(f.get("allowed") or ["0"])[0]=="1"); reload_runtime(); self.redirect(f"/group/{group}"); return
            if path=="/group/toggle":
                group=(f.get("group") or [""])[0]; set_group_enabled(group,(f.get("enabled") or ["0"])[0]=="1"); reload_runtime(); self.redirect(f"/group/{group}"); return
            if path=="/group/remove":
                group=(f.get("group") or [""])[0]
                if not remove_group(group): raise BridgeError("Gruppo non trovato.")
                reload_runtime(); self.redirect("/"); return
            if path=="/acl":
                device=(f.get("device") or [""])[0]; set_device_access_override((f.get("service") or [""])[0],device,(f.get("decision") or ["inherit"])[0]); reload_runtime()
                d=find_device(device); self.redirect(f"/device/{d['device_id']}" if d else "/"); return
            if path=="/device/add":
                name=(f.get("name") or [""])[0].strip()
                payload=create_pairing_payload(
                    name=name,
                    device_type=(f.get("device_type") or ["unknown"])[0],
                    owner=(f.get("owner") or [""])[0],
                    expires_at=(f.get("expires_at") or [""])[0] or None,
                    tags=normalize_tags([x for x in (f.get("tags") or [""])[0].split(",") if x.strip()]),
                    group_names=[x for x in f.get("group",[]) if x],
                    ttl_seconds=int((f.get("ttl") or ["600"])[0]),
                )
                self.send_body(pairing_page(name,payload)); return
            if path=="/device/update":
                did=(f.get("device_id") or [""])[0]; current=find_device(did)
                if not current: raise BridgeError("Dispositivo non trovato.")
                new_name=(f.get("name") or [current["name"]])[0].strip()
                if new_name!=current["name"]: old=current["name"]; rename_device(did,new_name); drop_pairing(old)
                update_device_metadata(did,device_type=(f.get("device_type") or ["unknown"])[0],owner=(f.get("owner") or [""])[0],expires_at=(f.get("expires_at") or [""])[0] or None,notes=(f.get("notes") or [""])[0],tags=normalize_tags([x for x in (f.get("tags") or [""])[0].split(",") if x.strip()]))
                render_wg_config(); reload_runtime(); self.redirect(f"/device/{did}"); return
            if path=="/device/toggle":
                did=(f.get("device_id") or [""])[0]; set_device_enabled(did,(f.get("enabled") or ["0"])[0]=="1"); render_wg_config(); reload_runtime(); self.redirect(f"/device/{did}"); return
            if path=="/service/add":
                register_service((f.get("name") or [""])[0].strip(),int((f.get("bridge_port") or ["0"])[0]),(f.get("target_host") or ["127.0.0.1"])[0],int((f.get("target_port") or ["0"])[0]),[x for x in f.get("allow",[]) if x]); reload_runtime(); self.redirect("/"); return
            if path=="/service/remove":
                if not remove_service((f.get("name") or [""])[0]): raise BridgeError("Servizio non trovato.")
                reload_runtime(); self.redirect("/"); return
        except (BridgeError,ValueError) as exc:
            self.send_body(dashboard_page(str(exc)),400); return
        self.send_body("Not found",404,"text/plain")


def serve()->None:
    if not admin_token(): raise SystemExit("Token dashboard mancante: esegui install.sh")
    servers=[]
    for host in ("127.0.0.1",DEFAULT_SERVER_VPN_IP):
        try: server=ThreadingHTTPServer((host,PORT),Handler)
        except OSError as exc: print(f"[dashboard] {host}:{PORT} non disponibile: {exc}"); continue
        servers.append(server); threading.Thread(target=server.serve_forever,daemon=True).start()
    if not servers: raise SystemExit("Nessun bind dashboard disponibile")
    try:
        while True: time.sleep(3600)
    except KeyboardInterrupt: pass
    finally:
        for server in servers: server.shutdown(); server.server_close()


if __name__=="__main__": serve()
