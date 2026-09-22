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
    find_device, find_group, find_resource, list_devices, list_groups, list_resources, list_services, new_device_id,
    next_device_ip, normalize_tags, random_token, register_resource, register_service, remove_group,
    remove_resource, remove_service, rename_device, save_devices, service_access_source,
    set_device_access_override, set_device_enabled, set_group_device, set_group_enabled,
    set_group_service, update_device_metadata, update_resource, utc_now_iso, validate_device_type,
    validate_expiry, validate_name, wg_keypair,
)
from .pairing import create_pairing_payload, list_enrollments
from .health import check_resource, check_resources, health_summary
from .diagnostics import diagnose_resource
from .doctor import connection_doctor
from .audit import count_events, list_events
from .metrics import query_series
from .discovery import discover_backends, import_discovered_backend

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
    resources = list_resources()
    health_results = check_resources(resources)
    health_by_name = {h["name"]: h for h in health_results}
    devices = []
    for d in list_devices():
        peer = peers.get(d.get("public_key", ""), {})
        expired = device_is_expired(d)
        memberships = [g["name"] for g in groups if d["device_id"] in g.get("device_ids", [])]
        effective = [s["name"] for s in effective_services_for_device(d, resources, groups)]
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
    resource_rows = []
    for resource in resources:
        health = health_by_name.get(resource["name"], {})
        scheme = resource.get("protocol", "tcp")
        bridge_url = f"{scheme}://{DEFAULT_SERVER_VPN_IP}:{int(resource['bridge_port'])}"
        resource_rows.append({
            **resource,
            "bridge_url": bridge_url,
            "target": f"{resource['target_host']}:{resource['target_port']}",
            "target_reachable": bool(health.get("checks", {}).get("tcp", {}).get("ok")),
            "health": health,
        })
    summary = health_summary(health_results)
    env = load_env()
    return {
        "bridge": {"vpn_ip":DEFAULT_SERVER_VPN_IP,"wg_port":int(env.get("WG_PORT","51820")),"public_endpoint":endpoint()},
        "devices": devices,
        "groups": groups,
        "resources": resource_rows,
        "services": resource_rows,
        "health": {"summary": summary, "resources": health_results},
        "counts": {
            "devices": len(devices),
            "online_devices": sum(1 for d in devices if d["online"]),
            "groups": len(groups),
            "services": len(resource_rows),
            "healthy_services": summary.get("ONLINE", 0),
            "degraded_services": summary.get("DEGRADED", 0),
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
:root{color-scheme:dark;--bg:#07111f;--p:#0d1b2a;--b:#203b58;--t:#eef6ff;--m:#91a7bd;--ok:#3ddc97;--bad:#ff6b6b;--warn:#ffc857}*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--t);font:14px system-ui}.w{max-width:1220px;margin:auto;padding:22px}h1,h2,h3{margin-top:0}.top,.row{display:flex;gap:10px;align-items:center;justify-content:space-between;flex-wrap:wrap}.grid{display:grid;grid-template-columns:repeat(4,1fr);gap:12px}.card,.panel,.box{background:var(--p);border:1px solid var(--b);border-radius:14px;padding:16px}.panel{margin-top:14px}.n{font-size:28px;font-weight:800}.m{color:var(--m)}table{width:100%;border-collapse:collapse}th,td{padding:9px 7px;text-align:left;border-bottom:1px solid #19324b;vertical-align:middle}th{color:var(--m);font-size:11px;text-transform:uppercase}.dot{display:inline-block;width:9px;height:9px;border-radius:50%;background:var(--bad);margin-right:6px}.ok{background:var(--ok)}.warn{background:var(--warn)}button,.btn,input,select,textarea{border:1px solid var(--b);background:#091828;color:var(--t);padding:8px 10px;border-radius:9px;text-decoration:none}button,.btn{cursor:pointer}.primary{background:#116aa9}.danger{color:#ffbaba;border-color:#7b3037}.small{padding:5px 7px;font-size:12px}.forms,.detail{display:grid;grid-template-columns:1fr 1fr;gap:12px}.box label{display:block;color:var(--m);font-size:12px;margin:8px 0 4px}.box input,.box select,.box textarea{width:100%}.checks{display:flex;gap:8px;flex-wrap:wrap}.checks label{display:flex;gap:5px}.checks input{width:auto}.pill,.tag{display:inline-block;border:1px solid var(--b);border-radius:999px;padding:5px 8px;margin:2px}.tag{font-size:11px}.msg{padding:10px;border:1px solid #31577c;border-radius:10px;margin-bottom:12px}.err{border-color:#7b3037}.qr{background:white;padding:12px;border-radius:12px;max-width:360px}.qr svg{width:100%;height:auto}.mono{font-family:monospace;word-break:break-all}.login{max-width:420px;margin:12vh auto}.tw{overflow:auto}.chart{width:100%;height:74px;display:block;color:#9fd3ff}.metric-grid{display:grid;grid-template-columns:repeat(2,1fr);gap:12px}.metric-box{border:1px solid var(--b);border-radius:12px;padding:12px}@media(max-width:820px){.metric-grid{grid-template-columns:1fr}}@media(max-width:820px){.grid{grid-template-columns:1fr 1fr}.forms,.detail{grid-template-columns:1fr}}@media(max-width:500px){.grid{grid-template-columns:1fr}.w{padding:12px}}
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
        h=service.get("health") or {}
        state=h.get("state","OFFLINE")
        dot_class="ok" if state=="ONLINE" else ("warn" if state in {"DEGRADED","UNAUTHORIZED"} else "")
        checks=h.get("checks",{})
        tcp=checks.get("tcp",{})
        http=checks.get("http",{})
        js=checks.get("json",{})
        tls=checks.get("tls",{})
        details=[f"TCP {tcp.get('latency_ms')}ms" if tcp.get("ok") else "TCP KO"]
        if http.get("performed"):
            details.append(f"HTTP {http.get('status_code') or '—'} · {http.get('latency_ms') or '—'}ms")
        if js.get("performed"):
            details.append("JSON OK" if js.get("ok") else "JSON KO")
        if tls.get("performed"):
            details.append(f"TLS {tls.get('version') or ('OK' if tls.get('ok') else 'KO')}")
        error_html=f"<div class='m'>{esc(h.get('error'))}</div>" if h.get("error") else ""
        sv.append(f"<tr><td><b>{esc(service.get('icon','server'))} {esc(service['name'])}</b><div class='m'>{esc(service.get('description',''))}</div></td><td><span class='dot {dot_class}'></span><b>{esc(state)}</b><div class='m'>{esc(h.get('latency_ms') if h.get('latency_ms') is not None else '—')} ms</div><div class='m'>{esc(' · '.join(details))}</div>{error_html}</td><td><b>{esc(service.get('protocol','tcp').upper())}</b><div class='m mono'>{esc(service['bridge_url'])}</div><div class='m mono'>{esc(service['target'])}</div><div class='m'>health: {esc(service.get('health_url') or '—')} · timeout {esc(service.get('timeout_seconds',2.0))}s</div></td><td>{'<br>'.join(esc(x) for x in access) or '—'}</td><td><a class='btn small' href='/resource/{esc(service['name'])}'>Gestisci</a></td></tr>")
    service_checks="".join(f"<label><input type='checkbox' name='service' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in services) or "—"
    group_checks="".join(f"<label><input type='checkbox' name='group' value='{esc(x['name'])}'>{esc(x['name'])}</label>" for x in groups if x.get("enabled",True)) or "—"
    body=f"""<div class='w'><div class='top'><div><h1>GE360 Universal Bridge</h1><div class='m'>FASE 13 · Auto discovery backend</div></div><span class='pill mono'>{esc(s['bridge']['public_endpoint'])}</span></div>{banner}
<div class='grid'><div class='card'><div class='n'>{c['online_devices']}/{c['devices']}</div><div class='m'>device online</div></div><div class='card'><div class='n'>{c['healthy_services']}/{c['services']}</div><div class='m'>Resource ONLINE</div></div><div class='card'><div class='n'>{c.get('degraded_services',0)}</div><div class='m'>Resource DEGRADED</div></div><div class='card'><div class='n'>v0.15</div><div class='m'>Bridge</div></div></div>
<div class='panel'><h2>Dispositivi</h2><div class='tw'><table><tr><th>Device</th><th>Stato</th><th>Gruppi</th><th>Accesso effettivo</th><th>Handshake</th><th></th></tr>{''.join(dr) or '<tr><td colspan=6>Nessun device</td></tr>'}</table></div></div>
<div class='panel'><h2>Gruppi</h2><div class='tw'><table><tr><th>Gruppo</th><th>Device</th><th>Resource</th><th>Stato</th><th></th></tr>{''.join(gr) or '<tr><td colspan=5>Nessun gruppo</td></tr>'}</table></div></div>
<div class='panel'><h2>Audit Log</h2><div class='m'>Eventi persistenti: {count_events()}</div><div class='tw'><table><tr><th>Ora</th><th>Evento</th><th>Device</th><th>Resource</th><th>Risultato</th></tr>{''.join(f"<tr><td class='mono'>{esc(e.get('timestamp'))}</td><td>{esc(e.get('event'))}</td><td>{esc(e.get('device_name') or e.get('device_id') or '—')}</td><td>{esc(e.get('resource') or '—')}</td><td>{esc(e.get('result') or e.get('error') or '—')}</td></tr>" for e in list_events(limit=20)) or '<tr><td colspan=5>Nessun evento</td></tr>'}</table></div><p><a class='btn' href='/api/audit'>JSON audit</a></p></div>
<div class='panel'><h2>Health Engine · Resource</h2><div class='tw'><table><tr><th>Resource</th><th>Stato / controlli</th><th>Protocollo / target</th><th>ACL</th><th></th></tr>{''.join(sv) or '<tr><td colspan=5>Nessuna Resource</td></tr>'}</table></div></div>
<div class='panel'><h2>Registra Resource</h2><form method='post' action='/resource/add'><div class='forms'><div class='box'><label>Nome</label><input name='name' placeholder='rilievi' required><label>Icona</label><input name='icon' value='server'><label>Descrizione</label><textarea name='description'></textarea><label>Protocollo</label><select name='protocol'><option value='http'>HTTP</option><option value='https'>HTTPS</option><option value='tcp'>TCP</option></select></div><div class='box'><label>Bridge port</label><input type='number' name='bridge_port' min='1' max='65535' required><label>Target host</label><input name='target_host' value='127.0.0.1' required><label>Target port</label><input type='number' name='target_port' min='1' max='65535' required><label>Health URL/path opzionale</label><input name='health_url' placeholder='/healthz'><label>Timeout secondi</label><input type='number' name='timeout' min='0.1' max='30' step='0.1' value='2.0'><p><button class='primary'>Registra Resource</button></p></div></div></form></div>
<div class='panel forms'><div class='box'><h3>Crea gruppo</h3><form method='post' action='/group/create'><label>Nome</label><input name='name' placeholder='amministratori' required><label>Descrizione</label><textarea name='description'></textarea><p><button class='primary'>Crea gruppo</button></p></form></div>
<div class='box'><h3>Pairing sicuro v2</h3><form method='post' action='/device/add'><label>Nome device</label><input name='name' required><label>Tipo</label><select name='device_type'><option>android</option><option>tablet</option><option>linux</option><option>windows</option><option>server</option><option selected>unknown</option></select><label>Proprietario</label><input name='owner'><label>Tag</label><input name='tags'><label>Scadenza device</label><input type='date' name='expires_at'><label>Gruppi iniziali</label><div class='checks'>{group_checks}</div><label>TTL token</label><select name='ttl'><option value='300'>5 minuti</option><option value='600' selected>10 minuti</option><option value='1800'>30 minuti</option><option value='86400'>24 ore</option></select><p><button class='primary'>Genera QR v2 monouso</button></p></form></div></div>
<div class='panel'><b>Launcher device</b><div class='mono'>http://10.88.0.1:8788/hub</div><div class='m'>Visibile ai device VPN e filtrato dalle ACL effettive.</div></div><div class='panel row'><div><a class='btn' href='/discovery'>Backend discovery</a> <a class='btn' href='/metrics'>Metriche</a> <a class='btn' href='/api/status'>JSON</a></div><a class='btn' href='/logout'>Esci</a></div></div>"""
    return shell(body,refresh=True)



def discovery_page(error:str="")->str:
    report=discover_backends()
    rows=[]
    for proposal in report.get("proposals",[]):
        manifest=proposal["manifest"]
        suggested=proposal.get("suggested_bridge_port")
        bridge_value="" if suggested is None else str(suggested)
        status=proposal.get("status","")
        reason=proposal.get("reason","")
        if status in {"new","bridge_port_required"}:
            action=f"""<form method='post' action='/discovery/import'>
<input type='hidden' name='host' value='{esc(proposal["target_host"])}'>
<input type='hidden' name='target_port' value='{esc(proposal["target_port"])}'>
<input type='hidden' name='scheme' value='{esc(proposal["protocol"])}'>
<input type='number' name='bridge_port' min='1' max='65535' value='{esc(bridge_value)}' placeholder='bridge port' required>
<button class='primary small'>Importa</button></form>"""
        else:
            action="—"
        rows.append(f"<tr><td><b>{esc(manifest['name'])}</b><div class='m mono'>{esc(proposal['resource_name'])} · v{esc(manifest['version'])}</div></td><td class='mono'>{esc(proposal['protocol'])}://{esc(proposal['target_host'])}:{esc(proposal['target_port'])}</td><td>{esc(manifest['health'])}</td><td><b>{esc(status)}</b><div class='m'>{esc(reason)}</div></td><td>{action}</td></tr>")
    banner=f"<div class='err'>{esc(error)}</div>" if error else ""
    body=f"""<div class='w'><div class='top'><div><h1>Backend discovery</h1><div class='m'>Fase 13 · solo loopback · /.well-known/ge360</div></div><a class='btn' href='/'>← Dashboard</a></div>{banner}
<div class='panel'><div class='m'>Porte controllate: {esc(', '.join(str(x) for x in report.get('scanned_ports',[])) or 'nessuna')} · risposte valide: {len(report.get('proposals',[]))} · porte senza manifest valido: {len(report.get('errors',[]))}</div></div>
<div class='panel'><div class='tw'><table><tr><th>Backend</th><th>Target</th><th>Health</th><th>Stato</th><th></th></tr>{''.join(rows) or '<tr><td colspan=5>Nessun backend GE360 rilevato.</td></tr>'}</table></div></div>
<div class='panel'><p><a class='btn' href='/api/discovery'>JSON discovery</a></p><div class='m'>La scansione non importa automaticamente nulla e non esce dal loopback.</div></div></div>"""
    return shell(body)


def sparkline_svg(values:list[float|int|None], width:int=320, height:int=74)->str:
    clean=[float(v) for v in values if v is not None]
    if not clean:
        return "<div class='m'>Nessun campione</div>"
    lo=min(clean); hi=max(clean)
    span=hi-lo if hi!=lo else 1.0
    points=[]
    count=max(1,len(values)-1)
    for i,value in enumerate(values):
        if value is None:
            continue
        x=round(i/count*width,2)
        y=round(height-((float(value)-lo)/span)*(height-8)-4,2)
        points.append(f"{x},{y}")
    return f"<svg class='chart' viewBox='0 0 {width} {height}' preserveAspectRatio='none'><polyline fill='none' stroke='currentColor' stroke-width='2' points='{' '.join(points)}'/></svg>"


def metrics_page(window:str="24h")->str:
    try:
        data=query_series(window)
    except ValueError:
        window="24h"; data=query_series(window)
    nav=" ".join(f"<a class='btn small' href='/metrics?window={w}'>{w}</a>" for w in ("1h","24h","7d","30d"))
    bridge=data.get("bridge",[])
    conn=[x.get("connections",0) for x in bridge]
    errs=[x.get("errors",0) for x in bridge]
    uptime=bridge[-1].get("uptime_seconds") if bridge else None
    bridge_panel=f"""<div class='panel'><h2>Bridge · {esc(window)}</h2><div class='metric-grid'><div class='metric-box'><b>Connessioni</b><div class='n'>{sum(conn)}</div>{sparkline_svg(conn)}</div><div class='metric-box'><b>Errori</b><div class='n'>{sum(errs)}</div>{sparkline_svg(errs)}</div></div><p class='m'>Uptime sistema: {esc(round(float(uptime)/3600,1) if uptime is not None else '—')} h</p></div>"""

    resources=[]
    for name,points in data.get("resources",{}).items():
        latency=[x.get("latency_ms") for x in points]
        errors=sum(int(x.get("errors",0)) for x in points)
        online=round((sum(float(x.get("online_ratio",0)) for x in points)/len(points))*100,1) if points else 0
        resources.append(f"""<div class='metric-box'><h3>{esc(name)}</h3><div class='m'>Online {esc(online)}% · errori {esc(errors)}</div><b>Latenza ms</b>{sparkline_svg(latency)}</div>""")
    resource_panel=f"<div class='panel'><h2>Resource</h2><div class='metric-grid'>{''.join(resources) or '<div class="m">Nessun campione Resource</div>'}</div></div>"

    devices=[]
    for device_id,points in data.get("devices",{}).items():
        name=points[-1].get("device_name") if points else device_id
        rx=[x.get("rx_bytes",0) for x in points]
        tx=[x.get("tx_bytes",0) for x in points]
        hs=[x.get("handshake_age_seconds") for x in points]
        devices.append(f"""<div class='metric-box'><h3>{esc(name or device_id)}</h3><div class='m mono'>{esc(device_id)}</div><b>RX · {human_bytes(sum(rx))}</b>{sparkline_svg(rx)}<b>TX · {human_bytes(sum(tx))}</b>{sparkline_svg(tx)}<b>Handshake age (s)</b>{sparkline_svg(hs)}</div>""")
    device_panel=f"<div class='panel'><h2>Device</h2><div class='metric-grid'>{''.join(devices) or '<div class="m">Nessun campione Device</div>'}</div></div>"
    body=f"""<div class='w'><div class='top'><div><h1>Metriche GE360</h1><div class='m'>Fase 9 · campioni ogni 60s · retention 35 giorni</div></div><a class='btn' href='/'>← Dashboard</a></div><div class='panel row'><div>{nav}</div><a class='btn' href='/api/metrics?window={esc(window)}'>JSON</a></div>{bridge_panel}{resource_panel}{device_panel}</div>"""
    return shell(body,"Metriche GE360")


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
<div class='panel'><h2>ACL effettive e override</h2><table><tr><th>Resource</th><th>Sorgente</th><th>Override device</th></tr>{''.join(acl)}</table></div>
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
<div class='panel'><h2>Resource del gruppo</h2><table><tr><th>Resource</th><th>Accesso</th><th></th></tr>{svc_rows}</table></div>
<div class='panel row'><form method='post' action='/group/toggle'><input type='hidden' name='group' value='{esc(g['name'])}'><input type='hidden' name='enabled' value='{'0' if g.get('enabled',True) else '1'}'><button>{'Disabilita gruppo' if g.get('enabled',True) else 'Abilita gruppo'}</button></form><form method='post' action='/group/remove'><input type='hidden' name='group' value='{esc(g['name'])}'><button class='danger'>Elimina gruppo</button></form></div></div>"""
    return shell(body,g["name"])


def resource_page(name:str,error:str="")->str:
    r=find_resource(name)
    if not r:
        return shell("<div class='w panel'>Resource non trovata</div>")
    h=check_resource(r)
    banner=f"<div class='msg err'>{esc(error)}</div>" if error else ""
    selected=lambda x:" selected" if r.get("protocol","tcp")==x else ""
    checked="checked" if r.get("enabled",True) else ""
    checks=h.get("checks",{})
    health_panel=f"""<div class='panel'><div class='row'><div><h2>Health Engine</h2><div><b>{esc(h.get('state','OFFLINE'))}</b> · {esc(h.get('latency_ms') if h.get('latency_ms') is not None else '—')} ms</div><div class='m'>{esc(h.get('error') or 'nessun errore')}</div></div><div><div>TCP: {esc(checks.get('tcp',{}).get('latency_ms') if checks.get('tcp',{}).get('ok') else 'KO')} ms</div><div>HTTP: {esc(checks.get('http',{}).get('status_code') or '—')}</div><div>JSON: {esc('OK' if checks.get('json',{}).get('ok') else ('KO' if checks.get('json',{}).get('performed') else '—'))}</div><div>TLS: {esc(checks.get('tls',{}).get('version') or ('OK' if checks.get('tls',{}).get('ok') else ('KO' if checks.get('tls',{}).get('performed') else '—')))}</div></div></div></div>"""
    body=f"""<div class='w'><div class='top'><div><h1>{esc(r.get('icon','server'))} {esc(r['name'])}</h1><div class='m'>Resource Registry · Health Engine</div></div><a class='btn' href='/'>← Dashboard</a></div>{banner}{health_panel}
<div class='panel'><form method='post' action='/resource/update'><input type='hidden' name='name' value='{esc(r['name'])}'><div class='forms'><div class='box'><label>Icona</label><input name='icon' value='{esc(r.get('icon','server'))}'><label>Descrizione</label><textarea name='description'>{esc(r.get('description',''))}</textarea><label>Protocollo</label><select name='protocol'><option value='tcp'{selected('tcp')}>TCP</option><option value='http'{selected('http')}>HTTP</option><option value='https'{selected('https')}>HTTPS</option></select><label>Abilitata</label><input type='checkbox' name='enabled' value='1' {checked}></div><div class='box'><label>Bridge port</label><input type='number' name='bridge_port' value='{esc(r['bridge_port'])}' required><label>Target host</label><input name='target_host' value='{esc(r['target_host'])}' required><label>Target port</label><input type='number' name='target_port' value='{esc(r['target_port'])}' required><label>Health URL/path</label><input name='health_url' value='{esc(r.get('health_url',''))}'><label>Timeout secondi</label><input type='number' min='0.1' max='30' step='0.1' name='timeout' value='{esc(r.get('timeout_seconds',2.0))}'><p><button class='primary'>Salva Resource</button></p></div></div></form></div>
<div class='panel'><h2>Diagnostica avanzata · Fase 6</h2><form method='post' action='/diagnostics/run'><input type='hidden' name='resource' value='{esc(r['name'])}'><div class='forms'><div class='box'><label>Percorso API opzionale</label><input name='api_path' placeholder='{esc(r.get('health_url') or '/healthz')}'><p class='m'>Se vuoto usa health_url oppure /.</p></div><div class='box'><label>Percorso PDF opzionale</label><input name='pdf_path' placeholder='/api/report/123.pdf'><label>Device opzionale</label><input name='device' placeholder='telefono-milan o dev_...'><label><input type='checkbox' name='traceroute' value='1' checked style='width:auto'> includi traceroute</label><p><button class='primary'>Esegui diagnostica</button></p></div></div></form></div>
<div class='panel row'><div><b>ACL dirette</b><div class='m'>allow: {esc(', '.join(r.get('allowed_devices',[])) or '—')} · deny: {esc(', '.join(r.get('denied_devices',[])) or '—')}</div></div><form method='post' action='/resource/remove'><input type='hidden' name='name' value='{esc(r['name'])}'><button class='danger'>Rimuovi Resource</button></form></div></div>"""
    return shell(body,r["name"])


def diagnostics_page(resource:dict, report:dict, doctor:dict|None=None)->str:
    rows=[]
    for key,item in report.get("checks",{}).items():
        skipped=item.get("skipped",False)
        state="SKIPPED" if skipped else ("OK" if item.get("ok") else "FAIL")
        detail=[]
        for field in ("host","port","status_code","content_type","content_length","latency_ms","packet_loss_percent","rtt_avg_ms","error"):
            value=item.get(field)
            if value not in (None,""):
                detail.append(f"{field}={value}")
        if item.get("addresses"):
            detail.append("addresses="+", ".join(x.get("address","") for x in item["addresses"]))
        if item.get("hops"):
            detail.append("hops="+ " | ".join(item["hops"][:12]))
        if item.get("pdf_magic"):
            detail.append("pdf_magic=true")
        if item.get("json_valid") is not None:
            detail.append("json_valid="+str(item.get("json_valid")).lower())
        rows.append(f"<tr><td><b>{esc(key)}</b></td><td>{esc(state)}</td><td class='mono'>{esc(' · '.join(detail) or '—')}</td></tr>")
    summary=report.get("summary",{})
    doctor=doctor or {}
    findings="".join(f"<li><b>{esc(x.get('category'))}</b> — {esc(x.get('reason'))}</li>" for x in doctor.get("findings",[])) or "<li>Nessun problema classificato.</li>"
    doctor_panel=f"""<div class='panel'><h2>Connection Doctor</h2><div class='n'>{esc(doctor.get('category','—'))}</div><ul>{findings}</ul></div>""" if doctor else ""
    body=f"""<div class='w'><div class='top'><div><h1>Diagnostica · {esc(resource['name'])}</h1><div class='m'>Fase 7 · classificazione deterministica, risultati non persistiti</div></div><a class='btn' href='/resource/{esc(resource['name'])}'>← Resource</a></div>{doctor_panel}
<div class='grid'><div class='card'><div class='n'>{esc(summary.get('performed',0))}</div><div class='m'>test eseguiti</div></div><div class='card'><div class='n'>{esc(summary.get('ok',0))}</div><div class='m'>OK</div></div><div class='card'><div class='n'>{esc(summary.get('failed',0))}</div><div class='m'>falliti</div></div><div class='card'><div class='n'>v0.9</div><div class='m'>Connection Doctor</div></div></div>
<div class='panel'><div class='tw'><table><tr><th>Test</th><th>Esito</th><th>Dettagli</th></tr>{''.join(rows)}</table></div></div>
<div class='panel'><details><summary>JSON completo</summary><pre class='mono'>{esc(json.dumps({"doctor":doctor,"diagnostics":report},indent=2))}</pre></details></div></div>"""
    return shell(body,f"Diagnostica {resource['name']}")


def pairing_page(name:str,payload)->str:
    raw = json.dumps(payload,separators=(",",":")) if isinstance(payload,dict) else str(payload)
    svg=qr_svg(raw); qr=f"<div class='qr'>{svg}</div>" if svg else "QR non disponibile"
    if isinstance(payload,dict):
        info=f"<p><b>Enrollment:</b> <span class='mono'>{esc(payload.get('enrollment_id',''))}</span></p><p><b>HTTPS:</b> <span class='mono'>{esc(payload.get('enrollment_url',''))}</span></p><p><b>Scadenza token:</b> {esc(payload.get('expires_at',''))}</p><p class='m'>Il QR non contiene alcuna private key. Il client genera localmente la chiave WireGuard e invia solo la public key.</p>"
    else:
        info="<p class='m'>Pairing legacy v1 temporaneo.</p>"
    return shell(f"<div class='w'><div class='top'><h1>Pairing {esc(name)}</h1><a class='btn' href='/'>Dashboard</a></div><div class='panel row' style='align-items:flex-start'>{qr}<div style='flex:1;min-width:280px'>{info}<details><summary>Payload</summary><pre class='mono'>{esc(raw)}</pre></details></div></div></div>")


class Handler(BaseHTTPRequestHandler):
    server_version="GE360BridgeDashboard/0.13"
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
        elif path=="/metrics":
            q=parse_qs(urlparse(self.path).query)
            self.send_body(metrics_page((q.get("window") or ["24h"])[0]))
        elif path=="/api/metrics":
            q=parse_qs(urlparse(self.path).query)
            window=(q.get("window") or ["24h"])[0]
            try: data=query_series(window)
            except ValueError: self.send_body('{"error":"invalid_window"}',400,"application/json"); return
            self.send_body(json.dumps(data,indent=2),200,"application/json")
        elif path=="/api/status": self.send_body(json.dumps(status_data(),indent=2),200,"application/json")
        elif path=="/api/health":
            data=status_data().get("health",{})
            self.send_body(json.dumps(data,indent=2),200,"application/json")
        elif path=="/api/audit":
            self.send_body(json.dumps({"events":list_events(limit=200)},indent=2),200,"application/json")
        elif path=="/api/discovery":
            self.send_body(json.dumps(discover_backends(),indent=2),200,"application/json")
        elif path=="/discovery": self.send_body(discovery_page())
        elif path.startswith("/device/"): self.send_body(device_page(path.split("/",2)[2]))
        elif path.startswith("/group/"): self.send_body(group_page(path.split("/",2)[2]))
        elif path.startswith("/resource/"): self.send_body(resource_page(path.split("/",2)[2]))
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
            if path=="/diagnostics/run":
                name=(f.get("resource") or [""])[0]
                resource=find_resource(name)
                if not resource: raise BridgeError("Resource non trovata.")
                report=diagnose_resource(
                    resource,
                    api_path=(f.get("api_path") or [""])[0] or None,
                    pdf_path=(f.get("pdf_path") or [""])[0] or None,
                    include_traceroute=(f.get("traceroute") or ["0"])[0]=="1",
                )
                h=check_resource(resource,use_cache=False)
                doctor=connection_doctor(
                    resource,
                    report,
                    h,
                    device_identifier=(f.get("device") or [""])[0] or None,
                )
                self.send_body(diagnostics_page(resource,report,doctor)); return
            if path=="/discovery/import":
                bridge_raw=(f.get("bridge_port") or [""])[0].strip()
                resource=import_discovered_backend(
                    host=(f.get("host") or ["127.0.0.1"])[0],
                    target_port=int((f.get("target_port") or ["0"])[0]),
                    scheme=(f.get("scheme") or ["http"])[0],
                    bridge_port=int(bridge_raw) if bridge_raw else None,
                    timeout=1.0,
                )
                reload_runtime(); self.redirect(f"/resource/{resource.name}"); return
            if path=="/resource/add":
                register_resource(
                    (f.get("name") or [""])[0].strip(),
                    int((f.get("bridge_port") or ["0"])[0]),
                    (f.get("target_host") or ["127.0.0.1"])[0],
                    int((f.get("target_port") or ["0"])[0]),
                    [],
                    icon=(f.get("icon") or ["server"])[0],
                    description=(f.get("description") or [""])[0],
                    protocol=(f.get("protocol") or ["tcp"])[0],
                    health_url=(f.get("health_url") or [""])[0],
                    timeout_seconds=float((f.get("timeout") or ["2.0"])[0]),
                )
                reload_runtime(); self.redirect("/"); return
            if path=="/resource/update":
                name=(f.get("name") or [""])[0]
                update_resource(
                    name,
                    icon=(f.get("icon") or ["server"])[0],
                    description=(f.get("description") or [""])[0],
                    protocol=(f.get("protocol") or ["tcp"])[0],
                    bridge_port=int((f.get("bridge_port") or ["0"])[0]),
                    target_host=(f.get("target_host") or ["127.0.0.1"])[0],
                    target_port=int((f.get("target_port") or ["0"])[0]),
                    health_url=(f.get("health_url") or [""])[0],
                    timeout_seconds=float((f.get("timeout") or ["2.0"])[0]),
                    enabled=(f.get("enabled") or ["0"])[0]=="1",
                )
                reload_runtime(); self.redirect(f"/resource/{name}"); return
            if path=="/resource/remove":
                name=(f.get("name") or [""])[0]
                if not remove_resource(name): raise BridgeError("Resource non trovata.")
                reload_runtime(); self.redirect("/"); return
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
