from __future__ import annotations

import html
from typing import Any

from .core import effective_resources_for_device, list_groups, list_resources
from .health import check_resources

BRIDGE_IP = "10.88.0.1"


def launch_url(resource: dict[str, Any], bridge_ip: str = BRIDGE_IP) -> str:
    protocol = str(resource.get("protocol", "tcp")).lower()
    port = int(resource["bridge_port"])
    return f"{protocol}://{bridge_ip}:{port}"


def resources_for_launcher(
    device: dict[str, Any],
    *,
    resources: list[dict[str, Any]] | None = None,
    groups: list[dict[str, Any]] | None = None,
    health_results: list[dict[str, Any]] | None = None,
) -> list[dict[str, Any]]:
    source_resources = resources if resources is not None else list_resources()
    source_groups = groups if groups is not None else list_groups()
    effective = effective_resources_for_device(device, source_resources, source_groups)
    health = health_results if health_results is not None else check_resources(effective)
    health_by_name = {x["name"]: x for x in health}
    out=[]
    for r in effective:
        protocol=str(r.get("protocol","tcp")).lower()
        out.append({
            "name":r["name"],
            "icon":r.get("icon","server"),
            "description":r.get("description",""),
            "protocol":protocol,
            "bridge_port":int(r["bridge_port"]),
            "url":launch_url(r),
            "launchable":protocol in {"http","https"},
            "health":health_by_name.get(r["name"]),
        })
    return out


def multi_server_catalog_payload(
    device: dict[str, Any],
    local_resources: list[dict[str, Any]],
    catalog: dict[str, Any],
) -> dict[str, Any]:
    local_allowed = {item["name"] for item in local_resources}
    resources: list[dict[str, Any]] = []
    for item in catalog.get("resources", []):
        if item.get("local") and item.get("name") not in local_allowed:
            continue
        resources.append(dict(item))
    return {
        "schema": "ge360-resource-launcher-multi/v1",
        "device": device.get("name"),
        "device_id": device.get("device_id"),
        "control_server_id": catalog.get("control_server_id"),
        "servers": catalog.get("servers", []),
        "resources": resources,
        "remote_resource_proxy": False,
    }


def render_hub(device: dict[str, Any], resources: list[dict[str, Any]]) -> str:
    esc=lambda x: html.escape(str(x),quote=True)
    cards=[]
    for r in resources:
        h=r.get("health") or {}
        state=h.get("state","UNKNOWN")
        action=(
            f"<a class='open' href='{esc(r['url'])}'>Apri</a>"
            if r.get("launchable")
            else f"<span class='endpoint'>{esc(r['url'])}</span>"
        )
        cards.append(
            "<article class='card'>"
            f"<div class='icon'>{esc(r.get('icon','server'))}</div>"
            f"<h2>{esc(r['name'])}</h2>"
            f"<p>{esc(r.get('description') or 'GE360 Resource')}</p>"
            f"<div class='state'>{esc(state)}</div>"
            f"{action}"
            "</article>"
        )
    empty="<div class='empty'>Nessuna Resource autorizzata per questo dispositivo.</div>"
    return f"""<!doctype html>
<html lang='it'><head><meta charset='utf-8'><meta name='viewport' content='width=device-width,initial-scale=1'>
<title>GE360 HUB</title>
<style>
:root{{color-scheme:dark}}*{{box-sizing:border-box}}body{{margin:0;background:#07111f;color:#eef6ff;font:15px system-ui}}main{{max-width:980px;margin:auto;padding:22px}}header{{margin-bottom:20px}}.m{{color:#91a7bd}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(220px,1fr));gap:14px}}.card{{background:#0d1b2a;border:1px solid #203b58;border-radius:16px;padding:18px}}.icon{{font-size:26px}}h2{{margin:8px 0}}p{{color:#91a7bd;min-height:38px}}.state{{font-size:12px;margin:10px 0}}.open{{display:inline-block;background:#116aa9;color:white;text-decoration:none;padding:9px 13px;border-radius:9px}}.endpoint{{font:12px monospace;word-break:break-all}}.empty{{padding:20px;border:1px dashed #203b58;border-radius:14px}}
</style></head><body><main><header><h1>GE360 HUB</h1><div class='m'>Device: {esc(device.get('name',''))} · {esc(device.get('vpn_ip',''))}</div></header>
<div class='grid'>{''.join(cards) if cards else empty}</div></main></body></html>"""


def launcher_payload(device: dict[str, Any], resources: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "schema":"ge360-resource-launcher/v1",
        "device":device.get("name"),
        "device_id":device.get("device_id"),
        "vpn_ip":device.get("vpn_ip"),
        "resources":resources,
    }
