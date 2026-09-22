from __future__ import annotations

import os
import sqlite3
import subprocess
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

WINDOWS = {
    "1h": (3600, 60),
    "24h": (86400, 300),
    "7d": (604800, 1800),
    "30d": (2592000, 7200),
}
RETENTION_SECONDS = 35 * 86400


def metrics_db_path() -> Path:
    return Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge")) / "metrics.db"


def connect() -> sqlite3.Connection:
    path = metrics_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=5.0)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.executescript(
        """
        CREATE TABLE IF NOT EXISTS device_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_epoch INTEGER NOT NULL,
            device_id TEXT NOT NULL,
            device_name TEXT,
            rx_bytes INTEGER NOT NULL,
            tx_bytes INTEGER NOT NULL,
            handshake_age_seconds INTEGER,
            connected INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_device_samples_time ON device_samples(ts_epoch);
        CREATE INDEX IF NOT EXISTS idx_device_samples_device ON device_samples(device_id, ts_epoch);

        CREATE TABLE IF NOT EXISTS resource_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_epoch INTEGER NOT NULL,
            resource TEXT NOT NULL,
            state TEXT NOT NULL,
            latency_ms REAL,
            error TEXT
        );
        CREATE INDEX IF NOT EXISTS idx_resource_samples_time ON resource_samples(ts_epoch);
        CREATE INDEX IF NOT EXISTS idx_resource_samples_resource ON resource_samples(resource, ts_epoch);

        CREATE TABLE IF NOT EXISTS bridge_samples (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts_epoch INTEGER NOT NULL,
            uptime_seconds REAL,
            connections_total INTEGER NOT NULL,
            errors_total INTEGER NOT NULL
        );
        CREATE INDEX IF NOT EXISTS idx_bridge_samples_time ON bridge_samples(ts_epoch);
        """
    )
    db.commit()
    return db


def init_db() -> None:
    with connect():
        pass


def parse_wg_dump(text: str, now_epoch: int | None = None) -> dict[str, dict[str, Any]]:
    now = int(now_epoch or time.time())
    lines = [x for x in text.splitlines() if x.strip()]
    out: dict[str, dict[str, Any]] = {}
    for raw in lines[1:]:
        p = raw.split("\t")
        if len(p) < 7:
            continue
        try:
            latest = int(p[4])
        except ValueError:
            latest = 0
        try:
            rx = int(p[5])
            tx = int(p[6])
        except ValueError:
            rx = tx = 0
        age = None if latest <= 0 else max(0, now - latest)
        out[p[0]] = {
            "rx_bytes": max(0, rx),
            "tx_bytes": max(0, tx),
            "handshake_age_seconds": age,
            "connected": age is not None and age <= 180,
        }
    return out


def system_uptime_seconds() -> float | None:
    try:
        return round(float(Path("/proc/uptime").read_text(encoding="utf-8").split()[0]), 2)
    except (OSError, ValueError, IndexError):
        return None


def audit_totals() -> tuple[int, int]:
    try:
        from .audit import connect as audit_connect
        with audit_connect() as db:
            connections = db.execute(
                "SELECT COUNT(*) FROM audit_events WHERE event='RESOURCE_ACCESS'"
            ).fetchone()[0]
            errors = db.execute(
                """
                SELECT COUNT(*) FROM audit_events
                WHERE (event='RESOURCE_ACCESS' AND result IN ('ERROR','DENY'))
                   OR event='RESOURCE_OFFLINE'
                """
            ).fetchone()[0]
        return int(connections), int(errors)
    except Exception:
        return 0, 0


def read_wg_dump() -> str:
    try:
        proc = subprocess.run(
            ["wg", "show", "wg0", "dump"],
            text=True,
            capture_output=True,
            timeout=2,
            check=False,
        )
        return proc.stdout if proc.returncode == 0 else ""
    except (OSError, subprocess.TimeoutExpired):
        return ""


def persist_sample(
    *,
    ts_epoch: int,
    device_rows: list[dict[str, Any]],
    resource_rows: list[dict[str, Any]],
    bridge_row: dict[str, Any],
) -> None:
    cutoff = int(ts_epoch) - RETENTION_SECONDS
    with connect() as db:
        db.executemany(
            """
            INSERT INTO device_samples(
                ts_epoch,device_id,device_name,rx_bytes,tx_bytes,handshake_age_seconds,connected
            ) VALUES(?,?,?,?,?,?,?)
            """,
            [
                (
                    int(ts_epoch),
                    str(x["device_id"]),
                    x.get("device_name"),
                    int(x.get("rx_bytes", 0)),
                    int(x.get("tx_bytes", 0)),
                    x.get("handshake_age_seconds"),
                    1 if x.get("connected") else 0,
                )
                for x in device_rows
            ],
        )
        db.executemany(
            """
            INSERT INTO resource_samples(ts_epoch,resource,state,latency_ms,error)
            VALUES(?,?,?,?,?)
            """,
            [
                (
                    int(ts_epoch),
                    str(x["resource"]),
                    str(x.get("state") or "UNKNOWN"),
                    x.get("latency_ms"),
                    x.get("error"),
                )
                for x in resource_rows
            ],
        )
        db.execute(
            """
            INSERT INTO bridge_samples(ts_epoch,uptime_seconds,connections_total,errors_total)
            VALUES(?,?,?,?)
            """,
            (
                int(ts_epoch),
                bridge_row.get("uptime_seconds"),
                int(bridge_row.get("connections_total", 0)),
                int(bridge_row.get("errors_total", 0)),
            ),
        )
        db.execute("DELETE FROM device_samples WHERE ts_epoch < ?", (cutoff,))
        db.execute("DELETE FROM resource_samples WHERE ts_epoch < ?", (cutoff,))
        db.execute("DELETE FROM bridge_samples WHERE ts_epoch < ?", (cutoff,))
        db.commit()


def collect_snapshot() -> dict[str, Any]:
    from .core import list_devices, list_resources
    from .health import check_resources

    now = int(time.time())
    wg = parse_wg_dump(read_wg_dump(), now)
    devices = []
    for device in list_devices():
        peer = wg.get(device.get("public_key", ""), {})
        devices.append({
            "device_id": device["device_id"],
            "device_name": device.get("name"),
            "rx_bytes": peer.get("rx_bytes", 0),
            "tx_bytes": peer.get("tx_bytes", 0),
            "handshake_age_seconds": peer.get("handshake_age_seconds"),
            "connected": bool(peer.get("connected")) and bool(device.get("enabled", True)),
        })

    health = check_resources(list_resources())
    resources = [{
        "resource": h["name"],
        "state": h.get("state"),
        "latency_ms": h.get("latency_ms"),
        "error": h.get("error"),
    } for h in health]

    connections, errors = audit_totals()
    bridge = {
        "uptime_seconds": system_uptime_seconds(),
        "connections_total": connections,
        "errors_total": errors,
    }
    persist_sample(ts_epoch=now, device_rows=devices, resource_rows=resources, bridge_row=bridge)
    return {"ts_epoch": now, "devices": devices, "resources": resources, "bridge": bridge}


def _window(window: str) -> tuple[int, int]:
    if window not in WINDOWS:
        raise ValueError("Finestra non valida: usa 1h, 24h, 7d o 30d.")
    return WINDOWS[window]


def _bucket(ts: int, bucket_seconds: int) -> int:
    return int(ts // bucket_seconds * bucket_seconds)


def query_series(
    window: str = "24h",
    *,
    resource: str | None = None,
    device: str | None = None,
    now_epoch: int | None = None,
) -> dict[str, Any]:
    seconds, bucket_seconds = _window(window)
    now = int(now_epoch or time.time())
    since = now - seconds
    with connect() as db:
        db.row_factory = sqlite3.Row
        d_where = "ts_epoch >= ?"
        d_args: list[Any] = [since]
        if device:
            d_where += " AND (device_id=? OR device_name=?)"
            d_args.extend([device, device])
        device_rows = [dict(x) for x in db.execute(
            f"SELECT * FROM device_samples WHERE {d_where} ORDER BY device_id,ts_epoch", d_args
        ).fetchall()]

        r_where = "ts_epoch >= ?"
        r_args: list[Any] = [since]
        if resource:
            r_where += " AND resource=?"
            r_args.append(resource)
        resource_rows = [dict(x) for x in db.execute(
            f"SELECT * FROM resource_samples WHERE {r_where} ORDER BY resource,ts_epoch", r_args
        ).fetchall()]

        bridge_rows = [dict(x) for x in db.execute(
            "SELECT * FROM bridge_samples WHERE ts_epoch >= ? ORDER BY ts_epoch", (since,)
        ).fetchall()]

    device_series: dict[str, list[dict[str, Any]]] = {}
    by_device: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in device_rows:
        by_device[row["device_id"]].append(row)
    for device_id, rows in by_device.items():
        buckets: dict[int, dict[str, Any]] = {}
        prev_rx = prev_tx = None
        for row in rows:
            b = _bucket(int(row["ts_epoch"]), bucket_seconds)
            item = buckets.setdefault(b, {
                "ts_epoch": b,
                "device_id": device_id,
                "device_name": row.get("device_name"),
                "rx_bytes": 0,
                "tx_bytes": 0,
                "handshake_age_sum": 0.0,
                "handshake_samples": 0,
                "connected_samples": 0,
                "samples": 0,
            })
            rx = int(row["rx_bytes"])
            tx = int(row["tx_bytes"])
            if prev_rx is not None:
                item["rx_bytes"] += max(0, rx - prev_rx)
                item["tx_bytes"] += max(0, tx - prev_tx)
            prev_rx, prev_tx = rx, tx
            if row.get("handshake_age_seconds") is not None:
                item["handshake_age_sum"] += float(row["handshake_age_seconds"])
                item["handshake_samples"] += 1
            item["connected_samples"] += 1 if row.get("connected") else 0
            item["samples"] += 1
        device_series[device_id] = [{
            "ts_epoch": x["ts_epoch"],
            "device_id": device_id,
            "device_name": x["device_name"],
            "rx_bytes": x["rx_bytes"],
            "tx_bytes": x["tx_bytes"],
            "handshake_age_seconds": round(x["handshake_age_sum"] / x["handshake_samples"], 2) if x["handshake_samples"] else None,
            "connected_ratio": round(x["connected_samples"] / x["samples"], 3) if x["samples"] else 0,
        } for x in sorted(buckets.values(), key=lambda y:y["ts_epoch"])]

    resource_series: dict[str, list[dict[str, Any]]] = {}
    by_resource: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for row in resource_rows:
        by_resource[row["resource"]].append(row)
    for name, rows in by_resource.items():
        buckets: dict[int, dict[str, Any]] = {}
        for row in rows:
            b = _bucket(int(row["ts_epoch"]), bucket_seconds)
            item = buckets.setdefault(b, {
                "ts_epoch": b, "latency_sum":0.0, "latency_samples":0,
                "online":0, "errors":0, "samples":0,
            })
            if row.get("latency_ms") is not None:
                item["latency_sum"] += float(row["latency_ms"])
                item["latency_samples"] += 1
            item["online"] += 1 if row.get("state") == "ONLINE" else 0
            item["errors"] += 1 if row.get("state") != "ONLINE" or row.get("error") else 0
            item["samples"] += 1
        resource_series[name] = [{
            "ts_epoch": x["ts_epoch"],
            "latency_ms": round(x["latency_sum"]/x["latency_samples"],2) if x["latency_samples"] else None,
            "online_ratio": round(x["online"]/x["samples"],3) if x["samples"] else 0,
            "errors": x["errors"],
            "samples": x["samples"],
        } for x in sorted(buckets.values(), key=lambda y:y["ts_epoch"])]

    bridge_buckets: dict[int, dict[str, Any]] = {}
    prev_connections = prev_errors = None
    for row in bridge_rows:
        b = _bucket(int(row["ts_epoch"]), bucket_seconds)
        item = bridge_buckets.setdefault(b, {
            "ts_epoch":b,"uptime_seconds":row.get("uptime_seconds"),
            "connections":0,"errors":0,
        })
        current_connections = int(row.get("connections_total",0))
        current_errors = int(row.get("errors_total",0))
        if prev_connections is not None:
            item["connections"] += max(0,current_connections-prev_connections)
            item["errors"] += max(0,current_errors-prev_errors)
        prev_connections,prev_errors=current_connections,current_errors
        item["uptime_seconds"]=row.get("uptime_seconds")

    return {
        "window": window,
        "since_epoch": since,
        "until_epoch": now,
        "bucket_seconds": bucket_seconds,
        "devices": device_series,
        "resources": resource_series,
        "bridge": sorted(bridge_buckets.values(), key=lambda x:x["ts_epoch"]),
    }
