from __future__ import annotations

import os
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

def audit_db_path() -> Path:
    return Path(os.environ.get("GE360_BRIDGE_STATE_DIR", "/etc/ge360-bridge")) / "audit.db"

ALLOWED_EVENTS = {
    "DEVICE_CONNECTED",
    "DEVICE_DISCONNECTED",
    "RESOURCE_ACCESS",
    "RESOURCE_ONLINE",
    "RESOURCE_OFFLINE",
    "ACL_CHANGED",
    "SELF_HEAL_RESTART",
    "SELF_HEAL_BLOCKED",
    "SELF_HEAL_RECOVERED",
    "P2P_PREPARED",
    "P2P_SUCCEEDED",
    "P2P_FAILED",
    "RELAY_ACTIVE",
    "RELAY_FAILED",
}


def _now_iso() -> str:
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat()


def connect() -> sqlite3.Connection:
    path = audit_db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    db = sqlite3.connect(str(path), timeout=5.0)
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    db.execute("PRAGMA journal_mode=WAL")
    db.execute("PRAGMA synchronous=NORMAL")
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS audit_events (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            event TEXT NOT NULL,
            device_id TEXT,
            device_name TEXT,
            resource TEXT,
            action TEXT,
            result TEXT,
            ip TEXT,
            latency_ms REAL,
            error TEXT
        )
        """
    )
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_timestamp ON audit_events(timestamp DESC)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_device ON audit_events(device_id)")
    db.execute("CREATE INDEX IF NOT EXISTS idx_audit_resource ON audit_events(resource)")
    db.commit()
    return db


def init_db() -> None:
    with connect():
        pass


def _clean(value: Any, max_len: int = 256) -> str | None:
    if value is None:
        return None
    text = str(value).replace("\x00", "").strip()
    return text[:max_len] if text else None


def write_event(
    event: str,
    *,
    device_id: str | None = None,
    device_name: str | None = None,
    resource: str | None = None,
    action: str | None = None,
    result: str | None = None,
    ip: str | None = None,
    latency_ms: float | None = None,
    error: str | None = None,
    timestamp: str | None = None,
) -> int:
    if event not in ALLOWED_EVENTS:
        raise ValueError(f"Evento audit non consentito: {event}")
    latency = None if latency_ms is None else round(float(latency_ms), 2)
    with connect() as db:
        cur = db.execute(
            """
            INSERT INTO audit_events(
                timestamp,event,device_id,device_name,resource,action,result,ip,latency_ms,error
            ) VALUES(?,?,?,?,?,?,?,?,?,?)
            """,
            (
                timestamp or _now_iso(),
                event,
                _clean(device_id, 128),
                _clean(device_name, 128),
                _clean(resource, 128),
                _clean(action, 128),
                _clean(result, 128),
                _clean(ip, 128),
                latency,
                _clean(error, 512),
            ),
        )
        return int(cur.lastrowid)


def list_events(
    *,
    limit: int = 100,
    event: str | None = None,
    device: str | None = None,
    resource: str | None = None,
) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 1000))
    where: list[str] = []
    values: list[Any] = []
    if event:
        where.append("event = ?")
        values.append(event)
    if device:
        where.append("(device_id = ? OR device_name = ?)")
        values.extend([device, device])
    if resource:
        where.append("resource = ?")
        values.append(resource)
    clause = (" WHERE " + " AND ".join(where)) if where else ""
    query = (
        "SELECT id,timestamp,event,device_id,device_name,resource,action,result,ip,latency_ms,error "
        "FROM audit_events" + clause + " ORDER BY id DESC LIMIT ?"
    )
    values.append(limit)
    with connect() as db:
        db.row_factory = sqlite3.Row
        rows = db.execute(query, values).fetchall()
    return [dict(row) for row in rows]


def count_events() -> int:
    with connect() as db:
        row = db.execute("SELECT COUNT(*) FROM audit_events").fetchone()
    return int(row[0] if row else 0)
