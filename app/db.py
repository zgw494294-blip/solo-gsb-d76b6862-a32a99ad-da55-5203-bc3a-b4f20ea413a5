"""SQLite persistence for rule **templates** only.

The database stores rule definitions (paths, actions, parameters, per-rule
salts). It never stores source JSON, original values or masked output — see
README "安全边界".
"""
from __future__ import annotations

import json
import os
import sqlite3
import threading
import time
import uuid
from typing import Any

_write_lock = threading.Lock()

SCHEMA = """
CREATE TABLE IF NOT EXISTS templates (
    id          TEXT PRIMARY KEY,
    name        TEXT NOT NULL UNIQUE,
    description TEXT NOT NULL DEFAULT '',
    rules       TEXT NOT NULL,
    created_at  INTEGER NOT NULL,
    updated_at  INTEGER NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    directory = os.path.dirname(os.path.abspath(db_path))
    os.makedirs(directory, exist_ok=True)
    # check_same_thread=False: FastAPI runs sync endpoints in a worker
    # thread pool; the single local process serializes writes with the
    # module-level connection + WAL.
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA busy_timeout=5000")
    conn.execute(SCHEMA)
    conn.commit()
    return conn


def _row_to_template(row: sqlite3.Row) -> dict[str, Any]:
    return {
        "id": row["id"],
        "name": row["name"],
        "description": row["description"],
        "rules": json.loads(row["rules"]),
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
    }


def list_templates(conn: sqlite3.Connection) -> list[dict[str, Any]]:
    rows = conn.execute(
        "SELECT * FROM templates ORDER BY updated_at DESC"
    ).fetchall()
    return [_row_to_template(r) for r in rows]


def get_template(conn: sqlite3.Connection, template_id: str) -> dict[str, Any] | None:
    row = conn.execute("SELECT * FROM templates WHERE id = ?", (template_id,)).fetchone()
    return _row_to_template(row) if row else None


def create_template(
    conn: sqlite3.Connection,
    name: str,
    description: str,
    rules: list[dict],
) -> dict[str, Any]:
    template_id = uuid.uuid4().hex
    now = int(time.time())
    with _write_lock:
        conn.execute(
        "INSERT INTO templates (id, name, description, rules, created_at, updated_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
            (template_id, name, description, json.dumps(rules, ensure_ascii=False), now, now),
        )
        conn.commit()
    return get_template(conn, template_id)


def update_template(
    conn: sqlite3.Connection,
    template_id: str,
    name: str,
    description: str,
    rules: list[dict],
) -> dict[str, Any] | None:
    now = int(time.time())
    with _write_lock:
        cur = conn.execute(
        "UPDATE templates SET name = ?, description = ?, rules = ?, updated_at = ?"
        " WHERE id = ?",
            (name, description, json.dumps(rules, ensure_ascii=False), now, template_id),
        )
        conn.commit()
        if cur.rowcount == 0:
            return None
    return get_template(conn, template_id)


def delete_template(conn: sqlite3.Connection, template_id: str) -> bool:
    with _write_lock:
        cur = conn.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        conn.commit()
    return cur.rowcount > 0
