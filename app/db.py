"""SQLite 存储：仅保存“规则模板”。

安全约束：本模块只接受规则定义（name/path/action/参数），
绝不写入用户粘贴的原始 JSON 或任何原值。
"""
from __future__ import annotations

import json
import os
import sqlite3
import uuid
from datetime import datetime, timezone
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS templates (
    id         TEXT PRIMARY KEY,
    name       TEXT NOT NULL,
    rules_json TEXT NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
"""


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class TemplateStore:
    def __init__(self, db_path: str):
        os.makedirs(os.path.dirname(os.path.abspath(db_path)), exist_ok=True)
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(_SCHEMA)
        self._conn.commit()

    def close(self):
        self._conn.close()

    # -- CRUD ---------------------------------------------------------------
    def list(self) -> list[dict]:
        rows = self._conn.execute(
            "SELECT id, name, rules_json, created_at, updated_at "
            "FROM templates ORDER BY updated_at DESC"
        ).fetchall()
        return [
            {
                "id": r["id"],
                "name": r["name"],
                "rule_count": len(json.loads(r["rules_json"])),
                "created_at": r["created_at"],
                "updated_at": r["updated_at"],
            }
            for r in rows
        ]

    def get(self, template_id: str) -> Optional[dict]:
        r = self._conn.execute(
            "SELECT * FROM templates WHERE id = ?", (template_id,)
        ).fetchone()
        if r is None:
            return None
        return {
            "id": r["id"],
            "name": r["name"],
            "rules": json.loads(r["rules_json"]),
            "created_at": r["created_at"],
            "updated_at": r["updated_at"],
        }

    def create(self, name: str, rules: list[dict]) -> dict:
        tid = uuid.uuid4().hex[:12]
        now = _now()
        self._conn.execute(
            "INSERT INTO templates (id, name, rules_json, created_at, updated_at) "
            "VALUES (?, ?, ?, ?, ?)",
            (tid, name, json.dumps(rules, ensure_ascii=False), now, now),
        )
        self._conn.commit()
        return self.get(tid)

    def update(self, template_id: str, name: str, rules: list[dict]) -> Optional[dict]:
        cur = self._conn.execute(
            "UPDATE templates SET name = ?, rules_json = ?, updated_at = ? WHERE id = ?",
            (name, json.dumps(rules, ensure_ascii=False), _now(), template_id),
        )
        self._conn.commit()
        if cur.rowcount == 0:
            return None
        return self.get(template_id)

    def delete(self, template_id: str) -> bool:
        cur = self._conn.execute("DELETE FROM templates WHERE id = ?", (template_id,))
        self._conn.commit()
        return cur.rowcount > 0
