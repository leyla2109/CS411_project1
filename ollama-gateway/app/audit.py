"""Append-only audit trail of security-relevant events."""
from __future__ import annotations

import json
import time
from typing import Any

from .db import Database


class AuditLog:
    def __init__(self, db: Database) -> None:
        self.db = db

    def record(self, action: str, decision: str = "info", *, actor: str | None = None,
               actor_type: str = "system", resource: str | None = None, model: str | None = None,
               status: int | None = None, ip: str | None = None, request_id: str | None = None,
               detail: dict[str, Any] | str | None = None) -> None:
        if isinstance(detail, dict):
            detail = json.dumps(detail, separators=(",", ":"))
        self.db.run(
            "INSERT INTO audit_log (ts, actor, actor_type, action, resource, model, decision, status, ip, request_id, detail)"
            " VALUES (?,?,?,?,?,?,?,?,?,?,?)",
            (time.time(), actor, actor_type, action, resource, model, decision, status, ip, request_id, detail),
        )

    def recent(self, limit: int = 200, actor: str | None = None, decision: str | None = None) -> list[dict]:
        sql, params = "SELECT * FROM audit_log WHERE 1=1", []
        if actor:
            sql += " AND actor LIKE ?"
            params.append(f"%{actor}%")
        if decision:
            sql += " AND decision = ?"
            params.append(decision)
        sql += " ORDER BY id DESC LIMIT ?"
        params.append(limit)
        return [dict(r) for r in self.db.all(sql, tuple(params))]
