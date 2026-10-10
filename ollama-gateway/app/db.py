"""SQLite persistence (Repository layer).

The gateway keeps its own small database, completely separate from Ollama's
model store. Ollama is never modified: the IAM module only *sits in front of* it.
"""
from __future__ import annotations

import sqlite3
import threading
from contextlib import contextmanager
from pathlib import Path
from typing import Any, Iterator

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    username        TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name    TEXT NOT NULL,
    email           TEXT,
    password_hash   TEXT NOT NULL,
    auth_source     TEXT NOT NULL DEFAULT 'admin',   -- admin (created by an admin) | signup (self-registered)
    is_active       INTEGER NOT NULL DEFAULT 1,
    mfa_secret      TEXT,
    mfa_enabled     INTEGER NOT NULL DEFAULT 0,
    mfa_last_step   INTEGER NOT NULL DEFAULT 0,      -- replay protection for TOTP codes
    failed_logins   INTEGER NOT NULL DEFAULT 0,
    locked_until    REAL NOT NULL DEFAULT 0,
    model_allow     TEXT NOT NULL DEFAULT '*',       -- comma separated glob patterns
    created_at      REAL NOT NULL,
    last_login_at   REAL
);

CREATE TABLE IF NOT EXISTS user_roles (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role    TEXT NOT NULL,
    PRIMARY KEY (user_id, role)
);

CREATE TABLE IF NOT EXISTS sessions (
    id          TEXT PRIMARY KEY,
    user_id     INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at  REAL NOT NULL,
    expires_at  REAL NOT NULL,
    mfa_pending INTEGER NOT NULL DEFAULT 0,
    csrf        TEXT NOT NULL,
    ip          TEXT,
    user_agent  TEXT,
    auth_method TEXT NOT NULL DEFAULT 'password',
    revoked     INTEGER NOT NULL DEFAULT 0
);

-- Pending self sign-ups, waiting for the e-mailed code. Nothing lands in
-- `users` until the code is confirmed.
CREATE TABLE IF NOT EXISTS signups (
    id            TEXT PRIMARY KEY,      -- random token kept in a cookie
    email         TEXT NOT NULL COLLATE NOCASE,
    display_name  TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    role          TEXT NOT NULL,
    code_hash     TEXT NOT NULL,
    attempts      INTEGER NOT NULL DEFAULT 0,
    sends         INTEGER NOT NULL DEFAULT 1,
    last_sent_at  REAL NOT NULL,
    expires_at    REAL NOT NULL,
    created_at    REAL NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    ts          REAL NOT NULL,
    actor       TEXT,
    actor_type  TEXT,          -- session | anonymous | system
    action      TEXT NOT NULL,
    resource    TEXT,
    model       TEXT,
    decision    TEXT NOT NULL, -- allow | deny | info
    status      INTEGER,
    ip          TEXT,
    request_id  TEXT,
    detail      TEXT
);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON audit_log(ts DESC);
"""


class Database:
    """Thin thread-safe wrapper; one connection, serialized writes."""

    def __init__(self, path: Path | str) -> None:
        self._conn = sqlite3.connect(str(path), check_same_thread=False, isolation_level=None)
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA foreign_keys = ON")
        self._conn.execute("PRAGMA journal_mode = WAL")
        self._lock = threading.RLock()
        self._conn.executescript(SCHEMA)

    @contextmanager
    def tx(self) -> Iterator[sqlite3.Connection]:
        with self._lock:
            self._conn.execute("BEGIN")
            try:
                yield self._conn
                self._conn.execute("COMMIT")
            except Exception:
                self._conn.execute("ROLLBACK")
                raise

    def one(self, sql: str, params: tuple[Any, ...] = ()) -> sqlite3.Row | None:
        with self._lock:
            return self._conn.execute(sql, params).fetchone()

    def all(self, sql: str, params: tuple[Any, ...] = ()) -> list[sqlite3.Row]:
        with self._lock:
            return self._conn.execute(sql, params).fetchall()

    def run(self, sql: str, params: tuple[Any, ...] = ()) -> int:
        with self._lock:
            cur = self._conn.execute(sql, params)
            return cur.lastrowid or cur.rowcount

    def close(self) -> None:
        self._conn.close()
