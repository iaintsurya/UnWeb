"""Small persistent SQLite store for scan results.

The schema is initialized idempotently at application startup. Keep database
files out of version control; set UNWEB_DB_PATH to choose another location.
"""
import json
import os
import sqlite3
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import ScanResult

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "unweb.sqlite3"
DB_PATH = Path(os.environ.get("UNWEB_DB_PATH", str(DEFAULT_DB_PATH)))
MAX_STORED_SCANS = 250
MAX_AUDIT_EVENTS_PER_OWNER = 1000


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


@contextmanager
def _connection() -> Iterator[sqlite3.Connection]:
    connection = _connect()
    try:
        with connection:
            yield connection
    finally:
        connection.close()


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connection() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL DEFAULT 'local',
                requested_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                title TEXT,
                status_code INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        columns = {row["name"] for row in connection.execute("PRAGMA table_info(scans)")}
        if "owner_id" not in columns:
            connection.execute("ALTER TABLE scans ADD COLUMN owner_id TEXT NOT NULL DEFAULT 'local'")
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_owner_scanned_at ON scans(owner_id, scanned_at DESC)"
        )
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                owner_id TEXT NOT NULL,
                action TEXT NOT NULL,
                resource_id TEXT,
                occurred_at TEXT NOT NULL,
                metadata_json TEXT NOT NULL DEFAULT '{}'
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_audit_owner_time ON audit_events(owner_id, event_id DESC)"
        )


def save_scan(result: ScanResult, owner_id: str = "local") -> None:
    with _connection() as connection:
        connection.execute(
            """
            INSERT INTO scans (
                id, owner_id, requested_url, final_url, title, status_code, scanned_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                owner_id=excluded.owner_id,
                requested_url=excluded.requested_url,
                final_url=excluded.final_url,
                title=excluded.title,
                status_code=excluded.status_code,
                scanned_at=excluded.scanned_at,
                payload=excluded.payload
            """,
            (
                result.id,
                owner_id,
                result.requested_url,
                result.final_url,
                result.title,
                result.status_code,
                result.scanned_at,
                result.model_dump_json(),
            ),
        )
        connection.execute(
            """
            DELETE FROM scans
            WHERE owner_id = ? AND id NOT IN (
                SELECT id FROM scans
                WHERE owner_id = ?
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            )
            """,
            (owner_id, owner_id, MAX_STORED_SCANS),
        )


def get_scan(scan_id: str, owner_id: str = "local") -> ScanResult | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT payload FROM scans WHERE id = ? AND owner_id = ?", (scan_id, owner_id)
        ).fetchone()
    if row is None:
        return None
    return ScanResult.model_validate_json(row["payload"])


def list_scans(limit: int = 20, owner_id: str = "local") -> list[dict[str, object]]:
    safe_limit = max(1, min(int(limit), 100))
    with _connection() as connection:
        rows = connection.execute(
            """
            SELECT id, requested_url, final_url, title, status_code, scanned_at
            FROM scans
            WHERE owner_id = ?
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
            """,
            (owner_id, safe_limit),
        ).fetchall()
    return [dict(row) for row in rows]


def record_audit_event(
    owner_id: str,
    action: str,
    resource_id: str | None = None,
    metadata: dict[str, object] | None = None,
) -> None:
    """Persist a minimal owner-scoped event; callers must not include secrets or raw response data."""
    with _connection() as connection:
        connection.execute(
            """INSERT INTO audit_events (owner_id, action, resource_id, occurred_at, metadata_json)
            VALUES (?, ?, ?, ?, ?)""",
            (
                owner_id,
                action,
                resource_id,
                datetime.now(timezone.utc).isoformat(),
                json.dumps(metadata or {}, sort_keys=True, separators=(",", ":")),
            ),
        )
        connection.execute(
            """DELETE FROM audit_events
            WHERE owner_id = ? AND event_id NOT IN (
                SELECT event_id FROM audit_events WHERE owner_id = ?
                ORDER BY event_id DESC LIMIT ?
            )""",
            (owner_id, owner_id, MAX_AUDIT_EVENTS_PER_OWNER),
        )


def list_audit_events(owner_id: str, limit: int = 50) -> list[dict[str, object]]:
    safe_limit = max(1, min(int(limit), 100))
    with _connection() as connection:
        rows = connection.execute(
            """SELECT event_id, action, resource_id, occurred_at, metadata_json
            FROM audit_events WHERE owner_id = ? ORDER BY event_id DESC LIMIT ?""",
            (owner_id, safe_limit),
        ).fetchall()
    return [
        {
            "event_id": row["event_id"],
            "action": row["action"],
            "resource_id": row["resource_id"],
            "occurred_at": row["occurred_at"],
            "metadata": json.loads(row["metadata_json"]),
        }
        for row in rows
    ]
