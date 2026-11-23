"""Small persistent SQLite store for scan results.

The schema is initialized idempotently at application startup. Keep database
files out of version control; set UNWEB_DB_PATH to choose another location.
"""
import os
import sqlite3
from pathlib import Path

from .models import ScanResult

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "unweb.sqlite3"
DB_PATH = Path(os.environ.get("UNWEB_DB_PATH", str(DEFAULT_DB_PATH)))
MAX_STORED_SCANS = 1000


def _connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=5)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA busy_timeout = 5000")
    return connection


def initialize_database() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with _connect() as connection:
        connection.execute("PRAGMA journal_mode = WAL")
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                requested_url TEXT NOT NULL,
                final_url TEXT NOT NULL,
                title TEXT,
                status_code INTEGER NOT NULL,
                scanned_at TEXT NOT NULL,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_scanned_at ON scans(scanned_at DESC)"
        )


def save_scan(result: ScanResult) -> None:
    with _connect() as connection:
        connection.execute(
            """
            INSERT INTO scans (
                id, requested_url, final_url, title, status_code, scanned_at, payload
            ) VALUES (?, ?, ?, ?, ?, ?, ?)
            ON CONFLICT(id) DO UPDATE SET
                requested_url=excluded.requested_url,
                final_url=excluded.final_url,
                title=excluded.title,
                status_code=excluded.status_code,
                scanned_at=excluded.scanned_at,
                payload=excluded.payload
            """,
            (
                result.id,
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
            WHERE id NOT IN (
                SELECT id FROM scans
                ORDER BY scanned_at DESC, id DESC
                LIMIT ?
            )
            """,
            (MAX_STORED_SCANS,),
        )


def get_scan(scan_id: str) -> ScanResult | None:
    with _connect() as connection:
        row = connection.execute(
            "SELECT payload FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
    if row is None:
        return None
    return ScanResult.model_validate_json(row["payload"])


def list_scans(limit: int = 20) -> list[dict[str, object]]:
    safe_limit = max(1, min(int(limit), 100))
    with _connect() as connection:
        rows = connection.execute(
            """
            SELECT id, requested_url, final_url, title, status_code, scanned_at
            FROM scans
            ORDER BY scanned_at DESC, id DESC
            LIMIT ?
            """,
            (safe_limit,),
        ).fetchall()
    return [dict(row) for row in rows]
