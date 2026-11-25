"""Small persistent SQLite store for scan results.

The schema is initialized idempotently at application startup. Keep database
files out of version control; set UNWEB_DB_PATH to choose another location.
"""
import json
import os
import sqlite3
import secrets
from datetime import datetime, timezone
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator

from .models import ScanResult

DEFAULT_DB_PATH = Path(__file__).resolve().parents[1] / "data" / "unweb.sqlite3"
DB_PATH = Path(os.environ.get("UNWEB_DB_PATH", str(DEFAULT_DB_PATH)))
# Evidence retention is configurable so operators can keep longer audit trails.
# The default preserves the historical limit of the last 250 scans per owner.
MAX_STORED_SCANS = max(1, int(os.environ.get("UNWEB_MAX_STORED_SCANS", "250")))
MAX_STORED_REPOSITORY_REPORTS = 100
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
            CREATE TABLE IF NOT EXISTS repository_reports (
                report_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                repository TEXT NOT NULL,
                scanned_at TEXT NOT NULL,
                source_commit TEXT,
                payload TEXT NOT NULL
            )
            """
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_repository_reports_owner_time ON repository_reports(owner_id, scanned_at DESC)"
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
        connection.execute(
            """CREATE TABLE IF NOT EXISTS target_challenges (
                challenge_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ports_json TEXT NOT NULL,
                scope_paths_json TEXT NOT NULL,
                token_hash TEXT NOT NULL,
                created_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                used_at TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_target_challenges_owner ON target_challenges(owner_id, created_at DESC)"
        )
        connection.execute(
            """CREATE TABLE IF NOT EXISTS authorized_targets (
                target_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                hostname TEXT NOT NULL,
                ports_json TEXT NOT NULL,
                scope_paths_json TEXT NOT NULL,
                verified_at TEXT NOT NULL,
                expires_at TEXT NOT NULL,
                revoked_at TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_authorized_targets_owner ON authorized_targets(owner_id, expires_at DESC)"
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



def save_repository_report(
    report_id: str,
    report: dict[str, object],
    owner_id: str,
    scanned_at: str,
) -> None:
    """Persist a bounded repository assessment under the authenticated owner."""
    repository = str(report.get("repository", "repository"))[:255]
    source = report.get("source")
    source_commit = source.get("commit_sha") if isinstance(source, dict) else None
    with _connection() as connection:
        connection.execute(
            """INSERT INTO repository_reports
            (report_id, owner_id, repository, scanned_at, source_commit, payload)
            VALUES (?, ?, ?, ?, ?, ?)
            ON CONFLICT(report_id) DO UPDATE SET
                owner_id=excluded.owner_id, repository=excluded.repository,
                scanned_at=excluded.scanned_at, source_commit=excluded.source_commit,
                payload=excluded.payload""",
            (
                report_id, owner_id, repository, scanned_at, source_commit,
                json.dumps(report, sort_keys=True, separators=(",", ":")),
            ),
        )
        connection.execute(
            """DELETE FROM repository_reports
            WHERE owner_id = ? AND report_id NOT IN (
                SELECT report_id FROM repository_reports
                WHERE owner_id = ? ORDER BY scanned_at DESC, report_id DESC LIMIT ?
            )""",
            (owner_id, owner_id, MAX_STORED_REPOSITORY_REPORTS),
        )


def get_repository_report(report_id: str, owner_id: str) -> dict[str, object] | None:
    with _connection() as connection:
        row = connection.execute(
            "SELECT payload FROM repository_reports WHERE report_id = ? AND owner_id = ?",
            (report_id, owner_id),
        ).fetchone()
    return json.loads(row["payload"]) if row else None


def list_repository_reports(owner_id: str, limit: int = 20) -> list[dict[str, object]]:
    safe_limit = max(1, min(int(limit), 100))
    with _connection() as connection:
        rows = connection.execute(
            """SELECT report_id, repository, scanned_at, source_commit, payload
            FROM repository_reports WHERE owner_id = ?
            ORDER BY scanned_at DESC, report_id DESC LIMIT ?""",
            (owner_id, safe_limit),
        ).fetchall()
    items = []
    for row in rows:
        payload = json.loads(row["payload"])
        items.append({
            "report_id": row["report_id"],
            "repository": row["repository"],
            "scanned_at": row["scanned_at"],
            "source_commit": row["source_commit"],
            "files_scanned": payload.get("files_scanned", 0),
            "finding_count": len(payload.get("findings", [])),
            "dependency_count": payload.get("dependency_count", 0),
            "truncated": payload.get("truncated", False),
        })
    return items


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


def save_target_challenge(
    challenge_id: str,
    owner_id: str,
    hostname: str,
    ports: list[int],
    scope_paths: list[str],
    token_hash: str,
    created_at: str,
    expires_at: str,
) -> None:
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        connection.execute(
            "DELETE FROM target_challenges WHERE expires_at <= ? OR (used_at IS NOT NULL AND used_at < ?)",
            (created_at, created_at),
        )
        pending = connection.execute(
            "SELECT COUNT(*) AS count FROM target_challenges WHERE owner_id = ? AND used_at IS NULL AND expires_at > ?",
            (owner_id, created_at),
        ).fetchone()["count"]
        if pending >= 20:
            raise ValueError("Too many pending target verification challenges. Wait for existing challenges to expire.")
        connection.execute(
            """INSERT INTO target_challenges (
                challenge_id, owner_id, hostname, ports_json, scope_paths_json,
                token_hash, created_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
            (challenge_id, owner_id, hostname, json.dumps(ports), json.dumps(scope_paths), token_hash, created_at, expires_at),
        )


def get_target_challenge(challenge_id: str, owner_id: str) -> dict[str, object] | None:
    with _connection() as connection:
        row = connection.execute(
            """SELECT challenge_id, hostname, ports_json, scope_paths_json, token_hash,
            created_at, expires_at, used_at FROM target_challenges
            WHERE challenge_id = ? AND owner_id = ?""",
            (challenge_id, owner_id),
        ).fetchone()
    if row is None:
        return None
    return {
        "challenge_id": row["challenge_id"],
        "hostname": row["hostname"],
        "ports": json.loads(row["ports_json"]),
        "scope_paths": json.loads(row["scope_paths_json"]),
        "token_hash": row["token_hash"],
        "created_at": row["created_at"],
        "expires_at": row["expires_at"],
        "used_at": row["used_at"],
    }


def verify_target_challenge(
    challenge_id: str,
    owner_id: str,
    token_hash: str,
    verified_at: str,
    target_expires_at: str,
) -> dict[str, object] | None:
    with _connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            """SELECT hostname, ports_json, scope_paths_json, token_hash, expires_at, used_at
            FROM target_challenges WHERE challenge_id = ? AND owner_id = ?""",
            (challenge_id, owner_id),
        ).fetchone()
        if row is None or row["used_at"] is not None or row["expires_at"] <= verified_at:
            return None
        if not secrets.compare_digest(row["token_hash"], token_hash):
            return None
        connection.execute(
            "DELETE FROM authorized_targets WHERE expires_at <= ? OR (revoked_at IS NOT NULL AND revoked_at < ?)",
            (verified_at, verified_at),
        )
        active_targets = connection.execute(
            "SELECT COUNT(*) AS count FROM authorized_targets WHERE owner_id = ? AND revoked_at IS NULL AND expires_at > ?",
            (owner_id, verified_at),
        ).fetchone()["count"]
        if active_targets >= 100:
            raise ValueError("Maximum of 100 active verified targets per user reached. Revoke an existing target first.")
        cursor = connection.execute(
            "UPDATE target_challenges SET used_at = ? WHERE challenge_id = ? AND owner_id = ? AND used_at IS NULL",
            (verified_at, challenge_id, owner_id),
        )
        if cursor.rowcount != 1:
            return None
        connection.execute(
            """INSERT INTO authorized_targets (
                target_id, owner_id, hostname, ports_json, scope_paths_json, verified_at, expires_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (challenge_id, owner_id, row["hostname"], row["ports_json"], row["scope_paths_json"], verified_at, target_expires_at),
        )
    return {
        "target_id": challenge_id,
        "hostname": row["hostname"],
        "ports": json.loads(row["ports_json"]),
        "scope_paths": json.loads(row["scope_paths_json"]),
        "verified_at": verified_at,
        "expires_at": target_expires_at,
    }


def get_authorized_target(target_id: str, owner_id: str, now: str) -> dict[str, object] | None:
    with _connection() as connection:
        row = connection.execute(
            """SELECT target_id, hostname, ports_json, scope_paths_json, verified_at, expires_at
            FROM authorized_targets WHERE target_id = ? AND owner_id = ?
            AND revoked_at IS NULL AND expires_at > ?""",
            (target_id, owner_id, now),
        ).fetchone()
    if row is None:
        return None
    return {
        "target_id": row["target_id"],
        "hostname": row["hostname"],
        "ports": json.loads(row["ports_json"]),
        "scope_paths": json.loads(row["scope_paths_json"]),
        "verified_at": row["verified_at"],
        "expires_at": row["expires_at"],
    }


def list_authorized_targets(owner_id: str, now: str) -> list[dict[str, object]]:
    with _connection() as connection:
        rows = connection.execute(
            """SELECT target_id, hostname, ports_json, scope_paths_json, verified_at, expires_at
            FROM authorized_targets WHERE owner_id = ? AND revoked_at IS NULL AND expires_at > ?
            ORDER BY verified_at DESC""",
            (owner_id, now),
        ).fetchall()
    return [
        {
            "target_id": row["target_id"],
            "hostname": row["hostname"],
            "ports": json.loads(row["ports_json"]),
            "scope_paths": json.loads(row["scope_paths_json"]),
            "verified_at": row["verified_at"],
            "expires_at": row["expires_at"],
        }
        for row in rows
    ]


def revoke_authorized_target(target_id: str, owner_id: str, revoked_at: str) -> bool:
    with _connection() as connection:
        cursor = connection.execute(
            """UPDATE authorized_targets SET revoked_at = ?
            WHERE target_id = ? AND owner_id = ? AND revoked_at IS NULL""",
            (revoked_at, target_id, owner_id),
        )
    return cursor.rowcount == 1


def check_database() -> None:
    """Raise sqlite errors if the configured database cannot serve a query."""
    with _connection() as connection:
        connection.execute("SELECT 1").fetchone()
