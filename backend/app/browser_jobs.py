"""Redis-stream-backed, owner-scoped browser job persistence."""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from typing import Any

from . import database

STREAM_NAME = "unweb:browser-jobs"
CONSUMER_GROUP = "unweb-browser-workers"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def initialize() -> None:
    with database._connection() as connection:
        connection.execute(
            """CREATE TABLE IF NOT EXISTS browser_jobs (
                job_id TEXT PRIMARY KEY,
                owner_id TEXT NOT NULL,
                target_id TEXT,
                target_url TEXT NOT NULL,
                scope_paths_json TEXT NOT NULL,
                max_requests INTEGER NOT NULL,
                status TEXT NOT NULL CHECK(status IN ('queued','running','completed','failed','cancelled')),
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                started_at TEXT,
                finished_at TEXT,
                result_json TEXT,
                error_code TEXT
            )"""
        )
        connection.execute(
            "CREATE INDEX IF NOT EXISTS idx_browser_jobs_owner_created "
            "ON browser_jobs(owner_id, created_at DESC)"
        )


def create_job(owner_id: str, target_id: str | None, target_url: str,
               scope_paths: list[str], max_requests: int) -> dict[str, Any]:
    job_id = uuid.uuid4().hex
    now = _now()
    with database._connection() as connection:
        connection.execute(
            """INSERT INTO browser_jobs
            (job_id, owner_id, target_id, target_url, scope_paths_json, max_requests,
             status, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?, 'queued', ?, ?)""",
            (job_id, owner_id, target_id, target_url,
             json.dumps(scope_paths), max_requests, now, now),
        )
    return get_job(job_id, owner_id)  # type: ignore[return-value]


def enqueue(client: Any, job_id: str) -> None:
    client.xadd(STREAM_NAME, {"job_id": job_id}, maxlen=10000, approximate=True)


def _decode(row: Any, include_result: bool = True) -> dict[str, Any]:
    result = {
        "job_id": row["job_id"],
        "target_id": row["target_id"],
        "url": row["target_url"],
        "scope_paths": json.loads(row["scope_paths_json"]),
        "max_requests": row["max_requests"],
        "status": row["status"],
        "created_at": row["created_at"],
        "updated_at": row["updated_at"],
        "started_at": row["started_at"],
        "finished_at": row["finished_at"],
        "error_code": row["error_code"],
    }
    if include_result and row["result_json"] is not None:
        result["result"] = json.loads(row["result_json"])
    return result


def get_job(job_id: str, owner_id: str, include_result: bool = True) -> dict[str, Any] | None:
    with database._connection() as connection:
        row = connection.execute(
            "SELECT * FROM browser_jobs WHERE job_id = ? AND owner_id = ?",
            (job_id, owner_id),
        ).fetchone()
    return _decode(row, include_result) if row else None


def list_jobs(owner_id: str, limit: int = 20) -> list[dict[str, Any]]:
    safe_limit = max(1, min(int(limit), 100))
    with database._connection() as connection:
        rows = connection.execute(
            "SELECT * FROM browser_jobs WHERE owner_id = ? ORDER BY created_at DESC LIMIT ?",
            (owner_id, safe_limit),
        ).fetchall()
    return [_decode(row, include_result=False) for row in rows]


def claim_job(job_id: str) -> dict[str, Any] | None:
    now = _now()
    with database._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        cursor = connection.execute(
            """UPDATE browser_jobs SET status='running', started_at=?, updated_at=?
            WHERE job_id=? AND status='queued'""",
            (now, now, job_id),
        )
        if cursor.rowcount != 1:
            return None
        row = connection.execute(
            "SELECT * FROM browser_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
    return _decode(row, include_result=False)


def cancel_job(job_id: str, owner_id: str) -> str | None:
    now = _now()
    with database._connection() as connection:
        connection.execute("BEGIN IMMEDIATE")
        row = connection.execute(
            "SELECT status FROM browser_jobs WHERE job_id=? AND owner_id=?",
            (job_id, owner_id),
        ).fetchone()
        if row is None:
            return None
        if row["status"] == "queued":
            connection.execute(
                """UPDATE browser_jobs SET status='cancelled', updated_at=?, finished_at=?
                WHERE job_id=? AND owner_id=? AND status='queued'""",
                (now, now, job_id, owner_id),
            )
            return "cancelled"
        return str(row["status"])


def complete_job(job_id: str, result: dict[str, Any]) -> bool:
    now = _now()
    with database._connection() as connection:
        cursor = connection.execute(
            """UPDATE browser_jobs SET status='completed', result_json=?, updated_at=?, finished_at=?
            WHERE job_id=? AND status='running'""",
            (json.dumps(result, separators=(",", ":"), ensure_ascii=False),
             now, now, job_id),
        )
    return cursor.rowcount == 1


def fail_job(job_id: str, error_code: str) -> bool:
    now = _now()
    with database._connection() as connection:
        cursor = connection.execute(
            """UPDATE browser_jobs SET status='failed', error_code=?, updated_at=?, finished_at=?
            WHERE job_id=? AND status='running'""",
            (error_code[:80], now, now, job_id),
        )
    return cursor.rowcount == 1


def fail_queued_job(job_id: str, error_code: str) -> bool:
    now = _now()
    with database._connection() as connection:
        cursor = connection.execute(
            """UPDATE browser_jobs SET status='failed', error_code=?, updated_at=?, finished_at=?
            WHERE job_id=? AND status='queued'""",
            (error_code[:80], now, now, job_id),
        )
    return cursor.rowcount == 1


def recover_interrupted_jobs() -> int:
    """Requeue jobs left running after the single configured worker was interrupted."""
    now = _now()
    with database._connection() as connection:
        cursor = connection.execute(
            """UPDATE browser_jobs SET status='queued', started_at=NULL, updated_at=?
            WHERE status='running'""",
            (now,),
        )
    return cursor.rowcount


def get_job_owner(job_id: str) -> str:
    with database._connection() as connection:
        row = connection.execute(
            "SELECT owner_id FROM browser_jobs WHERE job_id=?", (job_id,)
        ).fetchone()
    if row is None:
        raise RuntimeError("Browser job disappeared.")
    return str(row["owner_id"])
