import sqlite3
from pathlib import Path

import pytest

from app import database
from app.maintenance import backup_database, restore_database
from app.models import PageSummary, ScanResult


def _seed_database(path: Path) -> None:
    database.DB_PATH = path
    database.initialize_database()
    result = ScanResult(
        id="maintenance-scan",
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        scanned_at="2026-11-24T10:00:00+00:00",
        title="Example",
        headers={},
        technologies=[],
        assets=[],
        page=PageSummary(url="https://example.com/"),
    )
    database.save_scan(result, owner_id="maintenance-test")


def test_online_backup_includes_committed_wal_data_and_is_private(tmp_path, monkeypatch):
    source = tmp_path / "source.sqlite3"
    destination = tmp_path / "backups" / "snapshot.sqlite3"
    _seed_database(source)

    created = backup_database(source, destination)

    assert created == destination.resolve()
    assert destination.stat().st_mode & 0o777 == 0o600
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute("SELECT COUNT(*) FROM scans").fetchone()[0] == 1


def test_restore_replaces_destination_only_when_explicitly_allowed(tmp_path):
    source = tmp_path / "source.sqlite3"
    backup = tmp_path / "backup.sqlite3"
    destination = tmp_path / "restored.sqlite3"
    _seed_database(source)
    backup_database(source, backup)

    destination.write_bytes(b"existing")
    with pytest.raises(FileExistsError):
        restore_database(backup, destination)

    restore_database(backup, destination, overwrite=True)
    with sqlite3.connect(destination) as connection:
        assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        assert connection.execute(
            "SELECT id FROM scans WHERE owner_id = ?", ("maintenance-test",)
        ).fetchone()[0] == "maintenance-scan"


def test_backup_rejects_same_path_missing_source_and_corrupt_database(tmp_path):
    source = tmp_path / "source.sqlite3"
    _seed_database(source)
    with pytest.raises(ValueError):
        backup_database(source, source)
    with pytest.raises(FileNotFoundError):
        backup_database(tmp_path / "missing.sqlite3", tmp_path / "out.sqlite3")

    corrupt = tmp_path / "corrupt.sqlite3"
    corrupt.write_bytes(b"not a sqlite database")
    with pytest.raises(sqlite3.DatabaseError):
        backup_database(corrupt, tmp_path / "corrupt-copy.sqlite3")
    assert not (tmp_path / "corrupt-copy.sqlite3").exists()
