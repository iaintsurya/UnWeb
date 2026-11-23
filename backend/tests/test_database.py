import pytest
from pydantic import ValidationError

from app import database
from app.models import ScanResult, PageSummary


def sample_result(scan_id="scan-1"):
    return ScanResult(
        id=scan_id,
        requested_url="https://example.com/",
        final_url="https://example.com/",
        status_code=200,
        scanned_at="2026-11-23T10:00:00+00:00",
        title="Example",
        headers={"content-type": "text/html"},
        technologies=[],
        assets=[],
        page=PageSummary(url="https://example.com/", title="Example"),
    )


def test_scan_persists_and_can_be_loaded_after_reinitialization(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unweb.sqlite3")
    database.initialize_database()
    database.save_scan(sample_result())

    # Opening a fresh connection must still return the full structured result.
    loaded = database.get_scan("scan-1")
    assert loaded is not None
    assert loaded.title == "Example"
    assert loaded.page.url == "https://example.com/"


def test_scan_history_returns_only_summary_fields(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unweb.sqlite3")
    database.initialize_database()
    database.save_scan(sample_result())

    history = database.list_scans()
    assert len(history) == 1
    assert history[0]["id"] == "scan-1"
    assert history[0]["final_url"] == "https://example.com/"
    assert "payload" not in history[0]


def test_unknown_scan_returns_none(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unweb.sqlite3")
    database.initialize_database()
    assert database.get_scan("missing") is None


def test_history_limit_is_clamped(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unweb.sqlite3")
    database.initialize_database()
    assert database.list_scans(0) == []
