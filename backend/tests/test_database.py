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



def test_old_scan_results_are_pruned_to_the_retention_limit(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "unweb.sqlite3")
    monkeypatch.setattr(database, "MAX_STORED_SCANS", 2)
    database.initialize_database()

    for index in range(3):
        result = sample_result(f"scan-{index}")
        result.scanned_at = f"2026-11-2{index + 1}T10:00:00+00:00"
        database.save_scan(result)

    history = database.list_scans(10)
    assert [item["id"] for item in history] == ["scan-2", "scan-1"]
    assert database.get_scan("scan-0") is None


def test_scan_records_are_isolated_by_owner(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "owners.sqlite3")
    database.initialize_database()
    database.save_scan(sample_result("alice-scan"), owner_id="alice")
    database.save_scan(sample_result("bob-scan"), owner_id="bob")

    assert database.get_scan("alice-scan", "alice") is not None
    assert database.get_scan("alice-scan", "bob") is None
    assert [item["id"] for item in database.list_scans(owner_id="alice")] == ["alice-scan"]
    assert [item["id"] for item in database.list_scans(owner_id="bob")] == ["bob-scan"]


def test_existing_database_is_migrated_to_local_owner(tmp_path, monkeypatch):
    import sqlite3
    path = tmp_path / "legacy.sqlite3"
    monkeypatch.setattr(database, "DB_PATH", path)
    connection = sqlite3.connect(path)
    connection.execute("""CREATE TABLE scans (
        id TEXT PRIMARY KEY, requested_url TEXT NOT NULL, final_url TEXT NOT NULL,
        title TEXT, status_code INTEGER NOT NULL, scanned_at TEXT NOT NULL, payload TEXT NOT NULL
    )""")
    legacy = sample_result("legacy-scan")
    connection.execute(
        "INSERT INTO scans VALUES (?, ?, ?, ?, ?, ?, ?)",
        (legacy.id, legacy.requested_url, legacy.final_url, legacy.title, legacy.status_code, legacy.scanned_at, legacy.model_dump_json()),
    )
    connection.commit()
    connection.close()

    database.initialize_database()
    assert database.get_scan("legacy-scan", "local") is not None
    assert database.get_scan("legacy-scan", "alice") is None


def test_retention_limit_does_not_delete_another_owners_scans(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "retention-owners.sqlite3")
    monkeypatch.setattr(database, "MAX_STORED_SCANS", 1)
    database.initialize_database()
    database.save_scan(sample_result("bob-scan"), owner_id="bob")
    alice_old = sample_result("alice-old")
    alice_old.scanned_at = "2026-11-20T10:00:00+00:00"
    alice_new = sample_result("alice-new")
    alice_new.scanned_at = "2026-11-24T10:00:00+00:00"
    database.save_scan(alice_old, owner_id="alice")
    database.save_scan(alice_new, owner_id="alice")

    assert database.get_scan("bob-scan", "bob") is not None
    assert database.get_scan("alice-old", "alice") is None
    assert database.get_scan("alice-new", "alice") is not None
