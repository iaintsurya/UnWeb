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


def test_audit_events_are_owner_scoped_and_return_structured_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "audit.sqlite3")
    database.initialize_database()
    database.record_audit_event("alice", "website_scan.completed", "scan-1", {"pages": 3})
    database.record_audit_event("bob", "website_scan.completed", "scan-2")

    alice_events = database.list_audit_events("alice")
    assert len(alice_events) == 1
    assert alice_events[0]["action"] == "website_scan.completed"
    assert alice_events[0]["resource_id"] == "scan-1"
    assert alice_events[0]["metadata"] == {"pages": 3}
    assert database.list_audit_events("bob")[0]["resource_id"] == "scan-2"


def test_dns_verified_targets_are_owner_scoped_single_use_and_revocable(tmp_path, monkeypatch):
    from datetime import datetime, timedelta, timezone
    import hashlib

    monkeypatch.setattr(database, "DB_PATH", tmp_path / "targets.sqlite3")
    database.initialize_database()
    now = datetime.now(timezone.utc)
    created = now.isoformat()
    expires = (now + timedelta(minutes=15)).isoformat()
    target_expires = (now + timedelta(days=30)).isoformat()
    token_hash = hashlib.sha256(b"unweb-verification=test-token").hexdigest()

    database.save_target_challenge(
        "challenge-1", "alice", "example.com", [443, 80], ["/app"], token_hash, created, expires
    )
    challenge = database.get_target_challenge("challenge-1", "alice")
    assert challenge["hostname"] == "example.com"
    assert challenge["scope_paths"] == ["/app"]
    assert database.get_target_challenge("challenge-1", "bob") is None

    verified = database.verify_target_challenge(
        "challenge-1", "alice", token_hash, created, target_expires
    )
    assert verified["target_id"] == "challenge-1"
    assert database.verify_target_challenge(
        "challenge-1", "alice", token_hash, created, target_expires
    ) is None
    assert database.get_authorized_target("challenge-1", "alice", created) is not None
    assert database.get_authorized_target("challenge-1", "bob", created) is None
    assert len(database.list_authorized_targets("alice", created)) == 1
    assert database.revoke_authorized_target("challenge-1", "alice", created)
    assert database.get_authorized_target("challenge-1", "alice", created) is None


def test_repository_reports_persist_with_owner_scoping_and_summary_metadata(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "repository-reports.sqlite3")
    database.initialize_database()
    report = {
        "repository": "owner/project",
        "source": {"commit_sha": "0123456789abcdef"},
        "files_scanned": 12,
        "findings": [{"id": "rule-1"}, {"id": "rule-2"}],
        "dependency_count": 4,
        "truncated": False,
    }
    database.save_repository_report("report-alice", report, "alice", "2026-11-24T10:00:00+00:00")
    database.save_repository_report("report-bob", report, "bob", "2026-11-24T10:01:00+00:00")

    loaded = database.get_repository_report("report-alice", "alice")
    assert loaded == report
    assert database.get_repository_report("report-alice", "bob") is None
    history = database.list_repository_reports("alice")
    assert history == [{
        "report_id": "report-alice",
        "repository": "owner/project",
        "scanned_at": "2026-11-24T10:00:00+00:00",
        "source_commit": "0123456789abcdef",
        "files_scanned": 12,
        "finding_count": 2,
        "dependency_count": 4,
        "truncated": False,
    }]
    assert database.list_repository_reports("bob")[0]["report_id"] == "report-bob"


def test_repository_report_retention_is_owner_scoped(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "repository-retention.sqlite3")
    monkeypatch.setattr(database, "MAX_STORED_REPOSITORY_REPORTS", 1)
    database.initialize_database()
    report = {"repository": "project", "findings": [], "dependency_count": 0}
    database.save_repository_report("bob-report", report, "bob", "2026-11-24T10:00:00+00:00")
    database.save_repository_report("alice-old", report, "alice", "2026-11-24T10:01:00+00:00")
    database.save_repository_report("alice-new", report, "alice", "2026-11-24T10:02:00+00:00")

    assert database.get_repository_report("bob-report", "bob") is not None
    assert database.get_repository_report("alice-old", "alice") is None
    assert database.get_repository_report("alice-new", "alice") is not None
