import pytest

from app import browser_jobs, database
from app.browser_worker import _path_in_scope


def configure_database(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "browser-jobs.sqlite3")
    database.initialize_database()
    browser_jobs.initialize()


def test_stream_trim_uses_pending_minimum(monkeypatch):
    calls = []

    class FakeRedis:
        def xpending(self, stream, group):
            assert stream == browser_jobs.STREAM_NAME
            assert group == browser_jobs.CONSUMER_GROUP
            return {"pending": 2, "min": "2-0", "max": "3-0", "consumers": []}

        def xtrim(self, stream, **kwargs):
            calls.append((stream, kwargs))

    browser_jobs.trim_acknowledged_stream(FakeRedis())
    assert calls == [(browser_jobs.STREAM_NAME, {"minid": "2-0", "approximate": True})]


def test_pending_browser_jobs_are_bounded_per_owner(monkeypatch, tmp_path):
    configure_database(monkeypatch, tmp_path)
    monkeypatch.setattr(browser_jobs, "MAX_PENDING_JOBS_PER_OWNER", 1)

    first = browser_jobs.create_job(
        "alice", "target-a", "https://example.com/app", ["/app"], 40
    )
    with pytest.raises(browser_jobs.BrowserJobCapacityError):
        browser_jobs.create_job(
            "alice", "target-a", "https://example.com/app", ["/app"], 40
        )

    assert browser_jobs.cancel_job(first["job_id"], "alice") == "cancelled"
    second = browser_jobs.create_job(
        "alice", "target-a", "https://example.com/app", ["/app"], 40
    )
    assert second["status"] == "queued"


def test_browser_jobs_are_owner_scoped_and_store_results(monkeypatch, tmp_path):
    configure_database(monkeypatch, tmp_path)
    job = browser_jobs.create_job(
        "alice", "target-a", "https://example.com/app",
        ["/app"], 40
    )
    job_id = job["job_id"]

    assert job["status"] == "queued"
    assert browser_jobs.get_job(job_id, "bob") is None
    assert browser_jobs.claim_job(job_id)["status"] == "running"
    assert browser_jobs.claim_job(job_id) is None
    assert browser_jobs.cancel_job(job_id, "alice") == "running"

    assert browser_jobs.complete_job(job_id, {"title": "Example"})
    saved = browser_jobs.get_job(job_id, "alice")
    assert saved["status"] == "completed"
    assert saved["result"] == {"title": "Example"}
    assert browser_jobs.get_job(job_id, "bob") is None


def test_queued_browser_job_can_be_cancelled_once(monkeypatch, tmp_path):
    configure_database(monkeypatch, tmp_path)
    job = browser_jobs.create_job("alice", "target-a", "https://example.com/",
                                  ["/"], 80)
    assert browser_jobs.cancel_job(job["job_id"], "bob") is None
    assert browser_jobs.cancel_job(job["job_id"], "alice") == "cancelled"
    assert browser_jobs.claim_job(job["job_id"]) is None
    assert browser_jobs.get_job(job["job_id"], "alice")["status"] == "cancelled"


def test_interrupted_running_job_is_requeued(monkeypatch, tmp_path):
    configure_database(monkeypatch, tmp_path)
    job = browser_jobs.create_job("alice", "target-a", "https://example.com/",
                                  ["/"], 80)
    browser_jobs.claim_job(job["job_id"])
    assert browser_jobs.recover_interrupted_jobs() == 1
    assert browser_jobs.get_job(job["job_id"], "alice")["status"] == "queued"


def test_queue_failure_only_marks_queued_jobs(monkeypatch, tmp_path):
    configure_database(monkeypatch, tmp_path)
    job = browser_jobs.create_job("alice", "target-a", "https://example.com/",
                                  ["/"], 80)
    assert browser_jobs.fail_queued_job(job["job_id"], "QueueUnavailable")
    assert browser_jobs.get_job(job["job_id"], "alice")["status"] == "failed"
    assert browser_jobs.claim_job(job["job_id"]) is None


@pytest.mark.parametrize(
    ("url", "scope", "expected"),
    [
        ("https://example.com/app", ["/app"], True),
        ("https://example.com/app/users", ["/app"], True),
        ("https://example.com/application", ["/app"], False),
        ("https://example.com/outside", ["/app"], False),
        ("https://example.com/app/%2e%2e/admin", ["/app"], False),
        ("https://example.com/app%2fadmin", ["/app"], False),
        ("https://example.com/app\\admin", ["/app"], False),
    ],
)
def test_browser_requests_obey_segment_aware_path_scope(url, scope, expected):
    assert _path_in_scope(url, scope) is expected
