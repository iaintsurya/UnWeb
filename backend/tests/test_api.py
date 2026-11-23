from fastapi.testclient import TestClient

from app import database, main
from app.limits import SlidingWindowLimiter
from app.models import PageSummary, ScanResult


def make_result():
    return ScanResult(
        id="api-test-scan",
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


def test_scan_api_persists_result_and_lists_history(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api-test.sqlite3")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(10, 60))

    async def fake_scan_site(url, max_pages, include_reconstruction):
        return make_result()

    monkeypatch.setattr(main, "scan_site", fake_scan_site)

    with TestClient(main.app) as client:
        created = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4},
        )
        assert created.status_code == 200
        assert created.json()["id"] == "api-test-scan"

        history = client.get("/api/scans?limit=10")
        assert history.status_code == 200
        assert history.json()["items"][0]["id"] == "api-test-scan"

        loaded = client.get("/api/scans/api-test-scan")
        assert loaded.status_code == 200
        assert loaded.json()["title"] == "Example"


def test_scan_api_returns_404_for_unknown_saved_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "missing.sqlite3")

    with TestClient(main.app) as client:
        response = client.get("/api/scans/does-not-exist")

    assert response.status_code == 404
