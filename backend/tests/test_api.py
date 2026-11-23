from fastapi.testclient import TestClient
import io
import json
import zipfile

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



def test_scan_api_returns_retry_after_when_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "limited.sqlite3")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(1, 60))

    async def fake_scan_site(url, max_pages, include_reconstruction):
        return make_result()

    monkeypatch.setattr(main, "scan_site", fake_scan_site)

    with TestClient(main.app) as client:
        first = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4},
        )
        second = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4},
        )

    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]
    assert second.json()["detail"]["code"] == "scan_rate_limited"



def make_repository_zip() -> bytes:
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr(
            "sample-project/src/app.py",
            'API_KEY="repository-secret-value-123"\neval(user_input)\n',
        )
        archive.writestr(
            "sample-project/package.json",
            json.dumps({"dependencies": {"express": "^4.18.0"}}),
        )
    return buffer.getvalue()


def repository_headers(**extra):
    return {
        "Content-Type": "application/zip",
        "X-UnWeb-Authorised": "true",
        "X-Repository-Filename": "sample-project.zip",
        **extra,
    }


def test_repository_scan_api_returns_redacted_report_and_inventory(monkeypatch):
    monkeypatch.setattr(main, "REPOSITORY_SCAN_LIMITER", SlidingWindowLimiter(5, 60))
    with TestClient(main.app) as client:
        response = client.post(
            "/api/repository-scans",
            content=make_repository_zip(),
            headers=repository_headers(),
        )

    assert response.status_code == 200
    report = response.json()
    assert report["repository"] == "sample-project"
    assert report["files_scanned"] == 2
    assert any(item["id"] == "python-dynamic-evaluation" for item in report["findings"])
    assert any(item["name"] == "express" for item in report["dependency_inventory"])
    assert "repository-secret-value-123" not in response.text


def test_repository_scan_api_requires_explicit_authorisation():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/repository-scans",
            content=make_repository_zip(),
            headers={"Content-Type": "application/zip"},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "repository_authorisation_required"


def test_repository_scan_api_rejects_non_zip_media_type():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/repository-scans",
            content=b"not a zip",
            headers={
                "Content-Type": "text/plain",
                "X-UnWeb-Authorised": "true",
            },
        )
    assert response.status_code == 415


def test_repository_scan_api_rejects_invalid_zip():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/repository-scans",
            content=b"not a zip",
            headers=repository_headers(),
        )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_repository_archive"


def test_repository_scan_api_enforces_streamed_upload_size(monkeypatch):
    monkeypatch.setattr(main, "MAX_ARCHIVE_BYTES", 32)
    payload = b"x" * 64
    with TestClient(main.app) as client:
        response = client.post(
            "/api/repository-scans",
            content=payload,
            headers=repository_headers(),
        )
    assert response.status_code == 413
    assert response.json()["detail"]["code"] == "repository_archive_too_large"


def test_repository_scan_api_rate_limits_uploads(monkeypatch):
    monkeypatch.setattr(main, "REPOSITORY_SCAN_LIMITER", SlidingWindowLimiter(1, 60))
    with TestClient(main.app) as client:
        first = client.post(
            "/api/repository-scans",
            content=make_repository_zip(),
            headers=repository_headers(),
        )
        second = client.post(
            "/api/repository-scans",
            content=make_repository_zip(),
            headers=repository_headers(),
        )
    assert first.status_code == 200
    assert second.status_code == 429
    assert second.headers["retry-after"]
    assert second.json()["detail"]["code"] == "repository_scan_rate_limited"
