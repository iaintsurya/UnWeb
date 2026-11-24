from fastapi.testclient import TestClient
import io
import json
import zipfile
from pathlib import Path
import pytest

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


def test_scan_api_requires_explicit_authorisation():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4},
        )

    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "website_authorisation_required"


def test_scan_api_persists_result_and_lists_history(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "api-test.sqlite3")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(10, 60))

    async def fake_scan_site(url, max_pages, include_reconstruction, scope_paths=None):
        return make_result()

    monkeypatch.setattr(main, "scan_site", fake_scan_site)

    with TestClient(main.app) as client:
        created = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4, "authorised": True},
        )
        assert created.status_code == 200
        assert created.json()["id"] == "api-test-scan"

        history = client.get("/api/scans?limit=10")
        assert history.status_code == 200
        assert history.json()["items"][0]["id"] == "api-test-scan"

        loaded = client.get("/api/scans/api-test-scan")
        assert loaded.status_code == 200
        assert loaded.json()["title"] == "Example"

        security = client.get("/api/scans/api-test-scan/security")
        assert security.status_code == 200
        assert security.json()["security_findings"] == []

        audit = client.get("/api/audit-events")
        assert audit.status_code == 200
        assert audit.json()["items"][0]["action"] == "website_scan.completed"


def test_scan_api_returns_404_for_unknown_saved_scan(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "missing.sqlite3")

    with TestClient(main.app) as client:
        response = client.get("/api/scans/does-not-exist")

    assert response.status_code == 404



def test_scan_api_returns_retry_after_when_rate_limited(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "limited.sqlite3")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(1, 60))

    async def fake_scan_site(url, max_pages, include_reconstruction, scope_paths=None):
        return make_result()

    monkeypatch.setattr(main, "scan_site", fake_scan_site)

    with TestClient(main.app) as client:
        first = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4, "authorised": True},
        )
        second = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "max_pages": 4, "authorised": True},
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
        archive.writestr(
            "sample-project/src/routes.py",
            "from fastapi import FastAPI\napp = FastAPI()\n@app.get('/api/health')\ndef health(): return {'ok': True}\n",
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
    assert report["files_scanned"] == 3
    assert any(item["source"] == "repository" for item in report["security_findings"])
    assert any(item["path"] == "/api/health" for item in report["route_inventory"])
    assert any(item["id"] == "python-dynamic-evaluation" for item in report["findings"])
    assert any(item["name"] == "express" for item in report["dependency_inventory"])
    assert any(item["method"] == "GET" and item["path"] == "/api/health" for item in report["route_inventory"])
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


def test_github_repository_scan_requires_explicit_authorisation():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/github-repository-scans",
            json={"repository_url": "https://github.com/owner/repo"},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "repository_authorisation_required"


def test_github_repository_scan_returns_report_pinned_to_commit(tmp_path, monkeypatch):
    async def fake_fetch(repository_url, ref, destination):
        Path(destination).write_bytes(make_repository_zip())
        return {
            "provider": "github",
            "full_name": "owner/repo",
            "requested_ref": ref or "main",
            "default_branch": "main",
            "commit_sha": "0123456789abcdef0123456789abcdef01234567",
            "archive_bytes": len(make_repository_zip()),
        }

    from pathlib import Path
    monkeypatch.setattr(main, "fetch_github_repository_archive", fake_fetch)
    monkeypatch.setattr(main, "REPOSITORY_SCAN_LIMITER", SlidingWindowLimiter(5, 60))
    with TestClient(main.app) as client:
        response = client.post(
            "/api/github-repository-scans",
            json={
                "repository_url": "https://github.com/owner/repo",
                "ref": "main",
                "authorised": True,
            },
        )

    assert response.status_code == 200
    report = response.json()
    assert report["repository"] == "owner/repo"
    assert report["source"]["commit_sha"] == "0123456789abcdef0123456789abcdef01234567"
    assert report["source"]["requested_ref"] == "main"
    assert any(item["source"] == "repository" for item in report["security_findings"])
    assert any(item["id"] == "python-dynamic-evaluation" for item in report["findings"])
    assert "repository-secret-value-123" not in response.text


def test_github_repository_scan_rejects_invalid_repository_url():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/github-repository-scans",
            json={
                "repository_url": "https://github.com.evil.test/owner/repo",
                "authorised": True,
            },
        )
    assert response.status_code == 400
    assert response.json()["detail"]["code"] == "invalid_github_repository_url"



def test_dependency_advisory_api_requires_authorisation():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/dependency-advisories",
            json={"packages": [{"name": "requests", "ecosystem": "PyPI", "version": "2.31.0"}]},
        )
    assert response.status_code == 403
    assert response.json()["detail"]["code"] == "dependency_advisory_authorisation_required"


def test_dependency_advisory_api_rejects_invalid_package_versions():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/dependency-advisories",
            json={
                "authorised": True,
                "packages": [{"name": "requests", "ecosystem": "PyPI", "version": ""}],
            },
        )
    assert response.status_code == 422
    assert response.json()["detail"]["code"] == "invalid_dependency_batch"


def test_dependency_advisory_api_returns_provider_results(monkeypatch):
    async def fake_query(packages):
        assert packages == [{"name": "requests", "ecosystem": "PyPI", "version": "2.31.0"}]
        return {
            "provider": "OSV",
            "packages_checked": 1,
            "packages_with_advisories": 1,
            "advisory_matches": 1,
            "results": [{"package": "requests", "ecosystem": "PyPI", "version": "2.31.0", "advisory_count": 1, "advisories": [{"id": "GHSA-test"}]}],
            "limitations": [],
        }

    monkeypatch.setattr(main, "query_advisories", fake_query)
    monkeypatch.setattr(main, "ADVISORY_LOOKUP_LIMITER", SlidingWindowLimiter(10, 60))
    with TestClient(main.app) as client:
        response = client.post(
            "/api/dependency-advisories",
            json={
                "authorised": True,
                "packages": [{"name": "requests", "ecosystem": "PyPI", "version": "2.31.0"}],
            },
        )
    assert response.status_code == 200
    assert response.json()["provider"] == "OSV"
    assert response.json()["advisory_matches"] == 1


def test_scan_api_passes_explicit_path_scope_to_scanner(monkeypatch, tmp_path):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "scoped.sqlite3")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(10, 60))
    observed = {}

    async def fake_scan_site(url, max_pages, include_reconstruction, scope_paths=None):
        observed["scope_paths"] = scope_paths
        result = make_result()
        result.scope_paths = scope_paths or ["/"]
        return result

    monkeypatch.setattr(main, "scan_site", fake_scan_site)
    with TestClient(main.app) as client:
        response = client.post(
            "/api/scans",
            json={
                "url": "https://example.com/app",
                "max_pages": 4,
                "authorised": True,
                "scope_paths": ["/app", "/api/v1"],
            },
        )

    assert response.status_code == 200
    assert observed["scope_paths"] == ["/app", "/api/v1"]
    assert response.json()["scope_paths"] == ["/app", "/api/v1"]


def test_scan_api_rejects_empty_path_scope():
    with TestClient(main.app) as client:
        response = client.post(
            "/api/scans",
            json={
                "url": "https://example.com/",
                "authorised": True,
                "scope_paths": [],
            },
        )
    assert response.status_code == 422


def test_auth_proxy_rejects_missing_or_invalid_identity(monkeypatch):
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "test-proxy-secret")
    monkeypatch.setattr(main, "UNWEB_ENV", "development")
    with TestClient(main.app) as client:
        missing = client.get("/api/scans")
        invalid = client.get("/api/scans", headers={
            "X-UnWeb-Auth-Token": "wrong",
            "X-UnWeb-Auth-User": "alice",
        })
        accepted = client.get("/api/scans", headers={
            "X-UnWeb-Auth-Token": "test-proxy-secret",
            "X-UnWeb-Auth-User": "alice",
        })
    assert missing.status_code == 401
    assert missing.json()["detail"]["code"] == "authentication_required"
    assert invalid.status_code == 401
    assert accepted.status_code == 200


def test_scan_history_and_detail_are_isolated_by_authenticated_user(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "ownership.sqlite3")
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "test-proxy-secret")
    monkeypatch.setattr(main, "UNWEB_ENV", "production")
    async def fake_scan_site(url, max_pages, include_reconstruction, scope_paths=None):
        return make_result()
    monkeypatch.setattr(main, "scan_site", fake_scan_site)
    headers = lambda user: {"X-UnWeb-Auth-Token": "test-proxy-secret", "X-UnWeb-Auth-User": user}
    with TestClient(main.app) as client:
        created = client.post("/api/scans", json={"url":"https://example.com/", "authorised":True}, headers=headers("alice"))
        assert created.status_code == 200
        alice_history = client.get("/api/scans", headers=headers("alice"))
        bob_history = client.get("/api/scans", headers=headers("bob"))
        bob_detail = client.get("/api/scans/api-test-scan", headers=headers("bob"))
    assert len(alice_history.json()["items"]) == 1
    assert bob_history.json()["items"] == []
    assert bob_detail.status_code == 404


def test_auth_gateway_allows_cors_preflight_without_identity(monkeypatch):
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "test-proxy-secret")
    monkeypatch.setattr(main, "UNWEB_ENV", "production")
    with TestClient(main.app) as client:
        response = client.options(
            "/api/scans",
            headers={
                "Origin": "http://localhost:5173",
                "Access-Control-Request-Method": "POST",
                "Access-Control-Request-Headers": "content-type,x-unweb-auth-token,x-unweb-auth-user",
            },
        )
    assert response.status_code == 200
    assert response.headers["access-control-allow-origin"] == "http://localhost:5173"


def test_scan_rate_limit_is_scoped_to_authenticated_user(tmp_path, monkeypatch):
    monkeypatch.setattr(database, "DB_PATH", tmp_path / "user-limits.sqlite3")
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "test-proxy-secret")
    monkeypatch.setattr(main, "UNWEB_ENV", "production")
    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", SlidingWindowLimiter(1, 60))

    async def fake_scan_site(url, max_pages, include_reconstruction, scope_paths=None):
        result = make_result()
        result.id = url
        result.requested_url = url
        result.final_url = url
        result.page.url = url
        return result

    monkeypatch.setattr(main, "scan_site", fake_scan_site)
    headers = lambda user: {"X-UnWeb-Auth-Token": "test-proxy-secret", "X-UnWeb-Auth-User": user}
    with TestClient(main.app) as client:
        alice_first = client.post("/api/scans", json={"url":"https://example.com/a", "authorised":True}, headers=headers("alice"))
        alice_second = client.post("/api/scans", json={"url":"https://example.com/b", "authorised":True}, headers=headers("alice"))
        bob_first = client.post("/api/scans", json={"url":"https://example.com/c", "authorised":True}, headers=headers("bob"))

    assert alice_first.status_code == 200
    assert alice_second.status_code == 429
    assert bob_first.status_code == 200


def test_scan_api_fails_closed_when_shared_rate_limit_store_is_unavailable(monkeypatch):
    from redis.exceptions import ConnectionError as RedisConnectionError

    class UnavailableLimiter:
        def check(self, key):
            raise RedisConnectionError("redis unavailable")

    monkeypatch.setattr(main, "SCAN_RATE_LIMITER", UnavailableLimiter())
    with TestClient(main.app) as client:
        response = client.post(
            "/api/scans",
            json={"url": "https://example.com/", "authorised": True},
        )
    assert response.status_code == 503
    assert response.json()["detail"]["code"] == "rate_limit_store_unavailable"
    assert response.headers["retry-after"] == "5"


def test_production_startup_requires_authentication_secret(monkeypatch):
    monkeypatch.setattr(main, "UNWEB_ENV", "production")
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "")
    monkeypatch.setattr(main, "REDIS_CLIENT", None)
    with pytest.raises(RuntimeError, match="UNWEB_AUTH_PROXY_SECRET"):
        with TestClient(main.app):
            pass


def test_production_startup_requires_shared_redis(monkeypatch):
    monkeypatch.setattr(main, "UNWEB_ENV", "production")
    monkeypatch.setattr(main, "AUTH_PROXY_SECRET", "configured-secret")
    monkeypatch.setattr(main, "REDIS_CLIENT", None)
    with pytest.raises(RuntimeError, match="UNWEB_REDIS_URL"):
        with TestClient(main.app):
            pass
