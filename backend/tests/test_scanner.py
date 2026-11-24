import asyncio

import pytest

from app import scanner
from app.scanner import UnsupportedContentType


def html_page(title: str, *links: str) -> bytes:
    anchors = "".join(f'<a href="{link}">{link}</a>' for link in links)
    return f"<html><head><title>{title}</title></head><body>{anchors}</body></html>".encode()


def test_origin_normalization_uses_default_ports():
    assert scanner._origin("https://Example.com/path") == ("https", "example.com", 443)
    assert scanner._origin("http://example.com:80/path") == ("http", "example.com", 80)


def test_html_content_type_validation():
    assert scanner._is_html({"content-type": "text/html; charset=utf-8"})
    assert scanner._is_html({"Content-Type": "application/xhtml+xml"})
    assert scanner._is_html({})
    assert not scanner._is_html({"content-type": "application/json"})
    assert not scanner._is_html({"content-type": "image/png"})


def test_initial_fetch_is_constrained_to_requested_origin(monkeypatch):
    observed = {}

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        observed["url"] = url
        observed["allowed_origin"] = allowed_origin
        return url, 200, {"content-type": "text/html"}, html_page("Home")

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    asyncio.run(scanner.scan_site("https://example.com/start", max_pages=1, include_reconstruction=False))

    assert observed["url"] == "https://example.com/start"
    assert observed["allowed_origin"] == ("https", "example.com", 443)


def test_recursive_crawl_records_only_observed_edges(monkeypatch):
    responses = {
        "https://example.com/": html_page("Home", "/a", "/b"),
        "https://example.com/a": html_page("Page A", "/c"),
        "https://example.com/b": html_page("Page B", "/c"),
        "https://example.com/c": html_page("Page C", "/"),
    }
    calls = []

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        calls.append(url)
        if url not in responses:
            raise AssertionError(f"Unexpected fetch: {url}")
        return url, 200, {"content-type": "text/html; charset=utf-8"}, responses[url]

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(scanner.scan_site("https://example.com", max_pages=4, include_reconstruction=False))

    assert [page.url for page in result.pages] == [
        "https://example.com/",
        "https://example.com/a",
        "https://example.com/b",
        "https://example.com/c",
    ]
    assert set((edge.source, edge.target) for edge in result.edges) == {
        ("https://example.com/", "https://example.com/a"),
        ("https://example.com/", "https://example.com/b"),
        ("https://example.com/a", "https://example.com/c"),
        ("https://example.com/b", "https://example.com/c"),
        ("https://example.com/c", "https://example.com/"),
    }
    assert len(calls) == 4


def test_crawl_respects_page_limit(monkeypatch):
    responses = {
        "https://example.com/": html_page("Home", "/a", "/b"),
        "https://example.com/a": html_page("A", "/c"),
        "https://example.com/b": html_page("B"),
    }
    calls = []

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        calls.append(url)
        return url, 200, {"content-type": "text/html"}, responses[url]

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(scanner.scan_site("https://example.com", max_pages=2, include_reconstruction=False))

    assert len(result.pages) == 2
    assert calls == ["https://example.com/", "https://example.com/a"]


def test_non_html_target_is_rejected(monkeypatch):
    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        return url, 200, {"content-type": "application/json"}, b'{"ok":true}'

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    with pytest.raises(UnsupportedContentType):
        asyncio.run(scanner.scan_site("https://example.com", include_reconstruction=False))


def test_non_html_link_is_not_added_as_a_page(monkeypatch):
    responses = {
        "https://example.com/": html_page("Home", "/data.json"),
    }

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        if url == "https://example.com/data.json":
            return url, 200, {"content-type": "application/json"}, b'{"ok":true}'
        return url, 200, {"content-type": "text/html"}, responses[url]

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(scanner.scan_site("https://example.com", max_pages=3, include_reconstruction=False))

    assert len(result.pages) == 1
    assert result.edges == []



def test_safe_fetch_rejects_off_origin_redirect_before_following(monkeypatch):
    requested_urls = []

    class RedirectResponse:
        status_code = 302
        headers = {"location": "https://outside.example/landing"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            requested_urls.append(url)
            assert headers["Host"] == "example.com"
            assert extensions["sni_hostname"] == "example.com"
            return RedirectResponse()

    monkeypatch.setattr(
        scanner,
        "validate_resolved_addresses",
        lambda url: ["93.184.216.34"],
    )
    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)

    with pytest.raises(scanner.URLRejected, match="original site origin"):
        asyncio.run(
            scanner.safe_fetch(
                "https://example.com/start",
                allowed_origin=scanner._origin("https://example.com"),
            )
        )

    assert requested_urls == ["https://93.184.216.34/start"]



def test_assets_and_scripts_are_collected_across_discovered_pages(monkeypatch):
    root = (
        b'<html><head><title>Home</title><script src="/root.js"></script>'
        b'</head><body><a href="/about">About</a><img src="/hero.png"></body></html>'
    )
    about = (
        b'<html><head><title>About</title><script src="/about.js"></script>'
        b'<link rel="stylesheet" href="/about.css"></head><body>'
        b'<!-- observed /wp-content/themes/site marker -->About</body></html>'
    )
    responses = {
        "https://example.com/": ({"content-type": "text/html"}, root),
        "https://example.com/about": ({"content-type": "text/html"}, about),
        "https://example.com/root.js": ({"content-type": "text/javascript"}, b'fetch("/api/home")'),
        "https://example.com/about.js": ({"content-type": "application/javascript"}, b'fetch("/api/about")'),
    }
    calls = []

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        calls.append(url)
        headers, body = responses[url]
        return url, 200, headers, body

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(
        scanner.scan_site("https://example.com", max_pages=2, include_reconstruction=False)
    )

    asset_pairs = {(asset["kind"], asset["url"]) for asset in result.assets}
    assert ("script", "https://example.com/root.js") in asset_pairs
    assert ("script", "https://example.com/about.js") in asset_pairs
    assert ("stylesheet", "https://example.com/about.css") in asset_pairs
    assert ("image", "https://example.com/hero.png") in asset_pairs
    assert {item["url"] for item in result.js_analysis} == {
        "https://example.com/root.js",
        "https://example.com/about.js",
    }
    assert any(item["name"] == "WordPress" for item in result.technologies)



def test_pinned_request_connects_to_ip_but_preserves_host_and_tls_identity():
    pinned_url, host_header, extensions = scanner._pinned_request(
        "https://www.example.com:8443/path?q=1",
        "93.184.216.34",
    )
    assert pinned_url == "https://93.184.216.34:8443/path?q=1"
    assert host_header == "www.example.com:8443"
    assert extensions == {"sni_hostname": "www.example.com"}


def test_pinned_request_handles_ipv6_literal():
    pinned_url, host_header, extensions = scanner._pinned_request(
        "https://[2606:4700:4700::1111]/",
        "2606:4700:4700::1111",
    )
    assert pinned_url == "https://[2606:4700:4700::1111]/"
    assert host_header == "[2606:4700:4700::1111]"
    assert extensions == {}


def test_pinned_request_rejects_invalid_resolved_address():
    with pytest.raises(scanner.URLRejected, match="invalid address"):
        scanner._pinned_request("https://example.com/", "not-an-ip")



def test_scan_result_redacts_set_cookie_values_from_persistable_headers(monkeypatch):
    import json

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        return (
            url,
            200,
            {
                "content-type": "text/html",
                "set-cookie": "sessionid=top-secret-value; Path=/; SameSite=None",
            },
            html_page("Home"),
        )

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(
        scanner.scan_site(
            "https://example.com",
            max_pages=1,
            include_reconstruction=False,
        )
    )

    assert "set-cookie" not in result.headers
    serialized = json.dumps(result.model_dump())
    assert "top-secret-value" not in serialized
    assert "sessionid" in serialized
    assert any(item.id == "cookie-sessionid-missing-secure" for item in result.findings)


def test_scope_prefixes_are_segment_aware_and_reject_traversal():
    scopes = scanner.normalize_scope_paths(["/app", "/admin/"])
    assert scanner._path_in_scope("https://example.com/app", scopes)
    assert scanner._path_in_scope("https://example.com/app/users", scopes)
    assert scanner._path_in_scope("https://example.com/admin/settings", scopes)
    assert not scanner._path_in_scope("https://example.com/application", scopes)
    assert not scanner._path_in_scope("https://example.com/public", scopes)
    with pytest.raises(scanner.URLRejected):
        scanner.normalize_scope_paths(["/app/../admin"])
    with pytest.raises(scanner.URLRejected):
        scanner.normalize_scope_paths(["/app/%252e%252e/admin"])
    with pytest.raises(scanner.URLRejected):
        scanner.normalize_scope_paths(["https://evil.example/path"])


def test_scan_rejects_start_url_outside_explicit_scope(monkeypatch):
    async def unexpected_fetch(*args, **kwargs):
        raise AssertionError("Out-of-scope target must not be fetched")

    monkeypatch.setattr(scanner, "safe_fetch", unexpected_fetch)
    with pytest.raises(scanner.URLRejected, match="Starting URL is outside"):
        asyncio.run(
            scanner.scan_site(
                "https://example.com/public",
                include_reconstruction=False,
                scope_paths=["/app"],
            )
        )


def test_crawler_does_not_fetch_or_report_pages_outside_scope(monkeypatch):
    responses = {
        "https://example.com/app": html_page("App", "/app/users", "/admin", "/application"),
        "https://example.com/app/users": html_page("Users"),
    }
    calls = []

    async def fake_safe_fetch(url, max_bytes=scanner.MAX_HTML, allowed_origin=None, allowed_paths=None):
        calls.append(url)
        headers = {"content-type": "text/html"}
        return url, 200, headers, responses[url]

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(
        scanner.scan_site(
            "https://example.com/app",
            max_pages=10,
            include_reconstruction=False,
            scope_paths=["/app"],
        )
    )

    assert calls == ["https://example.com/app", "https://example.com/app/users"]
    assert [page.url for page in result.pages] == [
        "https://example.com/app",
        "https://example.com/app/users",
    ]
    assert result.scope_paths == ["/app"]


def test_safe_fetch_rejects_out_of_scope_url_before_dns(monkeypatch):
    def unexpected_resolve(url):
        raise AssertionError("Out-of-scope URL must be rejected before DNS resolution")

    monkeypatch.setattr(scanner, "validate_resolved_addresses", unexpected_resolve)
    with pytest.raises(scanner.URLRejected, match="outside the approved path scope"):
        asyncio.run(
            scanner.safe_fetch(
                "https://example.com/admin",
                allowed_paths=["/app"],
            )
        )


def test_encoded_path_separators_are_not_scope_ambiguous():
    assert not scanner._path_in_scope(
        "https://example.com/app%2f..%2fadmin",
        ["/app"],
    )
    with pytest.raises(scanner.URLRejected, match="Encoded path separators"):
        scanner.normalize_scope_paths(["/app%2fadmin"])
