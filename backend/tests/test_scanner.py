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


def test_recursive_crawl_records_only_observed_edges(monkeypatch):
    responses = {
        "https://example.com/": html_page("Home", "/a", "/b"),
        "https://example.com/a": html_page("Page A", "/c"),
        "https://example.com/b": html_page("Page B", "/c"),
        "https://example.com/c": html_page("Page C", "/"),
    }
    calls = []

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None):
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

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None):
        calls.append(url)
        return url, 200, {"content-type": "text/html"}, responses[url]

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    result = asyncio.run(scanner.scan_site("https://example.com", max_pages=2, include_reconstruction=False))

    assert len(result.pages) == 2
    assert calls == ["https://example.com/", "https://example.com/a"]


def test_non_html_target_is_rejected(monkeypatch):
    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None):
        return url, 200, {"content-type": "application/json"}, b'{"ok":true}'

    monkeypatch.setattr(scanner, "safe_fetch", fake_safe_fetch)
    with pytest.raises(UnsupportedContentType):
        asyncio.run(scanner.scan_site("https://example.com", include_reconstruction=False))


def test_non_html_link_is_not_added_as_a_page(monkeypatch):
    responses = {
        "https://example.com/": html_page("Home", "/data.json"),
    }

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None):
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

        def stream(self, method, url):
            requested_urls.append(url)
            return RedirectResponse()

    monkeypatch.setattr(scanner, "validate_resolved_addresses", lambda url: [])
    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)

    with pytest.raises(scanner.URLRejected, match="original site origin"):
        asyncio.run(
            scanner.safe_fetch(
                "https://example.com/start",
                allowed_origin=scanner._origin("https://example.com"),
            )
        )

    assert requested_urls == ["https://example.com/start"]



def test_assets_and_scripts_are_collected_across_discovered_pages(monkeypatch):
    root = (
        b'<html><head><title>Home</title><script src="/root.js"></script>'
        b'</head><body><a href="/about">About</a><img src="/hero.png"></body></html>'
    )
    about = (
        b'<html><head><title>About</title><script src="/about.js"></script>'
        b'<link rel="stylesheet" href="/about.css"></head><body>About</body></html>'
    )
    responses = {
        "https://example.com/": ({"content-type": "text/html"}, root),
        "https://example.com/about": ({"content-type": "text/html"}, about),
        "https://example.com/root.js": ({"content-type": "text/javascript"}, b'fetch("/api/home")'),
        "https://example.com/about.js": ({"content-type": "application/javascript"}, b'fetch("/api/about")'),
    }
    calls = []

    async def fake_safe_fetch(url: str, max_bytes: int = scanner.MAX_HTML, allowed_origin=None):
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
