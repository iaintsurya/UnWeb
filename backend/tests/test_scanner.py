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
