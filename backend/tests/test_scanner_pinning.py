import asyncio

from app import scanner


def test_safe_fetch_falls_back_to_another_validated_ip(monkeypatch):
    requested_urls = []

    class SuccessResponse:
        status_code = 200
        headers = {"content-type": "text/plain"}

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        async def aiter_bytes(self):
            yield b"pinned"

    class FakeClient:
        def __init__(self, **kwargs):
            pass

        async def __aenter__(self):
            return self

        async def __aexit__(self, exc_type, exc, traceback):
            return False

        def stream(self, method, url, headers=None, extensions=None):
            requested_urls.append(url)
            if len(requested_urls) == 1:
                raise scanner.httpx.ConnectError("IPv6 route unavailable")
            assert headers["Host"] == "example.com"
            assert extensions["sni_hostname"] == "example.com"
            return SuccessResponse()

    addresses = ["2606:4700:4700::1111", "93.184.216.34"]
    monkeypatch.setattr(
        scanner,
        "validate_resolved_addresses",
        lambda url: addresses,
    )
    monkeypatch.setattr(scanner.httpx, "AsyncClient", FakeClient)

    result = asyncio.run(scanner.safe_fetch("https://example.com/path"))

    assert requested_urls == [
        "https://[2606:4700:4700::1111]/path",
        "https://93.184.216.34/path",
    ]
    assert result[0] == "https://example.com/path"
    assert result[3] == b"pinned"
