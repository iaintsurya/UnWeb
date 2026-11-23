import asyncio

import pytest

from app import browser_worker
from app.url_policy import URLRejected


def test_browser_worker_requires_https_and_rejects_private_targets():
    with pytest.raises(URLRejected, match="requires an HTTPS"):
        browser_worker.TargetConnectProxy("http://example.com/")

    with pytest.raises(URLRejected):
        browser_worker.TargetConnectProxy("https://127.0.0.1/")


@pytest.mark.parametrize(
    ("authority", "expected"),
    [
        ("example.com:443", ("example.com", 443)),
        ("EXAMPLE.com:8443", ("example.com", 8443)),
        ("[2606:4700:4700::1111]:443", ("2606:4700:4700::1111", 443)),
    ],
)
def test_parse_connect_authority(authority, expected):
    assert browser_worker._parse_connect_authority(authority) == expected


@pytest.mark.parametrize(
    "authority",
    [
        "",
        "example.com:bad",
        "user@example.com:443",
        "example.com:443/path",
        "example.com:99999",
        "localhost:443",
    ],
)
def test_rejects_malformed_connect_authorities(authority):
    if authority == "localhost:443":
        assert browser_worker._parse_connect_authority(authority) == ("localhost", 443)
    else:
        with pytest.raises(URLRejected):
            browser_worker._parse_connect_authority(authority)


def test_display_url_removes_query_and_fragment():
    assert browser_worker._display_url(
        "https://example.com/private/path?token=secret#fragment"
    ) == "https://example.com/private/path"


def test_proxy_is_bound_to_loopback_and_denies_other_origins(monkeypatch):
    monkeypatch.setattr(
        browser_worker,
        "validate_resolved_addresses",
        lambda url: ["93.184.216.34"],
    )

    async def exercise():
        proxy = browser_worker.TargetConnectProxy("https://example.com/")
        proxy_url = await proxy.start()
        reader, writer = await asyncio.open_connection("127.0.0.1", int(proxy_url.rsplit(":", 1)[1]))
        writer.write(b"CONNECT 127.0.0.1:443 HTTP/1.1\r\nHost: 127.0.0.1:443\r\n\r\n")
        await writer.drain()
        response = await asyncio.wait_for(reader.read(), timeout=2)
        writer.close()
        await writer.wait_closed()
        await proxy.close()
        return proxy, response

    proxy, response = asyncio.run(exercise())
    assert response.startswith(b"HTTP/1.1 403 Forbidden")
    assert proxy.denied_count == 1


def test_proxy_connects_to_the_validated_ip_literal(monkeypatch):
    opened = []

    monkeypatch.setattr(
        browser_worker,
        "validate_resolved_addresses",
        lambda url: ["93.184.216.34", "2606:4700:4700::1111"],
    )

    async def fake_open_connection(host, port):
        opened.append((host, port))
        return "reader", "writer"

    monkeypatch.setattr(browser_worker.asyncio, "open_connection", fake_open_connection)

    async def exercise():
        proxy = browser_worker.TargetConnectProxy("https://example.com/")
        return await proxy._validated_upstream("example.com", 443)

    assert asyncio.run(exercise()) == ("reader", "writer")
    assert opened == [("93.184.216.34", 443)]


def test_cli_refuses_to_run_without_explicit_isolation_acknowledgement(capsys):
    assert browser_worker.main(["--url", "https://example.com/"]) == 2
    assert "disposable non-root worker" in capsys.readouterr().err
