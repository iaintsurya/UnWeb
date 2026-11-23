import asyncio
import sys
import types
from types import SimpleNamespace

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
    ["", "example.com:bad", "user@example.com:443", "example.com:443/path", "example.com:99999"],
)
def test_rejects_malformed_connect_authorities(authority):
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
        reader, writer = await asyncio.open_connection(
            "127.0.0.1", int(proxy_url.rsplit(":", 1)[1])
        )
        writer.write(
            b"CONNECT 127.0.0.1:443 HTTP/1.1\\r\\n"
            b"Host: 127.0.0.1:443\\r\\n\\r\\n"
        )
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


def test_proxy_does_not_connect_when_dns_policy_rejects(monkeypatch):
    opened = []

    def reject_private_dns(url):
        raise URLRejected("Hostname resolves to a private address.")

    async def fake_open_connection(host, port):
        opened.append((host, port))
        return "reader", "writer"

    monkeypatch.setattr(browser_worker, "validate_resolved_addresses", reject_private_dns)
    monkeypatch.setattr(browser_worker.asyncio, "open_connection", fake_open_connection)

    async def exercise():
        proxy = browser_worker.TargetConnectProxy("https://example.com/")
        return await proxy._validated_upstream("example.com", 443)

    with pytest.raises(URLRejected, match="private address"):
        asyncio.run(exercise())
    assert opened == []


def test_browser_render_uses_sandbox_proxy_and_blocks_other_origins(monkeypatch):
    launch_options = {}
    context_options = {}
    events = {}

    class FakeRoute:
        def __init__(self, url):
            self.request = SimpleNamespace(
                url=url,
                method="GET",
                resource_type="document",
            )
            self.action = None

        async def abort(self):
            self.action = "abort"

        async def continue_(self):
            self.action = "continue"

    class FakePage:
        url = "https://example.com/"

        def __init__(self, context):
            self.context = context
            self.handlers = {}

        def on(self, event, callback):
            self.handlers[event] = callback

        async def goto(self, url, **kwargs):
            assert url == "https://example.com/"
            assert kwargs["wait_until"] == "domcontentloaded"
            events["same_origin"] = FakeRoute("https://example.com/app.js")
            events["other_origin"] = FakeRoute("https://assets.other.test/app.js")
            await self.context.route_handler(events["same_origin"])
            await self.context.route_handler(events["other_origin"])
            response = SimpleNamespace(status=200, url=url)
            for callback in self.context.handlers.get("response", []):
                callback(
                    SimpleNamespace(
                        url=url,
                        status=200,
                        headers={"content-type": "text/html", "content-length": "42"},
                    )
                )
            return response

        async def wait_for_timeout(self, timeout):
            assert timeout == 400

        async def evaluate(self, script):
            assert script == browser_worker.DOM_EXTRACTOR
            return {"title": "Example", "headings": [{"level": 1, "text": "Hello"}]}

    class FakeContext:
        def __init__(self):
            self.handlers = {}
            self.route_handler = None

        async def route(self, pattern, handler):
            assert pattern == "**/*"
            self.route_handler = handler

        def on(self, event, callback):
            self.handlers.setdefault(event, []).append(callback)

        async def new_page(self):
            return FakePage(self)

        async def close(self):
            events["context_closed"] = True

    class FakeBrowser:
        async def new_context(self, **kwargs):
            context_options.update(kwargs)
            return FakeContext()

        async def close(self):
            events["browser_closed"] = True

    class FakeChromium:
        async def launch(self, **kwargs):
            launch_options.update(kwargs)
            return FakeBrowser()

    class FakePlaywrightManager:
        async def __aenter__(self):
            return SimpleNamespace(chromium=FakeChromium())

        async def __aexit__(self, exc_type, exc, traceback):
            return False

    playwright_package = types.ModuleType("playwright")
    playwright_api = types.ModuleType("playwright.async_api")
    playwright_api.async_playwright = lambda: FakePlaywrightManager()
    monkeypatch.setitem(sys.modules, "playwright", playwright_package)
    monkeypatch.setitem(sys.modules, "playwright.async_api", playwright_api)
    monkeypatch.setattr(
        browser_worker,
        "validate_resolved_addresses",
        lambda url: ["93.184.216.34"],
    )

    report = asyncio.run(browser_worker.run_browser_intelligence("https://example.com/"))

    assert launch_options["chromium_sandbox"] is True
    assert launch_options["proxy"]["server"].startswith("http://127.0.0.1:")
    assert context_options["service_workers"] == "block"
    assert context_options["accept_downloads"] is False
    assert events["same_origin"].action == "continue"
    assert events["other_origin"].action == "abort"
    assert events["context_closed"] is True
    assert events["browser_closed"] is True
    assert report["title"] == "Example"
    assert report["network"]["request_count"] == 2
    assert report["network"]["blocked_request_count"] == 1
    assert report["network"]["declared_response_bytes"] == 42


def test_cli_refuses_to_run_without_explicit_isolation_acknowledgement(capsys):
    assert browser_worker.main(["--url", "https://example.com/"]) == 2
    assert "disposable non-root worker" in capsys.readouterr().err
