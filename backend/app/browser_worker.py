"""Optional one-shot Chromium intelligence worker.

This module is deliberately not imported or called by the FastAPI request path.
Run it only in a disposable, non-root worker with an external default-deny
egress policy. The local CONNECT proxy is defence in depth, not a replacement
for that network boundary.
"""
from __future__ import annotations

import argparse
import asyncio
import json
import re
import sys
from urllib.parse import urlsplit, urlunsplit

from .url_policy import URLRejected, normalize_url, validate_resolved_addresses

MAX_PROXY_HEADER = 16_384
MAX_REQUESTS_DEFAULT = 80
PROXY_CONNECT_TIMEOUT = 4.0
MAX_CAPTURE_ITEMS = 100
DOM_EXTRACTOR = r"""
() => {
  const clip = (value, max = 160) => String(value || '').trim().slice(0, max);
  const safeSameOrigin = (value) => {
    try {
      const url = new URL(value, location.href);
      if (url.protocol !== 'https:' || url.origin !== location.origin) return null;
      url.search = '';
      url.hash = '';
      return url.href;
    } catch (_) { return null; }
  };
  const style = (element) => {
    if (!element) return null;
    const css = getComputedStyle(element);
    return {
      color: css.color,
      backgroundColor: css.backgroundColor,
      fontFamily: clip(css.fontFamily, 120),
      fontSize: css.fontSize,
      fontWeight: css.fontWeight,
      lineHeight: css.lineHeight,
      display: css.display
    };
  };
  const body = document.body;
  const root = document.documentElement;
  const headings = Array.from(document.querySelectorAll('h1,h2,h3,h4,h5,h6'))
    .slice(0, 40)
    .map((node) => ({
      level: Number(node.tagName.slice(1)),
      text: clip(node.innerText || node.textContent, 180)
    }))
    .filter((item) => item.text);
  const links = Array.from(document.querySelectorAll('a[href]'))
    .map((node) => ({
      text: clip(node.innerText || node.textContent, 120),
      url: safeSameOrigin(node.href)
    }))
    .filter((item) => item.url)
    .slice(0, 60);
  const images = Array.from(document.images)
    .map((node) => ({
      url: safeSameOrigin(node.currentSrc || node.src),
      alt: clip(node.alt, 120),
      width: Number(node.naturalWidth || 0),
      height: Number(node.naturalHeight || 0)
    }))
    .filter((item) => item.url)
    .slice(0, 40);
  const selectors = ['body', 'main', 'header', 'nav', 'footer', 'h1', 'h2', 'a'];
  const styles = {};
  for (const selector of selectors) {
    styles[selector] = style(document.querySelector(selector));
  }
  const stylesheetLinks = Array.from(document.querySelectorAll('link[rel~="stylesheet"][href]'))
    .map((node) => safeSameOrigin(node.href))
    .filter(Boolean)
    .slice(0, 30);
  const scriptLinks = Array.from(document.querySelectorAll('script[src]'))
    .map((node) => safeSameOrigin(node.src))
    .filter(Boolean)
    .slice(0, 30);
  const classTokens = Array.from(document.querySelectorAll('[class]'))
    .flatMap((node) => Array.from(node.classList))
    .filter(Boolean);
  return {
    title: clip(document.title, 200),
    description: clip(document.querySelector('meta[name="description" i]')?.content, 300),
    headings,
    links,
    images,
    stylesheetLinks,
    scriptLinks,
    landmarks: {
      main: document.querySelectorAll('main,[role="main"]').length,
      navigation: document.querySelectorAll('nav,[role="navigation"]').length,
      header: document.querySelectorAll('header,[role="banner"]').length,
      footer: document.querySelectorAll('footer,[role="contentinfo"]').length
    },
    styles,
    classSamples: Array.from(new Set(classTokens)).slice(0, 80),
    document: {
      width: Number(root?.scrollWidth || 0),
      height: Number(root?.scrollHeight || 0),
      viewportWidth: Number(window.innerWidth || 0),
      viewportHeight: Number(window.innerHeight || 0),
      characterCount: Number(root?.outerHTML?.length || 0)
    }
  };
}
"""


def _canonical_host(host: str) -> str:
    value = host.rstrip(".").lower()
    try:
        return value.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise URLRejected("Hostname could not be encoded safely.") from exc


def _origin_tuple(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    if not parts.hostname:
        raise URLRejected("URL has no hostname.")
    return (
        parts.scheme.lower(),
        _canonical_host(parts.hostname),
        parts.port or (443 if parts.scheme.lower() == "https" else 80),
    )


def _display_url(url: str) -> str:
    """Remove query strings and fragments from captured URLs."""
    try:
        parts = urlsplit(url)
        if parts.scheme not in {"http", "https", "wss", "ws"} or not parts.hostname:
            return ""
        host = parts.hostname
        netloc = f"[{host}]" if ":" in host else host
        if parts.port is not None:
            netloc += f":{parts.port}"
        return urlunsplit((parts.scheme, netloc, parts.path[:500], "", ""))
    except ValueError:
        return ""


def _parse_connect_authority(authority: str) -> tuple[str, int]:
    if not authority or len(authority) > 512 or "@" in authority:
        raise URLRejected("Invalid CONNECT authority.")
    try:
        parts = urlsplit("https://" + authority)
        if not parts.hostname or parts.path not in {"", "/"} or parts.query or parts.fragment:
            raise URLRejected("Invalid CONNECT authority.")
        port = parts.port or 443
    except ValueError as exc:
        raise URLRejected("Invalid CONNECT authority.") from exc
    if not 1 <= port <= 65535:
        raise URLRejected("Invalid CONNECT port.")
    return _canonical_host(parts.hostname), port


def _authority_url(host: str, port: int) -> str:
    netloc = f"[{host}]" if ":" in host else host
    return f"https://{netloc}:{port}/"


class TargetConnectProxy:
    """Loopback-only HTTPS CONNECT proxy locked to one target origin.

    Every CONNECT re-resolves the hostname, rejects any non-public result via
    the shared URL policy, and opens the TCP socket to a validated IP literal.
    Plain HTTP proxy requests and every other host/port are denied.
    """

    def __init__(self, target_url: str):
        normalized = normalize_url(target_url)
        scheme, host, port = _origin_tuple(normalized)
        if scheme != "https":
            raise URLRejected("Browser intelligence currently requires an HTTPS target.")
        self.target_url = normalized
        self.allowed_host = host
        self.allowed_port = port
        self.server: asyncio.AbstractServer | None = None
        self.proxy_url: str | None = None
        self.connection_count = 0
        self.denied_count = 0

    async def start(self) -> str:
        # Validate before starting Chromium; every later CONNECT is validated again.
        await asyncio.to_thread(validate_resolved_addresses, self.target_url)
        self.server = await asyncio.start_server(
            self._handle,
            host="127.0.0.1",
            port=0,
            limit=MAX_PROXY_HEADER,
        )
        address = self.server.sockets[0].getsockname()
        self.proxy_url = f"http://127.0.0.1:{address[1]}"
        return self.proxy_url

    async def close(self) -> None:
        if self.server is not None:
            self.server.close()
            await self.server.wait_closed()
            self.server = None

    async def _validated_upstream(self, host: str, port: int):
        if host != self.allowed_host or port != self.allowed_port:
            raise URLRejected("The browser worker proxy only permits the exact target origin.")
        target = _authority_url(host, port)
        addresses = await asyncio.to_thread(validate_resolved_addresses, target)
        last_error: OSError | None = None
        for address in addresses:
            try:
                return await asyncio.wait_for(
                    asyncio.open_connection(host=address, port=port),
                    timeout=PROXY_CONNECT_TIMEOUT,
                )
            except (OSError, asyncio.TimeoutError) as exc:
                last_error = exc
        if last_error is not None:
            raise OSError("Could not connect to a validated target address.") from last_error
        raise URLRejected("Target hostname resolved to no usable public addresses.")

    @staticmethod
    async def _pipe(source: asyncio.StreamReader, destination: asyncio.StreamWriter) -> None:
        while True:
            chunk = await source.read(64 * 1024)
            if not chunk:
                break
            destination.write(chunk)
            await destination.drain()
        try:
            destination.write_eof()
        except (AttributeError, OSError, RuntimeError):
            pass

    @staticmethod
    async def _reply(writer: asyncio.StreamWriter, status: str) -> None:
        writer.write(
            f"HTTP/1.1 {status}\r\nConnection: close\r\nContent-Length: 0\r\n\r\n".encode("ascii")
        )
        try:
            await writer.drain()
        except OSError:
            pass

    async def _handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
        upstream_writer: asyncio.StreamWriter | None = None
        try:
            header = await asyncio.wait_for(
                reader.readuntil(b"\r\n\r\n"),
                timeout=PROXY_CONNECT_TIMEOUT,
            )
            first_line = header.split(b"\r\n", 1)[0].decode("ascii", errors="replace")
            pieces = first_line.split()
            if len(pieces) != 3 or pieces[0].upper() != "CONNECT" or not pieces[2].startswith("HTTP/"):
                self.denied_count += 1
                await self._reply(writer, "403 Forbidden")
                return

            host, port = _parse_connect_authority(pieces[1])
            upstream_reader, upstream_writer = await self._validated_upstream(host, port)
            self.connection_count += 1
            writer.write(b"HTTP/1.1 200 Connection Established\r\nProxy-Agent: UnWeb\r\n\r\n")
            await writer.drain()
            await asyncio.gather(
                self._pipe(reader, upstream_writer),
                self._pipe(upstream_reader, writer),
            )
        except (URLRejected, UnicodeError, ValueError):
            self.denied_count += 1
            await self._reply(writer, "403 Forbidden")
        except (OSError, asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            await self._reply(writer, "502 Bad Gateway")
        finally:
            if upstream_writer is not None:
                upstream_writer.close()
                try:
                    await upstream_writer.wait_closed()
                except OSError:
                    pass
            writer.close()
            try:
                await writer.wait_closed()
            except OSError:
                pass


async def run_browser_intelligence(
    raw_url: str,
    *,
    max_requests: int = MAX_REQUESTS_DEFAULT,
    navigation_timeout_ms: int = 20_000,
    scope_paths: list[str] | None = None,
) -> dict[str, object]:
    """Render one HTTPS page and return bounded, query-redacted evidence."""
    target_url = normalize_url(raw_url)
    target_origin = _origin_tuple(target_url)
    if target_origin[0] != "https":
        raise URLRejected("Browser intelligence currently requires an HTTPS target.")

    scope_paths = scope_paths or ["/"]
    if not _path_in_scope(target_url, scope_paths):
        raise URLRejected("Browser start URL is outside the approved path scope.")

    max_requests = max(1, min(int(max_requests), 150))
    navigation_timeout_ms = max(1_000, min(int(navigation_timeout_ms), 30_000))

    try:
        from playwright.async_api import async_playwright
    except ImportError as exc:
        raise RuntimeError(
            "Playwright is optional. Install backend/requirements-browser.txt and Chromium first."
        ) from exc

    proxy = TargetConnectProxy(target_url)
    proxy_url = await proxy.start()
    requests: list[dict[str, object]] = []
    responses: list[dict[str, object]] = []
    failures: list[dict[str, str]] = []
    websockets: list[str] = []
    console_error_count = 0
    page_error_count = 0
    request_count = 0
    blocked_request_count = 0
    declared_response_bytes = 0
    browser = None
    context = None

    async def inspect() -> dict[str, object]:
        nonlocal console_error_count, page_error_count
        nonlocal request_count, blocked_request_count, declared_response_bytes

        async with async_playwright() as playwright:
            browser_instance = await playwright.chromium.launch(
                headless=True,
                chromium_sandbox=True,
                proxy={"server": proxy_url},
                args=[
                    "--disable-quic",
                    "--proxy-bypass-list=<-loopback>",
                    "--disable-background-networking",
                    "--disable-component-update",
                    "--disable-sync",
                    "--metrics-recording-only",
                ],
            )
            nonlocal browser
            browser = browser_instance
            browser_context = await browser.new_context(
                accept_downloads=False,
                service_workers="block",
                ignore_https_errors=False,
                java_script_enabled=True,
                viewport={"width": 1365, "height": 900},
                device_scale_factor=1,
            )
            nonlocal context
            context = browser_context

            async def guard_request(route) -> None:
                nonlocal request_count, blocked_request_count
                request = route.request
                request_count += 1
                safe_url = _display_url(request.url)
                if len(requests) < MAX_CAPTURE_ITEMS:
                    requests.append({
                        "url": safe_url,
                        "method": request.method,
                        "resource_type": request.resource_type,
                    })
                try:
                    request_origin = _origin_tuple(request.url)
                    allowed = request_origin == target_origin
                except (URLRejected, ValueError):
                    allowed = False
                if request_count > max_requests or not allowed or not _path_in_scope(request.url, scope_paths):
                    blocked_request_count += 1
                    await route.abort()
                    return
                await route.continue_()

            await browser_context.route("**/*", guard_request)

            def on_response(response) -> None:
                nonlocal declared_response_bytes
                if len(responses) >= MAX_CAPTURE_ITEMS:
                    return
                headers = response.headers
                raw_length = headers.get("content-length", "")
                try:
                    length = max(0, int(raw_length))
                except (TypeError, ValueError):
                    length = None
                if length is not None:
                    declared_response_bytes += length
                responses.append({
                    "url": _display_url(response.url),
                    "status": response.status,
                    "content_type": headers.get("content-type", "")[:120],
                    "content_length_declared": length,
                })

            def on_request_failed(request) -> None:
                if len(failures) < 40:
                    failures.append({
                        "url": _display_url(request.url),
                        "resource_type": request.resource_type,
                    })

            browser_context.on("response", on_response)
            browser_context.on("requestfailed", on_request_failed)
            page = await browser_context.new_page()
            page.on("console", lambda message: _increment_console_error(message))
            page.on("pageerror", lambda error: _increment_page_error())
            page.on("websocket", lambda socket: _record_websocket(socket.url))

            navigation_status = None
            navigation_error = None
            try:
                response = await page.goto(
                    target_url,
                    wait_until="domcontentloaded",
                    timeout=navigation_timeout_ms,
                )
                navigation_status = response.status if response is not None else None
            except Exception as exc:
                # Do not store exception text; it can contain target-provided data.
                navigation_error = type(exc).__name__

            try:
                await page.wait_for_timeout(400)
            except Exception:
                pass

            dom = None
            try:
                dom = await page.evaluate(DOM_EXTRACTOR)
            except Exception as exc:
                navigation_error = navigation_error or type(exc).__name__

            final_url = _display_url(page.url) or _display_url(target_url)
            return {
                "engine": "playwright-chromium",
                "target_url": _display_url(target_url),
                "final_url": final_url,
                "navigation_status": navigation_status,
                "navigation_error_type": navigation_error,
                "title": (dom or {}).get("title", ""),
                "dom": dom,
                "network": {
                    "request_count": request_count,
                    "blocked_request_count": blocked_request_count,
                    "requests": requests,
                    "responses": responses,
                    "failed_requests": failures,
                    "declared_response_bytes": declared_response_bytes,
                    "websockets": websockets,
                    "proxy_connections": proxy.connection_count,
                    "proxy_denials": proxy.denied_count,
                },
                "browser_errors": {
                    "console_error_count": console_error_count,
                    "page_error_count": page_error_count,
                },
                "limitations": [
                    "This is one unauthenticated render; no login, form submission, or user interaction is performed.",
                    "Cross-origin subresources are blocked, so styles or content served from third-party hosts may be missing from this render.",
                    "Captured network paths omit query strings and fragments; request bodies and headers are not stored.",
                    "Response byte counts are only those declared by Content-Length and are not a hard transfer cap.",
                    "The exact-origin CONNECT proxy is defence in depth; an external per-job egress firewall is mandatory.",
                    "Browser execution is performed by an isolated queue worker, not the synchronous website scan.",
                ],
            }

    def _increment_console_error(message) -> None:
        nonlocal console_error_count
        try:
            if message.type == "error":
                console_error_count += 1
        except Exception:
            pass

    def _increment_page_error() -> None:
        nonlocal page_error_count
        page_error_count += 1

    def _record_websocket(url: str) -> None:
        safe = _display_url(url)
        if safe and len(websockets) < 30:
            websockets.append(safe)

    try:
        return await asyncio.wait_for(inspect(), timeout=45)
    except asyncio.TimeoutError as exc:
        raise RuntimeError("Browser worker exceeded its 45-second wall-clock limit.") from exc
    finally:
        if context is not None:
            try:
                await context.close()
            except Exception:
                pass
        if browser is not None:
            try:
                await browser.close()
            except Exception:
                pass
        await proxy.close()


def _scope_contains(allowed: str, requested: str) -> bool:
    base = allowed.rstrip("/") or "/"
    return base == "/" or requested == base or requested.startswith(base + "/")


def _path_in_scope(url: str, scope_paths: list[str]) -> bool:
    from urllib.parse import unquote
    path = urlsplit(url).path or "/"
    if re.search(r"%(?:2f|5c)", path, re.IGNORECASE) or chr(92) in path:
        return False
    decoded = unquote(path)
    if chr(92) in decoded or any(part in {".", ".."} for part in decoded.split("/")):
        return False
    return any(_scope_contains(prefix, decoded) for prefix in scope_paths)


async def _execute_browser_job(job_id: str) -> None:
    from datetime import datetime, timezone
    from . import browser_jobs, database

    job = await asyncio.to_thread(browser_jobs.claim_job, job_id)
    if job is None:
        return
    owner_id = await asyncio.to_thread(browser_jobs.get_job_owner, job_id)
    try:
        target_id = job.get("target_id")
        if not target_id:
            raise URLRejected("A verified target authorization is required for browser jobs.")
        target = await asyncio.to_thread(
            database.get_authorized_target, target_id, owner_id,
            datetime.now(timezone.utc).isoformat()
        )
        if target is None:
            raise URLRejected("The verified target authorization is expired, revoked, or unavailable.")
        parts = urlsplit(normalize_url(job["url"]))
        hostname = parts.hostname.encode("idna").decode("ascii").lower() if parts.hostname else ""
        port = parts.port or 443
        if parts.scheme != "https" or hostname != target["hostname"] or port not in target["ports"]:
            raise URLRejected("Browser job URL is outside its verified HTTPS host/port scope.")
        if not all(any(_scope_contains(allowed, requested) for allowed in target["scope_paths"])
                   for requested in job["scope_paths"]):
            raise URLRejected("Browser job path scope exceeds the verified target authorization.")
        result = await run_browser_intelligence(
            job["url"], max_requests=job["max_requests"], scope_paths=job["scope_paths"]
        )
        await asyncio.to_thread(browser_jobs.complete_job, job_id, result)
        await asyncio.to_thread(database.record_audit_event, owner_id,
                                 "browser_scan.completed", job_id, {"target_id": target_id})
    except Exception as exc:
        await asyncio.to_thread(browser_jobs.fail_job, job_id, type(exc).__name__)
        await asyncio.to_thread(database.record_audit_event, owner_id,
                                 "browser_scan.failed", job_id, {"error_code": type(exc).__name__})


async def run_browser_worker() -> None:
    """Consume durable browser jobs; production Compose intentionally runs one consumer."""
    import os
    import socket
    import uuid
    from redis import Redis
    from redis.exceptions import ResponseError
    from . import browser_jobs, database

    redis_url = os.environ.get("UNWEB_REDIS_URL", "").strip()
    if not redis_url:
        raise RuntimeError("UNWEB_REDIS_URL is required for browser worker mode.")
    client = Redis.from_url(redis_url, socket_connect_timeout=3, socket_timeout=15,
                            decode_responses=True)
    await asyncio.to_thread(client.ping)
    await asyncio.to_thread(database.initialize_database)
    await asyncio.to_thread(browser_jobs.initialize)
    try:
        await asyncio.to_thread(client.xgroup_create, browser_jobs.STREAM_NAME,
                                browser_jobs.CONSUMER_GROUP, id="0", mkstream=True)
    except ResponseError as exc:
        if "BUSYGROUP" not in str(exc):
            raise
    await asyncio.to_thread(browser_jobs.recover_interrupted_jobs)
    consumer = f"{socket.gethostname()}-{uuid.uuid4().hex[:8]}"
    while True:
        await asyncio.to_thread(client.set, 'unweb:browser-worker:heartbeat', consumer, ex=90)
        reclaimed = await asyncio.to_thread(
            client.xautoclaim, browser_jobs.STREAM_NAME, browser_jobs.CONSUMER_GROUP,
            consumer, 60_000, "0-0", 1
        )
        messages = reclaimed[1] if reclaimed and len(reclaimed) > 1 else []
        if not messages:
            batches = await asyncio.to_thread(
                client.xreadgroup, browser_jobs.CONSUMER_GROUP, consumer,
                {browser_jobs.STREAM_NAME: ">"}, 1, 5000
            )
            messages = batches[0][1] if batches else []
        for message_id, fields in messages:
            try:
                job_id = fields.get("job_id")
                if job_id:
                    await _execute_browser_job(job_id)
            finally:
                await asyncio.to_thread(client.xack, browser_jobs.STREAM_NAME,
                                        browser_jobs.CONSUMER_GROUP, message_id)



def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="One-shot, exact-origin UnWeb Chromium intelligence worker."
    )
    parser.add_argument("--worker", action="store_true", help="Run the Redis-backed job consumer.")
    parser.add_argument("--url", help="HTTPS URL that you own or are authorised to analyse.")
    parser.add_argument("--max-requests", type=int, default=MAX_REQUESTS_DEFAULT)
    parser.add_argument("--navigation-timeout-ms", type=int, default=20_000)
    parser.add_argument(
        "--confirm-isolated-egress",
        action="store_true",
        help="Confirm this runs in a disposable non-root worker with external per-job egress filtering.",
    )
    args = parser.parse_args(argv)
    if args.worker:
        try:
            asyncio.run(run_browser_worker())
        except KeyboardInterrupt:
            return 0
        return 0
    if not args.url:
        parser.error("--url is required unless --worker is selected.")
    if not args.confirm_isolated_egress:
        print(
            "Refusing to launch: run inside a disposable non-root worker with an external "
            "default-deny egress policy, then pass --confirm-isolated-egress.",
            file=sys.stderr,
        )
        return 2
    try:
        result = asyncio.run(
            run_browser_intelligence(
                args.url,
                max_requests=args.max_requests,
                navigation_timeout_ms=args.navigation_timeout_ms,
            )
        )
    except (URLRejected, RuntimeError) as exc:
        print(json.dumps({"error": str(exc)}), file=sys.stderr)
        return 1
    print(json.dumps(result, ensure_ascii=False, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
