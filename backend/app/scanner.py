import asyncio
import uuid
import httpx
import ipaddress

from collections import deque
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urldefrag

from .models import ScanResult
from .url_policy import normalize_url, validate_resolved_addresses, URLRejected
from .engines import analyze_html, analyze_security, analyze_javascript

MAX_HTML = 1_500_000
MAX_SCRIPT = 500_000
TIMEOUT = httpx.Timeout(8.0, connect=4.0)
MAX_REDIRECTS = 5
UA = "UnWeb/0.1 (authorised passive analysis)"


class UnsupportedContentType(ValueError):
    """Raised when the requested target is not an HTML document."""


def _origin(url: str) -> tuple[str, str, int]:
    parts = urlsplit(url)
    scheme = parts.scheme.lower()
    host = (parts.hostname or "").rstrip(".").lower()
    port = parts.port or (443 if scheme == "https" else 80)
    return scheme, host, port


def _same_origin(url: str, origin: tuple[str, str, int]) -> bool:
    try:
        return _origin(url) == origin
    except ValueError:
        return False


def _pinned_request(url: str, address: str) -> tuple[str, str, dict[str, str]]:
    """Build an IP-literal request while preserving Host and TLS identity."""
    parts = urlsplit(url)
    hostname = parts.hostname
    if not hostname:
        raise URLRejected("URL has no hostname.")

    try:
        ipaddress.ip_address(hostname)
        is_ip_literal = True
        origin_host = hostname
    except ValueError:
        is_ip_literal = False
        try:
            origin_host = hostname.encode("idna").decode("ascii")
        except UnicodeError as exc:
            raise URLRejected("Hostname could not be encoded safely.") from exc

    try:
        ipaddress.ip_address(address)
    except ValueError as exc:
        raise URLRejected("DNS returned an invalid address.") from exc

    pinned_host = f"[{address}]" if ":" in address else address
    pinned_netloc = pinned_host
    host_header = f"[{origin_host}]" if ":" in origin_host else origin_host
    if parts.port is not None:
        pinned_netloc += f":{parts.port}"
        host_header += f":{parts.port}"

    pinned_url = urlunsplit((
        parts.scheme,
        pinned_netloc,
        parts.path or "/",
        parts.query,
        "",
    ))
    extensions: dict[str, str] = {}
    if parts.scheme == "https" and not is_ip_literal:
        # HTTPX passes this through to httpcore for SNI and certificate
        # hostname validation, while TCP connects to the validated IP.
        extensions["sni_hostname"] = origin_host
    return pinned_url, host_header, extensions


def _is_html(headers: dict[str, str]) -> bool:
    content_type = next(
        (value for key, value in headers.items() if key.lower() == "content-type"),
        "",
    )
    media_type = content_type.split(";", 1)[0].strip().lower()
    # Some servers omit Content-Type. Preserve the previous HTML fallback in
    # that case, but never parse a response explicitly labelled as another type.
    return not media_type or media_type in {"text/html", "application/xhtml+xml"}


async def safe_fetch(
    url: str,
    max_bytes: int = MAX_HTML,
    allowed_origin: tuple[str, str, int] | None = None,
):
    current = normalize_url(url)
    for hop in range(MAX_REDIRECTS + 1):
        # Resolve and validate once, then connect to each validated IP literal
        # in turn. HTTPX never performs another DNS lookup for these requests.
        addresses = await asyncio.to_thread(validate_resolved_addresses, current)
        last_connect_error = None
        redirected = False

        for address in addresses:
            pinned_url, host_header, extensions = _pinned_request(current, address)
            try:
                async with httpx.AsyncClient(
                    timeout=TIMEOUT,
                    follow_redirects=False,
                    trust_env=False,
                ) as client:
                    async with client.stream(
                        "GET",
                        pinned_url,
                        headers={
                            "User-Agent": UA,
                            "Accept": "text/html,*/*;q=0.5",
                            "Host": host_header,
                        },
                        extensions=extensions,
                    ) as response:
                        if response.status_code in {301, 302, 303, 307, 308}:
                            location = response.headers.get("location")
                            if not location:
                                return current, response.status_code, dict(response.headers), b""
                            if hop >= MAX_REDIRECTS:
                                raise URLRejected("Too many redirects.")
                            redirect_url = normalize_url(urljoin(current, location))
                            if allowed_origin is not None and not _same_origin(redirect_url, allowed_origin):
                                raise URLRejected("Redirect left the original site origin.")
                            current = redirect_url
                            redirected = True
                            break

                        chunks = []
                        total = 0
                        async for chunk in response.aiter_bytes():
                            total += len(chunk)
                            if total > max_bytes:
                                raise URLRejected(f"Response exceeded the {max_bytes} byte limit.")
                            chunks.append(chunk)
                        return current, response.status_code, dict(response.headers), b"".join(chunks)
            except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
                last_connect_error = exc
                continue

        if redirected:
            continue
        if last_connect_error is not None:
            raise last_connect_error
        raise URLRejected("Hostname resolved to no usable addresses.")

    raise URLRejected("Too many redirects.")


async def scan_site(raw_url: str, max_pages: int = 8, include_reconstruction: bool = True):
    start = normalize_url(raw_url)
    final_url, status, headers, body = await safe_fetch(start)
    if not _is_html(headers):
        raise UnsupportedContentType("The target returned a non-HTML response. UnWeb analyses HTML pages.")

    html = body.decode("utf-8", errors="replace")
    page, assets, tech = analyze_html(final_url, html)
    page.status_code = status
    findings = analyze_security(headers, final_url)

    pages = [page]
    origin = _origin(final_url)
    visited = {urldefrag(final_url)[0]}
    queued = set()
    queue = deque()
    edges: list[tuple[str, str]] = []
    seen_edges: set[tuple[str, str]] = set()

    def discover_links(source_page):
        source_url = urldefrag(source_page.url)[0]
        for link in source_page.links:
            target_url = urldefrag(link)[0]
            if not _same_origin(target_url, origin):
                continue

            edge = (source_url, target_url)
            if edge not in seen_edges:
                seen_edges.add(edge)
                edges.append(edge)

            if target_url not in visited and target_url not in queued:
                queued.add(target_url)
                queue.append(target_url)

    # Breadth-first discovery: pages found on each successfully fetched page
    # are added to the queue, while visited/queued sets prevent repeat requests.
    discover_links(page)

    while queue and len(pages) < max_pages:
        requested_url = queue.popleft()
        queued.discard(requested_url)
        if requested_url in visited:
            continue
        visited.add(requested_url)

        try:
            fetched_url, page_status, page_headers, page_body = await safe_fetch(
                requested_url, allowed_origin=origin
            )
        except (URLRejected, httpx.HTTPError, OSError):
            continue

        # The starting page defines the crawl boundary. Do not follow a
        # same-origin link to a different host through a redirect.
        if not _same_origin(fetched_url, origin) or not _is_html(page_headers):
            continue

        final_page_url = urldefrag(fetched_url)[0]
        if final_page_url != requested_url:
            edges = [
                (source, final_page_url if target == requested_url else target)
                for source, target in edges
            ]
            seen_edges = set(edges)
            visited.add(final_page_url)

        if any(existing.url == fetched_url for existing in pages):
            continue

        page_html = page_body.decode("utf-8", errors="replace")
        discovered_page, _, page_technologies = analyze_html(fetched_url, page_html)
        discovered_page.status_code = page_status
        pages.append(discovered_page)
        for technology in page_technologies:
            if not any(existing.get("name") == technology.get("name") for existing in tech):
                tech.append(technology)
        discover_links(discovered_page)

    # Consolidate assets across every discovered HTML page, not just the
    # landing page. De-duplicate by (kind, URL) while preserving discovery order.
    asset_keys = {(item["kind"], item["url"]) for item in assets}
    for scanned_page in pages:
        for kind, urls in (
            ("script", scanned_page.scripts),
            ("stylesheet", scanned_page.stylesheets),
            ("image", scanned_page.images),
        ):
            for asset_url in urls:
                key = (kind, asset_url)
                if key not in asset_keys:
                    asset_keys.add(key)
                    assets.append({"kind": kind, "url": asset_url})

    # Analyse a bounded, de-duplicated set of same-origin scripts across all
    # scanned pages. Every script redirect remains pinned to the crawl origin.
    script_urls = list(dict.fromkeys(
        script_url
        for scanned_page in pages
        for script_url in scanned_page.scripts
        if _same_origin(script_url, origin)
    ))[:20]
    js = []
    for script_url in script_urls:
        try:
            fetched_script_url, _, script_headers, script = await safe_fetch(
                script_url, MAX_SCRIPT, allowed_origin=origin
            )
            if not _same_origin(fetched_script_url, origin):
                raise URLRejected("Script redirected outside the target origin.")
            content_type = next(
                (value for key, value in script_headers.items() if key.lower() == "content-type"),
                "",
            ).split(";", 1)[0].strip().lower()
            if content_type and not (
                "javascript" in content_type
                or "ecmascript" in content_type
                or content_type in {"text/plain", "application/octet-stream"}
            ):
                raise URLRejected("Script response did not have a recognised JavaScript content type.")
            js.append(
                analyze_javascript(
                    fetched_script_url,
                    script.decode("utf-8", errors="replace"),
                )
            )
        except (URLRejected, httpx.HTTPError, OSError):
            js.append({
                "url": script_url,
                "error": "Script could not be safely fetched or analysed.",
            })

    reconstruction = None
    if include_reconstruction:
        from .rebuild import make_reconstruction
        reconstruction = make_reconstruction(final_url, html)

    scanned_page_urls = {scanned_page.url for scanned_page in pages}
    edges = [
        (source, target) for source, target in edges
        if source in scanned_page_urls and target in scanned_page_urls
    ]

    return ScanResult(
        id=str(uuid.uuid4()),
        requested_url=start,
        final_url=final_url,
        status_code=status,
        scanned_at=datetime.now(timezone.utc).isoformat(),
        title=page.title,
        description=page.metadata.get("description") or page.metadata.get("og:description"),
        headers={key.lower(): value for key, value in headers.items()},
        technologies=tech,
        assets=assets,
        page=page,
        pages=pages,
        edges=[{"source": source, "target": target} for source, target in edges],
        findings=findings,
        js_analysis=js,
        notes=[
            "Only public responses and delivered assets were inspected.",
            "Technology and JavaScript string matches are heuristic clues, not proof.",
            f"Crawler follows same-origin links breadth-first and stops at the requested {max_pages}-page limit.",
            "Page relationships include only links observed in fetched HTML.",
        ],
        reconstruction=reconstruction,
    )
