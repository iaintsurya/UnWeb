# Architecture

## Current preview pipeline

```text
URL normalisation
  -> DNS address validation (off the async event loop)
  -> bounded HTTP fetch and redirect checks
  -> HTML content-type validation
  -> breadth-first same-origin page discovery
  -> metadata, technology, and cross-page asset extraction
  -> comment-aware JavaScript route, library, and source-map evidence
  -> passive security-header observations
  -> optional structured React reconstruction and script-free HTML preview
  -> SQLite persistence and JSON API response
```

The sitemap contains only directed links observed in fetched HTML between pages that were successfully scanned. The API currently performs a scan in the request/response lifecycle, with a per-process limit of two active scans, a 120-second wall-clock timeout, and a small in-process 10-per-minute direct-peer rate guard. CORS origins are configurable through `UNWEB_CORS_ORIGINS`. These controls are not shared across workers or instances.

## Optional browser worker

The Playwright engine is a separate CLI path, not an API dependency:

```text
Operator launches one disposable, non-root worker
  -> HTTPS target URL normalisation and public DNS validation
  -> loopback-only CONNECT proxy starts
  -> Chromium launches with its sandbox enabled and proxy configured
  -> fresh non-persistent context (downloads off, service workers blocked)
  -> context route guard permits only the target HTTPS origin
  -> CONNECT proxy revalidates DNS and opens a socket to a validated IP literal
  -> one DOM-ready render (request/time budgets)
  -> bounded DOM/style and network metadata report (query strings omitted)
  -> browser, context, proxy and process exit
```

The proxy denies non-CONNECT traffic and any host/port other than the initial target origin. Every allowed CONNECT resolves the hostname again, rejects the entire answer set if any address is non-public, and connects to a validated IP literal rather than allowing the browser to perform the destination DNS lookup. Redirects therefore have to pass through the same proxy before the browser can open the next TLS tunnel. Browser route interception is an additional application-level control, not the security boundary.

**Mandatory external controls:** run the image as a non-root user in a disposable container with Chromium sandboxing available; apply a per-job default-deny egress policy that allows only the validated public target IP address(es) on the target HTTPS port and a trusted DNS resolver; deny loopback, private, link-local, multicast, IPv6 ULA, cloud metadata, and all other destinations; and enforce CPU, memory, process, and wall-clock limits. A standard Docker bridge network is not enough. The CLI acknowledgement flag does not inspect or enforce those controls. Since response byte counts are based on declared Content-Length headers, they are not a hard transfer cap.

The worker currently handles one unauthenticated HTTPS page per process. It does not click links, submit forms, use a saved browser profile, or write scan output to SQLite. It is intentionally not callable from the API until UnWeb has a durable job queue and a separately managed worker pool with enforceable per-job network policy.

## Persistence

The preview uses the Python standard library's SQLite driver. Scan payloads are stored as JSON with indexed summary columns; the newest 250 results are retained by default. This avoids requiring a separate database service for local use. It is a single-instance development store, not a horizontally scalable production database. The path is configurable through `UNWEB_DB_PATH`.

## Security boundary

URL policy checks are defence in depth, not a complete SSRF boundary. The current fetcher resolves and validates the host once per hop, then connects to the validated IP literal while preserving the original Host header and TLS SNI/certificate hostname. This avoids a separate HTTP-client DNS lookup between validation and connection for that request. Keep this behavior covered by tests against the pinned HTTPX version. Public deployments still require network-level egress controls, isolated workers, and an independent security review; do not expose the preview API publicly until those controls are in place.

Production also needs an authenticated API, per-user rate limits, durable background jobs, isolated unprivileged workers, CPU/memory/wall-clock limits, audit logs, evidence retention policy, and security review.

## Roadmap

- **v0.2 foundation:** recursive bounded crawler, observed graph edges, SQLite scan history, cross-page asset/script collection, bounded scan concurrency, frontend API helper, tests and CI.
- **v1.0 hardening:** network-level egress enforcement and independent SSRF review, authentication and shared per-user rate limiting, durable workers, stronger JavaScript analysis, evidence provenance and deeper tests.
- **v2.0 advanced:** integrated isolated Playwright jobs, DOM/style inspector, improved reconstruction, progress events, multi-user storage, and CLI/CI scan mode.
