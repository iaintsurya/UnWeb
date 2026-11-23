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

## Persistence

The preview uses the Python standard library's SQLite driver. Scan payloads are stored as JSON with indexed summary columns; the newest 250 results are retained by default. This avoids requiring a separate database service for local use. It is a single-instance development store, not a horizontally scalable production database. The path is configurable through `UNWEB_DB_PATH`.

## Security boundary

URL policy checks are defence in depth, not a complete SSRF boundary. The current fetcher resolves and validates the host once per hop, then connects to the validated IP literal while preserving the original Host header and TLS SNI/certificate hostname. This avoids a separate HTTP-client DNS lookup between validation and connection for that request. Keep this behavior covered by tests against the pinned HTTPX version. Public deployments still require network-level egress controls, isolated workers, and an independent security review; do not expose the preview API publicly until those controls are in place.

Production also needs an authenticated API, per-user rate limits, durable background jobs, isolated unprivileged workers, CPU/memory/wall-clock limits, audit logs, evidence retention policy, and security review. Browser automation should run in disposable workers with explicit network policy rather than in the API process.

## Roadmap

- **v0.2 foundation:** recursive bounded crawler, observed graph edges, SQLite scan history, cross-page asset/script collection, bounded scan concurrency, frontend API helper, tests and CI.
- **v1.0 hardening:** network-level egress enforcement and independent SSRF review, authentication and shared per-user rate limiting, durable workers, stronger JavaScript analysis, evidence provenance and deeper tests.
- **v2.0 advanced:** isolated Playwright network capture, DOM/style inspector, improved reconstruction, progress events, multi-user storage, and CLI/CI scan mode.
