# Architecture
Current pipeline: URL normalisation -> DNS address validation -> bounded HTTP fetch -> HTML parsing -> fingerprinting -> JS lexical clues -> passive header checks -> optional reconstruction -> JSON response.

Production pipeline should use authenticated API, durable jobs, isolated workers, egress-enforcing proxy/firewall, persistent evidence store and real progress events. Application-level DNS checks alone cannot fully eliminate DNS rebinding/TOCTOU risk. Public deployment requires network-level egress controls, unprivileged disposable browser containers, CPU/memory/wall-clock limits, rate limiting, audit logs and security review.

v0.1: safe URL intake, bounded fetch, metadata/assets/fingerprints.
v1.0: bounded crawler, JS inventory, passive security, exports and broader tests.
v2.0: isolated Playwright network capture, DOM/style inspector, better reconstruction, job queue, WebSockets, durable DB, CLI and CI mode.
