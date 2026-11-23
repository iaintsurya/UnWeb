# Testing

Run the backend suite with `cd backend && python -m pytest -q`.

## Current regression coverage

Backend tests cover URL normalisation and private-address rejection, mocked breadth-first crawling, page limits, observed sitemap edges, same-origin redirect boundaries, IP-pinned DNS/Host/SNI behavior, response content types, cross-page assets/scripts, SQLite persistence/retention, sliding-window rate limits, API creation/history/lookup and 429 responses, HTML extraction, passive security-header evidence, and JavaScript comment-aware route/library/source-map evidence. Reconstruction tests cover output structure, safe URL handling, HTML escaping, removed active content, and empty states.

The optional browser-worker suite tests HTTPS-only target intake, CONNECT authority parsing, target-origin restrictions, proxy pinning to a validated IP literal, query-string redaction, same-origin request handling, cleanup behavior, and the explicit isolation acknowledgement. These tests use local loopback fixtures and fakes; they do not launch Chromium or send requests to third-party websites.

Run the frontend checks with `cd frontend && npm ci && npm run build && npm test`. Vitest tests the shared API request helper's success and error handling plus sitemap graph empty/self-link rendering; the build runs TypeScript's strict project checks before bundling.

## Repository-analysis regression coverage

The local repository-analysis suite uses temporary fixture repositories and verifies credential/token/private-key redaction, placeholder filtering, Python AST checks for multiline calls/comment exclusion, cross-language heuristic rule matches, npm/Python/Cargo/Go dependency manifest and lockfile inventory, skip-directory behavior, symlink handling, file/byte limits, invalid-input handling, CLI JSON output, and the suspected validation state. It does not clone repositories, execute scanned code, or query external vulnerability sources.

## Security test requirements (planned)

Before a vulnerability check is added, require tests for:
- scope allow/deny behavior, including redirects, alternate ports, IP literals, subdomains and discovered links;
- request count, concurrency, wall-clock and response-size budgets;
- harmless positive, negative and inconclusive fixtures;
- evidence provenance, confidence labels and redaction of credentials/cookies/tokens;
- absence of out-of-scope requests and unsafe side effects;
- repeatability and retest behavior after a simulated fix.

Authorization checks must use owner-provided synthetic accounts and records. Injection checks should use inert markers or a dedicated controlled lab, not payloads that alter or extract real data. SSRF-related tests should use a purpose-built local harness or approved callback endpoint, never cloud metadata or private production services.

GitHub Actions runs the current backend suite and frontend build/tests on pushes and pull requests. Use local fixtures and mocked responses, not third-party websites, as automated test targets. The standard CI job does not download or launch Chromium.

## Release gates (planned)

- A reviewed scope and consent model exists before active checks ship.
- Each check has documented prerequisites, expected signals, false-positive cases, request budgets and remediation.
- High-impact tests are disabled by default and require a separately approved lab/manual workflow.
- Findings clearly distinguish evidence from inference and do not overstate exploitability.
- Worker isolation, network egress policy, authentication, audit trail, retention/redaction and resource limits receive independent review.

