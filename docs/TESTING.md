# Testing

Run the backend suite with `cd backend && python -m pytest -q`.

## Current regression coverage

Backend tests cover URL normalisation and private-address rejection, mocked breadth-first crawling, page limits, observed sitemap edges, same-origin redirect boundaries, IP-pinned DNS/Host/SNI behavior, response content types, cross-page assets/scripts, SQLite persistence/retention, sliding-window rate limits, API creation/history/lookup and 429 responses, HTML extraction, passive security-header evidence, and JavaScript comment-aware route/library/source-map evidence. Reconstruction tests cover output structure, safe URL handling, HTML escaping, removed active content, and empty states.

The optional browser-worker suite tests HTTPS-only target intake, CONNECT authority parsing, target-origin restrictions, proxy pinning to a validated IP literal, query-string redaction, same-origin request handling, cleanup behavior, and the explicit isolation acknowledgement. These tests use local loopback fixtures and fakes; they do not launch Chromium or send requests to third-party websites.

Run the frontend checks with `cd frontend && npm ci && npm run build && npm test`. Vitest tests the shared API request helper's success and error handling plus sitemap graph empty/self-link rendering; the build runs TypeScript's strict project checks before bundling.

## Repository-analysis regression coverage

API tests cover the raw ZIP upload route, explicit authorisation header, content type, malformed ZIP handling, streamed size limits, per-address rate limiting, result JSON, dependency inventory, and secret redaction. GitHub-source tests cover canonical URL/ref validation, default-branch resolution, immutable commit pinning, approved archive-host redirects, streamed size limits, explicit authorisation, report source identity, and evidence redaction. HTTP interactions use `httpx.MockTransport`; CI never downloads a third-party repository. The frontend GitHub and ZIP forms are covered by the TypeScript/Vite production build; there is not yet a dedicated component test for the full upload interaction.

The local repository-analysis suite uses temporary fixture repositories and verifies credential/token/private-key redaction, placeholder filtering, Python AST checks for multiline calls/comment exclusion, cross-language heuristic rule matches, npm/Python/Cargo/Go dependency manifest and lockfile inventory (including iterative handling of nested npm v1 trees, malformed input guards, and the 5,000-record cap/truncation signal), skip-directory behavior, symlink handling, file/byte limits, invalid-input handling, CLI JSON output, and the suspected validation state. It does not clone repositories, execute scanned code, or query external vulnerability sources.

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
## Common finding schema tests

The backend suite includes adapter tests for website and repository evidence, stable IDs for repeated check/location pairs, independent severity and confidence values, safe validation-state normalisation, and API exposure of the common records. Existing source-specific response fields remain covered for compatibility.
## Repository route inventory tests

Route inventory tests cover Python decorator methods, JavaScript/TypeScript route calls, comment/string false-positive guards, Go/Spring/PHP/Ruby lexical patterns, source locations, and explicit truncation at the 2,000-route budget. The checks remain static and do not execute repository code.
## Website/repository correlation tests

Frontend tests cover exact path overlap, query/trailing-slash normalisation, parameterised repository paths, known HTTP method conflicts, unknown JavaScript methods, dynamic-template confidence downgrades, and missing route-inventory handling. The correlation view must retain explicit limitations and never label a path overlap as a vulnerability.
## Website scan authorisation tests

The API test suite verifies that `POST /api/scans` returns HTTP 403 with `website_authorisation_required` when `authorised` is missing/false, and accepts the request only when the explicit acknowledgement is true. The UI disables submission until the consent checkbox is checked; this acknowledgement is not a substitute for production identity and target-scope enforcement.
## Dynamic SQL heuristic tests

Backend tests cover f-string interpolation, concatenation, percent formatting and `.format()` as suspected SQL construction, while asserting that a literal placeholder query with a separate bind-parameter argument is not flagged.

## Dependency advisory tests

The OSV lookup tests use `httpx.MockTransport` and never call the live provider in CI. They cover ecosystem mapping, package de-duplication, advisory field allowlisting, unresolved/unsupported package rejection, the 100-package cap, and provider failures. API tests verify explicit acknowledgement and invalid package rejection. The UI uses only lockfile-resolved versions and submits at most 100 package coordinates per request; it does not infer versions from broad manifest constraints.
