# UnWeb

**An authorised web application security assessment and vulnerability validation platform.**

UnWeb is being built to help website owners and defenders discover attack surface, identify likely security weaknesses, safely validate whether findings are exploitable, understand their impact, and fix them before attackers can abuse them. Website structure, JavaScript clues, browser observations, and reconstruction are supporting evidence—not the product's primary purpose.

**Core workflow:** define authorised scope → map the attack surface → run bounded security checks → validate findings safely → explain impact and evidence → recommend fixes → retest.

See [docs/SECURITY_ASSESSMENT.md](docs/SECURITY_ASSESSMENT.md) for the finding states, minimum evidence model, initial coverage catalogue, and safe validation policy.

> Early engineering preview — not production-ready. Use only on sites you own or are explicitly authorised to analyse.

## Security assessment model

UnWeb is intended for websites and APIs that the operator owns or is explicitly authorised to assess. The first release is a bounded passive reconnaissance and evidence-collection preview; the current scanner is **not yet a full vulnerability scanner or penetration-testing engine**. It currently collects HTML, same-origin page relationships, assets, JavaScript clues, selected response headers, passive `Set-Cookie` attribute observations with cookie values redacted, and optional browser-render evidence. Those observations can inform an assessment, but they do not prove that a vulnerability exists.

The planned assessment workflow is:

1. **Scope and authorisation:** record the approved hostnames, schemes, ports, paths, test window, request budget, and permitted test profile. Out-of-scope redirects and hosts must be denied.
2. **Attack-surface discovery:** inventory pages, API routes, scripts, forms, assets, technologies, security headers, and browser-observed requests.
3. **Vulnerability checks:** run explicit, bounded checks against the authorised target. Start with passive and low-impact checks before any active validation.
4. **Safe validation:** use benign proof markers, controlled test accounts, or an owner-provided test environment to verify suspected issues. Do not steal data, change real user records, persist access, evade controls, or cause service disruption.
5. **Evidence and impact:** record the affected URL/component, check identifier, timestamp, evidence, confidence, preconditions, potential impact, and whether validation was passive, active, or inconclusive.
6. **Remediation and retest:** provide concrete fixes and a repeatable retest that can confirm whether the issue is resolved.

### Initial security coverage priorities

Use the [OWASP Web Security Testing Guide](https://wstg.owasp.org/) as the testing-method reference, the [OWASP Top 10:2025](https://owasp.org/Top10/2025/) as a high-level risk taxonomy, and the [OWASP API Security Top 10:2023](https://owasp.org/www-project-api-security/) for API-specific risks. These are coverage guides, not a claim that UnWeb currently detects every category.

Planned checks will be introduced in levels:

- **Passive:** TLS and security-header observations, exposed files and directories, technology/version clues, public API inventory, cookie attributes, and security-relevant configuration clues.
- **Low-impact active:** bounded method and CORS checks, harmless input markers, endpoint behavior comparisons, and carefully rate-limited configuration probes.
- **Controlled validation:** only with explicit authorisation and suitable test fixtures/accounts—for example, checking object-level authorization using two owner-provided test accounts and non-sensitive test records.

High-impact testing such as destructive injection, denial-of-service, credential attacks, persistent payloads, real data extraction, or attempts to access cloud metadata/internal services is not an automatic scan feature. Those activities require a separately approved lab or manual assessment plan and must never be silently triggered by a URL scan.

## Stack

- Frontend: React, TypeScript, Vite 8, Lucide icons, custom CSS
- Backend: Python 3.11+, FastAPI, HTTPX, Beautiful Soup, Pydantic
- Persistence: SQLite scan history (last 250 results by default)
- Optional browser worker: Playwright Python with pinned Chromium
- Tests: pytest, Vitest, and GitHub Actions CI

## Requirements

- Python 3.11 or newer
- Node.js 20.19+ or 22.12+ (Node 24 is used in CI)
- npm

## Run locally

### Windows PowerShell

```powershell
# Terminal 1 — backend
cd backend
py -3.11 -m venv .venv
.\\.venv\\Scripts\\python.exe -m pip install -r requirements.txt
.\\.venv\\Scripts\\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2 — frontend, from the repository root
cd frontend
npm ci
npm run dev
```

### macOS / Linux

```bash
# Terminal 1 — backend
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2 — frontend, from the repository root
cd frontend
npm ci
npm run dev
```

Frontend: `http://127.0.0.1:5173`; API docs: `http://127.0.0.1:8000/docs`.

The Vite development server proxies `/api` requests to the local FastAPI server. For a deployed frontend, set `VITE_API_BASE_URL` to the backend's public base URL before building.

## Scan storage

Scan results are saved to a local SQLite database at `backend/data/unweb.sqlite3`. The database is created automatically at backend startup and is excluded from Git. The application retains the newest 250 scan records by default.

Set `UNWEB_DB_PATH` in the backend process environment to use a different database file. Set `UNWEB_CORS_ORIGINS` to a comma-separated list of trusted frontend origins for a deployed frontend; do not use a wildcard for a public service. Back up the database file if scan history matters. This single-file SQLite setup is intended for local development and a single backend instance, not horizontally scaled public deployment.

## API

- `GET /api/health` and `GET /api/health/ready`; `GET /api/health/browser-worker` reports the Redis-stream worker heartbeat.
- `GET /api/health`
- `POST /api/scans` with `{"url":"https://example.com","max_pages":8,"authorised":true}`; the explicit acknowledgement is not authentication or proof of ownership.
- `POST /api/repository-scans` with a raw ZIP request body, `Content-Type: application/zip`, `X-UnWeb-Authorised: true`, and optional URL-encoded `X-Repository-Filename`; streams up to 50 MB into a temporary file, analyses it, returns JSON, and deletes the archive.
- `POST /api/github-repository-scans` with JSON `{"repository_url":"https://github.com/owner/repository","ref":"main","authorised":true}`; accepts public canonical GitHub repository URLs only, resolves the ref to a 40-character commit SHA, streams a source ZIP from GitHub's approved archive host (maximum 50 MB), analyses it, returns the commit identity with the report, and deletes the temporary archive. Omit `ref` to use the repository default branch.
- `GET /api/scans?limit=20` — recent scan summaries (limit 1–100)
- `GET /api/scans/{scan_id}` — full saved scan result
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap` — observed page nodes and directed same-origin link edges
- `GET /api/scans/{scan_id}/security`
- `POST /api/dependency-advisories` with JSON `{"authorised":true,"packages":[{"name":"requests","ecosystem":"PyPI","version":"2.31.0"}]}`; queries OSV for exact resolved versions (npm, PyPI/Python, Go, crates.io/Cargo), up to 100 unique package coordinates and a 2 MB response budget. This is advisory matching, not a complete dependency audit or proof of safety.
- `GET /api/scans/{scan_id}/reconstruction`

The scan request accepts `max_pages` from 1 to 30. The UI offers 4, 8, 12, 20, and 30 page presets. These are discovery limits, not a security test profile.

## Optional Playwright browser worker

The browser engine is intentionally **not** part of the FastAPI scan endpoint. It is a separate, one-target CLI that renders one HTTPS page in a fresh Chromium process and records bounded DOM/style evidence, request/response metadata, failed-request counts, WebSocket endpoints, and browser error counts. It does not log query strings, request headers, cookies, or request bodies.

Build the optional non-root worker image from the repository root:

```bash
docker build -f Dockerfile.browser-worker -t unweb-browser-worker .
```

Run it only on a disposable Docker network with an external per-job egress policy:

```bash
docker run --rm \
  --network <your-policy-controlled-network> \
  --read-only \
  --tmpfs /tmp:rw,nosuid,nodev,noexec,size=256m \
  --memory=1g --cpus=1 --pids-limit=128 \
  --cap-drop=ALL --security-opt=no-new-privileges \
  unweb-browser-worker \
  --url https://example.com/ \
  --max-requests 80 \
  --confirm-isolated-egress
```

The network name above is a placeholder, not a network created by this repository. Configure it outside UnWeb so each job can reach only the validated public IP address(es) for its target over the target HTTPS port, plus DNS through a resolver restricted to the target hostname; explicitly deny loopback, private, link-local, multicast, IPv6 ULA, cloud metadata, and all other destinations. A normal Docker bridge network is **not** sufficient. The image runs as UID 10001, uses Chromium's sandbox, and does not add `--no-sandbox`. The host must support Chromium sandboxing; otherwise the worker should fail rather than silently disable it.

The `--confirm-isolated-egress` flag is an operator acknowledgement only. It does not install, inspect, or enforce firewall rules. The worker's loopback-only CONNECT proxy re-resolves and validates every tunnel, pins the connection to a validated public IP literal, and permits only the exact target host and port. Playwright request routing is an additional guard; neither it nor the proxy replaces the external firewall, because browser processes must be treated as untrusted. The worker has a 45-second wall-clock limit and a request-count cap, but declared response lengths are informational rather than a hard transfer cap; enforce memory, CPU, and process limits at the container/runtime layer.

Install locally for development with `cd backend && pip install -r requirements-browser.txt && python -m playwright install chromium`, but do not run the browser worker directly on a machine or network that lacks the external egress controls above. The feature is optional; the standard API and CI do not install browser binaries or depend on Playwright.

This is a single unauthenticated render: it does not submit forms, bypass access controls, reuse your browser profile, or crawl links. It is runtime evidence collection, not active vulnerability validation. Browser renders are submitted through `POST /api/browser-jobs`, persisted as owner-scoped jobs in SQLite, dispatched through Redis Streams, and executed by the separate non-root worker container. Results are available from `GET /api/browser-jobs/{job_id}` and in the Browser Jobs dashboard. `GET /api/health/browser-worker` reports the consumer heartbeat. Production still requires a separately enforced host/cloud default-deny egress policy; the in-container proxy is defence in depth, not the external boundary.

## Local repository analysis preview

UnWeb also includes an early **read-only static analysis CLI** for a local repository checkout. It checks selected source and configuration files for credential-like assignments, common provider-token shapes, private-key markers, dynamic evaluation, risky process/deserialization calls, disabled TLS verification, wildcard CORS configuration, and dependency inventory from npm, Python, Cargo, and Go manifests/lockfiles.

Run it from the backend directory:

```bash
cd backend
python -m app.repository_analysis /path/to/local/checkout

# Or analyse a downloaded repository ZIP (for example, GitHub's Source code ZIP)
python -m app.repository_analysis /path/to/repository.zip --archive
```

The CLI emits JSON. Default limits are 1,500 files, 1 MB per file, 20 MB total input, and 500 findings. It skips common dependency/build/VCS directories and symbolic links; detected secret values are redacted from evidence. It records declared constraints and lockfile-resolved versions where supported, but does not execute repository code, install dependencies, contact GitHub, or make network requests. The separate API advisory endpoint can query OSV for exact resolved versions. Dependency inventory alone is not an advisory scan and does not establish whether a package version is vulnerable.

This is an initial prototype: Python dangerous-call checks use the standard-library AST, while cross-language/configuration rules are lexical and line-based. It is not CodeQL, Semgrep, complete dependency vulnerability auditing, data-flow/reachability analysis, or a complete SAST product. Results are labelled **suspected** and need human review. It can also inspect a bounded ZIP archive such as a downloaded GitHub source archive; archive paths, symlinks, entry counts, and uncompressed file/byte limits are checked before temporary extraction. It is also available in the dashboard through the Repository workspace, which uploads a ZIP to the bounded local API endpoint. The endpoint is upload-based, not connected to the GitHub App or remote clone API; reports are returned to the browser and are not persisted. Only analyse repositories you own or are authorised to assess.

## Tests

```bash
# Backend tests
cd backend
python -m pytest -q

# Frontend build and unit tests
cd ../frontend
npm ci
npm run build
npm test
```

Automated tests use local fixtures and mocked network responses. Repository-analysis tests use temporary local directories and do not clone or contact repositories. They do not scan third-party websites or launch a browser.

## Safety and limits

UnWeb restricts URL schemes to HTTP(S), rejects non-global IP destinations, resolves and validates hostnames, then connects to the validated IP literal while preserving the original HTTP Host header and TLS SNI/certificate identity. It revalidates every redirect, disables ambient proxy configuration, caps response bytes and timeouts, bounds page/script counts, and rejects explicitly non-HTML page responses. DNS resolution runs off the async event loop. The crawler follows same-origin links breadth-first up to the requested page limit; its sitemap graph contains only observed links between successfully scanned HTML pages. Assets and bounded JavaScript clues are collected across discovered pages. JavaScript route references include source lines, confidence, and nearby lexical evidence; comment text is ignored for route discovery. Reconstruction exports a data-driven React component, starter CSS, a script-free HTML preview, a manifest, and usage notes.

The API allows at most two concurrent website scans per process and applies a 120-second scan time limit. In production, Redis-backed atomic sliding windows enforce 10 website scans/minute/user, 5 repository analyses/minute/user, and 10 dependency advisory lookups/minute/user across API processes. Production startup requires Redis and a trusted authentication gateway; if Redis fails, rate-limited operations fail closed with HTTP 503. Local development retains an in-memory limiter. Set `UNWEB_CORS_ORIGINS` to a comma-separated allowlist of frontend origins when hosting the API separately. The IP-pinned fetch path narrows the DNS-rebinding/time-of-check-to-time-of-use risk, but the application is still not a complete SSRF boundary; retain network-level egress controls in any public deployment.

**Important:** application-level DNS checks do not fully eliminate DNS rebinding or time-of-check/time-of-use risks. A production Compose baseline, trusted identity-gateway integration, shared Redis rate limits, and container resource restrictions are now included. Before public deployment, operators must still configure and independently verify outbound network filtering, isolated per-job workers, and append-only audit logging, then obtain an independent security review. The SQLite store remains single-instance only.

UnWeb does not bypass authentication, CAPTCHAs, access controls, or rate limits. Technology and JavaScript matches are clues, not proof. The current security observations are passive and do not establish exploitability; the current release is not a penetration test. Future active checks must require an explicit authorised scope and bounded profile, use non-destructive validation, and preserve evidence without collecting unnecessary sensitive data. A finding must distinguish confirmed, likely, informational, and inconclusive results. Reconstruction is an editable supporting feature, not recovered source code or guaranteed pixel-perfect cloning.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 Preview | Safe URL intake, bounded fetch, metadata, initial fingerprints and UI |
| v0.2 Foundation | Recursive bounded crawl, observed sitemap edges, SQLite history, cross-page asset/script inventory, scan capacity limits, frontend API helper, tests and CI |
| v0.3 Security preview | Passive cookie-attribute checks with value redaction; local read-only repository-analysis CLI with Python AST and lexical checks, supported dependency manifest/lockfile inventory, bounded OSV advisory lookup for exact resolved versions, suspected findings and regression tests |
| v1.0 Hardening | Trusted identity-gateway integration, owner-scoped scan history/audit, Redis shared per-user rate limits, and production Compose baseline are implemented; verified target ownership, external egress enforcement, durable isolated workers, external append-only audit, and independent SSRF review remain required |
| v2.0 Advanced | Cross-source website/API-to-repository correlation, deeper language-aware and dependency analysis, integrated isolated Playwright jobs, progress events, multi-user storage and CLI/CI assessment workflows |

## AI and human collaboration

AI tools may help brainstorm, scaffold, document, and debug. The maintainer is responsible for reviewing code, verifying security assumptions, running tests, checking dependencies, and describing limitations honestly. Do not claim reviews or test coverage that have not occurred.

## License

MIT. See `LICENSE`.
## Common security evidence

Website and repository scans now expose a shared `security_findings` record alongside the existing source-specific `findings` for compatibility. Each common record carries a stable location-based `finding_id`, `check_id`, source and target, structured location, severity, confidence, validation state, evidence, remediation, and scanner version. Severity and confidence are independent. Passive website response observations are marked `observed`; static repository indicators remain `suspected`. Unknown impact and preconditions are left explicit rather than guessed. These records are evidence containers, not proof of exploitability.
## Repository route inventory

Repository scans also build a bounded static route inventory from literal Python route decorators and lexical JavaScript/TypeScript, Go, Spring-style, PHP, and Ruby route declarations. Each entry includes method, literal path, source file, line, and syntax hint. This is source reconnaissance for future website-to-repository correlation—not proof that a route is deployed, reachable, or protected. Dynamic paths and router composition are not resolved. The inventory is capped at 2,000 records and reports truncation.
## Website ↔ repository route correlation

When a website scan and repository analysis are both available, the dashboard's **Correlation** view compares fetched website page paths and conservative JavaScript route references with the repository's bounded static route inventory. Exact and parameterised path overlaps are shown with their source evidence and confidence. Known HTTP method conflicts are excluded. Exact path/method overlaps are capped at medium confidence, and parameterised or unknown-method overlaps are low confidence. The view is reconnaissance only: it does not prove that the website runs the supplied repository commit, that a route is deployed or reachable, or that its authentication and authorisation controls are correct. Dynamic routing, middleware, reverse-proxy rewrites and runtime registration remain out of scope.
## Website scan authorisation

The website scan API now requires the request field `authorised: true`; otherwise it returns HTTP 403 with `website_authorisation_required`. The dashboard exposes a consent checkbox and disables the Analyse action until it is checked. This is an explicit operator acknowledgement only: it does not authenticate the operator, verify ownership, establish legal permission, or replace a production scope/identity model. Requests are still bounded by the configured page, concurrency, time and rate limits, and the crawler remains same-origin.
## Additional Python injection heuristic

The read-only repository analyser now flags direct dynamically constructed SQL expressions passed to Python `execute`, `executemany`, and `executescript` calls. It checks f-string interpolation, string concatenation, `%` formatting and `.format()` calls, while leaving a literal SQL statement with separate bind parameters unflagged. Findings remain medium-confidence `suspected` indicators: the rule does not trace tainted values, understand ORM/query-builder semantics, or prove SQL injection.


## Production authentication gateway

The API can accept authenticated identities from a trusted reverse proxy. For production set `UNWEB_ENV=production` and `UNWEB_AUTH_PROXY_SECRET` to a high-entropy secret shared only with the proxy. The proxy must authenticate users, strip any incoming `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User` headers supplied by clients, and inject those headers itself: the token header contains the shared secret and the user header contains the authenticated stable user ID. The API rejects missing/invalid identities and scopes persisted scan history/details to that user. Production startup fails closed if the shared secret is absent. Keep the API private behind the proxy; do not expose its port directly. This is an integration point for an identity provider/reverse proxy, not a built-in login system. In local development with no gateway configured, all scans belong to the single `local` owner.


## Production deployment

A containerised single-instance deployment is provided in `docker-compose.production.yml`. It builds the API and frontend images, runs Redis on an internal-only network, persists SQLite/Redis data, and applies non-root/read-only/capability/resource restrictions. The API is not published to the host; the frontend is intended to sit behind an external trusted authentication gateway.

See [Production deployment guide](docs/DEPLOYMENT.md). The deployment requires an external ingress identity gateway (OIDC/SAML or equivalent) that protects both frontend and API requests, strips client-supplied identity headers, and injects the trusted identity headers. It also requires externally created ingress/egress Docker networks and host/cloud firewall rules restricting outbound traffic. Compose does not itself enforce target-specific egress policy. The stack remains single-instance because SQLite is not a multi-instance database.


## Verified website targets

Production scans require a target authorization created in the dashboard's **Target ownership verification** panel. UnWeb generates a one-time DNS TXT challenge for the exact hostname, verifies it, and grants a 30-day owner-scoped scope limited to selected ports and path prefixes. Users can revoke grants at any time. This proves DNS control at verification time; it does not replace legal permission for every service behind the domain or external egress firewall policy.
