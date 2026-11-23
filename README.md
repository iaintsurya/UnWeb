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

- `GET /api/health`
- `POST /api/scans` with `{"url":"https://example.com","max_pages":8}`
- `GET /api/scans?limit=20` — recent scan summaries (limit 1–100)
- `GET /api/scans/{scan_id}` — full saved scan result
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap` — observed page nodes and directed same-origin link edges
- `GET /api/scans/{scan_id}/security`
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

This is a single unauthenticated render: it does not submit forms, bypass access controls, reuse your browser profile, or crawl links. It is runtime evidence collection, not active vulnerability validation. Browser output is not yet persisted or shown in the web UI; durable isolated job orchestration is required before API integration.

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

Automated tests use local fixtures and mocked network responses. They do not scan third-party websites or launch a browser.

## Safety and limits

UnWeb restricts URL schemes to HTTP(S), rejects non-global IP destinations, resolves and validates hostnames, then connects to the validated IP literal while preserving the original HTTP Host header and TLS SNI/certificate identity. It revalidates every redirect, disables ambient proxy configuration, caps response bytes and timeouts, bounds page/script counts, and rejects explicitly non-HTML page responses. DNS resolution runs off the async event loop. The crawler follows same-origin links breadth-first up to the requested page limit; its sitemap graph contains only observed links between successfully scanned HTML pages. Assets and bounded JavaScript clues are collected across discovered pages. JavaScript route references include source lines, confidence, and nearby lexical evidence; comment text is ignored for route discovery. Reconstruction exports a data-driven React component, starter CSS, a script-free HTML preview, a manifest, and usage notes.

The preview API allows at most two active scans per process, applies a 120-second scan time limit, and permits 10 scan submissions per minute per direct peer IP in each process. These are basic abuse controls, not a replacement for authentication or shared per-user rate limits. Set `UNWEB_CORS_ORIGINS` to a comma-separated allowlist of frontend origins when hosting the API separately. The IP-pinned fetch path narrows the DNS-rebinding/time-of-check-to-time-of-use risk, but the application is still not a complete SSRF boundary; retain network-level egress controls in any public deployment.

**Important:** application-level DNS checks do not fully eliminate DNS rebinding or time-of-check/time-of-use risks. Before any public deployment, enforce outbound network filtering outside the app, isolate scan workers, set CPU/memory/concurrency limits, add authentication and rate limits, and conduct a security review. The local SQLite store is not designed for multi-instance deployment.

UnWeb does not bypass authentication, CAPTCHAs, access controls, or rate limits. Technology and JavaScript matches are clues, not proof. The current security observations are passive and do not establish exploitability; the current release is not a penetration test. Future active checks must require an explicit authorised scope and bounded profile, use non-destructive validation, and preserve evidence without collecting unnecessary sensitive data. A finding must distinguish confirmed, likely, informational, and inconclusive results. Reconstruction is an editable supporting feature, not recovered source code or guaranteed pixel-perfect cloning.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 Preview | Safe URL intake, bounded fetch, metadata, initial fingerprints and UI |
| v0.2 Foundation | Recursive bounded crawl, observed sitemap edges, SQLite history, cross-page asset/script inventory, scan capacity limits, frontend API helper, tests and CI |
| v1.0 Hardening | Network-level egress enforcement and independent SSRF review, authentication, shared per-user rate limits, durable job workers, richer JavaScript analysis, audit retention and deeper tests |
| v2.0 Advanced | Integrated isolated Playwright jobs, observed network requests, DOM/style inspector, improved reconstruction, progress events, multi-user storage and CLI/CI scan mode |

## AI and human collaboration

AI tools may help brainstorm, scaffold, document, and debug. The maintainer is responsible for reviewing code, verifying security assumptions, running tests, checking dependencies, and describing limitations honestly. Do not claim reviews or test coverage that have not occurred.

## License

MIT. See `LICENSE`.
