# UnWeb

**A website reverse-engineering, intelligence, and reconstruction platform.**

UnWeb gathers bounded, publicly observable website evidence; extracts metadata and assets across discovered pages; maps same-origin page relationships; inspects delivered JavaScript with conservative heuristics; reports passive security observations; and generates an editable React starter from observed headings and text.

> Early engineering preview — not production-ready. Use only on sites you own or are explicitly authorised to analyse.

## Stack

- Frontend: React, TypeScript, Vite 8, Lucide icons, custom CSS
- Backend: Python 3.11+, FastAPI, HTTPX, Beautiful Soup, Pydantic
- Persistence: SQLite scan history (last 250 results by default)
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
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

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

Set `UNWEB_DB_PATH` in the backend process environment to use a different database file. Back up this file if scan history matters. This single-file SQLite setup is intended for local development and a single backend instance, not horizontally scaled public deployment.

## API

- `GET /api/health`
- `POST /api/scans` with `{"url":"https://example.com","max_pages":8}`
- `GET /api/scans?limit=20` — recent scan summaries (limit 1–100)
- `GET /api/scans/{scan_id}` — full saved scan result
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap` — observed page nodes and directed same-origin link edges
- `GET /api/scans/{scan_id}/security`
- `GET /api/scans/{scan_id}/reconstruction`

The scan request accepts `max_pages` from 1 to 30. The UI offers 4, 8, 12, 20, and 30 page presets.

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

Automated tests use local fixtures and mocked network responses. They do not scan third-party websites.

## Safety and limits

UnWeb restricts URL schemes to HTTP(S), rejects non-global IP destinations, resolves and validates hostnames, then connects to the validated IP literal while preserving the original HTTP Host header and TLS SNI/certificate identity. It revalidates every redirect, disables ambient proxy configuration, caps response bytes and timeouts, bounds page/script counts, and rejects explicitly non-HTML page responses. DNS resolution runs off the async event loop. The crawler follows same-origin links breadth-first up to the requested page limit; its sitemap graph contains only observed links between successfully scanned HTML pages. Assets and bounded JavaScript clues are collected across discovered pages.

The preview API allows at most two active scans per process and applies a 120-second scan time limit. These are basic resource controls, not a replacement for per-user authentication or rate limits. The IP-pinned fetch path narrows the DNS-rebinding/time-of-check-to-time-of-use risk, but the application is still not a complete SSRF boundary; retain network-level egress controls in any public deployment.

**Important:** application-level DNS checks do not fully eliminate DNS rebinding or time-of-check/time-of-use risks. Before any public deployment, enforce outbound network filtering outside the app, isolate scan workers, set CPU/memory/concurrency limits, add authentication and rate limits, and conduct a security review. The local SQLite store is not designed for multi-instance deployment.

UnWeb does not bypass authentication, CAPTCHAs, access controls, or rate limits. Technology and JavaScript matches are clues, not proof. Security checks are passive response observations, not a penetration test or an overall security verdict. Reconstruction is an editable starting point, not recovered source code or guaranteed pixel-perfect cloning.

## Roadmap

| Version | Scope |
|---|---|
| v0.1 Preview | Safe URL intake, bounded fetch, metadata, initial fingerprints and UI |
| v0.2 Foundation | Recursive bounded crawl, observed sitemap edges, SQLite history, cross-page asset/script inventory, scan capacity limits, frontend API helper, tests and CI |
| v1.0 Hardening | Connection-time DNS pinning/egress enforcement, authentication, per-user rate limits, durable job workers, richer JavaScript analysis, audit retention and deeper tests |
| v2.0 Advanced | Disposable Playwright workers, observed network requests, DOM/style inspector, improved reconstruction, progress events, multi-user storage and CLI |

## AI and human collaboration

AI tools may help brainstorm, scaffold, document, and debug. The maintainer is responsible for reviewing code, verifying security assumptions, running tests, checking dependencies, and describing limitations honestly. Do not claim reviews or test coverage that have not occurred.

## License

MIT. See `LICENSE`.
