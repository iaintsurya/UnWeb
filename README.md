# UnWeb
**A website reverse engineering, intelligence, and reconstruction platform.**

UnWeb gathers bounded, publicly observable website evidence; extracts metadata and assets; maps same-origin pages; inspects delivered JavaScript with conservative heuristics; reports passive security observations; and generates an editable React starter from observed headings and text.

> Early engineering preview — not production-ready. Use only on sites you own or are explicitly authorised to analyse.

## Stack
- Frontend: React, TypeScript, Vite, Lucide icons, custom CSS
- Backend: Python 3.11+, FastAPI, HTTPX, Beautiful Soup, Pydantic
- Tests: pytest
- Storage: in-memory preview store; restart clears results

## Windows PowerShell
```powershell
# Terminal 1
cd backend
py -3.11 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
.\.venv\Scripts\python.exe -m uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# Terminal 2, repository root
cd frontend
npm install
npm run dev
```
Frontend: `http://127.0.0.1:5173`; API docs: `http://127.0.0.1:8000/docs`.

## macOS / Linux
```bash
cd backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
uvicorn app.main:app --reload --host 127.0.0.1 --port 8000

# second terminal
cd frontend
npm install
npm run dev
```

## API
- `GET /api/health`
- `POST /api/scans` with `{"url":"https://example.com","max_pages":8}`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap`
- `GET /api/scans/{scan_id}/security`
- `GET /api/scans/{scan_id}/reconstruction`

## Safety and limits
UnWeb restricts URL schemes to HTTP(S), rejects non-global IP destinations, resolves hostnames before requests, revalidates redirects, disables ambient proxy configuration, caps response bytes and timeouts, and bounds page/script counts. These application-level checks do not fully eliminate DNS rebinding or time-of-check/time-of-use risks. Before any public deployment, enforce outbound network filtering outside the app, isolate scan workers, set CPU/memory/concurrency limits, add authentication/rate limits, and conduct a security review.

It does not bypass authentication, CAPTCHAs, access controls, or rate limits. Technology matches and JavaScript string matches are clues, not proof. Reconstruction is a safe editable starting point, not recovered source code or guaranteed pixel-perfect cloning.

## Roadmap
| Version | Scope |
|---|---|
| v0.1 MVP | Safe URL handling, bounded fetch, metadata, headers, assets, fingerprints, first UI |
| v1.0 Launch | Bounded sitemap discovery, JavaScript inventory and route clues, passive security findings, exports and expanded tests |
| v2.0 Advanced | Disposable Playwright workers, observed network requests, DOM/style inspector, improved reconstruction, async jobs, WebSockets, durable DB and CLI |

## AI and human collaboration
AI tools may help brainstorm, scaffold, document, and debug. The maintainer is responsible for reviewing code, verifying security assumptions, running tests, checking dependencies, and describing limitations honestly. Do not claim reviews or test coverage that have not occurred.

## License
MIT. See `LICENSE`.
