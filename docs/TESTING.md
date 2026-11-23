# Testing

Run the backend suite with `cd backend && python -m pytest -q`.

Backend tests cover URL normalisation and private-address rejection, mocked breadth-first crawling, page limits, observed sitemap edges, same-origin redirect boundaries, IP-pinned DNS/Host/SNI behavior, response content types, cross-page assets/scripts, SQLite persistence/retention, sliding-window rate limits, HTML extraction, passive security-header evidence, and JavaScript lexical clues.

Run the frontend checks with `cd frontend && npm ci && npm run build && npm test`. Vitest tests the shared API request helper's success and error handling; the build runs TypeScript's strict project checks before bundling.

GitHub Actions runs backend tests and frontend build/tests on pushes and pull requests. Use local fixtures and mocked responses, not third-party websites, as automated test targets.

Before release, add end-to-end browser tests for the URL form, saved history, filters, evidence drawer, empty/error states and responsive behavior. Agent-browser should be installed and invoked in a separately named session when the browser CLI is available.
