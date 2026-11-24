# API reference

The API is a local engineering preview. It does not currently authenticate users or enforce per-user scan ownership. Do not expose it as a public multi-user service. The operator acknowledgement fields below are not authentication or proof of permission.

## Health and website scans

- `GET /api/health` — service status and version.
- `GET /api/audit-events?limit=50` — recent owner-scoped audit events (limit 1–100).
- `POST /api/scans` — JSON body such as `{"url":"https://example.com","max_pages":8,"authorised":true}`. Requires `authorised: true`; accepts 1–30 pages. The scan is constrained to the submitted scheme/host/port origin, including initial redirects, later page requests and JavaScript fetches.
- `GET /api/scans?limit=20` — recent scan summaries; limit 1–100.
- `GET /api/scans/{scan_id}` — complete stored scan result.
- `GET /api/scans/{scan_id}/intelligence` — title, headers, technology clues and assets.
- `GET /api/scans/{scan_id}/sitemap` — observed page nodes and directed same-origin links.
- `GET /api/scans/{scan_id}/security` — legacy findings and common structured security findings.
- `GET /api/scans/{scan_id}/reconstruction` — supporting page reconstruction data.

Website scans are stored in the configured SQLite database. The default path is `backend/data/unweb.sqlite3`; set `UNWEB_DB_PATH` to change it. The newest 250 scans are retained by default.

## Repository analysis

- `POST /api/repository-scans` — raw ZIP request body with `Content-Type: application/zip`, `X-UnWeb-Authorised: true`, and optional URL-encoded `X-Repository-Filename`. Streams up to 50 MB into a temporary file, analyses it, returns JSON, and deletes the archive.
- `POST /api/github-repository-scans` — JSON body such as `{"repository_url":"https://github.com/owner/repository","ref":"main","authorised":true}`. Accepts canonical public GitHub repository URLs, resolves the ref to an immutable commit SHA, streams a source ZIP from the approved GitHub archive host (maximum 50 MB), analyses it, returns commit identity and deletes the temporary archive. Omit `ref` to use the repository default branch.

The acknowledgement is not authentication. Public GitHub ingestion does not support private repositories, OAuth/App installation or personal access tokens. Repository reports are returned to the caller and are not persisted.

## Dependency advisory lookup

- `POST /api/dependency-advisories` — JSON body such as `{"authorised":true,"packages":[{"name":"requests","ecosystem":"PyPI","version":"2.31.0"}]}`. Queries OSV for exact resolved versions in npm, PyPI/Python, Go and crates.io/Cargo. Accepts up to 100 package coordinates and caps the provider response at 2 MB.

This is advisory matching, not a complete dependency audit or proof of safety. An empty result means OSV returned no matching advisory for that exact coordinate/version; coverage may be incomplete or delayed.

## Limits and deployment notes

- Website scans: at most two concurrent scans per API process, 120-second scan deadline, 10 submissions/minute per authenticated user in the API process.
- Repository scans: one concurrent repository analysis per process. ZIP uploads are limited to 5 submissions/minute per authenticated user in the API process (ZIP and GitHub source scans share the repository bucket).
- Advisory lookups: bounded in-process rate limit of 10 requests/minute per authenticated user in the API process.
- These are process-local per-identity abuse controls, not shared/distributed rate limits. Reverse-proxy deployments must configure trusted proxy handling before relying on client IPs.
- CORS origins are configured with `UNWEB_CORS_ORIGINS`; configure an explicit allowlist.
- URL validation and IP pinning are defence-in-depth. Public deployment requires external network egress controls, isolated workers, authentication, audit logging, shared rate limits and an independent security review.
- The optional Playwright worker is a separate CLI and is not invoked by the API. Its container requires an externally enforced per-job default-deny egress policy.

## Website scan path scopes

Website scan requests accept `scope_paths`, a list of 1–20 absolute URL path prefixes. The default is `["/"]`, which retains the existing whole-origin crawl behavior. To narrow a scan, provide values such as `["/app", "/api/v1"]`. Matching is segment-aware (`/app` includes `/app` and `/app/users`, but not `/application`). Query strings, fragments, hostnames, control characters, backslashes, encoded separators, and dot segments are rejected in scope entries. The starting URL, discovered page links, redirects, and same-origin JavaScript fetches are constrained to the approved prefixes. The response records the normalized scope paths. This remains a path boundary within the submitted origin; it does not add authentication, ownership verification, or network egress enforcement.


## Trusted authentication gateway and scan ownership

The API supports identity injection from a trusted reverse proxy. Configure both backend environment variables:

- `UNWEB_ENV=production` — enables production fail-closed behavior.
- `UNWEB_AUTH_PROXY_SECRET` — a high-entropy random secret shared only between the reverse proxy and the API.

For every request under `/api/` except `/api/health`, the proxy must authenticate the user, **remove any client-supplied** `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User` headers, then inject `X-UnWeb-Auth-Token` with the shared secret and `X-UnWeb-Auth-User` with the authenticated stable user identifier. The API compares the secret in constant time, validates the user identifier, and returns 401 when the identity is absent or invalid. The backend must not be reachable directly from untrusted networks; restrict it to the proxy at the network layer and use TLS between proxy and API where they cross hosts.

Scan history and scan-detail endpoints are filtered by the authenticated user identifier. Existing SQLite records are migrated with owner `local`; they are not automatically reassigned to newly authenticated users. In non-production development mode, requests without a configured gateway retain the single local owner. Production startup fails if the gateway secret is missing. This is a **trusted-proxy integration**, not a built-in account/password or OAuth system; user login, account lifecycle, MFA, team sharing and role-based access remain responsibilities of the identity gateway and future product work.


## Audit events

Completed website scans, ZIP repository analyses, public GitHub repository analyses, and dependency advisory lookups write minimal owner-scoped audit events. The authenticated user can read their own events through `GET /api/audit-events`. Event records contain an action, resource identifier where applicable, UTC timestamp, and small allowlisted metadata; they do not store scan response bodies, secrets, cookies, or repository archives. The database retains up to 1,000 events per owner. These application audit records are useful for traceability but are not tamper-proof: production deployments should forward logs to an independently controlled append-only logging system.


## Shared rate limiting and production deployment

Production startup requires `UNWEB_REDIS_URL` in addition to the trusted authentication gateway secret. The API pings Redis at startup and installs atomic Redis Lua sliding-window limiters shared across API processes: 10 website scan submissions/minute/user, 5 repository analyses/minute/user (ZIP and GitHub share this bucket), and 10 dependency advisory lookups/minute/user. Redis server time is used for consistent windows. If Redis becomes unavailable, rate-limited endpoints fail closed with HTTP 503 rather than silently falling back to a process-local limiter. The in-memory limiter remains for local development and unit tests.

The production Compose deployment runs one API worker with SQLite on a persistent volume, Redis on an internal-only network, and a non-root frontend container. It does not publish API or frontend ports to the host: an external trusted ingress/authentication gateway must be attached to the ingress network and route users to the frontend. The gateway must protect both the UI and all `/api/` routes, strip client-supplied identity headers, and inject the configured secret and authenticated stable user ID. The API must not be exposed directly. See `docs/DEPLOYMENT.md` for setup and network requirements.
