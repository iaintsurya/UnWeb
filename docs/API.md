# API reference

The API is a local engineering preview. It does not currently authenticate users or enforce per-user scan ownership. Do not expose it as a public multi-user service. The operator acknowledgement fields below are not authentication or proof of permission.

## Health and website scans

- `GET /api/health` — service status and version.
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

- Website scans: at most two concurrent scans per API process, 120-second scan deadline, 10 submissions/minute per direct peer IP.
- Repository scans: one concurrent repository analysis per process, bounded upload/download size and 5 submissions/minute per direct peer IP.
- Advisory lookups: bounded in-process rate limit of 10 requests/minute per direct peer IP.
- These are process-local abuse controls, not shared identity-aware rate limits. Reverse-proxy deployments must configure trusted proxy handling before relying on client IPs.
- CORS origins are configured with `UNWEB_CORS_ORIGINS`; configure an explicit allowlist.
- URL validation and IP pinning are defence-in-depth. Public deployment requires external network egress controls, isolated workers, authentication, audit logging, shared rate limits and an independent security review.
- The optional Playwright worker is a separate CLI and is not invoked by the API. Its container requires an externally enforced per-job default-deny egress policy.
