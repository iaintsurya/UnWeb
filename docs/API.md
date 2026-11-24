# API reference
- `GET /api/health`
- `POST /api/scans` — body `{"url":"https://example.com","max_pages":8}`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap`
- `GET /api/scans/{scan_id}/security`
- `GET /api/scans/{scan_id}/reconstruction`

Results are in memory in this preview and are cleared when the API process restarts. Errors: 400 target rejected; 502 request/network failure; 504 timeout; 404 missing scan.

## Dependency advisory lookup

- `POST /api/dependency-advisories` with JSON `{"authorised":true,"packages":[{"name":"requests","ecosystem":"PyPI","version":"2.31.0"}]}` queries the OSV batch API for exact resolved package versions. Supported ecosystems: npm, PyPI/Python, Go, and crates.io/Cargo. The request is capped at 100 unique package coordinates and the provider response at 2 MB. Advisory summaries, IDs, aliases, dates and HTTPS references are returned; upstream details are not copied. This is an advisory lookup, not a complete dependency audit or proof that a package is safe. The operator acknowledgement is not authenticated identity or proof of ownership. A bounded in-process rate limit applies.
