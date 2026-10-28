# API reference
- `GET /api/health`
- `POST /api/scans` — body `{"url":"https://example.com","max_pages":8}`
- `GET /api/scans/{scan_id}`
- `GET /api/scans/{scan_id}/intelligence`
- `GET /api/scans/{scan_id}/sitemap`
- `GET /api/scans/{scan_id}/security`
- `GET /api/scans/{scan_id}/reconstruction`

Results are in memory in this preview and are cleared when the API process restarts. Errors: 400 target rejected; 502 request/network failure; 504 timeout; 404 missing scan.
