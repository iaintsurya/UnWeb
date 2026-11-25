# Environment reference

## Backend/API

| Variable | Required | Meaning |
|---|---:|---|
| `UNWEB_ENV` | No | `development` by default. Set `production` to require trusted identity configuration and Redis. |
| `UNWEB_AUTH_PROXY_SECRET` | Production | High-entropy secret shared only with the trusted identity gateway. Production startup requires at least 32 characters. |
| `UNWEB_REDIS_URL` | Production | Redis URL used for shared rate limits, readiness, and browser-job dispatch. |
| `UNWEB_DB_PATH` | No | SQLite path. Local default is `backend/data/unweb.sqlite3`; production uses `/data/unweb.sqlite3`. |
| `UNWEB_CORS_ORIGINS` | No | Comma-separated exact browser origins. Defaults to the local Vite origins. Do not use `*` for a public deployment. |
| `UNWEB_INGRESS_NETWORK` | Compose | External Docker network shared with the trusted gateway. |
| `UNWEB_EGRESS_NETWORK` | Compose | External Docker network that must be protected by host/cloud egress policy. |

The API also accepts gateway headers `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User`. These are not client credentials: the gateway must remove browser-supplied values and inject trusted values after authentication.

## Frontend

Set `VITE_API_BASE_URL` at build time only when the API is hosted at a different origin. Leave it empty for the Vite `/api` proxy or same-origin production deployment. The frontend accepts both relative API paths and already-resolved absolute paths without duplicating the base URL.

## Security rules

- Never commit a real `.env` file, proxy secret, Redis password, backup, or SQLite volume.
- Keep Redis and the API off public host ports.
- Use an exact CORS allowlist and terminate TLS at a trusted gateway.
- Rotate the proxy secret through the gateway and deployment secret manager, not through source control.
