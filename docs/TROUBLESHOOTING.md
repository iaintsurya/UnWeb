# Troubleshooting

## API does not start in production

Check the logs:

```bash
docker compose --env-file .env -f docker-compose.production.yml logs api
```

Production startup requires `UNWEB_AUTH_PROXY_SECRET` with at least 32 characters and `UNWEB_REDIS_URL`. Missing Redis or a failed Redis ping is intentional fail-closed behavior.

## Readiness is failing

```bash
curl -fsS http://<trusted-gateway>/api/health/ready
docker compose --env-file .env -f docker-compose.production.yml ps
docker compose --env-file .env -f docker-compose.production.yml logs redis api
```

Readiness checks SQLite and Redis. Liveness at `/api/health` does not prove that the identity gateway or egress policy is working.

## API returns 401

The request did not arrive with valid gateway-injected `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User` headers. Do not copy these headers from a browser. Verify that the gateway strips client values, injects the shared secret, and forwards a stable subject ID.

## Website scan is rejected

Common causes are missing `authorised: true`, an unverified target grant in production, a URL outside the granted scheme/host/port/path, a private or non-global destination, or a redirect outside the exact origin. These are safety controls, not transient errors.

## Browser jobs remain queued

Check Redis and the worker heartbeat:

```bash
docker compose --env-file .env -f docker-compose.production.yml logs redis browser-worker
curl -fsS -H 'X-UnWeb-Auth-Token: gateway-only' -H 'X-UnWeb-Auth-User: operator' \
  https://<trusted-gateway>/api/health/browser-worker
```

Do not publish the API directly to bypass authentication. Check queue capacity, target grant expiry, and the external egress firewall.

## Backup or restore fails

Stop API and browser-worker writers before restore. Ensure the backup path is readable by UID 10001, use `--confirm-restore`, and use `--overwrite` only when replacement is intended. A busy WAL or failed integrity check should abort the operation.

## Frontend build failures

Use the declared Node engine and a clean lockfile install:

```bash
cd frontend
node --version
npm ci
npm run build
npm test
```

The current project requires Node `^20.19.0 || >=22.12.0`; unsupported runtimes can fail inside Vite/Vitest before application code runs.
