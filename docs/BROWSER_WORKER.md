# Browser worker guide

The browser worker is optional and is separate from the passive HTTP scanner. API-managed jobs require an HTTPS target, explicit acknowledgement, a verified target grant, and path prefixes contained by that grant.

## Runtime model

- Redis Streams carries job IDs; SQLite stores owner-scoped job state and bounded results.
- The worker runs as UID 10001 without added capabilities and without ingress-network access.
- Chromium runs in a fresh context with the sandbox enabled; `--no-sandbox` is not an accepted workaround.
- The worker revalidates the target grant immediately before execution.
- Browser requests and WebSockets are restricted to the exact target origin and approved paths.
- A request count, wall-clock timeout, response metadata budget, and container CPU/memory/PID limits are applied.
- Pending jobs are capped at 100 per owner and 1,000 globally. The newest 100 terminal rows per owner are retained.

## Required external control

The worker's local CONNECT proxy is defense in depth. It is not an egress firewall. The host/cloud policy must default-deny loopback, private, link-local, multicast, IPv6 ULA, metadata, and unapproved destinations. Permit only the validated public target address/port and controlled DNS. Verify this from the worker network, not only with unit tests.

## Operations

```bash
docker compose --env-file .env -f docker-compose.production.yml ps
docker compose --env-file .env -f docker-compose.production.yml logs browser-worker
```

The worker heartbeat is exposed through the authenticated API route `/api/health/browser-worker`. A stale or missing heartbeat should page an operator before browser jobs are accepted as reliable evidence.

## Known limitation

Declared response lengths are telemetry, not a hard byte-transfer cap for every chunked or under-declared browser response. Enforce container memory, CPU, temporary-storage, and process limits, and treat hard transfer-byte enforcement as remaining release work.
