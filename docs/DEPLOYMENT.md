# Production deployment

This is a **single-instance, containerised deployment baseline**, not a turnkey public scanner. It provides repeatable images, Redis-backed shared rate limits, persistent local storage, and container hardening. You must supply the identity gateway and network egress policy before exposing it to users.

## Prerequisites

- Docker Engine with the Compose plugin.
- A trusted OIDC/SAML authentication gateway/reverse proxy that can inject authenticated identity headers.
- Host/cloud firewall control for the API's outbound network.
- A DNS resolver available to the API container.

## 1. Configure secrets and networks

Copy the example environment file and replace the placeholder with a fresh secret:

```bash
cp .env.production.example .env
openssl rand -hex 32
```

Put the generated value in `UNWEB_AUTH_PROXY_SECRET`. Keep `.env` out of version control and restrict file access. Do not reuse this secret for another application.

Create the external networks before starting Compose:

```bash
docker network create unweb-ingress
docker network create unweb-egress
```

Attach only the trusted ingress gateway to `unweb-ingress`. The frontend and API join this network; the API also joins the egress network. Redis is isolated on an internal-only Compose network and is not published.

The egress network is **not** a firewall. Configure host/cloud network policy before starting the service. Deny loopback, RFC1918/private, link-local, multicast, IPv6 ULA, cloud metadata and infrastructure destinations. Permit only public HTTP/HTTPS destinations needed for authorised targets and the OSV advisory provider. Allow DNS only through a resolver you control. Account for Docker's embedded DNS forwarding when writing host firewall rules. Do not rely on application DNS checks as the only SSRF control.

## 2. Configure the identity gateway

The deployment does not implement a login screen or identity provider itself. Use an OIDC/SAML gateway (for example, an organisation-managed identity proxy) and route authenticated browser traffic to the frontend container on port 8080.

The gateway must:

1. Authenticate every user before allowing access to the frontend and its `/api/` routes.
2. Remove incoming `X-UnWeb-Auth-Token` and `X-UnWeb-Auth-User` headers from the client request. Never trust values supplied by a browser.
3. Inject `X-UnWeb-Auth-Token` with the exact `UNWEB_AUTH_PROXY_SECRET` value.
4. Inject `X-UnWeb-Auth-User` with a stable, non-empty authenticated subject identifier from the identity provider (not a user-controlled display name).
5. Preserve those gateway-generated headers when proxying to the frontend. The included Nginx configuration forwards them only on its internal API proxy request to FastAPI.
6. Terminate public TLS and set the forwarded host/protocol headers correctly.

The FastAPI service compares the shared secret in constant time and scopes saved scan history, details, audit events and rate-limit buckets to that authenticated identifier. Do not publish port 8000, do not attach untrusted containers to the ingress network, and do not allow clients to connect directly to the API.

## 3. Start the stack

```bash
docker compose --env-file .env -f docker-compose.production.yml config
docker compose --env-file .env -f docker-compose.production.yml up -d --build
docker compose --env-file .env -f docker-compose.production.yml ps
```

The gateway should route its authenticated upstream to the frontend service at `frontend:8080` on the ingress network. Do not add a host port mapping for either frontend or API unless a separate, trusted ingress layer is enforcing the same authentication boundary.

The API waits for Redis health and refuses production startup if either the auth secret or `UNWEB_REDIS_URL` is missing. Redis rate limiting is atomic and shared across API processes. If Redis is unavailable after startup, rate-limited operations return HTTP 503; they do not fall back to a weaker in-memory limiter.

## 4. Runtime boundaries

- API runs as UID 10001, one Uvicorn worker, with a read-only root filesystem, dropped capabilities, no-new-privileges, a bounded temporary filesystem, and CPU/memory/PID limits.
- Frontend runs using the unprivileged Nginx image on port 8080 with a read-only root filesystem and bounded writable tmpfs mounts.
- Redis is not host-published and is connected only to an internal Compose network.
- SQLite and Redis data use persistent Docker volumes.
- API and frontend ports are exposed only inside the ingress network; Compose does not publish them on the host.
- The single API instance is intentional. SQLite is not a multi-writer database and this stack is not horizontally scalable.

## 5. Backups and upgrades

Back up the `unweb_data` and `redis_data` Docker volumes using your host's supported volume snapshot/backup process. For a consistent SQLite backup, stop the API container or use SQLite's online backup API from a trusted maintenance job. Test restores before upgrades. Do not copy a live SQLite database file without accounting for its WAL state.

Update code only after CI passes, rebuild with Compose, and retain a known-good image and volume backup for rollback. Do not run multiple API replicas against the same SQLite volume.

## 6. Verify the deployment

- `GET /api/health` returns service health; it does not prove that auth or egress policy is correct.
- An unauthenticated request to any other `/api/` route must return HTTP 401.
- A request passing through the trusted gateway must receive the gateway-injected identity and be able to access only its own scans and audit events.
- Confirm a user cannot fetch another user's scan ID (the API should return 404).
- Confirm Redis outage causes rate-limited endpoints to fail closed with HTTP 503.
- Independently test egress blocks for loopback, private, link-local, IPv6 local, metadata and unapproved destinations. Do not test this only from application-level URL validation.
- Confirm the API is unreachable from the public internet and from containers outside the trusted ingress network.

## 7. Deliberate limitations

This deployment does not supply a configured OIDC/SAML provider, verify legal ownership of target hosts, create signed authorisation grants, enforce per-job dynamic egress allowlists, or provide tamper-proof external audit storage. Website path scopes are enforced within the submitted origin, but the consent boolean remains an operator acknowledgement. The Playwright worker remains a separate CLI/container prototype; it is not launched by API jobs. Repository analysis is a bounded static-analysis preview, not a complete SAST/SCA engine. Obtain an independent security review and implement these controls before offering the service as a public multi-tenant scanner.
