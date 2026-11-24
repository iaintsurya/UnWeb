import asyncio
import hashlib
import ipaddress
import os
import re
import secrets
import tempfile
from pathlib import Path
from datetime import datetime, timedelta, timezone
from urllib.parse import unquote, urlsplit
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from . import database
from .models import ScanRequest, ScanResult, GitHubRepositoryScanRequest
from .limits import SlidingWindowLimiter, RedisSlidingWindowLimiter
from redis import Redis
from redis.exceptions import RedisError
import dns.resolver
from .scanner import scan_site, UnsupportedContentType, normalize_scope_paths
from .url_policy import URLRejected, normalize_url
from .repository_analysis import analyse_repository_archive, MAX_ARCHIVE_BYTES
from .github_source import fetch_github_repository_archive, GitHubSourceError
from .models import DependencyAdvisoryRequest, TargetAuthorizationChallengeRequest
from .dependency_advisories import query_advisories, AdvisoryLookupError

AUTH_PROXY_SECRET = os.environ.get("UNWEB_AUTH_PROXY_SECRET", "")
UNWEB_ENV = os.environ.get("UNWEB_ENV", "development").strip().lower()
REDIS_URL = os.environ.get("UNWEB_REDIS_URL", "").strip()
REDIS_CLIENT = Redis.from_url(REDIS_URL, socket_connect_timeout=2, socket_timeout=2) if REDIS_URL else None


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if UNWEB_ENV == "production" and not AUTH_PROXY_SECRET:
        raise RuntimeError("UNWEB_AUTH_PROXY_SECRET is required when UNWEB_ENV=production.")
    if UNWEB_ENV == "production" and not REDIS_CLIENT:
        raise RuntimeError("UNWEB_REDIS_URL is required in production for shared rate limits.")
    if REDIS_CLIENT:
        await asyncio.to_thread(REDIS_CLIENT.ping)
        _configure_rate_limiters(REDIS_CLIENT)
    await asyncio.to_thread(database.initialize_database)
    yield


app = FastAPI(
    title="UnWeb API",
    version="0.2.0",
    description="Bounded passive website intelligence.",
    lifespan=lifespan,
)
DEFAULT_CORS_ORIGINS = "http://127.0.0.1:5173,http://localhost:5173"
CORS_ORIGINS = [
    origin.strip()
    for origin in os.environ.get("UNWEB_CORS_ORIGINS", DEFAULT_CORS_ORIGINS).split(",")
    if origin.strip()
]
app.add_middleware(
    CORSMiddleware,
    allow_origins=CORS_ORIGINS,
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "X-UnWeb-Authorised", "X-Repository-Filename", "X-UnWeb-Auth-Token", "X-UnWeb-Auth-User"],
)



@app.middleware("http")
async def require_trusted_identity(request: Request, call_next):
    """Trust identity only from a reverse proxy holding the configured shared secret."""
    if request.method == "OPTIONS":
        return await call_next(request)
    if not request.url.path.startswith("/api/") or request.url.path == "/api/health":
        return await call_next(request)

    if not AUTH_PROXY_SECRET:
        if UNWEB_ENV == "production":
            return JSONResponse(
                status_code=503,
                content={"detail": {"code": "auth_proxy_not_configured", "message": "Trusted authentication is not configured."}},
            )
        request.state.user_id = "local"
        return await call_next(request)

    supplied_secret = request.headers.get("x-unweb-auth-token", "")
    user_id = request.headers.get("x-unweb-auth-user", "").strip()
    if (
        not secrets.compare_digest(supplied_secret, AUTH_PROXY_SECRET)
        or not user_id
        or len(user_id) > 128
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._:+|~-]*", user_id)
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": {"code": "authentication_required", "message": "Sign in through the configured authentication gateway."}},
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.user_id = user_id
    return await call_next(request)


# Development defaults use in-process limiters; production startup replaces them
# with shared Redis-backed, authenticated-user sliding windows.
SCAN_SEMAPHORE = asyncio.Semaphore(2)
SCAN_RATE_LIMITER = SlidingWindowLimiter(max_requests=10, window_seconds=60)
SCAN_QUEUE_TIMEOUT = 0.5
SCAN_TIMEOUT_SECONDS = 120
REPOSITORY_SCAN_SEMAPHORE = asyncio.Semaphore(1)
REPOSITORY_SCAN_LIMITER = SlidingWindowLimiter(max_requests=5, window_seconds=60)
REPOSITORY_SCAN_QUEUE_TIMEOUT = 0.5
ADVISORY_LOOKUP_LIMITER = SlidingWindowLimiter(max_requests=10, window_seconds=60)
TARGET_AUTH_LIMITER = SlidingWindowLimiter(max_requests=5, window_seconds=60)


async def _check_rate_limit(limiter, key: str) -> float:
    try:
        return await asyncio.to_thread(limiter.check, key)
    except RedisError as exc:
        raise HTTPException(
            503,
            detail={"code": "rate_limit_store_unavailable", "message": "The shared rate-limit service is temporarily unavailable."},
            headers={"Retry-After": "5"},
        ) from exc


def _configure_rate_limiters(client) -> None:
    global SCAN_RATE_LIMITER, REPOSITORY_SCAN_LIMITER, ADVISORY_LOOKUP_LIMITER, TARGET_AUTH_LIMITER
    SCAN_RATE_LIMITER = RedisSlidingWindowLimiter(client, 10, 60, "website-scan")
    REPOSITORY_SCAN_LIMITER = RedisSlidingWindowLimiter(client, 5, 60, "repository-scan")
    ADVISORY_LOOKUP_LIMITER = RedisSlidingWindowLimiter(client, 10, 60, "dependency-advisory")
    TARGET_AUTH_LIMITER = RedisSlidingWindowLimiter(client, 5, 60, "target-authorization")




TARGET_CHALLENGE_TTL = timedelta(minutes=15)
TARGET_AUTHORIZATION_TTL = timedelta(days=30)


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _normalize_authorization_hostname(raw: str) -> str:
    if not isinstance(raw, str) or raw != raw.strip() or any(char in raw for char in ":/@?#\\\\"):
        raise ValueError("Enter a hostname only, without a scheme, port, path, or credentials.")
    host = raw.rstrip(".").lower()
    try:
        host = host.encode("idna").decode("ascii")
        ipaddress.ip_address(host)
        raise ValueError("DNS verification requires a domain name, not an IP address.")
    except ValueError as exc:
        if str(exc) == "DNS verification requires a domain name, not an IP address.":
            raise
    if len(host) > 253 or not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", host):
        raise ValueError("Enter a valid fully-qualified domain name.")
    normalize_url(f"https://{host}")
    return host


def lookup_target_dns_txt(hostname: str) -> list[str]:
    try:
        answers = dns.resolver.resolve(f"_unweb-verification.{hostname}", "TXT", lifetime=5)
    except dns.exception.DNSException:
        return []
    values: list[str] = []
    for answer in answers:
        try:
            values.append(b"".join(answer.strings).decode("utf-8"))
        except (AttributeError, UnicodeDecodeError):
            continue
    return values


def _scope_prefix_contains(allowed_prefix: str, requested_prefix: str) -> bool:
    base = allowed_prefix.rstrip("/") or "/"
    return base == "/" or requested_prefix == base or requested_prefix.startswith(base + "/")


def _enforce_verified_target(payload: ScanRequest, owner_id: str) -> None:
    if not payload.target_id:
        raise HTTPException(
            403,
            detail={"code": "verified_target_required", "message": "Verify control of this domain in Target Authorizations before scanning in production."},
        )
    now = _utc_now().isoformat()
    target = database.get_authorized_target(payload.target_id, owner_id, now)
    if target is None:
        raise HTTPException(403, detail={"code": "target_authorization_invalid", "message": "This target authorization is missing, expired, revoked, or belongs to another user."})
    try:
        normalized = normalize_url(payload.url)
        parts = urlsplit(normalized)
        hostname = (parts.hostname or "").encode("idna").decode("ascii").lower()
        port = parts.port or (443 if parts.scheme == "https" else 80)
        requested_paths = normalize_scope_paths(payload.scope_paths)
    except (URLRejected, ValueError, UnicodeError) as exc:
        raise HTTPException(422, detail={"code": "invalid_target_scope", "message": str(exc)}) from exc
    if hostname != target["hostname"] or port not in target["ports"]:
        raise HTTPException(403, detail={"code": "target_outside_verified_scope", "message": "The scan hostname or port is outside the verified target authorization."})
    if not all(any(_scope_prefix_contains(allowed, requested) for allowed in target["scope_paths"]) for requested in requested_paths):
        raise HTTPException(403, detail={"code": "path_outside_verified_scope", "message": "One or more requested path prefixes exceed the verified authorization scope."})


async def load_scan(scan_id: str, owner_id: str) -> ScanResult:
    result = await asyncio.to_thread(database.get_scan, scan_id, owner_id)
    if result is None:
        raise HTTPException(404, detail="Scan not found.")
    return result


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "unweb-api", "version": "0.2.0"}


@app.post("/api/scans", response_model=ScanResult)
async def create_scan(payload: ScanRequest, request: Request):
    if not payload.authorised:
        raise HTTPException(
            403,
            detail={
                "code": "website_authorisation_required",
                "message": "Confirm that you own or are explicitly authorised to assess this website.",
            },
        )

    if UNWEB_ENV == "production":
        _enforce_verified_target(payload, request.state.user_id)

    client_key = request.state.user_id
    retry_after = await _check_rate_limit(SCAN_RATE_LIMITER, client_key)
    if retry_after:
        raise HTTPException(
            429,
            detail={
                "code": "scan_rate_limited",
                "message": "Too many scans for this account. Try again shortly.",
            },
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )

    acquired = False
    try:
        try:
            await asyncio.wait_for(SCAN_SEMAPHORE.acquire(), timeout=SCAN_QUEUE_TIMEOUT)
            acquired = True
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                429,
                detail={
                    "code": "scan_capacity_reached",
                    "message": "UnWeb is already processing scans. Try again shortly.",
                },
                headers={"Retry-After": "2"},
            ) from exc

        result = await asyncio.wait_for(
            scan_site(payload.url, payload.max_pages, True, payload.scope_paths),
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        await asyncio.to_thread(database.save_scan, result, request.state.user_id)
        await asyncio.to_thread(database.record_audit_event, request.state.user_id, "website_scan.completed", result.id)
        return result
    except asyncio.TimeoutError as exc:
        raise HTTPException(
            504,
            detail={"code": "scan_timeout", "message": "Scan exceeded the 120-second time limit."},
        ) from exc
    except UnsupportedContentType as exc:
        raise HTTPException(
            415,
            detail={"code": "unsupported_media_type", "message": str(exc)},
        ) from exc
    except URLRejected as exc:
        raise HTTPException(
            400,
            detail={"code": "target_rejected", "message": str(exc)},
        ) from exc
    except httpx.TimeoutException as exc:
        raise HTTPException(
            504,
            detail={"code": "target_timeout", "message": "Target timed out."},
        ) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(
            502,
            detail={"code": "fetch_failed", "message": "Target request failed."},
        ) from exc
    except OSError as exc:
        raise HTTPException(
            502,
            detail={"code": "network_error", "message": "Network operation failed."},
        ) from exc
    finally:
        if acquired:
            SCAN_SEMAPHORE.release()



@app.post("/api/repository-scans")
async def create_repository_scan(request: Request):
    """Analyse an explicitly authorised ZIP upload without persisting the archive."""
    if request.headers.get("x-unweb-authorised", "").strip().lower() != "true":
        raise HTTPException(
            403,
            detail={
                "code": "repository_authorisation_required",
                "message": "Confirm that you own or are authorised to assess this repository.",
            },
        )

    content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
    if content_type not in {"application/zip", "application/x-zip-compressed", "application/octet-stream"}:
        raise HTTPException(
            415,
            detail={
                "code": "repository_archive_type_required",
                "message": "Upload a ZIP archive using application/zip.",
            },
        )

    content_length = request.headers.get("content-length")
    if content_length:
        try:
            if int(content_length) > MAX_ARCHIVE_BYTES:
                raise HTTPException(
                    413,
                    detail={
                        "code": "repository_archive_too_large",
                        "message": "Repository ZIP uploads are limited to 50 MB.",
                    },
                )
        except ValueError:
            raise HTTPException(
                400,
                detail={"code": "invalid_content_length", "message": "Invalid Content-Length header."},
            )

    retry_after = await _check_rate_limit(REPOSITORY_SCAN_LIMITER, request.state.user_id)
    if retry_after:
        raise HTTPException(
            429,
            detail={
                "code": "repository_scan_rate_limited",
                "message": "Too many repository scans for this account. Try again shortly.",
            },
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )

    acquired = False
    temporary_path: str | None = None
    try:
        try:
            await asyncio.wait_for(
                REPOSITORY_SCAN_SEMAPHORE.acquire(),
                timeout=REPOSITORY_SCAN_QUEUE_TIMEOUT,
            )
            acquired = True
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                429,
                detail={
                    "code": "repository_scan_capacity_reached",
                    "message": "A repository analysis is already running. Try again shortly.",
                },
                headers={"Retry-After": "2"},
            ) from exc

        descriptor, temporary_path = tempfile.mkstemp(prefix="unweb-upload-", suffix=".zip")
        total_bytes = 0
        with os.fdopen(descriptor, "wb") as destination:
            async for chunk in request.stream():
                total_bytes += len(chunk)
                if total_bytes > MAX_ARCHIVE_BYTES:
                    raise HTTPException(
                        413,
                        detail={
                            "code": "repository_archive_too_large",
                            "message": "Repository ZIP uploads are limited to 50 MB.",
                        },
                    )
                destination.write(chunk)

        if total_bytes == 0:
            raise HTTPException(
                400,
                detail={"code": "empty_repository_archive", "message": "The uploaded ZIP archive is empty."},
            )

        try:
            report = await asyncio.to_thread(analyse_repository_archive, temporary_path)
        except ValueError as exc:
            raise HTTPException(
                400,
                detail={"code": "invalid_repository_archive", "message": str(exc)},
            ) from exc
        except OSError as exc:
            raise HTTPException(
                400,
                detail={"code": "repository_archive_read_failed", "message": "The repository archive could not be read."},
            ) from exc

        supplied_name = unquote(request.headers.get("x-repository-filename", "repository.zip"))
        safe_name = Path(supplied_name.replace("\\", "/")).name
        repository_name = Path(safe_name).stem
        report.repository = repository_name[:100] or "repository"
        await asyncio.to_thread(database.record_audit_event, request.state.user_id, "repository_zip_scan.completed", report.repository)
        return report.to_dict()
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        if acquired:
            REPOSITORY_SCAN_SEMAPHORE.release()




@app.post("/api/github-repository-scans")
async def create_github_repository_scan(payload: GitHubRepositoryScanRequest, request: Request):
    """Analyse a public GitHub repository after an explicit owner-authorisation acknowledgement."""
    if not payload.authorised:
        raise HTTPException(
            403,
            detail={
                "code": "repository_authorisation_required",
                "message": "Confirm that you own or are explicitly authorised to assess this repository.",
            },
        )

    retry_after = await asyncio.to_thread(REPOSITORY_SCAN_LIMITER.check, request.state.user_id)
    if retry_after:
        raise HTTPException(
            429,
            detail={
                "code": "github_repository_scan_rate_limited",
                "message": "Too many GitHub repository scans. Try again shortly.",
            },
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )

    acquired = False
    temporary_path: str | None = None
    try:
        try:
            await asyncio.wait_for(
                REPOSITORY_SCAN_SEMAPHORE.acquire(),
                timeout=REPOSITORY_SCAN_QUEUE_TIMEOUT,
            )
            acquired = True
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                429,
                detail={
                    "code": "repository_scan_capacity_reached",
                    "message": "A repository analysis is already running. Try again shortly.",
                },
                headers={"Retry-After": "2"},
            ) from exc

        descriptor, temporary_path = tempfile.mkstemp(prefix="unweb-github-", suffix=".zip")
        os.close(descriptor)
        try:
            source = await asyncio.wait_for(
                fetch_github_repository_archive(
                    payload.repository_url, payload.ref, temporary_path
                ),
                timeout=60,
            )
        except GitHubSourceError as exc:
            raise HTTPException(
                exc.status_code,
                detail={"code": exc.code, "message": str(exc)},
            ) from exc
        except (httpx.TimeoutException, httpx.NetworkError) as exc:
            raise HTTPException(
                502,
                detail={
                    "code": "github_network_error",
                    "message": "UnWeb could not complete the bounded GitHub source download.",
                },
            ) from exc
        except asyncio.TimeoutError as exc:
            raise HTTPException(
                504,
                detail={
                    "code": "github_download_timeout",
                    "message": "GitHub source resolution and download exceeded 60 seconds.",
                },
            ) from exc

        try:
            report = await asyncio.to_thread(analyse_repository_archive, temporary_path)
        except ValueError as exc:
            raise HTTPException(
                400,
                detail={"code": "invalid_github_repository_archive", "message": str(exc)},
            ) from exc
        except OSError as exc:
            raise HTTPException(
                502,
                detail={
                    "code": "github_archive_read_failed",
                    "message": "The downloaded GitHub source archive could not be read.",
                },
            ) from exc

        report.repository = str(source["full_name"])
        result = report.to_dict()
        result["source"] = source
        await asyncio.to_thread(database.record_audit_event, request.state.user_id, "github_repository_scan.completed", str(source["full_name"]))
        return result
    finally:
        if temporary_path:
            try:
                os.unlink(temporary_path)
            except FileNotFoundError:
                pass
        if acquired:
            REPOSITORY_SCAN_SEMAPHORE.release()


@app.post("/api/dependency-advisories")
async def dependency_advisories(payload: DependencyAdvisoryRequest, request: Request):
    """Look up advisories for exact, resolved dependency versions using OSV."""
    if not payload.authorised:
        raise HTTPException(
            403,
            detail={
                "code": "dependency_advisory_authorisation_required",
                "message": "Confirm that you are authorised to analyse these dependency records.",
            },
        )

    retry_after = await _check_rate_limit(ADVISORY_LOOKUP_LIMITER, request.state.user_id)
    if retry_after:
        raise HTTPException(
            429,
            detail={"code": "dependency_advisory_rate_limited", "message": "Too many advisory lookups for this account. Try again shortly."},
            headers={"Retry-After": str(max(1, int(retry_after + 0.999)))},
        )
    try:
        result = await query_advisories(payload.packages)
        await asyncio.to_thread(
            database.record_audit_event,
            request.state.user_id,
            "dependency_advisory_lookup.completed",
            metadata={"package_count": len(payload.packages)},
        )
        return result
    except ValueError as exc:
        raise HTTPException(422, detail={"code": "invalid_dependency_batch", "message": str(exc)}) from exc
    except AdvisoryLookupError as exc:
        raise HTTPException(502, detail={"code": "advisory_provider_error", "message": str(exc)}) from exc




@app.get("/api/targets")
async def list_authorized_targets(request: Request):
    return {"items": await asyncio.to_thread(database.list_authorized_targets, request.state.user_id, _utc_now().isoformat())}


@app.post("/api/targets/challenges")
async def create_target_challenge(payload: TargetAuthorizationChallengeRequest, request: Request):
    retry_after = await _check_rate_limit(TARGET_AUTH_LIMITER, request.state.user_id)
    if retry_after:
        raise HTTPException(429, detail={"code": "target_authorization_rate_limited", "message": "Too many target verification attempts."}, headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})
    try:
        hostname = _normalize_authorization_hostname(payload.hostname)
        ports = list(dict.fromkeys(payload.ports))
        if not ports or any(port < 1 or port > 65535 for port in ports):
            raise ValueError("Choose between 1 and 10 valid TCP ports.")
        scope_paths = normalize_scope_paths(payload.scope_paths)
    except (ValueError, URLRejected) as exc:
        raise HTTPException(422, detail={"code": "invalid_target_authorization", "message": str(exc)}) from exc
    now = _utc_now()
    challenge_id = secrets.token_urlsafe(24)
    token = secrets.token_urlsafe(32)
    token_value = f"unweb-verification={token}"
    token_hash = hashlib.sha256(token_value.encode("utf-8")).hexdigest()
    expires_at = (now + TARGET_CHALLENGE_TTL).isoformat()
    await asyncio.to_thread(
        database.save_target_challenge,
        challenge_id,
        request.state.user_id,
        hostname,
        ports,
        scope_paths,
        token_hash,
        now.isoformat(),
        expires_at,
    )
    await asyncio.to_thread(database.record_audit_event, request.state.user_id, "target_authorization.challenge_created", hostname, {"ports": ports, "scope_paths": scope_paths})
    return {
        "challenge_id": challenge_id,
        "hostname": hostname,
        "record_name": f"_unweb-verification.{hostname}",
        "record_type": "TXT",
        "record_value": token_value,
        "ports": ports,
        "scope_paths": scope_paths,
        "expires_at": expires_at,
        "instructions": "Add this TXT record to your DNS zone, wait for DNS propagation, then verify it. The token is shown only once.",
    }


@app.post("/api/targets/challenges/{challenge_id}/verify")
async def verify_target_challenge(challenge_id: str, request: Request):
    retry_after = await _check_rate_limit(TARGET_AUTH_LIMITER, request.state.user_id)
    if retry_after:
        raise HTTPException(429, detail={"code": "target_authorization_rate_limited", "message": "Too many target verification attempts."}, headers={"Retry-After": str(max(1, int(retry_after + 0.999)))})
    challenge = await asyncio.to_thread(database.get_target_challenge, challenge_id, request.state.user_id)
    if challenge is None:
        raise HTTPException(404, detail={"code": "target_challenge_not_found", "message": "Target verification challenge not found."})
    if challenge["used_at"] is not None:
        raise HTTPException(409, detail={"code": "target_challenge_used", "message": "This verification challenge has already been used."})
    now = _utc_now()
    if challenge["expires_at"] <= now.isoformat():
        raise HTTPException(410, detail={"code": "target_challenge_expired", "message": "The DNS challenge expired. Create a new challenge."})
    try:
        records = await asyncio.to_thread(lookup_target_dns_txt, challenge["hostname"])
    except Exception as exc:
        raise HTTPException(502, detail={"code": "target_dns_lookup_failed", "message": "DNS verification could not be completed."}) from exc
    matched = False
    for value in records:
        candidate = hashlib.sha256(value.encode("utf-8")).hexdigest()
        if secrets.compare_digest(candidate, challenge["token_hash"]):
            matched = True
            break
    if not matched:
        raise HTTPException(422, detail={"code": "target_dns_proof_missing", "message": f"The expected TXT value was not found at _unweb-verification.{challenge['hostname']}. Wait for DNS propagation and try again."})
    expires_at = (now + TARGET_AUTHORIZATION_TTL).isoformat()
    target = await asyncio.to_thread(database.verify_target_challenge, challenge_id, request.state.user_id, challenge["token_hash"], now.isoformat(), expires_at)
    if target is None:
        raise HTTPException(409, detail={"code": "target_challenge_already_used", "message": "This verification challenge is no longer valid."})
    await asyncio.to_thread(database.record_audit_event, request.state.user_id, "target_authorization.verified", target["target_id"], {"hostname": target["hostname"], "ports": target["ports"], "scope_paths": target["scope_paths"]})
    return target


@app.post("/api/targets/{target_id}/revoke")
async def revoke_target(target_id: str, request: Request):
    revoked = await asyncio.to_thread(database.revoke_authorized_target, target_id, request.state.user_id, _utc_now().isoformat())
    if not revoked:
        raise HTTPException(404, detail={"code": "target_authorization_not_found", "message": "Target authorization not found."})
    await asyncio.to_thread(database.record_audit_event, request.state.user_id, "target_authorization.revoked", target_id)
    return {"target_id": target_id, "revoked": True}


@app.get("/api/audit-events")
async def audit_events(request: Request, limit: int = Query(default=50, ge=1, le=100)):
    return {"items": await asyncio.to_thread(database.list_audit_events, request.state.user_id, limit)}


@app.get("/api/scans")
async def scan_history(request: Request, limit: int = Query(default=20, ge=1, le=100)):
    return {"items": await asyncio.to_thread(database.list_scans, limit, request.state.user_id)}


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str, request: Request):
    return await load_scan(scan_id, request.state.user_id)


@app.get("/api/scans/{scan_id}/intelligence")
async def intelligence(scan_id: str, request: Request):
    result = await load_scan(scan_id, request.state.user_id)
    return {
        "id": result.id,
        "url": result.final_url,
        "title": result.title,
        "headers": result.headers,
        "technologies": result.technologies,
        "assets": result.assets,
    }


@app.get("/api/scans/{scan_id}/sitemap")
async def sitemap(scan_id: str, request: Request):
    result = await load_scan(scan_id, request.state.user_id)
    page_ids = {page.url: str(index) for index, page in enumerate(result.pages)}
    edges = [
        {"source": page_ids[edge.source], "target": page_ids[edge.target]}
        for edge in result.edges
        if edge.source in page_ids and edge.target in page_ids
    ]
    return {
        "nodes": [
            {
                "id": str(index),
                "url": page.url,
                "title": page.title,
                "status_code": page.status_code,
            }
            for index, page in enumerate(result.pages)
        ],
        "edges": edges,
    }


@app.get("/api/scans/{scan_id}/security")
async def security(scan_id: str, request: Request):
    result = await load_scan(scan_id, request.state.user_id)
    return {
        "findings": result.findings,
        "security_findings": result.security_findings,
    }


@app.get("/api/scans/{scan_id}/reconstruction")
async def reconstruction(scan_id: str, request: Request):
    result = await load_scan(scan_id, request.state.user_id)
    return result.reconstruction or {}
