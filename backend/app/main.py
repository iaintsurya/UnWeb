import asyncio
import os
import re
import secrets
import tempfile
from pathlib import Path
from urllib.parse import unquote
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from starlette.responses import JSONResponse

from . import database
from .models import ScanRequest, ScanResult, GitHubRepositoryScanRequest
from .limits import SlidingWindowLimiter
from .scanner import scan_site, UnsupportedContentType
from .url_policy import URLRejected
from .repository_analysis import analyse_repository_archive, MAX_ARCHIVE_BYTES
from .github_source import fetch_github_repository_archive, GitHubSourceError
from .models import DependencyAdvisoryRequest
from .dependency_advisories import query_advisories, AdvisoryLookupError

AUTH_PROXY_SECRET = os.environ.get("UNWEB_AUTH_PROXY_SECRET", "")
UNWEB_ENV = os.environ.get("UNWEB_ENV", "development").strip().lower()


@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
    if UNWEB_ENV == "production" and not AUTH_PROXY_SECRET:
        raise RuntimeError("UNWEB_AUTH_PROXY_SECRET is required when UNWEB_ENV=production.")
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
        or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9@._:+-]*", user_id)
    ):
        return JSONResponse(
            status_code=401,
            content={"detail": {"code": "authentication_required", "message": "Sign in through the configured authentication gateway."}},
            headers={"WWW-Authenticate": "Bearer"},
        )

    request.state.user_id = user_id
    return await call_next(request)


# Keep resource use bounded in the preview server. The in-process limiter is
# a local abuse guard, not a substitute for shared, identity-aware production controls.
SCAN_SEMAPHORE = asyncio.Semaphore(2)
SCAN_RATE_LIMITER = SlidingWindowLimiter(max_requests=10, window_seconds=60)
SCAN_QUEUE_TIMEOUT = 0.5
SCAN_TIMEOUT_SECONDS = 120
REPOSITORY_SCAN_SEMAPHORE = asyncio.Semaphore(1)
REPOSITORY_SCAN_LIMITER = SlidingWindowLimiter(max_requests=5, window_seconds=60)
REPOSITORY_SCAN_QUEUE_TIMEOUT = 0.5
ADVISORY_LOOKUP_LIMITER = SlidingWindowLimiter(max_requests=10, window_seconds=60)


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

    client_key = request.state.user_id
    retry_after = SCAN_RATE_LIMITER.check(client_key)
    if retry_after:
        raise HTTPException(
            429,
            detail={
                "code": "scan_rate_limited",
                "message": "Too many scans from this network address. Try again shortly.",
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

    client_key = request.client.host if request.client else "unknown"
    retry_after = REPOSITORY_SCAN_LIMITER.check(client_key)
    if retry_after:
        raise HTTPException(
            429,
            detail={
                "code": "repository_scan_rate_limited",
                "message": "Too many repository uploads from this network address. Try again shortly.",
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

    retry_after = REPOSITORY_SCAN_LIMITER.check(request.state.user_id)
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

    client_key = request.client.host if request.client else "unknown"
    retry_after = ADVISORY_LOOKUP_LIMITER.check(client_key)
    if retry_after:
        raise HTTPException(
            429,
            detail={"code": "dependency_advisory_rate_limited", "message": "Too many advisory lookups. Try again shortly."},
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
