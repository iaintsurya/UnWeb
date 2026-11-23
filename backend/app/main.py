import asyncio
import os
from contextlib import asynccontextmanager
from collections.abc import AsyncIterator

import httpx
from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware

from . import database
from .models import ScanRequest, ScanResult
from .limits import SlidingWindowLimiter
from .scanner import scan_site, UnsupportedContentType
from .url_policy import URLRejected

@asynccontextmanager
async def lifespan(_: FastAPI) -> AsyncIterator[None]:
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
    allow_headers=["Content-Type"],
)

# Keep resource use bounded in the preview server. The in-process limiter is
# a local abuse guard, not a substitute for shared, identity-aware production controls.
SCAN_SEMAPHORE = asyncio.Semaphore(2)
SCAN_RATE_LIMITER = SlidingWindowLimiter(max_requests=10, window_seconds=60)
SCAN_QUEUE_TIMEOUT = 0.5
SCAN_TIMEOUT_SECONDS = 120


async def load_scan(scan_id: str) -> ScanResult:
    result = await asyncio.to_thread(database.get_scan, scan_id)
    if result is None:
        raise HTTPException(404, detail="Scan not found.")
    return result


@app.get("/api/health")
async def health():
    return {"status": "ok", "service": "unweb-api", "version": "0.2.0"}


@app.post("/api/scans", response_model=ScanResult)
async def create_scan(payload: ScanRequest, request: Request):
    client_key = request.client.host if request.client else "unknown"
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
            scan_site(payload.url, payload.max_pages, True),
            timeout=SCAN_TIMEOUT_SECONDS,
        )
        await asyncio.to_thread(database.save_scan, result)
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


@app.get("/api/scans")
async def scan_history(limit: int = Query(default=20, ge=1, le=100)):
    return {"items": await asyncio.to_thread(database.list_scans, limit)}


@app.get("/api/scans/{scan_id}", response_model=ScanResult)
async def get_scan(scan_id: str):
    return await load_scan(scan_id)


@app.get("/api/scans/{scan_id}/intelligence")
async def intelligence(scan_id: str):
    result = await load_scan(scan_id)
    return {
        "id": result.id,
        "url": result.final_url,
        "title": result.title,
        "headers": result.headers,
        "technologies": result.technologies,
        "assets": result.assets,
    }


@app.get("/api/scans/{scan_id}/sitemap")
async def sitemap(scan_id: str):
    result = await load_scan(scan_id)
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
async def security(scan_id: str):
    result = await load_scan(scan_id)
    return {"findings": result.findings}


@app.get("/api/scans/{scan_id}/reconstruction")
async def reconstruction(scan_id: str):
    result = await load_scan(scan_id)
    return result.reconstruction or {}
