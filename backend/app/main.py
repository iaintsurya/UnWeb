from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import httpx
from .models import ScanRequest, ScanResult
from .scanner import scan_site
from .url_policy import URLRejected

app=FastAPI(title="UnWeb API",version="0.1.0",description="Bounded passive website intelligence.")
app.add_middleware(CORSMiddleware,allow_origins=["http://127.0.0.1:5173","http://localhost:5173"],
                   allow_credentials=False,allow_methods=["GET","POST"],allow_headers=["Content-Type"])
RESULTS:dict[str,ScanResult]={}

@app.get("/api/health")
async def health(): return {"status":"ok","service":"unweb-api","version":"0.1.0"}

@app.post("/api/scans",response_model=ScanResult)
async def create_scan(payload:ScanRequest):
    try: result=await scan_site(payload.url,payload.max_pages,True)
    except URLRejected as exc: raise HTTPException(400,detail={"code":"target_rejected","message":str(exc)}) from exc
    except httpx.TimeoutException as exc: raise HTTPException(504,detail={"code":"target_timeout","message":"Target timed out."}) from exc
    except httpx.HTTPError as exc: raise HTTPException(502,detail={"code":"fetch_failed","message":"Target request failed."}) from exc
    except OSError as exc: raise HTTPException(502,detail={"code":"network_error","message":"Network operation failed."}) from exc
    RESULTS[result.id]=result
    return result

@app.get("/api/scans/{scan_id}",response_model=ScanResult)
async def get_scan(scan_id:str):
    r=RESULTS.get(scan_id)
    if not r: raise HTTPException(404,detail="Scan not found; preview results are in memory.")
    return r

@app.get("/api/scans/{scan_id}/intelligence")
async def intelligence(scan_id:str):
    r=RESULTS.get(scan_id)
    if not r: raise HTTPException(404,detail="Scan not found.")
    return {"id":r.id,"url":r.final_url,"title":r.title,"headers":r.headers,"technologies":r.technologies,"assets":r.assets}

@app.get("/api/scans/{scan_id}/sitemap")
async def sitemap(scan_id:str):
    r=RESULTS.get(scan_id)
    if not r: raise HTTPException(404,detail="Scan not found.")
    return {"nodes":[{"id":str(i),"url":p.url,"title":p.title,"status_code":p.status_code} for i,p in enumerate(r.pages)],
            "edges":[{"source":"0","target":str(i)} for i in range(1,len(r.pages))]}

@app.get("/api/scans/{scan_id}/security")
async def security(scan_id:str):
    r=RESULTS.get(scan_id)
    if not r: raise HTTPException(404,detail="Scan not found.")
    return {"findings":r.findings}

@app.get("/api/scans/{scan_id}/reconstruction")
async def reconstruction(scan_id:str):
    r=RESULTS.get(scan_id)
    if not r: raise HTTPException(404,detail="Scan not found.")
    return r.reconstruction or {}
