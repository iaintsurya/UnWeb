import uuid, httpx, re
from datetime import datetime, timezone
from urllib.parse import urljoin, urlsplit, urldefrag
from .models import ScanResult
from .url_policy import normalize_url, validate_resolved_addresses, URLRejected
from .engines import analyze_html, analyze_security, analyze_javascript

MAX_HTML = 1_500_000
MAX_SCRIPT = 500_000
TIMEOUT = httpx.Timeout(8.0, connect=4.0)
MAX_REDIRECTS = 5
UA = "UnWeb/0.1 (authorised passive analysis)"

async def safe_fetch(url: str, max_bytes: int = MAX_HTML):
    current = normalize_url(url)
    for hop in range(MAX_REDIRECTS + 1):
        validate_resolved_addresses(current)
        async with httpx.AsyncClient(timeout=TIMEOUT, follow_redirects=False, trust_env=False,
                                     headers={"User-Agent":UA,"Accept":"text/html,*/*;q=0.5"}) as client:
            async with client.stream("GET", current) as response:
                if response.status_code in {301,302,303,307,308}:
                    location = response.headers.get("location")
                    if not location: return current,response.status_code,dict(response.headers),b""
                    if hop >= MAX_REDIRECTS: raise URLRejected("Too many redirects.")
                    current = normalize_url(urljoin(current,location))
                    continue
                chunks=[]; total=0
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total > max_bytes: raise URLRejected(f"Response exceeded the {max_bytes} byte limit.")
                    chunks.append(chunk)
                return str(response.url),response.status_code,dict(response.headers),b"".join(chunks)
    raise URLRejected("Too many redirects.")

async def scan_site(raw_url: str, max_pages: int = 8, include_reconstruction: bool = True):
    start = normalize_url(raw_url)
    final_url,status,headers,body = await safe_fetch(start)
    html = body.decode("utf-8",errors="replace")
    page,assets,tech = analyze_html(final_url,html)
    page.status_code = status
    findings = analyze_security(headers,final_url)
    pages=[page]; visited={urldefrag(final_url)[0]}
    p=urlsplit(final_url); origin=(p.scheme,p.hostname,p.port)
    queue=[]
    for link in page.links:
        lp=urlsplit(link)
        if (lp.scheme,lp.hostname,lp.port)==origin and urldefrag(link)[0] not in visited:
            queue.append(urldefrag(link)[0])
    queue=list(dict.fromkeys(queue))
    js=[]
    for script_url in page.scripts[:20]:
        sp=urlsplit(script_url)
        if (sp.scheme,sp.hostname,sp.port)!=origin: continue
        try:
            _,_,_,script=await safe_fetch(script_url,MAX_SCRIPT)
            js.append(analyze_javascript(script_url,script.decode("utf-8",errors="replace")))
        except (URLRejected,httpx.HTTPError,OSError):
            js.append({"url":script_url,"error":"Script could not be safely fetched or analysed."})
    for next_url in queue:
        if len(pages)>=max_pages: break
        if next_url in visited: continue
        visited.add(next_url)
        try:
            fu,sc,hd,b=await safe_fetch(next_url)
            ct=next((v for k,v in hd.items() if k.lower()=="content-type"),"text/html")
            if "html" not in ct.lower(): continue
            pg,_,_=analyze_html(fu,b.decode("utf-8",errors="replace")); pg.status_code=sc; pages.append(pg)
        except (URLRejected,httpx.HTTPError,OSError):
            continue
    reconstruction=None
    if include_reconstruction:
        from .rebuild import make_reconstruction
        reconstruction=make_reconstruction(final_url,html)
    return ScanResult(id=str(uuid.uuid4()),requested_url=start,final_url=final_url,status_code=status,
        scanned_at=datetime.now(timezone.utc).isoformat(),title=page.title,
        description=page.metadata.get("description") or page.metadata.get("og:description"),
        headers={k.lower():v for k,v in headers.items()},technologies=tech,assets=assets,page=page,
        pages=pages,findings=findings,js_analysis=js,
        notes=["Only public responses and delivered assets were inspected.",
               "Technology and JavaScript string matches are heuristic clues, not proof.",
               "Crawler is bounded and limited to same-origin links discovered from the first page."],
        reconstruction=reconstruction)
