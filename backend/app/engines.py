import re
from urllib.parse import urljoin, urlsplit
from bs4 import BeautifulSoup
from .models import Finding, PageSummary

SECURITY_HEADERS = {
    "content-security-policy": ("Content Security Policy not detected", "Evaluate a policy suitable for the site's required scripts, styles, frames, and connections."),
    "x-content-type-options": ("X-Content-Type-Options not detected", "Consider setting X-Content-Type-Options: nosniff."),
    "referrer-policy": ("Referrer-Policy not detected", "Set a Referrer-Policy appropriate to the site's privacy needs."),
    "permissions-policy": ("Permissions-Policy not detected", "Review browser features and restrict those the site does not need."),
}

def analyze_html(base_url: str, html: str):
    soup = BeautifulSoup(html, "html.parser")
    title = soup.title.get_text(" ", strip=True) if soup.title else None
    metadata = {}
    for tag in soup.find_all("meta"):
        key = tag.get("name") or tag.get("property") or tag.get("http-equiv")
        value = tag.get("content")
        if key and value:
            metadata[str(key).lower()] = str(value)[:2000]
    def absolute(value):
        u = urljoin(base_url, str(value))
        return u if urlsplit(u).scheme in {"http", "https"} else None
    links = list(dict.fromkeys(filter(None, (absolute(t["href"]) for t in soup.find_all("a", href=True)))))[:300]
    scripts = list(dict.fromkeys(filter(None, (absolute(t["src"]) for t in soup.find_all("script", src=True)))))[:100]
    stylesheets, images, assets = [], [], []
    for tag in soup.find_all("link", href=True):
        u = absolute(tag["href"])
        if not u: continue
        rel = " ".join(str(x).lower() for x in (tag.get("rel") or []))
        if "stylesheet" in rel:
            stylesheets.append(u); assets.append({"kind":"stylesheet","url":u})
        elif "icon" in rel:
            assets.append({"kind":"icon","url":u})
    for u in scripts: assets.append({"kind":"script","url":u})
    for tag in soup.find_all("img", src=True):
        u = absolute(tag["src"])
        if u: images.append(u); assets.append({"kind":"image","url":u})
    page = PageSummary(url=base_url, title=title, links=links, scripts=scripts,
                       stylesheets=list(dict.fromkeys(stylesheets)), images=list(dict.fromkeys(images)),
                       metadata=metadata)
    low = html.lower()
    tech = []
    for name, confidence, evidence, condition in [
        ("React","medium","React-related marker or string observed.", ("data-reactroot" in low or "__react" in low or "react-dom" in low)),
        ("Next.js","medium","Next.js marker or /_next/ asset path observed.", ("__next_data__" in low or "/_next/" in low)),
        ("WordPress","high","WordPress asset path observed.", ("wp-content/" in low or "wp-includes/" in low)),
        ("Vite dev client","high","@vite/client reference observed.", ("@vite/client" in low)),
    ]:
        if condition: tech.append({"name":name,"confidence":confidence,"evidence":evidence})
    return page, assets, tech

def analyze_security(headers: dict[str,str], final_url: str) -> list[Finding]:
    h = {k.lower():v for k,v in headers.items()}
    findings = []
    for key,(title,recommendation) in SECURITY_HEADERS.items():
        if key not in h:
            findings.append(Finding(id=f"missing-{key}", title=title, severity="low", confidence="high",
                evidence=f"The inspected response did not include the {key} header.", recommendation=recommendation))
    if urlsplit(final_url).scheme != "https":
        findings.append(Finding(id="http-not-https", title="Final page uses HTTP", severity="medium", confidence="high",
            evidence="The final page URL scheme was HTTP.", recommendation="Serve the site over HTTPS where appropriate."))
    return findings

def analyze_javascript(script_url: str, body: str) -> dict[str, object]:
    routes = sorted(set(re.findall(r"""['"`](/(?:api|v\d+|auth|graphql|admin)[^'"`\s]*)['"`]""", body)))[:100]
    libraries = [name for name,pattern in [
        ("React",r"\breact(?:-dom)?\b"),("Vue",r"\bvue(?:\.runtime)?\b"),
        ("Angular",r"@angular/"),("jQuery",r"jQuery|\$\(")] if re.search(pattern,body,re.I)]
    return {"url":script_url,"bytes_analyzed":len(body.encode("utf-8",errors="ignore")),
        "routes":routes,"possible_libraries":libraries,
        "source_mapping_url_reference":bool(re.search(r"sourceMappingURL\s*=\s*\S+",body)),
        "method":"bounded lexical heuristics",
        "limitations":"Strings are clues only; these lexical heuristics are not AST analysis and do not prove a route or dependency is active."}
