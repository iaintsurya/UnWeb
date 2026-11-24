import re
from http.cookies import SimpleCookie
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

def _cookie_observations(headers: dict[str, str]) -> list[Finding]:
    """Report cookie-attribute observations without retaining cookie values."""
    normalized = {str(key).lower(): value for key, value in headers.items()}
    raw = normalized.get("__unweb_set_cookie_headers") or normalized.get("set-cookie") or ""
    if not raw:
        return []

    findings: list[Finding] = []
    seen: set[tuple[str, str]] = set()
    for raw_cookie in str(raw).splitlines():
        parsed = SimpleCookie()
        try:
            parsed.load(raw_cookie)
        except (TypeError, ValueError):
            continue
        for name, morsel in parsed.items():
            safe_name = re.sub(r"[^a-z0-9_-]+", "-", name.lower()).strip("-")[:48] or "unnamed"
            attributes = (
                ("secure", bool(morsel["secure"]), "Secure",
                 "Set Secure on cookies that should only be sent over HTTPS."),
                ("httponly", bool(morsel["httponly"]), "HttpOnly",
                 "For session or authentication cookies, set HttpOnly unless client-side script access is explicitly required."),
                ("samesite", bool(morsel["samesite"]), "SameSite",
                 "Choose an explicit SameSite policy that matches the application's cross-site flows."),
            )
            for attribute_id, present, label, recommendation in attributes:
                key = (safe_name, attribute_id)
                if present or key in seen:
                    continue
                seen.add(key)
                findings.append(Finding(
                    id=f"cookie-{safe_name}-missing-{attribute_id}",
                    title=f"Cookie '{name[:48]}' has no {label} attribute",
                    severity="low",
                    confidence="medium",
                    evidence=(
                        f"The response set cookie '{name[:48]}' without the {label} attribute; "
                        "the cookie value was deliberately redacted."
                    ),
                    recommendation=recommendation,
                ))
            if morsel["samesite"].lower() == "none" and not morsel["secure"]:
                key = (safe_name, "samesite-none-without-secure")
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding(
                        id=f"cookie-{safe_name}-samesite-none-without-secure",
                        title=f"Cookie '{name[:48]}' uses SameSite=None without Secure",
                        severity="low",
                        confidence="high",
                        evidence=(
                            f"The response set cookie '{name[:48]}' with SameSite=None but without Secure; "
                            "the cookie value was deliberately redacted."
                        ),
                        recommendation="Add Secure to cookies using SameSite=None and serve them only over HTTPS.",
                    ))
    return findings


def analyze_security(headers: dict[str,str], final_url: str) -> list[Finding]:
    h = {k.lower():v for k,v in headers.items()}
    findings = _cookie_observations(headers)
    for key,(title,recommendation) in SECURITY_HEADERS.items():
        if key not in h:
            findings.append(Finding(id=f"missing-{key}", title=title, severity="low", confidence="high",
                evidence=f"The inspected response did not include the {key} header.", recommendation=recommendation))
    is_https = urlsplit(final_url).scheme == "https"
    if not is_https:
        findings.append(Finding(
            id="http-not-https",
            title="Final page uses HTTP",
            severity="medium",
            confidence="high",
            evidence="The final page URL scheme was HTTP.",
            recommendation="Serve the site over HTTPS where appropriate.",
        ))
    elif "strict-transport-security" not in h:
        findings.append(Finding(
            id="missing-strict-transport-security",
            title="HTTP Strict Transport Security not detected",
            severity="low",
            confidence="high",
            evidence="The inspected HTTPS response did not include the strict-transport-security header.",
            recommendation="Consider enabling HSTS after confirming every relevant subdomain is HTTPS-ready.",
        ))

    # Header presence alone is not enough: a present but ineffective value
    # should not be treated as a successful configuration observation.
    xcto = h.get("x-content-type-options", "").strip().lower()
    if xcto and xcto != "nosniff":
        findings.append(Finding(
            id="invalid-x-content-type-options",
            title="X-Content-Type-Options does not use nosniff",
            severity="low",
            confidence="high",
            evidence=f"The response supplied X-Content-Type-Options with value '{xcto[:120]}', rather than 'nosniff'.",
            recommendation="Set X-Content-Type-Options: nosniff on applicable responses.",
        ))

    hsts = h.get("strict-transport-security", "")
    if is_https and hsts:
        max_age_values = re.findall(r"(?:^|;)\s*max-age\s*=\s*([^;\s]+)", hsts, flags=re.I)
        if len(max_age_values) != 1 or not max_age_values[0].isdigit() or max_age_values[0].lstrip("0") == "":
            findings.append(Finding(
                id="ineffective-strict-transport-security",
                title="Strict-Transport-Security has no effective max-age",
                severity="low",
                confidence="high",
                evidence="The HTTPS response supplied an HSTS header whose max-age directive is missing, ambiguous, invalid, or zero.",
                recommendation="After confirming HTTPS readiness, configure one positive max-age value in Strict-Transport-Security.",
            ))

    csp_value = h.get("content-security-policy", "")
    if "content-security-policy" in h and not csp_value.strip():
        findings.append(Finding(
            id="empty-content-security-policy",
            title="Content-Security-Policy header is empty",
            severity="low",
            confidence="high",
            evidence="The response included a Content-Security-Policy header with no policy directives.",
            recommendation="Configure an intentional Content-Security-Policy, starting with a policy appropriate to the application's resources and testing it in report-only mode.",
        ))

    csp = csp_value.lower()
    has_frame_ancestors = "frame-ancestors" in csp
    if "x-frame-options" not in h and not has_frame_ancestors:
        findings.append(Finding(
            id="missing-framing-protection",
            title="Framing protection not detected",
            severity="low",
            confidence="medium",
            evidence="The response did not include X-Frame-Options or a CSP frame-ancestors directive.",
            recommendation="Set an appropriate Content-Security-Policy frame-ancestors directive, or X-Frame-Options for legacy browser support.",
        ))

    # CORS and technology headers are passive configuration disclosures.
    # A wildcard origin can be intentional for public resources, so this is
    # an observation rather than a claim of exploitable cross-origin access.
    cors_origin = h.get("access-control-allow-origin", "").strip()
    if cors_origin == "*":
        findings.append(Finding(
            id="cors-wildcard-origin",
            title="Wildcard CORS origin observed",
            severity="low",
            confidence="high",
            evidence="The inspected response supplied Access-Control-Allow-Origin: *. This permits browser cross-origin reads of resources that are otherwise public; it does not by itself demonstrate access to private or credentialed data.",
            recommendation="If cross-origin access is not intentionally public, replace the wildcard with an explicit allowlist of trusted origins. Review credential and exposed-header settings separately.",
        ))

    server_value = h.get("server", "").strip()
    if server_value and re.search(r"\d+\.\d+(?:\.\d+)?", server_value):
        findings.append(Finding(
            id="server-version-disclosure",
            title="Server response exposes a version-like identifier",
            severity="info",
            confidence="medium",
            evidence="The Server response header contains a version-like identifier. The exact value is omitted from the finding.",
            recommendation="Consider minimising unnecessary server version details in response headers; keep software patched regardless of whether the version is disclosed.",
        ))

    powered_by = h.get("x-powered-by", "").strip()
    if powered_by:
        findings.append(Finding(
            id="technology-header-disclosure",
            title="X-Powered-By technology disclosure observed",
            severity="info",
            confidence="high",
            evidence="The response includes an X-Powered-By header identifying an implementation technology. The header value is omitted from the finding.",
            recommendation="Remove unnecessary X-Powered-By response headers where practical. This is informational hardening, not evidence that the disclosed technology is vulnerable.",
        ))

    if re.search(r"(?:^|[\s;])(?:script-src|default-src)[^;]*(?:'unsafe-inline'|'unsafe-eval'|\*)", csp):
        findings.append(Finding(
            id="csp-permissive-script-source",
            title="Content Security Policy contains a permissive script source",
            severity="low",
            confidence="medium",
            evidence="The inspected Content-Security-Policy includes unsafe-inline, unsafe-eval, or a wildcard in a script source directive. The impact depends on the complete policy and application behavior.",
            recommendation="Where compatible with the application, prefer nonces or hashes for inline scripts, avoid unsafe-eval, and narrow script sources to trusted origins. Test policy changes before enforcement.",
        ))
    return findings

def _decode_js_literal(value: str) -> str:
    """Decode common escapes needed to report URL-like JavaScript strings."""
    replacements = {
        "\\\\": "\\",
        "\\/": "/",
        "\\'": "'",
        '\\"': '"',
        "\\n": "\n",
        "\\r": "\r",
        "\\t": "\t",
    }
    for encoded, decoded in replacements.items():
        value = value.replace(encoded, decoded)
    return value


def _iter_js_string_literals(body: str):
    """Yield string/template literal clues while ignoring JS comments.

    This is a deliberately small lexer, not a complete JavaScript parser.
    Offsets and line numbers keep each match traceable to its delivered source.
    """
    index = 0
    line = 1
    length = len(body)
    backtick = chr(96)

    while index < length:
        char = body[index]
        next_char = body[index + 1] if index + 1 < length else ""

        if char == "/" and next_char == "/":
            index += 2
            while index < length and body[index] not in "\r\n":
                index += 1
            continue

        if char == "/" and next_char == "*":
            index += 2
            while index < length:
                if body[index] == "\n":
                    line += 1
                if body[index] == "*" and index + 1 < length and body[index + 1] == "/":
                    index += 2
                    break
                index += 1
            continue

        if char not in {"'", '"', backtick}:
            if char == "\n":
                line += 1
            index += 1
            continue

        quote = char
        start = index
        literal_line = line
        index += 1
        chars = []
        dynamic = False

        while index < length:
            current = body[index]
            if current == "\\" and index + 1 < length:
                escaped = body[index + 1]
                chars.extend([current, escaped])
                if escaped == "\n":
                    line += 1
                index += 2
                continue

            if quote == backtick and current == "$" and index + 1 < length and body[index + 1] == "{":
                dynamic = True
                break

            if current == quote:
                index += 1
                break

            chars.append(current)
            if current == "\n":
                line += 1
            index += 1

        value = _decode_js_literal("".join(chars))
        if value:
            yield {
                "value": value,
                "offset": start,
                "line": literal_line,
                "dynamic_template": dynamic,
            }

        # Skip a template interpolation with brace-depth tracking. Nested
        # strings and comments are skipped so their braces don't alter depth.
        if quote == backtick and dynamic:
            depth = 1
            index += 2
            while index < length and depth:
                current = body[index]
                following = body[index + 1] if index + 1 < length else ""
                if current == "\n":
                    line += 1
                if current in {"'", '"', backtick}:
                    nested_quote = current
                    index += 1
                    while index < length:
                        item = body[index]
                        if item == "\\" and index + 1 < length:
                            if body[index + 1] == "\n":
                                line += 1
                            index += 2
                            continue
                        if item == "\n":
                            line += 1
                        index += 1
                        if item == nested_quote:
                            break
                    continue
                if current == "/" and following == "/":
                    index += 2
                    while index < length and body[index] not in "\r\n":
                        index += 1
                    continue
                if current == "/" and following == "*":
                    index += 2
                    while index < length:
                        if body[index] == "\n":
                            line += 1
                        if body[index] == "*" and index + 1 < length and body[index + 1] == "/":
                            index += 2
                            break
                        index += 1
                    continue
                if current == "{":
                    depth += 1
                elif current == "}":
                    depth -= 1
                index += 1
            if index < length and body[index] == backtick:
                index += 1


def _mask_js_comments(body: str) -> str:
    """Replace comments with spaces while preserving strings and line numbers."""
    chars = list(body)
    index = 0
    quote = None
    backtick = chr(96)

    while index < len(body):
        current = body[index]
        following = body[index + 1] if index + 1 < len(body) else ""

        if quote:
            if current == "\\":
                index += 2
                continue
            if current == quote:
                quote = None
            index += 1
            continue

        if current in {"'", '"', backtick}:
            quote = current
            index += 1
            continue

        if current == "/" and following == "/":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index < len(body) and body[index] not in "\r\n":
                chars[index] = " "
                index += 1
            continue

        if current == "/" and following == "*":
            chars[index] = " "
            chars[index + 1] = " "
            index += 2
            while index < len(body):
                if body[index] == "*" and index + 1 < len(body) and body[index + 1] == "/":
                    chars[index] = " "
                    chars[index + 1] = " "
                    index += 2
                    break
                if body[index] not in "\r\n":
                    chars[index] = " "
                index += 1
            continue

        index += 1

    return "".join(chars)


def analyze_javascript(script_url: str, body: str) -> dict[str, object]:
    """Extract explainable route, library, and source-map clues from JS."""
    route_pattern = re.compile(r"^/(?:api|v\d+|auth|graphql|admin)(?:/|$)", re.I)
    call_context = re.compile(
        r"(?:\bfetch|\baxios(?:\.(get|post|put|patch|delete))?|"
        r"\b(?:get|post|put|patch|delete)\s*\(|"
        r"\b(?:url|path|endpoint)\s*[:=])\s*\(?\s*$",
        re.I,
    )

    references = []
    routes = []
    for literal in _iter_js_string_literals(body):
        value = literal["value"].strip()
        if len(value) > 500 or not route_pattern.match(value):
            continue

        offset = int(literal["offset"])
        prefix = body[max(0, offset - 180):offset]
        line_start = body.rfind("\n", 0, offset) + 1
        line_end = body.find("\n", offset)
        if line_end < 0:
            line_end = len(body)
        source_line = body[line_start:line_end].strip()[:180]

        context_match = call_context.search(prefix)
        confidence = "high" if context_match else "medium"
        method = context_match.group(1).upper() if context_match and context_match.group(1) else None
        context = "network-call-or-url-field" if context_match else "route-like-string"
        item = {
            "url": value,
            "line": literal["line"],
            "confidence": confidence,
            "context": context,
            "dynamic_template_prefix": bool(literal["dynamic_template"]),
            "evidence": source_line,
        }
        if method:
            item["method"] = method
        references.append(item)
        if value not in routes:
            routes.append(value)
        if len(references) >= 100:
            break

    library_rules = [
        ("React", r"React\.createElement|__REACT_DEVTOOLS_GLOBAL_HOOK__|react-dom/(?:client|server)|from\s*[\"']react[\"']"),
        ("Next.js", r"__NEXT_DATA__|next/(?:router|navigation)|/_next/(?:static|image)|next/font"),
        ("Vue", r"createApp\s*\(|from\s*[\"']vue[\"']|__VUE__"),
        ("Angular", r"@angular/core|ng-version=|ɵɵdefineComponent"),
        ("jQuery", r"jQuery(?:\.fn)?|window\.\$|\$\(\s*(?:document|[\"'])"),
        ("Svelte", r"svelte/internal|svelte-hmr"),
        ("Astro", r"astro-island|astro:"),
    ]
    libraries = []
    library_evidence = []
    searchable_body = _mask_js_comments(body)
    for name, pattern in library_rules:
        match = re.search(pattern, searchable_body, re.I)
        if match:
            libraries.append(name)
            evidence = body[max(0, match.start() - 45):min(len(body), match.end() + 65)].replace("\n", " ")[:140]
            library_evidence.append({
                "name": name,
                "confidence": "medium",
                "evidence": evidence,
                "offset": match.start(),
                "line": body.count("\n", 0, match.start()) + 1,
            })

    source_maps = []
    source_map_pattern = r"(?://#|//@|/\*[#@])\s*sourceMappingURL\s*=\s*([^\s*]+)"
    for match in re.finditer(source_map_pattern, body):
        source_maps.append({
            "reference": match.group(1).strip().rstrip("*/"),
            "line": body.count("\n", 0, match.start()) + 1,
        })
        if len(source_maps) >= 10:
            break

    byte_count = len(body.encode("utf-8", errors="ignore"))
    return {
        "url": script_url,
        "bytes_analyzed": byte_count,
        "line_count": body.count("\n") + 1,
        "routes": routes,
        "route_references": references,
        "possible_libraries": libraries,
        "library_evidence": library_evidence,
        "source_mapping_url_reference": bool(source_maps),
        "source_map_references": source_maps,
        "method": "comment-aware lexical heuristics",
        "limitations": (
            "Not AST analysis: these lexical heuristics inspect string paths, framework markers, and source-map comments "
            "are evidence clues only. They do not prove a route is reachable, a library "
            "is active, or a source map is publicly available."
        ),
    }
