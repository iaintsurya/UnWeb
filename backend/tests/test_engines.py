from app.engines import analyze_html, analyze_security, analyze_javascript

def test_html_extraction():
    html='<html><head><title>Demo</title><meta name="description" content="hello"><script src="/app.js"></script></head><body><a href="/about">About</a><img src="/x.png"></body></html>'
    page,assets,tech=analyze_html("https://example.com/",html)
    assert page.title=="Demo"
    assert page.metadata["description"]=="hello"
    assert "https://example.com/about" in page.links
    assert "https://example.com/app.js" in page.scripts

def test_security_header_evidence():
    result=analyze_security({},"https://example.com/")
    assert any(x.id=="missing-content-security-policy" for x in result)

def test_js_heuristics():
    result=analyze_javascript("https://example.com/app.js",'fetch("/api/products"); //# sourceMappingURL=app.js.map')
    assert "/api/products" in result["routes"]
    assert result["source_mapping_url_reference"]
    assert "heuristics" in result["limitations"]



def test_hsts_and_framing_checks_are_context_aware():
    https_findings = analyze_security(
        {"content-security-policy": "default-src 'self'; frame-ancestors 'none'"},
        "https://example.com/",
    )
    https_ids = {finding.id for finding in https_findings}
    assert "missing-strict-transport-security" in https_ids
    assert "missing-framing-protection" not in https_ids

    protected_findings = analyze_security(
        {
            "strict-transport-security": "max-age=31536000",
            "x-frame-options": "DENY",
        },
        "https://example.com/",
    )
    protected_ids = {finding.id for finding in protected_findings}
    assert "missing-strict-transport-security" not in protected_ids
    assert "missing-framing-protection" not in protected_ids



def test_cookie_attribute_observations_never_include_cookie_values():
    secret = "sessionid=super-secret-session-value; Path=/; SameSite=None"
    findings = analyze_security(
        {"set-cookie": secret, "content-type": "text/html"},
        "https://example.com/",
    )
    by_id = {finding.id: finding for finding in findings}
    assert "cookie-sessionid-missing-secure" in by_id
    assert "cookie-sessionid-missing-httponly" in by_id
    assert "cookie-sessionid-samesite-none-without-secure" in by_id
    rendered = " ".join(
        [finding.title + " " + finding.evidence + " " + finding.recommendation
         for finding in findings]
    )
    assert "super-secret-session-value" not in rendered
    assert "sessionid" in rendered


def test_cookie_attribute_parser_handles_multiple_set_cookie_lines():
    findings = analyze_security(
        {
            "__unweb_set_cookie_headers": (
                "theme=dark; Path=/; Secure; HttpOnly; SameSite=Lax\n"
                "sid=hidden-value; Path=/"
            )
        },
        "https://example.com/",
    )
    ids = {finding.id for finding in findings}
    assert not any(item.startswith("cookie-theme-") for item in ids)
    assert "cookie-sid-missing-secure" in ids
    assert "cookie-sid-missing-httponly" in ids
    assert "cookie-sid-missing-samesite" in ids



def test_cookie_header_lookup_is_case_insensitive():
    findings = analyze_security(
        {"Set-Cookie": "sid=redacted; Path=/"},
        "https://example.com/",
    )
    assert any(item.id == "cookie-sid-missing-secure" for item in findings)
