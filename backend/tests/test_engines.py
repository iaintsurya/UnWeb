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
