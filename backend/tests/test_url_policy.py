import pytest
from app.url_policy import normalize_url, validate_resolved_addresses, URLRejected

@pytest.mark.parametrize("url",["http://127.0.0.1","http://192.168.1.2","http://10.0.0.5",
 "http://169.254.169.254","file:///etc/passwd","http://user:pass@example.com"])
def test_rejects_unsafe_urls(url):
    with pytest.raises(URLRejected): normalize_url(url)

def test_adds_https():
    assert normalize_url("example.com")=="https://example.com/"

def test_rejects_private_dns(monkeypatch):
    import socket
    monkeypatch.setattr(socket,"getaddrinfo",lambda *a,**k:[(None,None,None,None,("127.0.0.1",0))])
    with pytest.raises(URLRejected): validate_resolved_addresses("https://example.com")
