"""URL checks are defence-in-depth; public deployments also need network egress controls."""
import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

class URLRejected(ValueError):
    pass

def normalize_url(raw: str) -> str:
    if not isinstance(raw, str) or not raw.strip():
        raise URLRejected("Enter a URL.")
    raw = raw.strip()
    if any(ord(c) < 32 for c in raw) or "\\" in raw:
        raise URLRejected("URL contains invalid control characters.")
    if "://" not in raw:
        raw = "https://" + raw
    try:
        p = urlsplit(raw)
        port = p.port
    except ValueError as exc:
        raise URLRejected("Malformed URL or port.") from exc
    if p.scheme.lower() not in {"http", "https"}:
        raise URLRejected("Only HTTP and HTTPS URLs are supported.")
    if not p.hostname or p.username is not None or p.password is not None:
        raise URLRejected("URL must have a hostname and must not contain credentials.")
    host = p.hostname.rstrip(".").lower()
    if "%" in host or host == "localhost" or host.endswith(".localhost"):
        raise URLRejected("Local or scoped hostnames are blocked.")
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        ip = None
    if ip is not None:
        if not ip.is_global:
            raise URLRejected("Private, local, reserved, or non-public IP destinations are blocked.")
    elif not all(part and len(part) <= 63 for part in host.split(".")):
        raise URLRejected("Invalid hostname.")
    netloc = f"[{host}]" if ":" in host and not host.startswith("[") else host
    if port is not None:
        netloc += f":{port}"
    return urlunsplit((p.scheme.lower(), netloc, p.path or "/", p.query, ""))

def validate_resolved_addresses(url: str) -> list[str]:
    p = urlsplit(url)
    host = p.hostname
    if not host:
        raise URLRejected("URL has no hostname.")
    try:
        ip = ipaddress.ip_address(host)
        addresses = [str(ip)]
    except ValueError:
        try:
            records = socket.getaddrinfo(host, p.port or (443 if p.scheme == "https" else 80), type=socket.SOCK_STREAM)
        except OSError as exc:
            raise URLRejected("Hostname could not be resolved.") from exc
        addresses = sorted({r[4][0].split("%")[0] for r in records})
    if not addresses:
        raise URLRejected("Hostname resolved to no addresses.")
    for addr in addresses:
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError as exc:
            raise URLRejected("DNS returned an invalid address.") from exc
        if not ip.is_global:
            raise URLRejected("Hostname resolves to a private, local, reserved, or non-public address.")
    return addresses
