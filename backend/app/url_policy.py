"""URL checks are defence-in-depth; public deployments also need network egress controls."""
import ipaddress
import os
import socket
from urllib.parse import urlsplit, urlunsplit

# Bounded DNS resolution: a slow or blackholed nameserver for an attacker-chosen
# hostname must not tie up the thread pool that serves unrelated requests.
DNS_TIMEOUT_SECONDS = float(os.environ.get("UNWEB_DNS_TIMEOUT_SECONDS", "5"))


def _resolve(host: str, port: int) -> list:
    """getaddrinfo with a wall-clock bound. The underlying C call cannot be
    interrupted mid-flight, so run it on a daemon thread and abandon (rather
    than block) if it exceeds the timeout."""
    import threading

    result: list = []
    error: list = []

    def worker() -> None:
        try:
            result.extend(socket.getaddrinfo(host, port, type=socket.SOCK_STREAM))
        except OSError as exc:
            error.append(exc)

    thread = threading.Thread(target=worker, daemon=True)
    thread.start()
    thread.join(DNS_TIMEOUT_SECONDS)
    if thread.is_alive():
        raise URLRejected("Hostname resolution timed out.")
    if error:
        raise URLRejected("Hostname could not be resolved.") from error[0]
    return result


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
    elif ":" not in host and not all(part and len(part) <= 63 for part in host.split(".")):
        # Hostnames with colons are bracketed IPv6 literals handled above; label
        # checks apply only to dotted DNS names.
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
        records = _resolve(host, p.port or (443 if p.scheme == "https" else 80))
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
