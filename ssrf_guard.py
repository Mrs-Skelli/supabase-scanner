import ipaddress
import socket
import logging
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# Blocked IP networks (private, loopback, link-local, metadata)
_BLOCKED_NETS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("0.0.0.0/8"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("198.18.0.0/15"),
    ipaddress.ip_network("224.0.0.0/4"),
    ipaddress.ip_network("240.0.0.0/4"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("::ffff:127.0.0.0/104"),
    ipaddress.ip_network("::ffff:169.254.0.0/112"),
    ipaddress.ip_network("::ffff:10.0.0.0/104"),
    ipaddress.ip_network("::ffff:172.16.0.0/108"),
    ipaddress.ip_network("::ffff:192.168.0.0/112"),
]

_MAX_REDIRECTS = 5


def _is_private_ip(ip_str: str) -> bool:
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # if we cant parse it, block it
    for net in _BLOCKED_NETS:
        if addr in net:
            return True
    return False


def validate_url(url: str) -> str | None:
    """Validate a URL is safe to fetch. Returns error message or None if OK."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "invalid URL"

    if parsed.scheme not in ("http", "https"):
        return f"blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return "no hostname"

    # Block obvious localhost aliases
    if hostname in ("localhost", "ip6-localhost", "ip6-loopback", "metadata.google.internal"):
        return f"blocked hostname: {hostname}"

    # Resolve DNS and check all IPs
    try:
        results = socket.getaddrinfo(hostname, parsed.port or 443, proto=socket.IPPROTO_TCP)
    except socket.gaierror:
        return f"DNS resolution failed for {hostname}"

    for family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            return f"blocked: {hostname} resolves to private IP {ip}"

    return None
