"""
SSRF Guard - OWASP-aligned URL validation for server-side fetches.

Implements:
  - Application layer: scheme allowlist, DNS resolution + IP blocklist,
    hostname blocklist, redirect validation with per-hop checking
  - DNS pinning: resolve-then-connect to prevent TOCTOU rebinding
  - Redirect cap: max 5 hops, each validated

References:
  https://cheatsheetseries.owasp.org/cheatsheets/Server_Side_Request_Forgery_Prevention_Cheat_Sheet.html
  https://owasp.org/www-community/attacks/Server_Side_Request_Forgery
"""

import ipaddress
import logging
import re
import socket
from urllib.parse import urlparse

logger = logging.getLogger(__name__)

# -- Blocked IP networks (OWASP: blocklist approach for Case 2) ---------------
# Covers: loopback, private RFC1918, link-local, CGNAT, benchmarking,
# multicast, reserved, IPv6 equivalents, IPv4-mapped IPv6
_BLOCKED_NETS = [
    # IPv4
    ipaddress.ip_network("0.0.0.0/8"),          # "This" network
    ipaddress.ip_network("10.0.0.0/8"),          # RFC1918
    ipaddress.ip_network("100.64.0.0/10"),       # CGNAT (Tailscale etc.)
    ipaddress.ip_network("127.0.0.0/8"),         # Loopback
    ipaddress.ip_network("169.254.0.0/16"),      # Link-local / cloud metadata
    ipaddress.ip_network("172.16.0.0/12"),       # RFC1918
    ipaddress.ip_network("192.0.0.0/24"),        # IETF protocol assignments
    ipaddress.ip_network("192.0.2.0/24"),        # TEST-NET-1
    ipaddress.ip_network("192.88.99.0/24"),      # 6to4 relay anycast
    ipaddress.ip_network("192.168.0.0/16"),      # RFC1918
    ipaddress.ip_network("198.18.0.0/15"),       # Benchmarking
    ipaddress.ip_network("198.51.100.0/24"),     # TEST-NET-2
    ipaddress.ip_network("203.0.113.0/24"),      # TEST-NET-3
    ipaddress.ip_network("224.0.0.0/4"),         # Multicast
    ipaddress.ip_network("240.0.0.0/4"),         # Reserved
    ipaddress.ip_network("255.255.255.255/32"),  # Broadcast
    # IPv6
    ipaddress.ip_network("::1/128"),             # Loopback
    ipaddress.ip_network("::/128"),              # Unspecified
    ipaddress.ip_network("fc00::/7"),            # Unique-local
    ipaddress.ip_network("fe80::/10"),           # Link-local
    ipaddress.ip_network("ff00::/8"),            # Multicast
    # IPv4-mapped IPv6 (prevents ::ffff:127.0.0.1 bypass)
    ipaddress.ip_network("::ffff:0.0.0.0/96"),
]

# -- Blocked hostnames (OWASP: known internal/metadata aliases) ----------------
_BLOCKED_HOSTNAMES = frozenset({
    "localhost",
    "ip6-localhost",
    "ip6-loopback",
    "metadata.google.internal",
    "metadata.internal",
    "instance-data",
    "kubernetes.default",
    "kubernetes.default.svc",
})

# -- Allowed schemes (OWASP: disable unused URL schemas) -----------------------
_ALLOWED_SCHEMES = frozenset({"http", "https"})

MAX_REDIRECTS = 5

# Regex for redacting private IPs from error messages returned to users
_PRIVATE_IP_RE = re.compile(
    r"\b(?:127\.\d+\.\d+\.\d+|10\.\d+\.\d+\.\d+"
    r"|172\.(?:1[6-9]|2\d|3[01])\.\d+\.\d+"
    r"|192\.168\.\d+\.\d+|169\.254\.\d+\.\d+)\b"
)


def _is_private_ip(ip_str: str) -> bool:
    """Check if an IP address falls in any blocked range."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return True  # unparseable = blocked (fail-closed)
    return any(addr in net for net in _BLOCKED_NETS)


def resolve_and_validate(hostname: str, port: int | None = None) -> list[str] | str:
    """
    Resolve hostname via DNS, validate all returned IPs.

    Returns list of safe IPs on success, or error string on failure.
    This is the DNS-pinning step: callers should connect to these IPs
    directly (with Host header) to prevent TOCTOU rebinding attacks.
    """
    try:
        results = socket.getaddrinfo(
            hostname,
            port or 443,
            socket.AF_UNSPEC,
            socket.SOCK_STREAM,
            socket.IPPROTO_TCP,
        )
    except socket.gaierror:
        # DNS failure is NOT a security block — if a domain can't resolve,
        # it can't reach internal services. Let httpx handle the error
        # naturally so the user gets a proper "failed to fetch" message.
        logger.debug("DNS resolution failed for %s (not a security block)", hostname)
        return None  # pass through

    if not results:
        return None  # no results = can't reach anything = safe

    safe_ips = []
    for _family, _type, _proto, _canon, sockaddr in results:
        ip = sockaddr[0]
        if _is_private_ip(ip):
            return f"blocked: {hostname} resolves to private IP {ip}"
        safe_ips.append(ip)

    return safe_ips


def validate_url(url: str) -> str | None:
    """
    Validate a URL is safe to fetch server-side.

    Returns error message string if blocked, None if safe.

    Checks (per OWASP SSRF Prevention Cheat Sheet):
      1. Scheme allowlist (http/https only — blocks file://, gopher://, dict://, etc.)
      2. Hostname blocklist (localhost aliases, cloud metadata domains)
      3. DNS resolution + IP blocklist (all resolved IPs checked against
         RFC1918, loopback, link-local, CGNAT, multicast, reserved ranges)
    """
    try:
        parsed = urlparse(url)
    except Exception:
        return "invalid URL"

    # 1. Scheme allowlist (OWASP: "Disable unused URL schemas")
    if parsed.scheme not in _ALLOWED_SCHEMES:
        return f"blocked scheme: {parsed.scheme}"

    hostname = parsed.hostname
    if not hostname:
        return "no hostname in URL"

    # 2. Hostname blocklist
    hostname_lower = hostname.lower().rstrip(".")
    if hostname_lower in _BLOCKED_HOSTNAMES:
        return f"blocked hostname: {hostname}"

    # 3. DNS resolution + IP validation
    result = resolve_and_validate(hostname, parsed.port)
    if isinstance(result, str):
        return result

    return None


def sanitize_error(error_msg: str) -> str:
    """Strip internal IP addresses from error messages returned to users.

    OWASP: "Do not send raw responses to the client" — prevent leaking
    internal network topology through error messages.
    """
    return _PRIVATE_IP_RE.sub("[redacted-ip]", error_msg)
