"""
Safe client IP extraction for the portal service.

Cloudflare-aware: only trusts CF-Connecting-IP when CF-Ray header is present
(CF-Ray is the Cloudflare request ID, always present on CF-proxied requests).

When IPWARE_TRUSTED_PROXY_LIST is non-empty, only forwards headers from IPs that fall
within a configured CIDR range are trusted. Uses our own CIDR validation so that
proxy trust is network-scoped rather than IP-prefix-matched.

Configuration (in Django settings):
    IPWARE_TRUSTED_PROXY_LIST: list[str] = []  # CIDR strings, e.g. ["10.0.0.0/8"]
"""

from __future__ import annotations

import ipaddress

from django.conf import settings
from django.http import HttpRequest

# Header precedence order for XFF-style proxy headers (most specific first)
_PROXY_HEADERS: list[str] = [
    "HTTP_X_FORWARDED_FOR",
    "HTTP_X_REAL_IP",
    "HTTP_X_CLUSTER_CLIENT_IP",
]


def get_safe_client_ip(request: HttpRequest) -> str:
    """
    Return the real client IP, only trusting forwarded headers from configured proxies.

    Falls back to REMOTE_ADDR if IPWARE_TRUSTED_PROXY_LIST is empty.
    """
    remote_addr: str = request.META.get("REMOTE_ADDR", "0.0.0.0")
    trusted_proxies: list[str] = getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", [])

    # Cloudflare: only trust CF-Connecting-IP when CF-Ray header is also present.
    # CF-Ray is always set by Cloudflare — its absence means the request is not CF-proxied.
    if request.META.get("HTTP_CF_RAY") and trusted_proxies and _is_trusted_proxy(remote_addr, trusted_proxies):
        cf_ip = str(request.META.get("HTTP_CF_CONNECTING_IP", "")).strip()
        if cf_ip and _is_valid_ip(cf_ip):
            return cf_ip

    if not trusted_proxies:
        # No proxy trust configured — use direct connection IP only.
        return remote_addr

    # If the direct connection is from a trusted proxy, extract the client IP
    # from the rightmost non-trusted XFF entry (prevents attacker-injected leftmost).
    if _is_trusted_proxy(remote_addr, trusted_proxies):
        for header in _PROXY_HEADERS:
            raw = request.META.get(header, "").strip()
            if raw:
                # Walk right-to-left: skip trusted proxies, return first untrusted IP.
                # Proxies *append* to XFF, so rightmost entries are most trustworthy.
                candidates = [ip.strip() for ip in raw.split(",")]
                for candidate in reversed(candidates):
                    if candidate and _is_valid_ip(candidate) and not _is_trusted_proxy(candidate, trusted_proxies):
                        return str(candidate)

    # No matching proxy header found, or proxy not trusted — fall back to direct IP.
    return remote_addr


def _is_trusted_proxy(addr: str, trusted: list[str]) -> bool:
    try:
        ip = ipaddress.ip_address(addr)
        return any(ip in ipaddress.ip_network(cidr, strict=False) for cidr in trusted)
    except ValueError:
        return False


def _is_valid_ip(addr: str) -> bool:
    try:
        ipaddress.ip_address(addr)
        return True
    except ValueError:
        return False
