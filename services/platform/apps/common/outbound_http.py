"""
Outbound HTTP Security Helper for PRAHO Platform.

Provides DNS-pinned connections, redirect control, HTTPS-by-default,
bounded timeouts, and audit logging for all outbound HTTP requests.

All production outbound HTTP must use safe_request() or safe_urlopen()
from this module — never raw requests.get/post or urllib.request.urlopen.
"""

from __future__ import annotations

import http.client
import ipaddress
import logging
import socket
import ssl
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

import requests
from requests.adapters import HTTPAdapter

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
DANGEROUS_PORTS: frozenset[int] = frozenset(
    {
        21,  # FTP
        22,  # SSH
        23,  # Telnet
        25,  # SMTP
        53,  # DNS
        135,  # RPC
        139,  # NetBIOS
        445,  # SMB
        993,  # IMAPS
        995,  # POP3S
        1433,  # MSSQL
        1521,  # Oracle
        3306,  # MySQL
        3389,  # RDP
        5432,  # PostgreSQL
        6379,  # Redis
        9200,  # Elasticsearch
        11211,  # Memcached
        27017,  # MongoDB
    }
)

MAX_URL_LENGTH = 2048
MAX_IPV4_VALUE = 0xFFFFFFFF
IPV4_OCTET_COUNT = 4
MAX_OCTET_VALUE = 255
HTTP_STATUS_SEE_OTHER = 303


# ---------------------------------------------------------------------------
# Exception
# ---------------------------------------------------------------------------
class OutboundSecurityError(Exception):
    """Raised when an outbound HTTP request violates security policy.

    Messages are safe to log — they never contain credentials or request bodies.
    """


# ---------------------------------------------------------------------------
# Policy dataclass
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class OutboundPolicy:
    """Frozen security constraints for outbound HTTP requests."""

    name: str
    require_https: bool = True
    allow_redirects: bool = False
    max_redirects: int = 0
    timeout_seconds: float = 30.0
    connect_timeout_seconds: float = 10.0
    allowed_schemes: frozenset[str] = field(default_factory=lambda: frozenset({"https"}))
    allowed_ports: frozenset[int] | None = None  # None = any non-blocked port
    blocked_ports: frozenset[int] = DANGEROUS_PORTS
    allowed_domains: frozenset[str] | None = None  # None = any domain
    verify_tls: bool = True
    max_retries: int = 0
    check_dns: bool = True


# ---------------------------------------------------------------------------
# Pre-built policies
# ---------------------------------------------------------------------------
STRICT_EXTERNAL = OutboundPolicy(name="strict_external")

TRUSTED_PROVIDER = OutboundPolicy(
    name="trusted_provider",
    timeout_seconds=60.0,
    max_retries=3,
)

INTERNAL_SERVICE = OutboundPolicy(
    name="internal_service",
    require_https=False,
    allowed_schemes=frozenset({"http", "https"}),
)


# ---------------------------------------------------------------------------
# Resolved target
# ---------------------------------------------------------------------------
@dataclass(frozen=True)
class ResolvedTarget:
    """Result of validate_and_resolve — holds pinned IPs for DNS-pinned connections."""

    original_url: str
    scheme: str
    hostname: str
    port: int
    pinned_ips: list[str]
    path: str


# ---------------------------------------------------------------------------
# IP validation helpers
# ---------------------------------------------------------------------------
def _is_dangerous_ip(ip_str: str) -> bool:
    """Check if an IP address is private, loopback, link-local, multicast, or reserved."""
    try:
        ip = ipaddress.ip_address(ip_str)
        return bool(ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved)
    except ValueError:
        return False


def _is_valid_domain_suffix(domain: str, allowed_domains: frozenset[str]) -> bool:
    """Check if domain matches or is a subdomain of an allowed domain."""
    domain = domain.lower().strip()
    if ":" in domain:
        domain = domain.split(":")[0]

    for allowed in allowed_domains:
        allowed_lower = allowed.lower()
        if domain == allowed_lower or domain.endswith(f".{allowed_lower}"):
            return True
    return False


def _hostname_is_ip_literal(hostname: str) -> bool:
    """Check if hostname is a direct IP address (v4 or v6)."""
    try:
        ipaddress.ip_address(hostname)
        return True
    except ValueError:
        return False


def _detect_ip_encoding_tricks(hostname: str) -> str | None:
    """Detect decimal, hex, octal IP encodings that bypass naive hostname checks.

    Returns the decoded IP string if a trick is detected, None otherwise.
    """
    # Decimal IP: e.g. 2130706433 = 127.0.0.1
    if hostname.isdigit():
        val = int(hostname)
        if 0 <= val <= MAX_IPV4_VALUE:
            return str(ipaddress.IPv4Address(val))

    # Hex IP: 0x7f000001
    if hostname.lower().startswith("0x"):
        try:
            val = int(hostname, 16)
            if 0 <= val <= MAX_IPV4_VALUE:
                return str(ipaddress.IPv4Address(val))
        except ValueError:
            pass

    # Octal dotted: 0177.0.0.1
    parts = hostname.split(".")
    if len(parts) == IPV4_OCTET_COUNT and any(p.startswith("0") and len(p) > 1 and p.isdigit() for p in parts):
        try:
            octets = [int(p, 8) if (p.startswith("0") and len(p) > 1) else int(p) for p in parts]
            if all(0 <= o <= MAX_OCTET_VALUE for o in octets):
                return f"{octets[0]}.{octets[1]}.{octets[2]}.{octets[3]}"
        except ValueError:
            pass

    return None


# ---------------------------------------------------------------------------
# URL parsing and policy checks (extracted from validate_and_resolve)
# ---------------------------------------------------------------------------
def _parse_and_check_url(url: str, policy: OutboundPolicy) -> tuple[str, str, int | None, str]:
    """Parse URL and validate scheme, credentials, hostname basics.

    Returns (scheme, hostname, port, path).
    """
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception:
        raise OutboundSecurityError("Malformed URL") from None

    scheme = (parsed.scheme or "").lower()
    hostname = (parsed.hostname or "").lower()
    port = parsed.port
    path = parsed.path or "/"

    if not scheme:
        raise OutboundSecurityError("Missing URL scheme")
    if scheme not in policy.allowed_schemes:
        raise OutboundSecurityError(f"Scheme '{scheme}' not allowed by policy '{policy.name}'")
    if parsed.username or parsed.password:
        raise OutboundSecurityError("Embedded credentials in URL not allowed")
    if not hostname:
        raise OutboundSecurityError("Missing hostname")
    if "%" in hostname:
        raise OutboundSecurityError("IPv6 zone IDs not allowed")

    return scheme, hostname, port, path


def _check_port(port: int, policy: OutboundPolicy) -> None:
    """Validate port against policy's allowed/blocked ports."""
    if policy.allowed_ports is not None and port not in policy.allowed_ports:
        raise OutboundSecurityError(f"Port {port} not in allowed ports for policy '{policy.name}'")
    if port in policy.blocked_ports:
        raise OutboundSecurityError(f"Port {port} is blocked")


def _resolve_dns(hostname: str, port: int) -> list[str]:
    """DNS-resolve hostname and validate all returned IPs are public.

    Returns deduplicated list of validated IP strings.
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, port, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, TimeoutError, OSError) as exc:
        raise OutboundSecurityError(f"DNS resolution failed for '{hostname}'") from exc

    pinned_ips: list[str] = []
    for info in addr_infos:
        ip_str = info[4][0]
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError:
            continue
        if _is_dangerous_ip(str(ip_obj)):
            raise OutboundSecurityError("URL target resolves to blocked IP range")
        pinned_ips.append(str(ip_obj))

    if not pinned_ips:
        raise OutboundSecurityError(f"No valid IP addresses resolved for '{hostname}'")

    # Deduplicate preserving order
    seen: set[str] = set()
    unique: list[str] = []
    for ip in pinned_ips:
        if ip not in seen:
            seen.add(ip)
            unique.append(ip)
    return unique


# ---------------------------------------------------------------------------
# Core validation
# ---------------------------------------------------------------------------
def validate_and_resolve(url: str, policy: OutboundPolicy = STRICT_EXTERNAL) -> ResolvedTarget:
    """Parse, validate, and DNS-resolve an outbound URL.

    Returns a ResolvedTarget with pinned IPs that must be used for the actual connection
    to prevent DNS rebinding (TOCTOU) attacks.

    Raises OutboundSecurityError on any violation.
    """
    if not url or not isinstance(url, str):
        raise OutboundSecurityError("Invalid URL")
    if len(url) > MAX_URL_LENGTH:
        raise OutboundSecurityError("URL too long")

    scheme, hostname, raw_port, path = _parse_and_check_url(url, policy)

    # Detect IP encoding tricks
    decoded_ip = _detect_ip_encoding_tricks(hostname)
    if decoded_ip is not None and _is_dangerous_ip(decoded_ip):
        raise OutboundSecurityError("URL target resolves to blocked IP range")
    hostname_for_resolve = decoded_ip if decoded_ip is not None else hostname

    # Default port
    port = raw_port if raw_port is not None else (443 if scheme == "https" else 80)

    _check_port(port, policy)

    # Domain allowlist
    if policy.allowed_domains is not None and not _is_valid_domain_suffix(hostname, policy.allowed_domains):
        raise OutboundSecurityError(f"Domain '{hostname}' not allowed by policy '{policy.name}'")

    # IP literal — validate directly
    if _hostname_is_ip_literal(hostname_for_resolve):
        if _is_dangerous_ip(hostname_for_resolve):
            raise OutboundSecurityError("URL target resolves to blocked IP range")
        return ResolvedTarget(
            original_url=url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            pinned_ips=[str(ipaddress.ip_address(hostname_for_resolve))],
            path=path,
        )

    # Skip DNS if policy says so
    if not policy.check_dns:
        return ResolvedTarget(
            original_url=url,
            scheme=scheme,
            hostname=hostname,
            port=port,
            pinned_ips=[],
            path=path,
        )

    # DNS resolution with IP validation
    pinned_ips = _resolve_dns(hostname_for_resolve, port)
    return ResolvedTarget(
        original_url=url,
        scheme=scheme,
        hostname=hostname,
        port=port,
        pinned_ips=pinned_ips,
        path=path,
    )


# ---------------------------------------------------------------------------
# PinnedIPAdapter — forces connections to pre-validated IP addresses
# ---------------------------------------------------------------------------
class PinnedIPAdapter(HTTPAdapter):
    """Custom HTTPAdapter that connects to a pinned IP while preserving TLS SNI."""

    _pinned_ip: str
    _hostname: str

    def __init__(self, pinned_ip: str, hostname: str) -> None:
        self._pinned_ip = pinned_ip
        self._hostname = hostname
        super().__init__()

    def init_poolmanager(self, *args: object, **kwargs: object) -> None:
        kwargs["server_hostname"] = self._hostname
        super().init_poolmanager(*args, **kwargs)

    def send(
        self,
        request: requests.PreparedRequest,
        **kwargs: object,
    ) -> requests.Response:
        """Rewrite URL to pinned IP, preserve Host header for routing."""
        if request.url:
            parsed = urllib.parse.urlparse(request.url)
            port = parsed.port or (443 if parsed.scheme == "https" else 80)
            ip_part = f"[{self._pinned_ip}]" if ":" in self._pinned_ip else self._pinned_ip
            request.url = parsed._replace(netloc=f"{ip_part}:{port}").geturl()
        if request.headers is not None:
            request.headers.setdefault("Host", self._hostname)
        return super().send(request, **kwargs)


# ---------------------------------------------------------------------------
# Redirect-following with per-hop re-validation
# ---------------------------------------------------------------------------
_REDIRECT_STATUSES: frozenset[int] = frozenset({301, 302, 303, 307, 308})


def _follow_redirects(
    session: requests.Session,
    response: requests.Response,
    policy: OutboundPolicy,
    remaining: int,
    method: str,
) -> requests.Response:
    """Manually follow redirects, re-validating each hop."""
    while response.status_code in _REDIRECT_STATUSES and remaining > 0:
        location = response.headers.get("Location")
        if not location:
            break

        location = urllib.parse.urljoin(response.url or "", location)
        target = validate_and_resolve(location, policy)

        pinned_ip = target.pinned_ips[0] if target.pinned_ips else target.hostname
        prefix = f"{target.scheme}://{target.hostname}"
        session.mount(prefix, PinnedIPAdapter(pinned_ip=pinned_ip, hostname=target.hostname))

        if response.status_code == HTTP_STATUS_SEE_OTHER:
            method = "GET"

        prepared = session.prepare_request(requests.Request(method=method, url=location))
        response = session.send(
            prepared,
            allow_redirects=False,
            verify=policy.verify_tls,
            timeout=(policy.connect_timeout_seconds, policy.timeout_seconds),
        )
        remaining -= 1

    return response


# ---------------------------------------------------------------------------
# safe_request — main entry point
# ---------------------------------------------------------------------------
def safe_request(
    method: str,
    url: str,
    *,
    policy: OutboundPolicy = STRICT_EXTERNAL,
    **kwargs: object,
) -> requests.Response:
    """Make an outbound HTTP request with DNS pinning and security policy enforcement.

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        policy: Security policy to enforce (default: STRICT_EXTERNAL)
        **kwargs: Additional arguments passed to requests.Request constructor

    Returns:
        requests.Response

    Raises:
        OutboundSecurityError: If the URL violates the security policy
        requests.RequestException: For transport errors
    """
    try:
        target = validate_and_resolve(url, policy)
    except OutboundSecurityError:
        logger.warning("⚠️ [OutboundHTTP] Blocked: policy=%s url=%s", policy.name, _redact_url(url))
        raise

    session = requests.Session()
    try:
        return _execute_pinned_request(session, target, method, url, policy, **kwargs)
    finally:
        session.close()


def _execute_pinned_request(
    session: requests.Session,
    target: ResolvedTarget,
    method: str,
    url: str,
    policy: OutboundPolicy,
    **kwargs: object,
) -> requests.Response:
    """Mount pinned adapter, send request, handle redirects."""
    if target.pinned_ips:
        prefix = f"{target.scheme}://"
        session.mount(prefix, PinnedIPAdapter(pinned_ip=target.pinned_ips[0], hostname=target.hostname))

    # Strip transport kwargs from Request constructor kwargs
    req = requests.Request(method=method.upper(), url=url, **kwargs)
    prepared = session.prepare_request(req)
    response = session.send(
        prepared,
        verify=policy.verify_tls,
        timeout=(policy.connect_timeout_seconds, policy.timeout_seconds),
        allow_redirects=False,
    )

    if policy.allow_redirects and policy.max_redirects > 0:
        response = _follow_redirects(session, response, policy, policy.max_redirects, method.upper())

    logger.info(
        "✅ [OutboundHTTP] Allow: policy=%s url=%s ip=%s status=%s",
        policy.name,
        _redact_url(url),
        target.pinned_ips[0] if target.pinned_ips else "unpinned",
        response.status_code,
    )
    return response


# ---------------------------------------------------------------------------
# safe_urlopen — urllib wrapper for validation_service.py
# ---------------------------------------------------------------------------
def safe_urlopen(
    url: str,
    *,
    policy: OutboundPolicy = STRICT_EXTERNAL,
    method: str = "GET",
    timeout: float | None = None,
    ssl_context: ssl.SSLContext | None = None,
) -> http.client.HTTPResponse:
    """Validate and open a URL using urllib — for callsites that need urllib's HTTPResponse.

    Args:
        url: Target URL
        policy: Security policy (default: STRICT_EXTERNAL)
        method: HTTP method
        timeout: Override policy timeout
        ssl_context: Custom SSL context (policy's verify_tls is enforced)

    Returns:
        http.client.HTTPResponse
    """
    target = validate_and_resolve(url, policy)
    effective_timeout = timeout if timeout is not None else policy.timeout_seconds

    # Build URL pointing to pinned IP
    if target.pinned_ips:
        pinned_ip = target.pinned_ips[0]
        ip_part = f"[{pinned_ip}]" if ":" in pinned_ip else pinned_ip
        pinned_url = f"{target.scheme}://{ip_part}:{target.port}{target.path}"
    else:
        pinned_url = url

    req = urllib.request.Request(pinned_url, method=method)  # noqa: S310
    req.add_header("Host", target.hostname)

    # SSL context
    ctx = _build_ssl_context(target, policy, ssl_context)
    result: http.client.HTTPResponse = urllib.request.urlopen(  # noqa: S310
        req,
        timeout=effective_timeout,
        context=ctx,
    )
    return result


def _build_ssl_context(
    target: ResolvedTarget,
    policy: OutboundPolicy,
    ssl_context: ssl.SSLContext | None,
) -> ssl.SSLContext | None:
    """Build SSL context for urlopen, enforcing policy's TLS settings."""
    if target.scheme != "https":
        return None

    if ssl_context is None:
        ssl_context = ssl.create_default_context()
    if not policy.verify_tls:
        ssl_context.check_hostname = False
        ssl_context.verify_mode = ssl.CERT_NONE
    else:
        ssl_context.check_hostname = True
        ssl_context.verify_mode = ssl.CERT_REQUIRED
    return ssl_context


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _redact_url(url: str) -> str:
    """Remove credentials and query params from URL for safe logging."""
    try:
        parsed = urllib.parse.urlparse(url)
        redacted = parsed._replace(query="", fragment="")
        if parsed.username:
            netloc = parsed.hostname or ""
            if parsed.port:
                netloc = f"{netloc}:{parsed.port}"
            redacted = redacted._replace(netloc=netloc)
        return urllib.parse.urlunparse(redacted)
    except Exception:
        return "<malformed-url>"
