"""
Portal outbound HTTP wrapper — enforces HTTPS, timeouts, and no-redirect policy.

Portal talks to a single known Platform URL from settings; DNS pinning is not
needed here. For the full SSRF-prevention engine, see Platform's
``apps.common.outbound_http``.
"""

from __future__ import annotations

import logging
from typing import Any
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

PORTAL_DEFAULT_TIMEOUT: float = 30.0
DEFAULT_USER_AGENT = "PRAHO-Portal/1.0 (+https://pragmatichost.com)"

# Module-level session for HTTP keep-alive connection reuse.
# requests.Session is thread-safe for concurrent reads; each request
# gets its own prepared-request/response cycle. The underlying urllib3
# connection pool handles per-host connection reuse automatically.
_session = requests.Session()
_session.headers["User-Agent"] = DEFAULT_USER_AGENT


class OutboundSecurityError(Exception):
    """Raised when an outbound request violates security policy."""


def portal_request(
    method: str,
    url: str,
    *,
    timeout: float | None = None,
    **kwargs: Any,
) -> requests.Response:
    """Enforced-safe request for Portal -> Platform communication.

    Guarantees:
    - HTTPS in production (non-DEBUG)
    - ``allow_redirects=False`` (prevents redirect-based SSRF)
    - Bounded timeout (never ``None``)
    - TLS verification enabled
    - HTTP keep-alive via connection pooling (reuses TCP connections)

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        timeout: Override default timeout
        **kwargs: Passed through to ``requests.Session.request``

    Returns:
        requests.Response

    Raises:
        OutboundSecurityError: If the URL violates portal security policy
    """
    parsed = urlparse(url)
    allow_insecure = bool(getattr(settings, "PLATFORM_API_ALLOW_INSECURE_HTTP", False))
    if parsed.scheme != "https" and not settings.DEBUG and not allow_insecure:
        raise OutboundSecurityError(f"Portal requires HTTPS in production, got {parsed.scheme}")

    kwargs["allow_redirects"] = False
    kwargs["timeout"] = timeout or getattr(settings, "PLATFORM_API_TIMEOUT", PORTAL_DEFAULT_TIMEOUT)
    kwargs["verify"] = True

    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    kwargs["headers"] = headers

    return _session.request(method=method, url=url, **kwargs)
