"""
Portal outbound HTTP wrapper — enforces HTTPS, timeouts, and no-redirect policy.

Portal talks to a single known Platform URL from settings; DNS pinning is not
needed here. For the full SSRF-prevention engine, see Platform's
``apps.common.outbound_http``.
"""

from __future__ import annotations

import logging
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

PORTAL_DEFAULT_TIMEOUT: float = 30.0


class OutboundSecurityError(Exception):
    """Raised when an outbound request violates security policy."""


def portal_request(
    method: str,
    url: str,
    *,
    timeout: float | None = None,
    **kwargs: object,
) -> requests.Response:
    """Enforced-safe request for Portal -> Platform communication.

    Guarantees:
    - HTTPS in production (non-DEBUG)
    - ``allow_redirects=False`` (prevents redirect-based SSRF)
    - Bounded timeout (never ``None``)
    - TLS verification enabled

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        timeout: Override default timeout
        **kwargs: Passed through to ``requests.request``

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

    return requests.request(method=method, url=url, **kwargs)  # noqa: S113  # timeout set via kwargs
