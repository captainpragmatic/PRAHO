"""
Portal outbound HTTP wrapper — enforces HTTPS, timeouts, and no-redirect policy.

Portal talks to a single known Platform URL from settings; DNS pinning is not
needed here. For the full SSRF-prevention engine, see Platform's
``apps.common.outbound_http``.

Per-request isolation contract
------------------------------
- ``_session.headers`` MUST NOT be mutated for per-request headers — pass
  ``headers=`` to :func:`portal_request`. The module-level Session is shared
  across all callers; mutating headers there leaks state between unrelated calls
  and would cause HMAC signatures to ride on the wrong request.
- ``_session.cookies`` is cleared after every call so a ``Set-Cookie`` from one
  Platform response cannot ride on the next :func:`portal_request` invocation.
  This prevents cross-tenant cookie leakage on the shared session.

Deployment assumption
---------------------
This module assumes single-threaded WSGI workers (``gunicorn --workers N``
without ``--worker-class gthread``). ``requests.Session`` is documented as
thread-safe for sending requests, but its mutable state (cookies, headers,
adapters) is shared. Switching the portal to a threaded worker model requires
either a ``threading.Lock`` around :func:`portal_request` or a thread-local
session strategy.

Per-worker session reset is configured via ``services/portal/gunicorn.conf.py``
(auto-loaded by gunicorn from the working directory). The ``post_fork`` hook
clears cookies and re-mounts adapters in each worker so a Session created in
the parent process cannot leak file descriptors across forks.
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
# See module docstring for the per-request isolation contract.
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
    - Per-call cookie isolation: ``cookies={}`` is passed and ``_session.cookies``
      is cleared after the call to prevent cross-tenant leakage on the shared
      Session.

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
    # Per-call cookie isolation. ``requests`` merges per-request cookies with
    # ``session.cookies``; passing an empty jar suppresses any session-level
    # leakage for this specific request. We additionally clear the session jar
    # in the finally block below so a ``Set-Cookie`` from this response also
    # cannot ride on the next call.
    kwargs["cookies"] = {}

    headers = dict(kwargs.pop("headers", None) or {})
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)
    kwargs["headers"] = headers

    try:
        return _session.request(method=method, url=url, **kwargs)
    finally:
        _session.cookies.clear()
