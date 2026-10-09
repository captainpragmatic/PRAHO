"""
Portal outbound HTTP wrapper — enforces HTTPS, timeouts, and no-redirect policy.

Portal talks to a single known Platform URL from settings; DNS pinning is not
needed here. For the full SSRF-prevention engine, see Platform's
``apps.common.outbound_http``.

Isolation contract
------------------
Several customers' requests can be served at once, on threads of one process. Nothing one
call sends or receives may reach another call:

- Each thread has its own ``requests.Session`` (:func:`_get_session`), so no mutable
  transport state is shared between concurrent calls. ``requests`` does not document
  ``Session`` as safe to share between threads.
- A Session's cookie jar refuses every cookie. ``requests`` merges the Session jar into
  every outbound request, and a per-call ``cookies={}`` does not prevent that, so a
  ``Set-Cookie`` from one Platform response would otherwise ride on the next call made on
  that thread, which may be serving a different customer.
- A caller cannot send a ``Cookie`` header; Portal -> Platform calls authenticate with HMAC
  headers built per call, never with cookies.
- Per-call headers are passed with ``headers=``; a Session's headers are only its fixed
  User-Agent and are never changed per call.

Tests fake Platform by patching :func:`_send`, the one place a call leaves the portal.

``services/portal/gunicorn.conf.py``'s ``post_fork`` hook calls :func:`reset_after_fork`,
so a worker never reuses a Session (or its pooled sockets) created before the fork.
"""

from __future__ import annotations

import http.cookiejar
import logging
import threading
from typing import Any
from urllib.parse import urlparse

import requests
from django.conf import settings

logger = logging.getLogger(__name__)

PORTAL_DEFAULT_TIMEOUT: float = 30.0
DEFAULT_USER_AGENT = "PRAHO-Portal/1.0 (+https://pragmatichost.com)"

# One Session per thread, created on first use; see the module docstring.
_sessions = threading.local()


def _new_session() -> requests.Session:
    session = requests.Session()
    session.headers["User-Agent"] = DEFAULT_USER_AGENT
    # allowed_domains=[] makes the policy refuse to store, or return, any cookie at all.
    session.cookies.set_policy(http.cookiejar.DefaultCookiePolicy(allowed_domains=[]))
    return session


def _get_session() -> requests.Session:
    """Return this thread's Session, which keeps its pooled connections between calls."""
    session: requests.Session | None = getattr(_sessions, "session", None)
    if session is None:
        session = _sessions.session = _new_session()
    return session


def reset_after_fork() -> None:
    """Forget every Session, so a forked worker never reuses one (or its sockets) from its parent."""
    global _sessions  # noqa: PLW0603  # Replacing the thread-local is the reset
    _sessions = threading.local()


def _send(method: str, url: str, **kwargs: Any) -> requests.Response:
    """Send one prepared Platform call. The single seam tests patch to fake Platform.

    Patching this module attribute reaches every thread, so tests never need to know
    which Session object carries a call.
    """
    return _get_session().request(method=method, url=url, **kwargs)


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
    - No cookies: the thread's Session refuses to store any, a caller-supplied
      ``Cookie`` header is refused, and the jar is cleared after every call

    Args:
        method: HTTP method (GET, POST, etc.)
        url: Target URL
        timeout: Override the default timeout; must be positive
        **kwargs: Passed through to ``requests.Session.request``

    Returns:
        requests.Response

    Raises:
        OutboundSecurityError: If the URL violates portal security policy, or a
            caller supplies a ``Cookie`` header
        ValueError: If ``timeout`` is not positive (a computed 0 must not become the default)
    """
    parsed = urlparse(url)
    allow_insecure = bool(getattr(settings, "PLATFORM_API_ALLOW_INSECURE_HTTP", False))
    if parsed.scheme != "https" and not settings.DEBUG and not allow_insecure:
        raise OutboundSecurityError(f"Portal requires HTTPS in production, got {parsed.scheme}")

    if timeout is None:
        timeout = getattr(settings, "PLATFORM_API_TIMEOUT", PORTAL_DEFAULT_TIMEOUT)
    if not timeout > 0:
        raise ValueError(f"Platform call timeout must be positive, got {timeout!r}")

    headers = dict(kwargs.pop("headers", None) or {})
    if any(name.lower() == "cookie" for name in headers):
        raise OutboundSecurityError("Portal -> Platform calls never carry a Cookie header")
    headers.setdefault("User-Agent", DEFAULT_USER_AGENT)

    kwargs["allow_redirects"] = False
    kwargs["timeout"] = timeout
    kwargs["verify"] = True
    kwargs["cookies"] = {}
    kwargs["headers"] = headers

    try:
        return _send(method=method, url=url, **kwargs)
    finally:
        _get_session().cookies.clear()  # Defence in depth: the policy already refuses every cookie
