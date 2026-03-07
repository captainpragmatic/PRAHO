"""Custom rate limiting decorator replacing django-ratelimit.

Drop-in replacement for ``django_ratelimit.decorators.ratelimit`` that uses
Django's cache framework directly instead of pulling in the django-ratelimit
library.  With ``block=False`` (default), it sets ``request.limited = True``
when the rate is exceeded but still calls the wrapped view.  With
``block=True``, it short-circuits and returns an HTTP 429 response.

Supported *key* types (matching django-ratelimit interface):
  - ``"ip"``           — client IP via ``get_safe_client_ip``
  - ``"user"``         — authenticated user PK, falls back to IP
  - ``"post:<field>"`` — value of a POST field
  - ``"header:<name>"`` — value of an HTTP header (e.g. ``"header:user-agent"``)
  - dotted path string — imported and called as ``fn(group, request)``
  - callable           — called as ``fn(group, request)``

Supported *rate* format: ``"<count>/<period>"`` where period is one of
``s`` (second), ``m`` (minute), ``h`` (hour), ``d`` (day).

Supported *method* values: ``"GET"``, ``"POST"``, ``"PUT"``, etc., or
``ratelimit.ALL`` (sentinel).  When set, only matching HTTP methods are
rate-limited.
"""

from __future__ import annotations

import functools
import hashlib
import importlib
import logging
import re
from typing import TYPE_CHECKING, Any, cast

from django.conf import settings
from django.core.cache import caches
from django.http import HttpRequest, HttpResponse

from apps.common.request_ip import get_safe_client_ip

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)

# Sentinel for "all HTTP methods"
ALL = "__all__"

# Rate string regex: "<count>/<period_char>"
_RATE_RE = re.compile(r"^(\d+)/([smhd])$")

# Max cache key length (memcached limit is 250; leave headroom)
_MAX_CACHE_KEY_LENGTH = 200

_PERIOD_SECONDS: dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}


def _parse_rate(rate_str: str) -> tuple[int, int]:
    """Parse a rate string like ``'5/m'`` into ``(count, window_seconds)``."""
    match = _RATE_RE.match(rate_str)
    if not match:
        msg = f"Invalid rate format: {rate_str!r} (expected '<count>/<s|m|h|d>')"
        raise ValueError(msg)
    count = int(match.group(1))
    period_char = match.group(2)
    return count, _PERIOD_SECONDS[period_char]


def _hash_value(value: str) -> str:
    """MD5-hash a value for use in cache keys (not cryptographic)."""
    return hashlib.md5(str(value).encode()).hexdigest()[:12]  # noqa: S324


def _resolve_key(key: str | Callable[..., str], group: str, request: HttpRequest) -> str:
    """Resolve a rate limit key to a string identifier."""
    if callable(key):
        return key(group, request)

    if key == "ip":
        return f"ip:{get_safe_client_ip(request)}"

    if key == "user":
        is_authed = hasattr(request, "user") and getattr(request.user, "is_authenticated", False)
        return f"user:{request.user.pk}" if is_authed else f"ip:{get_safe_client_ip(request)}"

    if key.startswith("post:"):
        field = key[5:]
        return f"post:{field}:{_hash_value(request.POST.get(field, ''))}"

    if key.startswith("header:"):
        header_name = key[7:]
        meta_key = f"HTTP_{header_name.upper().replace('-', '_')}"
        return f"header:{header_name}:{_hash_value(request.META.get(meta_key, ''))}"

    # Dotted path — import and call as fn(group, request)
    if "." in key:
        module_path, func_name = key.rsplit(".", 1)
        mod = importlib.import_module(module_path)
        return cast(str, getattr(mod, func_name)(group, request))

    msg = f"Unsupported rate limit key: {key!r}"
    raise ValueError(msg)


def _get_cache_name() -> str:
    """Return the cache alias to use for rate limiting."""
    return getattr(settings, "RATE_LIMIT_CACHE", "default")


def _log_rate_limit_audit(request: HttpRequest, endpoint: str, key_label: str, rate_str: str) -> None:
    """Log a rate-limit violation to the security audit trail."""
    try:
        from apps.audit.services import (  # noqa: PLC0415  # Deferred: avoids circular import at module level
            RateLimitEventData,
            SecurityAuditService,
        )

        user = getattr(request, "user", None)
        authed_user = user if getattr(user, "is_authenticated", False) else None
        event_data = RateLimitEventData(
            endpoint=endpoint,
            ip_address=get_safe_client_ip(request),
            user_agent=request.META.get("HTTP_USER_AGENT", ""),
            rate_limit_key=key_label,
            rate_limit_rate=rate_str,
        )
        SecurityAuditService.log_rate_limit_event(event_data=event_data, user=authed_user)
    except Exception:
        logger.exception("Failed to log rate limit audit event")


def rate_limit(
    key: str | Callable[..., str] = "ip",
    rate: str = "100/m",
    method: str = ALL,
    block: bool = False,
    group: str = "",
) -> Callable[..., Any]:
    """Decorator that rate-limits a view function.

    When the rate is exceeded, sets ``request.limited = True`` and logs the
    event to the security audit trail via ``SecurityAuditService``.  With
    ``block=True``, also short-circuits and returns HTTP 429.

    Args:
        key: How to identify the client (see module docstring).
        rate: Request limit in ``"<count>/<period>"`` format.
        method: HTTP method to limit, or ``ALL`` for all methods.
        block: If ``True``, return 429 when limited. Default ``False``.
        group: Optional group name for cache key namespacing.
    """
    max_requests, window_seconds = _parse_rate(rate)

    def decorator(fn: Callable[..., Any]) -> Callable[..., Any]:
        @functools.wraps(fn)
        def wrapper(request: HttpRequest, *args: Any, **kwargs: Any) -> HttpResponse:
            # Skip if rate limiting is disabled
            if not getattr(settings, "RATE_LIMITING_ENABLED", True):
                return cast(HttpResponse, fn(request, *args, **kwargs))

            # Skip if method doesn't match
            if method not in (ALL, request.method):
                return cast(HttpResponse, fn(request, *args, **kwargs))

            # Resolve the group name (default: module.function)
            resolved_group = group or f"{fn.__module__}.{fn.__qualname__}"

            key_label = key if isinstance(key, str) else getattr(key, "__name__", "callable")

            try:
                cache_key_id = _resolve_key(key, resolved_group, request)
                cache_key = f"rl:{resolved_group}:{cache_key_id}"
                # Truncate to avoid memcached 250-char key limit
                if len(cache_key) > _MAX_CACHE_KEY_LENGTH:
                    cache_key = f"rl:{hashlib.md5(cache_key.encode()).hexdigest()}"  # noqa: S324

                cache = caches[_get_cache_name()]

                # Atomic increment-first to avoid get/incr race under concurrency
                try:
                    new_count: int = cache.incr(cache_key)
                except ValueError:
                    # Key doesn't exist yet — atomically create it (or incr if another process won the race)
                    new_count = 1 if cache.add(cache_key, 1, window_seconds) else cache.incr(cache_key)

                if new_count > max_requests:
                    request.limited = True  # type: ignore[attr-defined]  # django-ratelimit compat
                    logger.debug(
                        "Rate limit exceeded: %s (%d/%d in %ds)",
                        cache_key,
                        new_count,
                        max_requests,
                        window_seconds,
                    )
                    _log_rate_limit_audit(request, resolved_group, key_label, rate)
                    if block:
                        return HttpResponse("Rate limit exceeded", status=429)

            except Exception:
                # Rate limiting should never break the view
                logger.exception("Rate limiting error for %s", fn.__qualname__)

            return cast(HttpResponse, fn(request, *args, **kwargs))

        return wrapper

    return decorator
