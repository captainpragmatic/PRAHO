"""
API Rate Limiting and Throttling for PRAHO Platform

THROTTLE ARCHITECTURE
─────────────────────
Layer 1 (global defaults; this module):
- Portal HMAC traffic: PortalHMACRateThrottle + PortalHMACBurstThrottle
- Direct traffic: CustomerRateThrottle + BurstRateThrottle

Layer 2 (per-viewset API throttles; this module, re-exported by apps.api.core.throttling):
- StandardAPIThrottle (sustained)
- BurstAPIThrottle (read-heavy)
- AuthThrottle (anonymous auth endpoints)

Layer 3 (portal middleware):
- Portal-side middleware limits requests before DRF is reached.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Sequence
from typing import Any, cast

from django.core.exceptions import ImproperlyConfigured
from django.utils.module_loading import import_string
from rest_framework.request import Request
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle, UserRateThrottle

logger = logging.getLogger(__name__)

_RATE_PATTERN = re.compile(r"^\s*(?P<num>\d+)\s*/\s*(?P<period>[A-Za-z0-9]+)\s*$")
_RATE_WORD_SECONDS: dict[str, int] = {
    "sec": 1,
    "second": 1,
    "seconds": 1,
    "min": 60,
    "minute": 60,
    "minutes": 60,
    "hour": 3600,
    "hours": 3600,
    "day": 86400,
    "days": 86400,
}
_RATE_UNIT_SECONDS: dict[str, int] = {
    "s": 1,
    "m": 60,
    "h": 3600,
    "d": 86400,
}
_KNOWN_THROTTLE_CLASS_SCOPES: dict[str, str] = {
    "apps.common.performance.rate_limiting.PortalHMACRateThrottle": "portal_hmac",
    "apps.common.performance.rate_limiting.PortalHMACBurstThrottle": "portal_hmac_burst",
    "apps.common.performance.rate_limiting.CustomerRateThrottle": "customer",
    "apps.common.performance.rate_limiting.BurstRateThrottle": "burst",
    "apps.api.core.throttling.StandardAPIThrottle": "sustained",
    "apps.api.core.throttling.BurstAPIThrottle": "api_burst",
    "apps.api.core.throttling.AuthThrottle": "auth",
    "apps.api.orders.views.OrderCreateThrottle": "order_create",
    "apps.api.orders.views.OrderCalculateThrottle": "order_calculate",
    "apps.api.orders.views.OrderListThrottle": "order_list",
    "apps.api.orders.views.ProductCatalogThrottle": "product_catalog",
    "rest_framework.throttling.AnonRateThrottle": "anon",
}


def parse_rate_string(rate: str) -> tuple[int, int]:
    """
    Parse DRF-like throttle rates with support for custom shorthand windows.

    Supported examples:
    - ``100/minute``
    - ``50/10s``
    - ``100/hour``
    """
    text_rate = str(rate).strip()
    match = _RATE_PATTERN.fullmatch(text_rate)
    if not match:
        raise ValueError(f"Invalid rate format: {rate!r}")

    num_requests = int(match.group("num"))
    if num_requests <= 0:
        raise ValueError(f"Rate request count must be > 0: {rate!r}")

    period = match.group("period").lower()
    if period in _RATE_WORD_SECONDS:
        return num_requests, _RATE_WORD_SECONDS[period]

    if period[-1] in _RATE_UNIT_SECONDS:
        unit_seconds = _RATE_UNIT_SECONDS[period[-1]]
        if len(period) == 1:
            multiplier = 1
        else:
            if not period[:-1].isdigit():
                raise ValueError(f"Invalid rate period: {rate!r}")
            multiplier = int(period[:-1])
            if multiplier <= 0:
                raise ValueError(f"Rate period multiplier must be > 0: {rate!r}")
        return num_requests, multiplier * unit_seconds

    raise ValueError(f"Unsupported rate period: {rate!r}")


def validate_throttle_rate_map(rates: dict[str, str]) -> None:
    """Validate throttle rates and raise clear startup errors for invalid values."""
    invalid_entries: list[str] = []
    for scope, rate in rates.items():
        try:
            parse_rate_string(rate)
        except (TypeError, ValueError) as exc:
            invalid_entries.append(f"{scope}={rate!r} ({exc})")

    if invalid_entries:
        joined = ", ".join(invalid_entries)
        raise ImproperlyConfigured(f"Invalid throttle rate configuration: {joined}")


def validate_throttle_class_scopes(class_paths: Sequence[str | type[Any]], rates: dict[str, str]) -> None:
    """
    Validate throttle class import paths and ensure scoped classes have configured rates.
    """
    errors: list[str] = []
    for class_path in class_paths:
        if isinstance(class_path, str):
            display_name = class_path
            known_scope = _KNOWN_THROTTLE_CLASS_SCOPES.get(class_path)
            if known_scope:
                scope = known_scope
            else:
                try:
                    throttle_cls = import_string(class_path)
                except Exception as exc:  # pragma: no cover - defensive startup validation
                    errors.append(f"{class_path} (import failed: {exc})")
                    continue
                scope = getattr(throttle_cls, "scope", None)
        elif isinstance(class_path, type):
            throttle_cls = class_path
            display_name = f"{class_path.__module__}.{class_path.__name__}"
            scope = getattr(throttle_cls, "scope", None)
        else:
            errors.append(f"{class_path!r} (invalid throttle class reference)")
            continue

        if scope and scope not in rates:
            errors.append(f"{display_name} (missing scope '{scope}' in THROTTLE_RATES)")

    if errors:
        raise ImproperlyConfigured("Invalid throttle class configuration: " + ", ".join(errors))


def _is_portal_authenticated(request: Request) -> bool:
    """True when request passed HMAC service authentication middleware."""
    return bool(getattr(request, "_portal_authenticated", False))


def _extract_hmac_identity(request: Request) -> str:
    """
    Build a stable HMAC throttle identity.

    Use a portal-only key so callers cannot bypass limits by rotating signed
    payload fields (customer_id/user_id) and creating unbounded cache keys.
    """
    return request.headers.get("X-Portal-Id", "unknown")


class _CustomTimeRateMixin:
    """Support custom shorthand rates such as `50/10s`."""

    def parse_rate(self, rate: str) -> tuple[int, int]:
        return parse_rate_string(rate)


class PortalHMACRateThrottle(SimpleRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Per-portal throttling for service-to-service HMAC requests."""

    scope = "portal_hmac"
    cache_format = "throttle_portal_hmac_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if not _is_portal_authenticated(request):
            return None
        ident = _extract_hmac_identity(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class PortalHMACBurstThrottle(_CustomTimeRateMixin, SimpleRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Burst throttling for HMAC traffic to protect against request spikes."""

    scope = "portal_hmac_burst"
    cache_format = "throttle_portal_hmac_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if not _is_portal_authenticated(request):
            return None
        ident = _extract_hmac_identity(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class CustomerRateThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Rate throttling based on customer account.
    Customers share rate limits across all their users.

    Rate limits can be customized per customer tier:
    - basic: 100 requests/minute
    - professional: 500 requests/minute
    - enterprise: 2000 requests/minute
    """

    scope = "customer"
    cache_format = "throttle_customer_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        """Generate a cache key based on customer ID."""
        if _is_portal_authenticated(request):
            # Portal HMAC traffic is handled by PortalHMAC*Throttle classes.
            return None

        if not request.user or not request.user.is_authenticated:
            # Use IP for unauthenticated requests
            ident = self.get_ident(request)
            return self.cache_format % {"scope": self.scope, "ident": ident}

        # Get customer ID from session or user
        customer_id = getattr(request, "current_customer_id", None)
        if customer_id is None:
            customer_id = getattr(request.session, "current_customer_id", None)

        if customer_id:
            return self.cache_format % {"scope": self.scope, "ident": f"customer_{customer_id}"}

        # Fall back to user-based limiting
        return self.cache_format % {"scope": self.scope, "ident": f"user_{request.user.pk}"}


class BurstRateThrottle(_CustomTimeRateMixin, SimpleRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """
    Throttle for burst traffic - short-term high-frequency limiting.
    Prevents API abuse from rapid requests.

    Default is configured via THROTTLE_RATES["burst"].
    """

    scope = "burst"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        """Generate cache key based on user or IP for burst limiting."""
        if _is_portal_authenticated(request):
            # Portal HMAC traffic is handled by PortalHMAC*Throttle classes.
            return None

        ident = str(request.user.pk) if request.user and request.user.is_authenticated else self.get_ident(request)
        return cast("str | None", self.cache_format % {"scope": self.scope, "ident": ident})


class StandardAPIThrottle(UserRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Per-view sustained throttle for standard API operations."""

    scope = "sustained"


class BurstAPIThrottle(UserRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Per-view burst throttle for read-heavy API operations."""

    scope = "api_burst"


class AuthThrottle(AnonRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Restrictive anonymous throttle for authentication-related endpoints."""

    scope = "auth"


# Rate limit header utilities


def get_rate_limit_headers(request: Request) -> dict[str, str]:
    """
    Generate rate limit headers for API responses.
    Follows the draft IETF standard for rate limit headers.

    Returns:
        dict with headers: X-RateLimit-Limit, X-RateLimit-Remaining,
                          X-RateLimit-Reset, Retry-After
    """
    headers = {}

    # Check for throttle info on request
    throttle_info = getattr(request, "_throttle_info", None)
    if throttle_info:
        headers["X-RateLimit-Limit"] = str(throttle_info.get("limit", 0))
        headers["X-RateLimit-Remaining"] = str(throttle_info.get("remaining", 0))
        headers["X-RateLimit-Reset"] = str(throttle_info.get("reset", 0))

    return headers


def add_rate_limit_headers(response: Any, request: Request) -> Any:
    """Add rate limit headers to a response."""
    headers = get_rate_limit_headers(request)
    for key, value in headers.items():
        response[key] = value
    return response
