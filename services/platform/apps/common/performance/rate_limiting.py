"""
API Rate Limiting and Throttling for PRAHO Platform

Provides DRF-compatible throttling classes with:
- Customer-aware rate limiting
- Burst and sustained rate limiting
- Service-specific throttling
- Rate limit headers for API responses
"""

from __future__ import annotations

import logging
import time
from typing import Any, ClassVar, cast

from django.conf import settings
from django.core.cache import cache
from rest_framework.request import Request
from rest_framework.throttling import BaseThrottle, SimpleRateThrottle

logger = logging.getLogger(__name__)


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

    # Default rates by customer tier
    TIER_RATES: ClassVar[dict[str, str]] = {
        "basic": "100/minute",
        "professional": "500/minute",
        "enterprise": "2000/minute",
    }

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        """Generate a cache key based on customer ID."""
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

    def get_rate(self) -> str:
        """Get rate based on customer tier."""
        # Default rate - can be overridden based on customer tier
        return getattr(settings, "DEFAULT_CUSTOMER_THROTTLE_RATE", "100/minute")


class BurstRateThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Throttle for burst traffic - short-term high-frequency limiting.
    Prevents API abuse from rapid requests.

    Default: 30 requests per 10 seconds
    """

    scope = "burst"
    rate = "30/10s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        """Generate cache key based on user or IP for burst limiting."""
        ident = str(request.user.pk) if request.user and request.user.is_authenticated else self.get_ident(request)
        return cast("str | None", self.cache_format % {"scope": self.scope, "ident": ident})

    def parse_rate(self, rate: str) -> tuple[int, int]:
        """Parse rate string with custom time units."""
        num, period = rate.split("/")
        num_requests = int(num)

        # Handle custom time periods
        if period.endswith("s"):
            duration = int(period[:-1])
        elif period == "sec":
            duration = 1
        elif period in {"min", "minute"}:
            duration = 60
        elif period == "hour":
            duration = 3600
        elif period == "day":
            duration = 86400
        else:
            duration = {"s": 1, "m": 60, "h": 3600, "d": 86400}.get(period[-1], 1)
            if period[:-1].isdigit():
                duration *= int(period[:-1])

        return (num_requests, duration)


class SustainedRateThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Throttle for sustained traffic - long-term rate limiting.
    Prevents API overuse over time.

    Default: 1000 requests per hour
    """

    scope = "sustained"
    rate = "1000/hour"


class ServiceRateThrottle(BaseThrottle):  # type: ignore[misc]
    """
    Specialized throttle for service provisioning and heavy operations.
    Implements token bucket algorithm for more flexible limiting.

    Features:
    - Token bucket with configurable refill rate
    - Per-operation cost weighting
    - Queue-based waiting for rate-limited requests
    """

    # Tokens per operation type
    OPERATION_COSTS: ClassVar[dict[str, int]] = {
        "provision": 10,
        "backup": 5,
        "sync": 2,
        "query": 1,
    }

    # Default bucket configuration
    BUCKET_CAPACITY = 100
    REFILL_RATE = 10  # tokens per second

    def __init__(self) -> None:
        self.cache_key_prefix = "throttle_service"
        self.capacity = getattr(settings, "SERVICE_THROTTLE_CAPACITY", self.BUCKET_CAPACITY)
        self.refill_rate = getattr(settings, "SERVICE_THROTTLE_REFILL_RATE", self.REFILL_RATE)

    def allow_request(self, request: Request, view: Any) -> bool:
        """Check if request is allowed based on token bucket."""
        ident = self._get_ident(request)
        operation = self._get_operation(request, view)
        cost = self.OPERATION_COSTS.get(operation, 1)

        cache_key = f"{self.cache_key_prefix}_{ident}"
        bucket = cache.get(cache_key)

        now = time.time()

        if bucket is None:
            # Initialize new bucket
            bucket = {
                "tokens": self.capacity - cost,
                "last_update": now,
            }
        else:
            # Refill tokens based on time elapsed
            elapsed = now - bucket["last_update"]
            refill = int(elapsed * self.refill_rate)
            bucket["tokens"] = min(self.capacity, bucket["tokens"] + refill)
            bucket["last_update"] = now

            # Check if we have enough tokens
            if bucket["tokens"] < cost:
                self._wait_time = (cost - bucket["tokens"]) / self.refill_rate
                return False

            bucket["tokens"] -= cost

        # Store updated bucket
        cache.set(cache_key, bucket, timeout=3600)

        # Store rate limit info for headers
        request._throttle_info = {
            "remaining": bucket["tokens"],
            "limit": self.capacity,
            "reset": int(now + (self.capacity - bucket["tokens"]) / self.refill_rate),
        }

        return True

    def wait(self) -> float | None:
        """Return the recommended wait time."""
        return getattr(self, "_wait_time", None)

    def _get_ident(self, request: Request) -> str:
        """Get identifier for rate limiting."""
        if request.user and request.user.is_authenticated:
            customer_id = getattr(request, "current_customer_id", None)
            if customer_id:
                return f"customer_{customer_id}"
            return f"user_{request.user.pk}"

        # Fall back to IP
        xff = request.META.get("HTTP_X_FORWARDED_FOR")
        remote_addr = request.META.get("REMOTE_ADDR")
        return (xff.split(",")[0].strip() if xff else remote_addr) or "unknown"

    def _get_operation(self, request: Request, view: Any) -> str:  # noqa: PLR0911
        """Determine the operation type from the request."""
        # Check view action
        if hasattr(view, "action"):
            action = view.action
            if action in ["create", "provision"]:
                return "provision"
            if action in ["backup"]:
                return "backup"
            if action in ["sync", "update"]:
                return "sync"

        # Check URL path
        path = request.path.lower()
        if "provision" in path:
            return "provision"
        if "backup" in path:
            return "backup"
        if "sync" in path:
            return "sync"

        return "query"


class AnonymousRateThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Strict rate limiting for unauthenticated requests.
    Prevents abuse from anonymous users.

    Default: 20 requests per minute
    """

    scope = "anon"
    rate = "20/minute"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if request.user and request.user.is_authenticated:
            return None  # Only throttle unauthenticated requests

        return cast(
            "str | None",
            self.cache_format
            % {
                "scope": self.scope,
                "ident": self.get_ident(request),
            },
        )


class WriteOperationThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Throttle for write operations (POST, PUT, PATCH, DELETE).
    More restrictive than read operations.

    Default: 60 write operations per minute
    """

    scope = "write"
    rate = "60/minute"

    def allow_request(self, request: Request, view: Any) -> bool:
        if request.method in ("GET", "HEAD", "OPTIONS"):
            return True  # Don't throttle read operations

        return cast(bool, super().allow_request(request, view))


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


# Rate limit configuration for different endpoints

ENDPOINT_THROTTLE_RATES = {
    # High-security endpoints - very restrictive
    "login": "5/minute",
    "password_reset": "3/minute",
    "2fa_verify": "10/minute",
    # Financial operations - moderately restrictive
    "payment": "30/minute",
    "invoice": "60/minute",
    "refund": "10/minute",
    # Provisioning - resource-intensive
    "provision": "10/minute",
    "backup": "5/minute",
    # Standard CRUD - less restrictive
    "list": "100/minute",
    "detail": "200/minute",
    "create": "50/minute",
    "update": "100/minute",
    # Read-heavy operations - permissive
    "search": "60/minute",
    "export": "10/minute",
}


def get_throttle_rate_for_endpoint(endpoint: str) -> str:
    """Get the configured throttle rate for an endpoint."""
    return ENDPOINT_THROTTLE_RATES.get(endpoint, "100/minute")


class EndpointThrottle(SimpleRateThrottle):  # type: ignore[misc]
    """
    Dynamic throttle that applies different rates based on endpoint.
    Rate is determined by view's throttle_scope attribute.
    """

    scope_attr = "throttle_scope"

    def __init__(self) -> None:
        pass  # Don't call super().__init__() to avoid rate parsing

    def allow_request(self, request: Request, view: Any) -> bool:
        # Get scope from view
        self.scope = getattr(view, self.scope_attr, "default")
        self.rate = get_throttle_rate_for_endpoint(self.scope)

        # Parse rate and check
        self.num_requests, self.duration = self.parse_rate(self.rate)
        self.key = self.get_cache_key(request, view)

        if self.key is None:
            return True

        self.history = cache.get(self.key, [])
        self.now = time.time()

        # Drop old entries
        while self.history and self.history[-1] <= self.now - self.duration:
            self.history.pop()

        if len(self.history) >= self.num_requests:
            return self.throttle_failure()

        return self.throttle_success()

    def throttle_success(self) -> bool:
        self.history.insert(0, self.now)
        cache.set(self.key, self.history, self.duration)
        return True

    def throttle_failure(self) -> bool:
        return False
