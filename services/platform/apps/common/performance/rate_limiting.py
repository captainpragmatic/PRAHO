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

import hashlib
import ipaddress
import json
import logging
import math
import re
import time
from collections.abc import Sequence
from typing import Any, cast

from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpRequest
from django.utils.module_loading import import_string
from rest_framework.request import Request
from rest_framework.throttling import AnonRateThrottle, SimpleRateThrottle, UserRateThrottle

from apps.common.request_ip import get_safe_client_ip

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
    "apps.common.performance.rate_limiting.PortalHMACCreateUserThrottle": "portal_hmac_create_user",
    "apps.common.performance.rate_limiting.CustomerRateThrottle": "customer",
    "apps.common.performance.rate_limiting.BurstRateThrottle": "burst",
    "apps.api.core.throttling.StandardAPIThrottle": "sustained",
    "apps.api.core.throttling.BurstAPIThrottle": "api_burst",
    "apps.api.core.throttling.AuthThrottle": "auth",
    "apps.api.orders.views.OrderCreateThrottle": "order_create",
    "apps.api.orders.views.OrderCalculateThrottle": "order_calculate",
    "apps.api.orders.views.OrderListThrottle": "order_list",
    "apps.api.orders.views.ProductCatalogThrottle": "product_catalog",
    "apps.api.users.views.SessionValidationThrottle": "session_validation",
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


def forwarded_client_ip(request: HttpRequest | Request) -> str | None:
    """Read an end-user IP only from a body authenticated by the HMAC middleware."""
    try:
        if getattr(request, "_portal_authenticated", False) is not True:
            return None
        request_data = request.data if hasattr(request, "data") else json.loads(request.body)
        raw = request_data.get("client_ip")
        if not isinstance(raw, str):
            return None
        return str(ipaddress.ip_address(raw))
    except Exception:
        return None


def fixed_window_limited(key: str, rate: str, *, charge: bool = True) -> tuple[bool, int]:
    """Charge or peek at a fixed-window counter, denying requests if the store fails.

    A peek denies when the budget is exhausted. A charge denies when the new
    count exceeds the budget. Window identity is independent of backend TTLs.
    """
    if not getattr(settings, "RATE_LIMITING_ENABLED", True):
        return False, 0

    # Deferred: apps.common.apps imports this module before the model registry is ready.
    from apps.common import counters  # noqa: PLC0415

    max_calls, window = parse_rate_string(rate)
    now = time.time()
    window_index = int(now // window)
    counter_key = f"{key}:{window_index}"
    try:
        if charge:
            current = counters.increment(counter_key, window * 2)
            limited = current > max_calls
        else:
            current = counters.peek(counter_key)
            limited = current >= max_calls

        if not limited:
            return False, 0
        return True, max(1, math.ceil(window - (now % window)))
    except Exception:
        logger.error("🔥 [RateLimiter] Counter store failure during fixed-window rate limiting — denying request")
        return True, window


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
        scope: str | None
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
        else:
            throttle_cls = class_path
            display_name = f"{class_path.__module__}.{class_path.__name__}"
            scope = getattr(throttle_cls, "scope", None)

        if scope and scope not in rates:
            errors.append(f"{display_name} (missing scope '{scope}' in THROTTLE_RATES)")

    if errors:
        raise ImproperlyConfigured("Invalid throttle class configuration: " + ", ".join(errors))


def _is_portal_authenticated(request: Request) -> bool:
    """True when request passed HMAC service authentication middleware."""
    return bool(getattr(request, "_portal_authenticated", False))


def _extract_portal_identity(request: Request) -> str:
    """
    The portal a verified HMAC request came from.

    Prefer the canonical portal ID stored by HMAC middleware after signature
    verification. The header fallback supports isolated tests and defensive
    compatibility with already-authenticated request adapters.
    """
    verified_portal_id = getattr(request, "_portal_id", None)
    return str(verified_portal_id or request.headers.get("X-Portal-Id", "unknown"))


def _extract_hmac_identity(request: Request) -> str:
    """
    Build a stable HMAC throttle identity: the portal and the principal it is acting for.

    The principal (``user:<id>``, ``ip:<addr>`` or ``anonymous``) is parsed once by the HMAC
    middleware from the verified body, so one customer cannot use up a budget every customer of
    the portal shares. A request the middleware never classified counts as anonymous.
    """
    principal = getattr(request, "_portal_principal", None) or "anonymous"
    return f"{_extract_portal_identity(request)}:{principal}"


class _CustomTimeRateMixin:
    """Shorthand-rate parsing + the system-wide rate-limiting kill switch.

    #277: startup validation (``validate_throttle_rate_map``) accepts every format
    ``parse_rate_string`` accepts, but DRF's stock ``parse_rate`` keys the window on
    ``period[0]`` alone — so a multi-digit window like ``50/10s`` reads as ``'1'`` and
    raises KeyError at REQUEST time after passing deploy checks cleanly. Any throttle
    whose rate is env-overridable must therefore parse with this mixin, not DRF's.

    The kill switch lives here too so it is honored by EVERY project throttle. It used
    to sit only on ``_ConfigurableRateThrottle``, which the DRF-base throttles
    (Customer/Burst/Standard/Auth) don't inherit — so ``RATE_LIMITING_ENABLED=False``
    silently failed to disable them (unexpected 429s in dev/E2E). Since this mixin is
    the one common ancestor of every project throttle, defining ``allow_request`` here
    makes the switch universal. ``super().allow_request`` reaches the real throttle base
    via cooperative MRO (the mixin is always followed by a DRF throttle class).
    """

    def parse_rate(self, rate: str) -> tuple[int, int]:
        return parse_rate_string(rate)

    def allow_request(self, request: Request, view: Any) -> bool:
        if not getattr(settings, "RATE_LIMITING_ENABLED", True):
            return True
        # super() resolves to the DRF throttle base at runtime via cooperative MRO — this
        # mixin is always mixed in *before* a SimpleRateThrottle subclass. mypy can't see
        # that from the standalone mixin, hence the ignore.
        return bool(super().allow_request(request, view))  # type: ignore[misc]  # cooperative-MRO super


class _ConfigurableRateThrottle(_CustomTimeRateMixin, SimpleRateThrottle):  # type: ignore[misc]  # dynamic DRF attributes
    """Base for PRAHO's own scoped throttles.

    Carries no behavior of its own now — shorthand parsing and the kill switch both
    live on ``_CustomTimeRateMixin`` so every project throttle honors them, not just
    this base's subclasses.
    """


class PortalHMACRateThrottle(_ConfigurableRateThrottle):
    """Per-portal throttling for service-to-service HMAC requests."""

    scope = "portal_hmac"
    cache_format = "throttle_portal_hmac_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if not _is_portal_authenticated(request):
            return None
        ident = _extract_hmac_identity(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class PortalHMACBurstThrottle(_ConfigurableRateThrottle):
    """Burst throttling for HMAC traffic to protect against request spikes."""

    scope = "portal_hmac_burst"
    cache_format = "throttle_portal_hmac_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if not _is_portal_authenticated(request):
            return None
        ident = _extract_hmac_identity(request)
        return self.cache_format % {"scope": self.scope, "ident": ident}


class PortalHMACCreateUserThrottle(_ConfigurableRateThrottle):
    """Strict per-portal throttle for the HMAC user-creation mutation.

    Layered on top of the global PortalHMAC*Throttle limits to bound account
    creation specifically. Keyed on the verified portal identity (X-Portal-Id)
    rather than client IP: customer_users_create runs with authentication_classes([])
    so request.user is AnonymousUser, which means any UserRateThrottle/AnonRateThrottle
    here would key on IP and be diluted by a caller distributing requests across IPs.
    Returns None (no throttling) for non-portal traffic — the endpoint already
    rejects unauthenticated callers via @require_customer_authentication.
    """

    scope = "portal_hmac_create_user"
    cache_format = "throttle_portal_hmac_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if not _is_portal_authenticated(request):
            return None
        ident = _extract_portal_identity(request)  # deliberately per portal, not per principal
        return self.cache_format % {"scope": self.scope, "ident": ident}


class EndpointRateThrottle(_ConfigurableRateThrottle):
    """Per-endpoint throttle for function-based API views.

    ``ScopedRateThrottle`` reads its scope from ``view.throttle_scope`` and
    therefore silently disables subclasses attached to DRF ``@api_view``
    functions. Endpoint subclasses declare their scope directly and use the
    verified portal identity for HMAC traffic, the authenticated user for
    direct API traffic, and the client IP for public endpoints.
    """

    cache_format = "throttle_endpoint_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        if _is_portal_authenticated(request):
            ident = f"portal_{_extract_hmac_identity(request)}"
        elif request.user and request.user.is_authenticated:
            ident = f"user_{request.user.pk}"
        else:
            # Canonical trusted-proxy-aware client IP (raw X-Forwarded-For is spoofable).
            ident = f"ip_{get_safe_client_ip(request)}"
        return self.cache_format % {"scope": self.scope, "ident": ident}


class ForwardedClientIPThrottle(EndpointRateThrottle):
    """Throttle the end-user IP supplied in the Portal's authenticated body."""

    # Unlike the endpoint base, this throttle can opt out when no signed IP exists.
    def get_cache_key(self, request: Request, view: Any) -> str | None:
        ip = forwarded_client_ip(request)
        if ip is None:
            return None
        return self.cache_format % {"scope": self.scope, "ident": f"client_{ip}"}


class LoginClientIPThrottle(ForwardedClientIPThrottle):
    """Carry auth_login_ip through startup scope validation.

    portal_login_api is a plain Django view and uses fixed_window_limited
    directly to peek before authentication and charge only failed logins.
    """

    scope = "auth_login_ip"


class ResetClientIPThrottle(ForwardedClientIPThrottle):
    """Limit password resets from an authenticated forwarded client IP."""

    scope = "auth_reset_ip"


class CustomerRateThrottle(_CustomTimeRateMixin, SimpleRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
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
            # Use the canonical trusted-proxy-aware client IP for unauthenticated requests.
            ident = get_safe_client_ip(request)
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

        ident = str(request.user.pk) if request.user and request.user.is_authenticated else get_safe_client_ip(request)
        return cast("str | None", self.cache_format % {"scope": self.scope, "ident": ident})


class StandardAPIThrottle(_CustomTimeRateMixin, UserRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Per-view sustained throttle for standard API operations.

    Keys on the authenticated user (or client IP when anonymous). Do NOT attach this
    to an HMAC endpoint running ``authentication_classes([])`` — request.user is
    AnonymousUser there, so it degrades to IP keying; use the PortalHMAC* throttles.
    """

    scope = "sustained"


class BurstAPIThrottle(_CustomTimeRateMixin, UserRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Per-view burst throttle for read-heavy API operations.

    Same user/IP keying caveat as StandardAPIThrottle — see its docstring.
    """

    scope = "api_burst"


class TokenRequestAccountThrottle(_ConfigurableRateThrottle):
    """Per-ACCOUNT limit on the public token endpoint, keyed on the submitted email.

    This is the replacement for that endpoint driving `increment_failed_login_attempts`.
    Five wrong passwords there used to apply a progressive account lock escalating to
    four hours, so an unauthenticated caller could lock any account it knew the address
    of, with no credentials and nothing to attribute the attempt to.

    Keying on the submitted address rather than on the client is deliberate and is what
    makes this work TODAY. Every client-keyed throttle here depends on
    `IPWARE_TRUSTED_PROXY_LIST`, which is empty in production, so a caller can rotate a
    forwarded header into a fresh bucket. An attacker cannot rotate the address they are
    trying to break into, so this budget binds regardless of proxy configuration.

    It also cannot become a denial of service against anyone else: exhausting one
    account's budget leaves every other account's untouched, which a shared or
    client-keyed budget would not.

    A request with no usable email is not throttled here. It is rejected before any
    password hashing, and endpoint volume is still covered by AuthThrottle.
    """

    scope = "token_request"
    cache_format = "throttle_token_request_%(scope)s_%(ident)s"

    def get_cache_key(self, request: Request, view: Any) -> str | None:
        email = request.data.get("email") if hasattr(request, "data") else None
        if not isinstance(email, str) or not email.strip():
            return None
        # Hashed, for two reasons. An address may be up to 254 characters and the
        # DatabaseCache backend stores keys in a 255-character column, so the raw value
        # plus prefix and version can overflow it. And it keeps the address itself out of
        # the cache table, which is not a place credentials-adjacent data needs to be.
        #
        # Case-folded rather than lowercased: `User.email` has no case-insensitive
        # uniqueness constraint, but authentication resolves the address case-sensitively,
        # so two spellings can be separate identities. Folding merges them into one
        # bucket ON PURPOSE — otherwise varying the case is a free way to get a fresh
        # budget, which is exactly the evasion this throttle exists to stop.
        ident = hashlib.sha256(email.strip().casefold().encode("utf-8")).hexdigest()[:32]
        return self.cache_format % {"scope": self.scope, "ident": ident}


class AuthThrottle(_CustomTimeRateMixin, AnonRateThrottle):  # type: ignore[misc]  # DRF throttle base uses dynamic attrs
    """Restrictive anonymous throttle for authentication-related endpoints.

    IP-keyed by design: correct for genuinely public/anonymous endpoints such as
    registration, wrong for HMAC service traffic.
    """

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
