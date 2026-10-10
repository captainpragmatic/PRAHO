"""
Rate Limiting Middleware for PRAHO Portal
DoS protection and brute force prevention for authentication endpoints.
"""

import hashlib
import logging
import random
import time
from collections.abc import Callable
from typing import Any, ClassVar

from django.conf import settings
from django.contrib import messages
from django.contrib.messages.storage import default_storage
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect, render
from django.utils.cache import add_never_cache_headers
from django.utils.translation import gettext as _

from apps.common import counters
from apps.common.request_ip import get_safe_client_ip
from apps.common.store_unavailable import (
    STORE_UNAVAILABLE_RETRY_AFTER_SECONDS,
    STORE_UNAVAILABLE_STATUS,
    store_unavailable_json,
    store_unavailable_message,
    store_unavailable_response,
    wants_json,
)

logger = logging.getLogger(__name__)
_proxy_warning_logged = False


def _client_ip_is_distinguishable() -> bool:
    """Report whether IP buckets can distinguish clients in this configuration."""
    global _proxy_warning_logged  # noqa: PLW0603
    distinguishable = settings.DEBUG or bool(getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", []))
    if not distinguishable and not _proxy_warning_logged:
        _proxy_warning_logged = True
        logger.warning(
            "🚨 [RateLimit] PORTAL_TRUSTED_PROXY_CIDRS is empty; authentication IP and volume limits are disabled."
        )
    return distinguishable


def mark_auth_failure(request: HttpRequest, bucket: str = "login") -> None:
    """Record the authentication outcome and the budget it should consume."""
    setattr(request, "_portal_auth_outcome", "failure")  # noqa: B010
    setattr(request, "_portal_auth_bucket", bucket)  # noqa: B010


def mark_auth_success(request: HttpRequest) -> None:
    """Set the request-local _portal_auth_outcome consumed by the authentication limiter."""
    setattr(request, "_portal_auth_outcome", "success")  # noqa: B010


# Pages reached from an emailed link: each has its own budgets (_password_reset_budgets).
LINK_PATHS = ("/password-reset/", "/register/confirm/")


class AuthenticationRateLimitMiddleware:
    """
    🔒 Rate limiting middleware for authentication endpoints to prevent brute force attacks.

    Features:
    - IP-based rate limiting (5 attempts per 15 minutes)
    - Account-based rate limiting (5 attempts per 30 minutes)
    - Exponential backoff on repeated failures
    - Fail-safe behavior when cache is unavailable
    - Uniform response timing to prevent timing attacks
    """

    # Rate limiting constants
    IP_RATE_LIMIT = 5  # Max attempts per IP
    IP_WINDOW_SECONDS = 900  # 15 minutes
    ACCOUNT_RATE_LIMIT = 5  # Max attempts per account
    ACCOUNT_WINDOW_SECONDS = 1800  # 30 minutes
    VOLUME_RATE_LIMIT = 10
    VOLUME_WINDOW_SECONDS = 900
    REAUTH_RATE_LIMIT = 5
    REAUTH_WINDOW_SECONDS = 900

    # Response timing constants

    MIN_RESPONSE_TIME = 0.1  # 100ms minimum response time
    MAX_RESPONSE_TIME = 0.5  # 500ms maximum response time

    # Monitored authentication paths
    AUTH_PATHS: ClassVar[list[str]] = [
        "/login/",
        "/register/",
        "/password-reset/",
        "/switch-customer/",
        "/mfa/",
    ]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request with rate limiting for authentication endpoints"""

        # Respect RATE_LIMITING_ENABLED setting (disabled during E2E testing)
        rate_limit_enabled: bool = getattr(settings, "RATE_LIMITING_ENABLED", True)
        if not rate_limit_enabled:
            return self.get_response(request)

        # Check if this is an authentication endpoint
        if not self._is_auth_endpoint(request):
            return self.get_response(request)

        # Recovery and registration-confirmation submissions consume their own budget even when
        # they succeed. They must neither clear login counters nor be cleared by a successful login.
        if request.path.startswith(LINK_PATHS):
            start_time = time.time()
            try:
                return self.get_response(request)
            finally:
                self._uniform_response_delay(start_time)

        # Apply rate limiting to POST requests (actual auth attempts)
        if request.method == "POST":
            rate_limit_response = self._check_rate_limits(request)
            if rate_limit_response:
                return rate_limit_response

        # Process the request
        start_time = time.time()
        response = self.get_response(request)

        # Volume requests were reserved before dispatch; failures are recorded after dispatch.
        if request.method == "POST":
            outcome = getattr(request, "_portal_auth_outcome", None)
            try:
                if outcome == "failure" and getattr(request, "_portal_auth_bucket", "login") == "reauth":
                    self._record_reauth_attempt(request)
                elif request.path.startswith("/login/"):
                    if outcome == "failure" or (outcome is None and self._is_auth_failure(response)):
                        self._record_failed_attempt(request)
                    elif outcome == "success":
                        self._clear_rate_limits(request)
            except Exception:
                logger.exception("🔥 [RateLimit] Counter store unavailable after authentication")
                self._uniform_response_delay(start_time)
                return self._store_unavailable_response(request)

        # Apply uniform response timing to prevent timing attacks
        self._uniform_response_delay(start_time)

        return response

    def process_view(
        self,
        request: HttpRequest,
        view_func: Callable[..., HttpResponse],
        view_args: tuple[Any, ...],
        view_kwargs: dict[str, Any],
    ) -> HttpResponse | None:
        """Render recovery feedback after session and message middleware have run."""
        if (
            getattr(settings, "RATE_LIMITING_ENABLED", True)
            and request.method == "POST"
            and request.path.startswith(LINK_PATHS)
        ):
            return self._check_password_reset_limits(request)
        return None

    def _check_password_reset_limits(self, request: HttpRequest) -> HttpResponse | None:
        """Use separate budgets for email requests, confirmations and ordinary login."""
        try:
            for key, window, maximum in self._password_reset_budgets(request):
                attempts = counters.increment(key, window)
                if attempts > maximum:
                    message = (
                        _("Too many attempts. Please try again later.")
                        if request.path.startswith("/register/confirm/")
                        else _("Too many password reset requests. Please try again later.")
                    )
                    return self._rate_limit_response(request, message, window, 429)
        except Exception:
            logger.exception("🔥 [RateLimit] Password reset limiter unavailable")
            return self._store_unavailable_response(request)
        return None

    def _password_reset_budgets(self, request: HttpRequest) -> list[tuple[str, int, int]]:
        from apps.users.constants import (  # noqa: PLC0415
            PASSWORD_RESET_SESSION_KEY,
            REGISTRATION_CONFIRM_SESSION_KEY,
        )

        if request.path.startswith("/register/confirm/"):
            limits = []
            if _client_ip_is_distinguishable():
                limits.append(
                    (f"register_confirm_ip_{self._get_client_ip(request)}", self.IP_WINDOW_SECONDS, self.IP_RATE_LIMIT)
                )
            link = request.session.get(REGISTRATION_CONFIRM_SESSION_KEY)
            if link:
                digest = hashlib.sha256(f"{link['registration_id']}:{link['token']}".encode()).hexdigest()
                limits.append((f"register_confirm_link_{digest}", self.IP_WINDOW_SECONDS, self.IP_RATE_LIMIT))
            return limits

        confirmation = request.path.startswith("/password-reset/confirm/")
        prefix = "password_reset_confirm" if confirmation else "password_reset"
        limits = []
        if _client_ip_is_distinguishable():
            limits.append((f"{prefix}_ip_{self._get_client_ip(request)}", self.IP_WINDOW_SECONDS, self.IP_RATE_LIMIT))
        email = self._extract_email_from_request(request)
        if email and not confirmation:
            digest = hashlib.sha256(email.encode()).hexdigest()
            limits.append((f"password_reset_email_{digest}", self.ACCOUNT_WINDOW_SECONDS, self.ACCOUNT_RATE_LIMIT))
        credentials = request.session.get(PASSWORD_RESET_SESSION_KEY)
        if confirmation and credentials:
            digest = hashlib.sha256(f"{credentials['uid']}:{credentials['token']}".encode()).hexdigest()
            limits.append((f"password_reset_link_{digest}", self.IP_WINDOW_SECONDS, self.IP_RATE_LIMIT))
        return limits

    def _is_auth_endpoint(self, request: HttpRequest) -> bool:
        """Check if request is for an authentication endpoint"""
        return any(request.path.startswith(path) for path in self.AUTH_PATHS)

    def _is_volume_endpoint(self, request: HttpRequest) -> bool:
        """Identify endpoints that consume a separate IP request budget."""
        return request.path.startswith("/register/")

    def _check_rate_limits(self, request: HttpRequest) -> HttpResponse | None:
        """Check the separate MFA, volume or login budgets, failing closed on cache errors."""
        try:
            if request.path.startswith("/mfa/"):
                return self._check_reauth_budget(request)
            if self._is_volume_endpoint(request):
                return self._check_volume_budget(request)
            if request.path.startswith("/login/"):
                return self._check_login_budgets(request)
            return None
        except Exception as e:
            logger.error("🔥 [RateLimit] Rate limiting check failed: %s", e)
            return self._store_unavailable_response(request)

    def _check_reauth_budget(self, request: HttpRequest) -> HttpResponse | None:
        """MFA re-authentication failures are budgeted per session user, never per address."""
        user_id = request.session.get("user_id")
        if user_id is None:
            return None
        attempts = counters.peek(f"auth_reauth_user_{user_id}")
        if attempts < self.REAUTH_RATE_LIMIT:
            return None
        error_msg = _("Too many authentication attempts. Please try again in 15 minutes.")
        return self._rate_limit_response(request, error_msg, self.REAUTH_WINDOW_SECONDS, 429)

    def _check_volume_budget(self, request: HttpRequest) -> HttpResponse | None:
        """Registration POSTs consume their own per-address volume budget."""
        if not _client_ip_is_distinguishable():
            return None
        client_ip = self._get_client_ip(request)
        volume_attempts = counters.increment(f"auth_volume_ip_{client_ip}", self.VOLUME_WINDOW_SECONDS)
        if volume_attempts <= self.VOLUME_RATE_LIMIT:
            return None
        logger.warning(
            "🚨 [RateLimit] Authentication volume limit exceeded: %s (%s requests)", client_ip, volume_attempts
        )
        error_msg = _("Too many authentication attempts. Please try again in 15 minutes.")
        return self._rate_limit_response(request, error_msg, self.VOLUME_WINDOW_SECONDS, 429)

    def _check_login_budgets(self, request: HttpRequest) -> HttpResponse | None:
        """Login failures are budgeted per address when clients are distinguishable, and per account."""
        if _client_ip_is_distinguishable():
            client_ip = self._get_client_ip(request)
            ip_attempts = counters.peek(f"auth_ip_attempts_{client_ip}")
            if ip_attempts >= self.IP_RATE_LIMIT:
                logger.warning("🚨 [RateLimit] IP rate limit exceeded: %s (%s attempts)", client_ip, ip_attempts)
                error_msg = _("Too many authentication attempts. Please try again in 15 minutes.")
                return self._rate_limit_response(request, error_msg, self.IP_WINDOW_SECONDS, 429)

        email = self._extract_email_from_request(request)
        if email:
            account_attempts = counters.peek(f"auth_account_attempts_{email}")
            if account_attempts >= self.ACCOUNT_RATE_LIMIT:
                logger.warning("🚨 [RateLimit] Account rate limit exceeded: %s (%s attempts)", email, account_attempts)
                error_msg = _("Account temporarily locked due to too many failed attempts.")
                return self._rate_limit_response(request, error_msg, self.ACCOUNT_WINDOW_SECONDS, 429)
        return None

    def _is_api_or_htmx_request(self, request: HttpRequest) -> bool:
        """Check if this is an API/HTMX request (expects JSON) vs browser form submission."""
        return wants_json(request)

    def _store_unavailable_response(self, request: HttpRequest) -> HttpResponse:
        """The shared store-failure contract (#554). A recovery page re-renders its form rather than redirecting."""
        recovery = request.path.startswith(LINK_PATHS)
        if recovery and not wants_json(request):
            return self._rate_limit_response(
                request, store_unavailable_message(), STORE_UNAVAILABLE_RETRY_AFTER_SECONDS, STORE_UNAVAILABLE_STATUS
            )
        response = store_unavailable_response(request, "users:login")
        if recovery:
            self._apply_recovery_headers(request, response, STORE_UNAVAILABLE_RETRY_AFTER_SECONDS)
        return response

    def _apply_recovery_headers(self, request: HttpRequest, response: HttpResponse, retry_after: int) -> None:
        response["Retry-After"] = str(retry_after)
        token_free = request.path in {"/password-reset/", "/password-reset/confirm/", "/register/confirm/"}
        response["Referrer-Policy"] = "same-origin" if token_free else "no-referrer"
        add_never_cache_headers(response)

    def _rate_limit_response(
        self, request: HttpRequest, error_msg: str, retry_after: int, status_code: int
    ) -> HttpResponse:
        """Return appropriate rate limit response based on request type."""
        recovery = request.path.startswith(LINK_PATHS)
        response: HttpResponse
        if self._is_api_or_htmx_request(request):
            response = JsonResponse(
                {"error": error_msg, "retry_after": retry_after, "attempts_remaining": 0},
                status=status_code,
            )
        elif request.path.startswith("/register/confirm/"):
            from apps.users.forms import RegistrationConfirmForm  # noqa: PLC0415

            response = render(
                request,
                "users/register_confirm.html",
                {"form": RegistrationConfirmForm(), "registration": None, "gone": "", "notice": error_msg},
                status=status_code,
            )
        elif recovery:
            from apps.users.constants import PASSWORD_RESET_SESSION_KEY  # noqa: PLC0415
            from apps.users.forms import PasswordResetConfirmForm, PasswordResetRequestForm  # noqa: PLC0415

            confirmation = request.path.startswith("/password-reset/confirm/")
            form = PasswordResetConfirmForm(request.POST) if confirmation else PasswordResetRequestForm(request.POST)
            form.add_error(None, error_msg)
            template = "users/password_reset_confirm.html" if confirmation else "users/password_reset.html"
            response = render(
                request,
                template,
                {"form": form, "validlink": bool(request.session.get(PASSWORD_RESET_SESSION_KEY))},
                status=status_code,
            )
        else:
            messages.error(request, error_msg)
            return redirect("users:login")
        if recovery:
            self._apply_recovery_headers(request, response, retry_after)
        return response

    def _record_reauth_attempt(self, request: HttpRequest) -> None:
        """Count MFA reauthentication failures against the session user."""
        user_id = request.session.get("user_id")
        if user_id is None:
            return
        key = f"auth_reauth_user_{user_id}"
        try:
            counters.increment(key, self.REAUTH_WINDOW_SECONDS)
        except Exception as e:
            logger.error("🔥 [RateLimit] Failed to record reauthentication attempt: %s", e)
            raise

    def _record_failed_attempt(self, request: HttpRequest) -> None:
        """🔒 Record failed authentication attempt for both IP and account"""

        try:
            client_ip = self._get_client_ip(request)

            ip_attempts = 0
            if _client_ip_is_distinguishable():
                ip_cache_key = f"auth_ip_attempts_{client_ip}"
                ip_attempts = counters.increment(ip_cache_key, self.IP_WINDOW_SECONDS)

            # Record account-based attempt (if email provided)
            email = self._extract_email_from_request(request)
            if email:
                account_cache_key = f"auth_account_attempts_{email}"
                account_attempts = counters.increment(account_cache_key, self.ACCOUNT_WINDOW_SECONDS)

                logger.info(
                    f"🔒 [RateLimit] Failed auth recorded: IP {client_ip} ({ip_attempts}), "
                    f"Account {email} ({account_attempts})"
                )
            else:
                logger.info(f"🔒 [RateLimit] Failed auth recorded: IP {client_ip} ({ip_attempts})")

        except Exception as e:
            logger.error(f"🔥 [RateLimit] Failed to record auth attempt: {e}")
            raise

    def _clear_rate_limits(self, request: HttpRequest) -> None:
        """🔒 Clear rate limits on successful authentication"""
        try:
            client_ip = self._get_client_ip(request)
            email = self._extract_email_from_request(request)

            # Clear the IP budget only when clients can be distinguished.
            if _client_ip_is_distinguishable():
                counters.reset(f"auth_ip_attempts_{client_ip}")

            # Clear account-based rate limit
            if email:
                counters.reset(f"auth_account_attempts_{email}")
                logger.info(f"✅ [RateLimit] Rate limits cleared for IP {client_ip}, Account {email}")
            else:
                logger.info(f"✅ [RateLimit] Rate limits cleared for IP {client_ip}")

        except Exception as e:
            logger.error(f"🔥 [RateLimit] Failed to clear rate limits: {e}")

    def _is_auth_failure(self, response: HttpResponse) -> bool:
        """Check if response indicates authentication failure"""
        # HTTP status codes that indicate auth failure
        return response.status_code in [400, 401, 403, 422, 423]

    def _extract_email_from_request(self, request: HttpRequest) -> str | None:
        """Safely extract email from request data"""
        try:
            # Try POST data first
            email = request.POST.get("email", "").lower().strip()
            if email:
                return email

            # Try JSON data
            if hasattr(request, "json"):
                json_data = getattr(request, "json", None)
                if json_data:
                    json_email: str = json_data.get("email", "").lower().strip()
                    if json_email:
                        return json_email

            return None
        except Exception:
            return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        return get_safe_client_ip(request)

    def _uniform_response_delay(self, start_time: float) -> None:
        """
        Apply the established minimum delay with jitter to short auth requests.

        Slower upstream calls can exceed the target and remain observable.
        """
        elapsed = time.time() - start_time
        target_delay = random.uniform(self.MIN_RESPONSE_TIME, self.MAX_RESPONSE_TIME)  # noqa: S311

        remaining_delay = target_delay - elapsed
        if remaining_delay > 0:
            time.sleep(remaining_delay)


class APIRateLimitMiddleware:
    """
    🔒 Rate limiting middleware for API endpoints to prevent DoS attacks.

    Features:
    - General API rate limiting (100 requests per minute per IP)
    - Burst protection (20 requests per 10 seconds per IP)
    - User-based rate limiting for authenticated users
    """

    # Rate limiting constants
    GENERAL_RATE_LIMIT = 100  # Requests per minute per IP
    GENERAL_WINDOW_SECONDS = 60  # 1 minute
    BURST_RATE_LIMIT = 20  # Requests per burst window per IP
    BURST_WINDOW_SECONDS = 10  # 10 seconds

    # Per-session rate limiting for cart mutation endpoints.
    # Each calculate_totals call triggers a Platform API call → DB chain,
    # so session-level limits prevent amplification even when IP limits are bypassed.
    CART_SESSION_RATE_LIMIT = 30  # Requests per minute per session
    CART_SESSION_WINDOW_SECONDS = 60

    # Cart mutation paths that get per-session rate limiting
    CART_MUTATION_PATHS: ClassVar[list[str]] = [
        "/order/cart/add/",
        "/order/cart/update/",
        "/order/cart/remove/",
        "/order/cart/totals/",
    ]

    # API paths that should be rate limited
    # Where a browser navigation lands when the store is down. It must stay outside API_PATHS, or the
    # redirected request would fail in this middleware again.
    STORE_UNAVAILABLE_REDIRECT = "/dashboard/"

    API_PATHS: ClassVar[list[str]] = [
        "/api/",
        "/billing/",
        "/tickets/",
        "/services/",
        "/order/",
    ]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request with general API rate limiting"""

        # Respect RATE_LIMITING_ENABLED setting (disabled during E2E testing)
        rate_limit_enabled: bool = getattr(settings, "RATE_LIMITING_ENABLED", True)
        if not rate_limit_enabled:
            return self.get_response(request)

        # Check if this is an API endpoint
        if not self._is_api_endpoint(request):
            return self.get_response(request)

        # Check rate limits
        rate_limit_response = self._check_api_rate_limits(request)
        if rate_limit_response:
            return rate_limit_response

        return self.get_response(request)

    def _is_api_endpoint(self, request: HttpRequest) -> bool:
        """Check if request is for an API endpoint"""
        return any(request.path.startswith(path) for path in self.API_PATHS)

    def _check_api_rate_limits(self, request: HttpRequest) -> HttpResponse | None:
        """Check API rate limits"""
        try:
            client_ip = self._get_client_ip(request)

            # Reserve each request before deciding whether it may proceed.
            burst_cache_key = f"api_burst_{client_ip}"
            burst_requests = counters.increment(burst_cache_key, self.BURST_WINDOW_SECONDS)

            if burst_requests > self.BURST_RATE_LIMIT:
                logger.warning(f"🚨 [APIRateLimit] Burst limit exceeded: {client_ip}")
                return JsonResponse(
                    {
                        "error": _("Too many requests in a short period. Please slow down."),
                        "retry_after": self.BURST_WINDOW_SECONDS,
                    },
                    status=429,
                )

            # Requests admitted by the burst budget also reserve the general budget.
            general_cache_key = f"api_general_{client_ip}"
            general_requests = counters.increment(general_cache_key, self.GENERAL_WINDOW_SECONDS)

            if general_requests > self.GENERAL_RATE_LIMIT:
                logger.warning(f"🚨 [APIRateLimit] General limit exceeded: {client_ip}")
                return JsonResponse(
                    {
                        "error": _("Rate limit exceeded. Please try again in 1 minute."),
                        "retry_after": self.GENERAL_WINDOW_SECONDS,
                    },
                    status=429,
                )

            # Reserve the cart budget after both IP budgets admit the request.
            if self._is_cart_mutation(request):
                cart_response = self._check_cart_session_rate_limit(request)
                if cart_response:
                    return cart_response

            return None  # Rate limits not exceeded

        except Exception:
            # Fail-closed with the shared store-failure contract (#554).
            logger.error("🔥 [APIRateLimit] Counter store error; denying request")
            # Only an explicit HTML page load is redirected. A caller without text/html in Accept
            # (health checks, load-balancer probes, scripts) keeps the 503 a redirect would hide.
            if wants_json(request) or "text/html" not in request.headers.get("Accept", ""):
                return store_unavailable_json()
            return self._browser_store_unavailable(request)

    def _browser_store_unavailable(self, request: HttpRequest) -> HttpResponse:
        """Notice and redirect for a page navigation.

        This middleware runs before MessageMiddleware, so it stores the notice itself and writes it to the
        response, which MessageMiddleware would otherwise do on the way out.
        """
        storage = default_storage(request)
        storage.add(messages.ERROR, store_unavailable_message())
        response = redirect(self.STORE_UNAVAILABLE_REDIRECT)
        storage.update(response)
        return response

    def _is_cart_mutation(self, request: HttpRequest) -> bool:
        """Check if request is a cart mutation endpoint"""
        return any(request.path.startswith(path) for path in self.CART_MUTATION_PATHS)

    def _check_cart_session_rate_limit(self, request: HttpRequest) -> JsonResponse | None:
        """
        🔒 Per-user rate limiting for cart mutation endpoints.
        Uses user_id (if available) to prevent a single user from hammering
        calculate_totals, which triggers Platform API calls and DB chains.
        Falls through to IP-level limiting when no authenticated session exists.
        """
        # Use user_id as the rate-limit key instead of session_key.
        # session_key is None under signed-cookie sessions, which would silently
        # disable per-session cart rate limiting.
        session = getattr(request, "session", None)
        user_id = session.get("user_id") if session else None
        if user_id is None:
            return None  # No session yet — IP-level limiting still applies

        cart_cache_key = f"cart_session_{user_id}"
        cart_requests = counters.increment(cart_cache_key, self.CART_SESSION_WINDOW_SECONDS)

        if cart_requests > self.CART_SESSION_RATE_LIMIT:
            logger.warning(f"🚨 [APIRateLimit] Cart session limit exceeded: user={user_id}...")
            return JsonResponse(
                {
                    "error": _("Too many cart updates. Please slow down."),
                    "retry_after": self.CART_SESSION_WINDOW_SECONDS,
                },
                status=429,
            )

        return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        return get_safe_client_ip(request)
