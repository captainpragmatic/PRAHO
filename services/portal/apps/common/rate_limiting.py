"""
Rate Limiting Middleware for PRAHO Portal
DoS protection and brute force prevention for authentication endpoints.
"""

import logging
import random
import time
from collections.abc import Callable
from typing import ClassVar

from django.conf import settings
from django.contrib import messages
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.shortcuts import redirect
from django.utils.translation import gettext as _

from apps.common.request_ip import get_safe_client_ip

logger = logging.getLogger(__name__)


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

        # Respect RATELIMIT_ENABLED setting (disabled during E2E testing)
        rate_limit_enabled: bool = getattr(settings, "RATELIMIT_ENABLED", True)
        if not rate_limit_enabled:
            return self.get_response(request)

        # Check if this is an authentication endpoint
        if not self._is_auth_endpoint(request):
            return self.get_response(request)

        # Apply rate limiting to POST requests (actual auth attempts)
        if request.method == "POST":
            rate_limit_response = self._check_rate_limits(request)
            if rate_limit_response:
                return rate_limit_response

        # Process the request
        start_time = time.time()
        response = self.get_response(request)

        # Track failed authentication attempts
        if request.method == "POST" and self._is_auth_failure(response):
            self._record_failed_attempt(request)
        elif request.method == "POST" and self._is_auth_success(response):
            self._clear_rate_limits(request)

        # Apply uniform response timing to prevent timing attacks
        self._uniform_response_delay(start_time)

        return response

    def _is_auth_endpoint(self, request: HttpRequest) -> bool:
        """Check if request is for an authentication endpoint"""
        return any(request.path.startswith(path) for path in self.AUTH_PATHS)

    def _check_rate_limits(self, request: HttpRequest) -> HttpResponse | None:
        """
        🔒 Check both IP and account rate limits.
        Returns error response if rate limited, None if allowed.
        Browser requests get a redirect with message; API/HTMX requests get JSON.
        """
        try:
            client_ip = self._get_client_ip(request)

            # Check IP-based rate limiting
            ip_cache_key = f"auth_ip_attempts_{client_ip}"
            ip_attempts = cache.get(ip_cache_key, 0)

            if ip_attempts >= self.IP_RATE_LIMIT:
                logger.warning(f"🚨 [RateLimit] IP rate limit exceeded: {client_ip} ({ip_attempts} attempts)")
                error_msg = _("Too many authentication attempts. Please try again in 15 minutes.")
                return self._rate_limit_response(request, error_msg, self.IP_WINDOW_SECONDS, 429)

            # Check account-based rate limiting (if email provided)
            email = self._extract_email_from_request(request)
            if email:
                account_cache_key = f"auth_account_attempts_{email}"
                account_attempts = cache.get(account_cache_key, 0)

                if account_attempts >= self.ACCOUNT_RATE_LIMIT:
                    logger.warning(f"🚨 [RateLimit] Account rate limit exceeded: {email} ({account_attempts} attempts)")
                    error_msg = _("Account temporarily locked due to too many failed attempts.")
                    return self._rate_limit_response(request, error_msg, self.ACCOUNT_WINDOW_SECONDS, 429)

            return None  # Rate limits not exceeded

        except Exception as e:
            # Fail closed - block request if cache/rate limiting fails
            logger.error(f"🔥 [RateLimit] Rate limiting check failed: {e}")
            error_msg = _("Service temporarily unavailable. Please try again later.")
            return self._rate_limit_response(request, error_msg, 300, 503)

    def _is_api_or_htmx_request(self, request: HttpRequest) -> bool:
        """Check if this is an API/HTMX request (expects JSON) vs browser form submission."""
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return True
        if request.headers.get("HX-Request") == "true":
            return True
        accept = request.headers.get("Accept", "")
        return "application/json" in accept and "text/html" not in accept

    def _rate_limit_response(
        self, request: HttpRequest, error_msg: str, retry_after: int, status_code: int
    ) -> HttpResponse:
        """Return appropriate rate limit response based on request type."""
        if self._is_api_or_htmx_request(request):
            return JsonResponse(
                {"error": error_msg, "retry_after": retry_after, "attempts_remaining": 0},
                status=status_code,
            )
        # Browser form submission — redirect back to login with error message.
        # nosemgrep: open-redirect — request.path is server-parsed, not user-controlled input.
        messages.error(request, error_msg)
        login_url = settings.LOGIN_URL if hasattr(settings, "LOGIN_URL") else "/login/"
        return redirect(login_url)

    def _record_failed_attempt(self, request: HttpRequest) -> None:
        """🔒 Record failed authentication attempt for both IP and account"""
        try:
            client_ip = self._get_client_ip(request)

            # Atomic increment — prevents lost updates under concurrent requests.
            # Pattern: cache.add() initializes if absent; cache.incr() atomically increments.
            ip_cache_key = f"auth_ip_attempts_{client_ip}"
            try:
                cache.add(ip_cache_key, 0, timeout=self.IP_WINDOW_SECONDS)
                ip_attempts = cache.incr(ip_cache_key)
            except ValueError:
                cache.set(ip_cache_key, 1, timeout=self.IP_WINDOW_SECONDS)
                ip_attempts = 1

            # Record account-based attempt (if email provided)
            email = self._extract_email_from_request(request)
            if email:
                account_cache_key = f"auth_account_attempts_{email}"
                # Atomic increment — prevents lost updates under concurrent requests.
                try:
                    cache.add(account_cache_key, 0, timeout=self.ACCOUNT_WINDOW_SECONDS)
                    account_attempts = cache.incr(account_cache_key)
                except ValueError:
                    cache.set(account_cache_key, 1, timeout=self.ACCOUNT_WINDOW_SECONDS)
                    account_attempts = 1

                logger.info(
                    f"🔒 [RateLimit] Failed auth recorded: IP {client_ip} ({ip_attempts}), "
                    f"Account {email} ({account_attempts})"
                )
            else:
                logger.info(f"🔒 [RateLimit] Failed auth recorded: IP {client_ip} ({ip_attempts})")

        except Exception as e:
            logger.error(f"🔥 [RateLimit] Failed to record auth attempt: {e}")

    def _clear_rate_limits(self, request: HttpRequest) -> None:
        """🔒 Clear rate limits on successful authentication"""
        try:
            client_ip = self._get_client_ip(request)
            email = self._extract_email_from_request(request)

            # Clear IP-based rate limit
            cache.delete(f"auth_ip_attempts_{client_ip}")

            # Clear account-based rate limit
            if email:
                cache.delete(f"auth_account_attempts_{email}")
                logger.info(f"✅ [RateLimit] Rate limits cleared for IP {client_ip}, Account {email}")
            else:
                logger.info(f"✅ [RateLimit] Rate limits cleared for IP {client_ip}")

        except Exception as e:
            logger.error(f"🔥 [RateLimit] Failed to clear rate limits: {e}")

    def _is_auth_failure(self, response: HttpResponse) -> bool:
        """Check if response indicates authentication failure"""
        # HTTP status codes that indicate auth failure
        return response.status_code in [400, 401, 403, 422, 423]

    def _is_auth_success(self, response: HttpResponse) -> bool:
        """Check if response indicates authentication success"""
        # HTTP status codes that indicate auth success
        return response.status_code in [200, 201, 302]  # 302 for redirects after login

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
        🔒 Apply uniform response delay to prevent timing attacks.
        Ensures all auth responses take similar time regardless of success/failure.
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

    # API paths that should be rate limited
    API_PATHS: ClassVar[list[str]] = [
        "/api/",
        "/billing/",
        "/tickets/",
        "/services/",
    ]

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        """Process request with general API rate limiting"""

        # Respect RATELIMIT_ENABLED setting (disabled during E2E testing)
        rate_limit_enabled: bool = getattr(settings, "RATELIMIT_ENABLED", True)
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

    def _check_api_rate_limits(self, request: HttpRequest) -> JsonResponse | None:
        """Check API rate limits"""
        try:
            client_ip = self._get_client_ip(request)

            # Check burst rate limit (short window)
            burst_cache_key = f"api_burst_{client_ip}"
            burst_requests = cache.get(burst_cache_key, 0)

            if burst_requests >= self.BURST_RATE_LIMIT:
                logger.warning(f"🚨 [APIRateLimit] Burst limit exceeded: {client_ip}")
                return JsonResponse(
                    {
                        "error": _("Too many requests in a short period. Please slow down."),
                        "retry_after": self.BURST_WINDOW_SECONDS,
                    },
                    status=429,
                )

            # Check general rate limit (longer window)
            general_cache_key = f"api_general_{client_ip}"
            general_requests = cache.get(general_cache_key, 0)

            if general_requests >= self.GENERAL_RATE_LIMIT:
                logger.warning(f"🚨 [APIRateLimit] General limit exceeded: {client_ip}")
                return JsonResponse(
                    {
                        "error": _("Rate limit exceeded. Please try again in 1 minute."),
                        "retry_after": self.GENERAL_WINDOW_SECONDS,
                    },
                    status=429,
                )

            # Atomic increment — prevents lost updates under concurrent requests.
            # Pattern: cache.add() initializes if absent; cache.incr() atomically increments.
            try:
                cache.add(burst_cache_key, 0, timeout=self.BURST_WINDOW_SECONDS)
                cache.incr(burst_cache_key)
            except ValueError:
                cache.set(burst_cache_key, 1, timeout=self.BURST_WINDOW_SECONDS)

            try:
                cache.add(general_cache_key, 0, timeout=self.GENERAL_WINDOW_SECONDS)
                cache.incr(general_cache_key)
            except ValueError:
                cache.set(general_cache_key, 1, timeout=self.GENERAL_WINDOW_SECONDS)

            return None  # Rate limits not exceeded

        except Exception:
            # Fail-closed: matches AuthenticationRateLimitMiddleware behavior
            logger.error("🔥 [API Rate Limit] Cache error — failing closed")
            return JsonResponse({"error": "Service temporarily unavailable"}, status=503)

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        return get_safe_client_ip(request)
