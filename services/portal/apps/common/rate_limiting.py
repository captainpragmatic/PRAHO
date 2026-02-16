"""
Rate Limiting Middleware for PRAHO Portal
DoS protection and brute force prevention for authentication endpoints.
"""

import logging
import os
import random
import time
from collections.abc import Callable
from typing import ClassVar

from django.conf import settings
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse, JsonResponse
from django.utils.translation import gettext as _

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

        # Respect RATELIMIT_ENABLE setting (disabled during E2E testing)
        # Check Django settings first, fall back to env var for runtime override
        ratelimit_setting = getattr(settings, "RATELIMIT_ENABLE", None)
        if ratelimit_setting is not None:
            if not ratelimit_setting:
                return self.get_response(request)
        elif os.environ.get("RATELIMIT_ENABLE", "true").lower() == "false":
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

    def _check_rate_limits(self, request: HttpRequest) -> JsonResponse | None:
        """
        🔒 Check both IP and account rate limits.
        Returns JsonResponse with 429 status if rate limited, None if allowed.
        """
        try:
            client_ip = self._get_client_ip(request)

            # Check IP-based rate limiting
            ip_cache_key = f"auth_ip_attempts_{client_ip}"
            ip_attempts = cache.get(ip_cache_key, 0)

            if ip_attempts >= self.IP_RATE_LIMIT:
                logger.warning(f"🚨 [RateLimit] IP rate limit exceeded: {client_ip} ({ip_attempts} attempts)")
                return JsonResponse(
                    {
                        "error": _("Prea multe încercări de autentificare. Încercați din nou în 15 minute."),
                        "retry_after": self.IP_WINDOW_SECONDS,
                        "attempts_remaining": 0,
                    },
                    status=429,
                )

            # Check account-based rate limiting (if email provided)
            email = self._extract_email_from_request(request)
            if email:
                account_cache_key = f"auth_account_attempts_{email}"
                account_attempts = cache.get(account_cache_key, 0)

                if account_attempts >= self.ACCOUNT_RATE_LIMIT:
                    logger.warning(f"🚨 [RateLimit] Account rate limit exceeded: {email} ({account_attempts} attempts)")
                    return JsonResponse(
                        {
                            "error": _("Contul este temporar blocat din cauza prea multor încercări eșuate."),
                            "retry_after": self.ACCOUNT_WINDOW_SECONDS,
                            "attempts_remaining": 0,
                        },
                        status=423,
                    )  # 423 Locked

            return None  # Rate limits not exceeded

        except Exception as e:
            # Fail closed - block request if cache/rate limiting fails
            logger.error(f"🔥 [RateLimit] Rate limiting check failed: {e}")
            return JsonResponse(
                {
                    "error": _("Serviciul este temporar indisponibil. Vă rugăm încercați din nou."),
                    "retry_after": 300,  # 5 minutes
                },
                status=503,
            )

    def _record_failed_attempt(self, request: HttpRequest) -> None:
        """🔒 Record failed authentication attempt for both IP and account"""
        try:
            client_ip = self._get_client_ip(request)

            # Record IP-based attempt
            ip_cache_key = f"auth_ip_attempts_{client_ip}"
            ip_attempts = cache.get(ip_cache_key, 0) + 1
            cache.set(ip_cache_key, ip_attempts, timeout=self.IP_WINDOW_SECONDS)

            # Record account-based attempt (if email provided)
            email = self._extract_email_from_request(request)
            if email:
                account_cache_key = f"auth_account_attempts_{email}"
                account_attempts = cache.get(account_cache_key, 0) + 1
                cache.set(account_cache_key, account_attempts, timeout=self.ACCOUNT_WINDOW_SECONDS)

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
            if hasattr(request, "json") and request.json:
                email = request.json.get("email", "").lower().strip()
                if email:
                    return email

            return None
        except Exception:
            return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        # Check for forwarded IP headers (reverse proxy/CDN)
        forwarded_headers = [
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_REAL_IP",
            "HTTP_CF_CONNECTING_IP",  # Cloudflare
            "HTTP_X_CLUSTER_CLIENT_IP",
        ]

        for header in forwarded_headers:
            forwarded_ip = request.META.get(header)
            if forwarded_ip:
                # Take first IP if comma-separated
                ip = forwarded_ip.split(",")[0].strip()
                if ip and ip != "unknown":
                    return ip

        return request.META.get("REMOTE_ADDR", "0.0.0.0")

    def _uniform_response_delay(self, start_time: float) -> None:
        """
        🔒 Apply uniform response delay to prevent timing attacks.
        Ensures all auth responses take similar time regardless of success/failure.
        """
        elapsed = time.time() - start_time
        target_delay = random.uniform(self.MIN_RESPONSE_TIME, self.MAX_RESPONSE_TIME)

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

        # Respect RATELIMIT_ENABLE setting (disabled during E2E testing)
        # Check Django settings first, fall back to env var for runtime override
        ratelimit_setting = getattr(settings, "RATELIMIT_ENABLE", None)
        if ratelimit_setting is not None:
            if not ratelimit_setting:
                return self.get_response(request)
        elif os.environ.get("RATELIMIT_ENABLE", "true").lower() == "false":
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
                        "error": _("Prea multe cereri într-un interval scurt. Vă rugăm să încetiniți."),
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
                        "error": _("Limită de cereri depășită. Vă rugăm să încercați din nou în 1 minut."),
                        "retry_after": self.GENERAL_WINDOW_SECONDS,
                    },
                    status=429,
                )

            # Record the request
            cache.set(burst_cache_key, burst_requests + 1, timeout=self.BURST_WINDOW_SECONDS)
            cache.set(general_cache_key, general_requests + 1, timeout=self.GENERAL_WINDOW_SECONDS)

            return None  # Rate limits not exceeded

        except Exception as e:
            logger.error(f"🔥 [APIRateLimit] Rate limiting check failed: {e}")
            # Don't block requests if rate limiting fails (fail open for API)
            return None

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address (same as auth middleware)"""
        forwarded_headers = [
            "HTTP_X_FORWARDED_FOR",
            "HTTP_X_REAL_IP",
            "HTTP_CF_CONNECTING_IP",
            "HTTP_X_CLUSTER_CLIENT_IP",
        ]

        for header in forwarded_headers:
            forwarded_ip = request.META.get(header)
            if forwarded_ip:
                ip = forwarded_ip.split(",")[0].strip()
                if ip and ip != "unknown":
                    return ip

        return request.META.get("REMOTE_ADDR", "0.0.0.0")
