"""
Common middleware for PRAHO Platform
Security headers, Romanian compliance, and audit logging.
"""

import base64
import hashlib
import hmac
import json
import logging
import math
import time
import traceback
import urllib.parse
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib import messages
from django.contrib.auth import get_user_model, logout
from django.core.cache import cache
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils import timezone
from django.utils.translation import gettext as _

from apps.common.constants import HMAC_NTP_SKEW_SECONDS, HMAC_TIMESTAMP_WINDOW_SECONDS, HTTP_CLIENT_ERROR_THRESHOLD
from apps.common.logging import clear_request_id, set_request_id
from apps.common.request_ip import get_safe_client_ip

# Security constants
HMAC_NONCE_MIN_LENGTH = 32
HMAC_NONCE_MAX_LENGTH = 256

# Import for session security - handle potential circular import gracefully
try:
    from apps.users.services import SessionSecurityService
except ImportError:
    SessionSecurityService = None

logger = logging.getLogger(__name__)
User = get_user_model()

# ===============================================================================
# REQUEST ID MIDDLEWARE
# ===============================================================================


class RequestIDMiddleware:
    """
    Add unique request ID for tracing and audit logs.

    This middleware:
    1. Generates a unique UUID for each request
    2. Stores it in request.META for access throughout the request
    3. Sets it in thread-local storage for structured logging (RequestIDFilter)
    4. Adds X-Request-ID header to response for client-side correlation
    5. Cleans up thread-local storage after request completes
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.META["REQUEST_ID"] = request_id

        # Set in thread-local storage for RequestIDFilter logging
        set_request_id(request_id)

        try:
            # Process request
            response = self.get_response(request)

            # Add to response headers for debugging and client correlation
            response["X-Request-ID"] = request_id

            return response
        finally:
            # Clean up thread-local storage
            clear_request_id()


# ===============================================================================
# SECURITY MIDDLEWARE
# ===============================================================================


class SecurityHeadersMiddleware:
    """Add security headers for Romanian hosting compliance"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Content Security Policy - Enhanced security with trusted CDN support
        if not response.get("Content-Security-Policy"):
            csp = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline' fonts.googleapis.com cdn.tailwindcss.com; "
                "font-src 'self' fonts.gstatic.com; "
                "script-src 'self' 'unsafe-inline' 'unsafe-eval' unpkg.com cdn.tailwindcss.com; "  # Allow trusted CDNs + Alpine.js
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "object-src 'none'; "  # Prevent Flash/Java execution
                "base-uri 'self'; "  # Prevent base tag injection
                "form-action 'self';"  # Restrict form submissions
            )
            response["Content-Security-Policy"] = csp

        # Other security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        response["Cross-Origin-Opener-Policy"] = "same-origin"

        # Romanian privacy compliance
        response["X-Powered-By"] = "PragmaticHost Romania"

        return response


# ===============================================================================
# AUDIT LOGGING MIDDLEWARE
# ===============================================================================


class AuditMiddleware:
    """Log all requests for Romanian legal compliance"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        start_time = time.time()

        # Log request
        self._log_request(request)

        response = self.get_response(request)

        # Log response
        duration = time.time() - start_time
        self._log_response(request, response, duration)

        return response

    def _log_request(self, request: HttpRequest) -> None:
        """Log incoming request"""
        user_id = request.user.id if request.user.is_authenticated else None

        audit_data = {
            "event": "request",
            "method": request.method,
            "path": request.path,
            "user_id": user_id,
            "ip_address": get_safe_client_ip(request),
            "user_agent": request.META.get("HTTP_USER_AGENT", ""),
            "timestamp": time.time(),
        }

        # Don't log sensitive data
        if request.path.startswith("/admin/") or "password" in request.path.lower():
            audit_data["sensitive"] = True
        else:
            audit_data["query_params"] = dict(request.GET)

        logger.info("audit", extra=audit_data)

    def _log_response(self, request: HttpRequest, response: HttpResponse, duration: float) -> None:
        """Log response"""
        user_id = request.user.id if request.user.is_authenticated else None

        audit_data = {
            "event": "response",
            "method": request.method,
            "path": request.path,
            "status_code": response.status_code,
            "user_id": user_id,
            "duration_ms": round(duration * 1000, 2),
            "timestamp": time.time(),
        }

        # Log errors with more detail
        if response.status_code >= HTTP_CLIENT_ERROR_THRESHOLD:
            audit_data["error"] = True
            if hasattr(response, "content"):
                audit_data["response_size"] = len(response.content)

        logger.info("audit", extra=audit_data)


# ===============================================================================
# ROMANIAN TIMEZONE MIDDLEWARE
# ===============================================================================


class RomanianTimezoneMiddleware:
    """Set Romanian timezone for all requests"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Django's USE_TZ setting handles this in settings
        # This middleware can be used for user-specific timezone handling later
        return self.get_response(request)


# ===============================================================================
# API MIDDLEWARE
# ===============================================================================


class JSONResponseMiddleware:
    """Handle JSON API responses and errors"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Add JSON content type for API responses
        if request.path.startswith("/api/") and not response.get("Content-Type"):
            response["Content-Type"] = "application/json"

        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse | None:
        """Handle API exceptions as JSON"""
        if request.path.startswith("/api/"):
            error_data = {
                "error": True,
                "message": str(exception),
                "type": exception.__class__.__name__,
            }

            if settings.DEBUG:
                error_data["traceback"] = traceback.format_exc()

            response = HttpResponse(json.dumps(error_data), content_type="application/json", status=500)

            # Log API errors
            logger.error(
                f"API Error: {exception}",
                extra={
                    "path": request.path,
                    "method": request.method,
                    "user_id": request.user.id if request.user.is_authenticated else None,
                },
            )

            return response

        return None


# ===============================================================================
# GDPR COMPLIANCE MIDDLEWARE
# ===============================================================================


class GDPRComplianceMiddleware:
    """GDPR compliance tracking for Romanian users"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Track consent for cookies and data processing
        if not request.session.get("gdpr_consent_shown"):
            # Mark that GDPR banner should be shown
            request.gdpr_banner_required = True
            request.session["gdpr_consent_shown"] = True

        response = self.get_response(request)

        # Add privacy policy header
        response["X-Privacy-Policy"] = "/privacy-policy/"

        return response


# ===============================================================================
# PORTAL SERVICE HMAC AUTHENTICATION MIDDLEWARE
# ===============================================================================


# Exempt paths: endpoints accessible WITHOUT HMAC authentication.
# These are for truly public/unauthenticated external callers only.
# The Portal's PlatformAPIClient always signs ALL requests with HMAC,
# so portal calls never rely on this exempt list.
# The startswith->exact-match change (commit 2577b41d) was intentional:
# it prevents unintended sub-path exemptions (e.g., /api/users/password/reset/confirm/).
# Exempt paths stored without trailing slash; matching normalizes both sides.
#
# Each exempt path must have @public_api_endpoint on the corresponding view.
# CI test tests.api.test_api_auth_coverage enforces this invariant.
_AUTH_EXEMPT_EXACT_PATHS_RAW: frozenset[str] = frozenset(
    {
        "/api/users/register",
        "/api/users/password/reset",
        "/api/users/health",
        "/api/orders/products",
    }
)


def _is_auth_exempt(path: str) -> bool:
    """Check if a request path is exempt from HMAC authentication.

    Normalizes trailing slashes so both '/api/users/register' and
    '/api/users/register/' match, regardless of Django's APPEND_SLASH setting.
    """
    return path.rstrip("/") in _AUTH_EXEMPT_EXACT_PATHS_RAW


class PortalServiceHMACMiddleware:
    """
    🔐 HMAC authentication middleware for portal service API requests.

    Validates HMAC signatures with nonce deduplication and timestamp validation.
    Only applies to /api/ endpoints. Replaces simple shared secret authentication.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        # Rate limit config (fallbacks if not in settings)
        self._rl_window = int(getattr(settings, "HMAC_RATE_LIMIT_WINDOW", 60))
        self._rl_max_calls = int(getattr(settings, "HMAC_RATE_LIMIT_MAX_CALLS", 300))

    def _rate_limited(self, portal_id: str, client_ip: str) -> tuple[bool, int]:
        """Rate limiting keyed by portal_id and IP with accurate remaining wait seconds."""
        key = f"hmac_rl:{portal_id}:{client_ip}"
        window_start_key = f"{key}:start"
        now = time.time()
        try:
            # Initialize counter if absent
            cache.add(key, 0, timeout=self._rl_window)
            cache.add(window_start_key, now, timeout=self._rl_window)
            # Increment atomically
            current = cache.incr(key)
        except Exception:
            # Fallback if backend doesn't support incr reliably
            current = (cache.get(key) or 0) + 1
            cache.set(key, current, timeout=self._rl_window)
            if cache.get(window_start_key) is None:
                cache.set(window_start_key, now, timeout=self._rl_window)

        if current <= self._rl_max_calls:
            return False, 0

        window_start_raw = cache.get(window_start_key)
        try:
            window_start = float(window_start_raw)
        except (TypeError, ValueError):
            window_start = now

        elapsed = max(0.0, now - window_start)
        retry_after = max(1, math.ceil(self._rl_window - elapsed))
        return True, retry_after

    def _validate_hmac_signature(  # noqa: C901, PLR0912, PLR0915  # Complexity: multi-step business logic
        self, request: HttpRequest
    ) -> tuple[bool, str]:  # Complexity: HMAC validation  # Complexity: multi-step business logic
        """
        Validate HMAC signature from portal service.
        Returns (is_valid, error_message)

        NOTE: High complexity is justified for security-critical HMAC validation.
        Each branch addresses a specific attack vector (replay, tampering, etc.)
        """
        error_msg = ""
        try:
            # Extract HMAC headers
            portal_id = request.META.get("HTTP_X_PORTAL_ID", "")
            nonce = request.META.get("HTTP_X_NONCE", "")
            timestamp = request.META.get("HTTP_X_TIMESTAMP", "")
            body_hash = request.META.get("HTTP_X_BODY_HASH", "")
            signature = request.META.get("HTTP_X_SIGNATURE", "")
            raw_content_type = request.META.get("CONTENT_TYPE", "")

            # Check required headers
            if not all([portal_id, nonce, timestamp, body_hash, signature]):
                error_msg = "Missing HMAC authentication headers"

            # Validate nonce format (must be sufficient length to prevent collisions)
            if not error_msg and (len(nonce) < HMAC_NONCE_MIN_LENGTH or len(nonce) > HMAC_NONCE_MAX_LENGTH):
                error_msg = "Invalid nonce format"

            # Validate timestamp (5-minute window)
            request_body = b""
            if not error_msg:
                try:
                    # int(float()) accepts both "123" and "123.456" for rolling-deploy safety
                    request_time = int(float(timestamp))
                    current_time = int(time.time())
                    # Allow 2s forward skew for NTP jitter between portal and platform clocks.
                    if not (-HMAC_NTP_SKEW_SECONDS <= (current_time - request_time) <= HMAC_TIMESTAMP_WINDOW_SECONDS):
                        error_msg = "Request timestamp outside allowed window"
                except ValueError:
                    error_msg = "Invalid timestamp format"

            # Check for nonce replay using shared cache with TTL (scoped by portal)
            if not error_msg:
                nonce_key = f"hmac_nonce:{portal_id}:{nonce}"
                # +30s buffer ensures nonces outlive their timestamp validity window
                added = cache.add(nonce_key, True, timeout=HMAC_TIMESTAMP_WINDOW_SECONDS + 30)
                if not added:
                    error_msg = "Nonce already used (replay attack)"

            # Enforce body size limit before reading into memory (DoS prevention)
            if not error_msg:
                max_body_size = 10 * 1024 * 1024  # 10 MB
                content_length = int(request.META.get("CONTENT_LENGTH") or 0)
                if content_length > max_body_size:
                    error_msg = "Request body too large"

            # Verify body hash
            if not error_msg:
                request_body = request.body
                computed_body_hash = base64.b64encode(hashlib.sha256(request_body).digest()).decode("ascii")
                if body_hash != computed_body_hash:
                    error_msg = "Body hash mismatch"

            # Get portal secret for this portal ID
            expected_secret = None
            if not error_msg:
                expected_secret = getattr(settings, "PLATFORM_API_SECRET", None)
                if not expected_secret:
                    error_msg = "Portal authentication not configured"

            # Build canonical string and verify signature
            if not error_msg:
                method = request.method.upper() if request.method else ""
                full_path = request.get_full_path()
                parsed = urllib.parse.urlsplit(full_path)
                query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                query_pairs.sort(key=lambda kv: (kv[0], kv[1]))
                normalized_query = urllib.parse.urlencode(query_pairs, doseq=True)
                normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

                content_type_main = raw_content_type.split(";")[0].strip().lower()

                canonical_new = "\n".join(
                    [
                        method,
                        normalized_path,
                        content_type_main,
                        body_hash,  # body_hash cryptographically covers any timestamp embedded in the body
                        portal_id,
                        nonce,
                        timestamp,  # authoritative timestamp; body hash makes a separate body check redundant
                    ]
                )

                expected_signature_new = hmac.new(
                    expected_secret.encode(),  # type: ignore[union-attr]
                    canonical_new.encode(),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(signature, expected_signature_new):
                    error_msg = "HMAC signature verification failed"

            if not error_msg:
                return True, ""

        except Exception as e:
            logger.error(f"🔥 [HMAC Auth] Signature validation error: {e}")
            error_msg = f"Signature validation error: {e!s}"

        return False, error_msg

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Process API and billing requests — both require HMAC authentication.
        # NOTE: /billing/ endpoints (create-payment-intent, confirm-payment, process-refund)
        # are inter-service endpoints called by Portal with HMAC signatures.
        if request.path.startswith("/api/") or request.path.startswith("/billing/"):
            # Skip HMAC validation for public endpoints only (exact match to prevent bypass).
            # NOTE: /api/users/login/ is NOT exempt - the portal service signs
            # login requests with HMAC, so we validate portal origin to prevent
            # direct credential brute-force from external attackers.
            if _is_auth_exempt(request.path):
                logger.debug("🔓 [HMAC Auth] Skipping HMAC validation for auth endpoint: %s", request.path)
                return self.get_response(request)

            client_ip = get_safe_client_ip(request)
            rate_limit_enabled: bool = getattr(settings, "RATE_LIMITING_ENABLED", True)

            # Validate HMAC signature first so rate limiting uses the verified portal_id,
            # not an attacker-controlled header value.
            is_valid, error_msg = self._validate_hmac_signature(request)

            if not is_valid:
                # Allow session-authenticated staff users to access specific API paths
                # that platform templates call via browser fetch() (no HMAC headers).
                # Restricted to an explicit allowlist to prevent broad bypass.
                staff_session_allowed_prefixes = [
                    "/api/customers/",  # Ticket form: fetch customer services
                    "/billing/invoices/",  # Staff billing UI: invoice list & detail
                    "/billing/proformas/",  # Staff billing UI: proforma management
                    "/billing/payments/",  # Staff billing UI: payment list
                    "/billing/reports/",  # Staff billing UI: billing reports
                    "/billing/e-factura/",  # Staff billing UI: e-Factura dashboard
                ]
                if (
                    getattr(request, "user", None)
                    and getattr(request.user, "is_authenticated", False)
                    and getattr(request.user, "is_staff", False)
                    and any(request.path.startswith(p) for p in staff_session_allowed_prefixes)
                ):
                    logger.debug(
                        f"🔓 [HMAC Auth] Allowing session-authenticated staff user {getattr(request.user, 'email', '')} for {request.path}"
                    )
                    return self.get_response(request)

                logger.warning(f"🔥 [HMAC Auth] Authentication failed from {client_ip}: {error_msg}")
                return HttpResponse(
                    json.dumps({"error": "HMAC authentication failed"}), status=401, content_type="application/json"
                )

            # Mark as portal-authenticated after successful HMAC validation.
            # Identity comes from signed body in API layer; X-User-Id header is ignored.
            request._portal_authenticated = True
            request._portal_id = request.META.get("HTTP_X_PORTAL_ID", "unknown")

            # Post-auth rate limiting: keyed by the verified portal_id (not the raw header).
            if rate_limit_enabled:
                is_limited, retry_after = self._rate_limited(request._portal_id, client_ip)
                if is_limited:
                    logger.warning(f"🚨 [HMAC Auth] Rate limit exceeded for portal={request._portal_id} ip={client_ip}")
                    response = HttpResponse(
                        json.dumps(
                            {
                                "success": False,
                                "error": "Too many requests",
                                "detail": "Too Many Requests",
                                "retry_after": retry_after,
                                "status": 429,
                            }
                        ),
                        status=429,
                        content_type="application/json",
                    )
                    response["Retry-After"] = str(retry_after)
                    return response

            logger.info(f"✅ [HMAC Auth] API request authenticated from portal {request._portal_id} at {client_ip}")

        response = self.get_response(request)

        # Add service identification header
        if request.path.startswith("/api/"):
            response["X-Service"] = "platform"
            response["X-Portal-Auth"] = "hmac-verified" if hasattr(request, "_portal_authenticated") else "none"

        return response


# ===============================================================================
# SESSION SECURITY MIDDLEWARE
# ===============================================================================


class SessionSecurityMiddleware:
    """
    🔒 Automatic session security management for Romanian hosting compliance

    Features:
    - Dynamic timeout adjustment based on user role/context
    - Suspicious activity detection and logging
    - Session activity tracking
    - Shared device mode handling
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Only process authenticated users with sessions
        if request.user.is_authenticated and hasattr(request, "session"):
            self._process_session_security(request)

        response = self.get_response(request)

        # Add session security headers
        if request.user.is_authenticated:
            self._add_security_headers(request, response)

        return response

    def _process_session_security(self, request: HttpRequest) -> None:
        """Process session security checks and updates"""
        try:
            if SessionSecurityService is None:
                # Service not available due to circular import - skip processing
                return  # type: ignore[unreachable]

            # Update session timeout based on current context
            SessionSecurityService.update_session_timeout(request)

            # Detect and log suspicious activity
            is_suspicious = SessionSecurityService.detect_suspicious_activity(request)

            # Log session activity for important paths
            if self._should_log_activity(request):
                activity_type = self._get_activity_type(request)
                SessionSecurityService.log_session_activity(request, activity_type, is_suspicious=is_suspicious)

            # Handle shared device mode expiry
            if request.session.get("shared_device_mode"):
                self._check_shared_device_expiry(request)

        except Exception as e:
            # Don't break the request if session security fails
            logger.error(f"🔥 [SessionSecurityMiddleware] Error processing session security: {e}")

    def _should_log_activity(self, request: HttpRequest) -> bool:
        """Determine if this request should be logged for activity tracking"""
        sensitive_paths = ["/users/", "/billing/", "/customers/", "/admin/", "/api/", "/settings/", "/tickets/"]
        return any(request.path.startswith(path) for path in sensitive_paths)

    def _get_activity_type(self, request: HttpRequest) -> str:
        """Get activity type based on request path and method"""
        if request.path.startswith("/admin/"):
            return "admin_access"
        elif request.path.startswith("/billing/"):
            return "billing_access"
        elif request.path.startswith("/api/"):
            return "api_access"
        elif request.method in ["POST", "PUT", "PATCH", "DELETE"]:
            return "data_modification"
        else:
            return "page_access"

    def _check_shared_device_expiry(self, request: HttpRequest) -> None:
        """Check if shared device mode should expire based on inactivity"""
        enabled_at_str = request.session.get("shared_device_enabled_at")
        if not enabled_at_str:
            return

        try:
            enabled_at = datetime.fromisoformat(enabled_at_str)
            max_shared_duration = timedelta(hours=2)  # Max 2 hours in shared mode

            if timezone.now() - enabled_at > max_shared_duration:
                # Auto-disable shared device mode after extended use
                request.session.pop("shared_device_mode", None)
                request.session.pop("shared_device_enabled_at", None)

                if SessionSecurityService is not None:
                    SessionSecurityService.log_session_activity(
                        request, "shared_device_auto_expired", reason="max_duration_exceeded"
                    )

        except Exception as e:
            logger.error(f"🔥 [SessionSecurity] Error checking shared device expiry: {e}")

    def _add_security_headers(self, request: HttpRequest, response: HttpResponse) -> None:
        """Add session security headers to response"""
        # Add session timeout info for client-side warnings
        if hasattr(request, "session") and request.session.get_expiry_age():
            response["X-Session-Timeout"] = str(request.session.get_expiry_age())

        # Add shared device mode indicator
        if request.session.get("shared_device_mode"):
            response["X-Shared-Device-Mode"] = "true"


# ===============================================================================
# STAFF-ONLY PLATFORM ACCESS MIDDLEWARE
# ===============================================================================


class StaffOnlyPlatformMiddleware:
    """
    🛡️ Middleware to ensure only staff users can access the platform.

    - Staff users: Full access to platform
    - Customer users: Logged out and redirected with error message
    - Unauthenticated: Normal login flow continues

    Platform = Staff admin interface
    Portal = Customer self-service interface
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Skip middleware for public paths that need to be accessible
        public_paths = {
            "/auth/login/",
            "/auth/logout/",
            "/admin/",  # Django admin has its own authentication
            "/api/",  # API has its own authentication via portal service
            "/i18n/",  # Language switching
        }

        # Skip for public paths
        if any(request.path.startswith(path) for path in public_paths):
            return self.get_response(request)

        # Skip for unauthenticated users (let them reach login page)
        if not request.user.is_authenticated:
            return self.get_response(request)

        # Allow staff users full access
        if request.user.is_staff or getattr(request.user, "staff_role", None):
            return self.get_response(request)

        # Block customer users - they should use portal
        if request.user.is_authenticated:
            logout(request)
            messages.error(
                request, _("❌ Customers cannot access the platform. Please use the customer portal instead.")
            )
            return redirect("users:login")
