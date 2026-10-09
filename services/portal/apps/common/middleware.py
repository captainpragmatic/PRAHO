"""
Common middleware for PRAHO Portal Service
Enhanced with security features for session protection and attack prevention.
"""

import hashlib
import logging
import threading
import time
import uuid
from collections.abc import Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

from apps.common.request_ip import get_safe_client_ip
from apps.common.store_unavailable import end_session_or_unavailable

logger = logging.getLogger(__name__)

# Thread-local storage for request ID (portal equivalent of platform's logging.py)
_request_context = threading.local()


def set_request_id(request_id: str) -> None:
    """Set the current request ID in thread-local storage."""
    _request_context.request_id = request_id


def get_request_id() -> str | None:
    """Get the current request ID from thread-local storage."""
    return getattr(_request_context, "request_id", None)


def clear_request_id() -> None:
    """Clear the request ID from thread-local storage."""
    _request_context.request_id = None


class RequestIDFilter(logging.Filter):
    """Add request_id to log records from thread-local storage."""

    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = getattr(_request_context, "request_id", None) or "-" * 36
        return True


class RequestIDMiddleware:
    """Add unique request ID for tracing"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.META["REQUEST_ID"] = request_id
        set_request_id(request_id)

        try:
            # Add to response headers for debugging
            response = self.get_response(request)
            response["X-Request-ID"] = request_id
            return response
        finally:
            clear_request_id()


class SessionSecurityMiddleware(MiddlewareMixin):
    """
    🔒 Enhanced session security middleware to prevent session attacks.

    Features:
    - Session IP binding validation
    - User agent binding validation
    - Session timeout enforcement
    - Automatic session rotation
    - Session hijacking detection
    """

    # Security constants
    SESSION_TIMEOUT_SECONDS = 3600  # 1 hour default
    ACTIVITY_STAMP_INTERVAL_SECONDS = 60  # Refresh last_activity at most this often
    MAX_SESSION_AGE_SECONDS = 8 * 3600  # 8 hours absolute max
    IP_CHANGE_TOLERANCE = False  # Strict IP binding by default

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        super().__init__(get_response)

    def process_request(self, request: HttpRequest) -> HttpResponse | None:
        """🔒 Process incoming request for session security validation"""

        # Skip security checks for certain paths
        if self._should_skip_security(request):
            return None

        # Only apply to authenticated sessions.
        # Guard on "user_id" rather than session_key so the middleware stays
        # backend-agnostic (signed-cookie sessions always return session_key=None).
        if "user_id" not in request.session:
            return None

        try:
            # 🔒 SECURITY: Validate session integrity
            if not self._validate_session_integrity(request):
                logger.warning(
                    f"🔒 [Session] Session integrity failed for {(request.session.session_key or 'unknown')[:8]}..."
                )
                return self._handle_security_violation(request, "session_integrity_failed")

            # 🔒 SECURITY: Check session timeout
            if self._is_session_expired(request):
                logger.info(f"🔒 [Session] Session expired for {(request.session.session_key or 'unknown')[:8]}...")
                return self._handle_session_timeout(request)

            # 🔒 SECURITY: Update last activity
            self._update_session_activity(request)

            return None

        except Exception as e:
            logger.error(f"🔥 [Session] Security middleware error: {e}", exc_info=True)
            # Fail CLOSED: programming bugs must not silently grant access (ADR-0017)
            return self._handle_security_violation(request, "middleware_error")

    def _should_skip_security(self, request: HttpRequest) -> bool:
        """Check if security validation should be skipped for this path"""
        skip_paths = [
            "/static/",
            "/media/",
            "/health/",
            "/favicon.ico",
            "/.well-known/",
        ]

        path = request.path
        return any(path.startswith(skip_path) for skip_path in skip_paths)

    def _validate_session_integrity(self, request: HttpRequest) -> bool:
        """🔒 Validate session hasn't been hijacked or tampered with"""

        # Get current session data
        session = request.session
        client_ip = self._get_client_ip(request)
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]

        # Check for first-time session setup
        if "security_fingerprint" not in session:
            # Initialize security fingerprint
            session["security_fingerprint"] = {
                "ip_hash": hashlib.sha256(client_ip.encode()).hexdigest()[:16],
                "user_agent_hash": user_agent_hash,
                "created_at": time.time(),
            }
            session.modified = True
            logger.info(f"🔒 [Session] Security fingerprint created for {(session.session_key or 'unknown')[:8]}...")
            return True

        fingerprint = session["security_fingerprint"]

        # 🔒 SECURITY: Validate IP address hasn't changed
        expected_ip_hash = fingerprint.get("ip_hash", "")
        current_ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]

        if not self.IP_CHANGE_TOLERANCE and expected_ip_hash != current_ip_hash:
            logger.warning(
                f"🔒 [Session] IP address changed for session {(session.session_key or 'unknown')[:8]}... "
                f"(expected: {expected_ip_hash}, got: {current_ip_hash})"
            )
            return False

        # 🔒 SECURITY: Validate user agent hasn't changed significantly
        expected_ua_hash = fingerprint.get("user_agent_hash", "")
        if expected_ua_hash != user_agent_hash:
            logger.warning(
                f"🔒 [Session] User agent changed for session {(session.session_key or 'unknown')[:8]}... "
                f"(expected: {expected_ua_hash}, got: {user_agent_hash})"
            )
            return False

        return True

    def _is_session_expired(self, request: HttpRequest) -> bool:
        """🔒 Check if session has exceeded timeout limits"""

        session = request.session
        current_time = time.time()

        # Check last activity timeout
        last_activity = session.get("last_activity", current_time)
        if current_time - last_activity > self.SESSION_TIMEOUT_SECONDS:
            return True

        # Check absolute session age
        fingerprint = session.get("security_fingerprint", {})
        created_at = fingerprint.get("created_at", current_time)
        return bool(current_time - created_at > self.MAX_SESSION_AGE_SECONDS)

    def _update_session_activity(self, request: HttpRequest) -> None:
        """Refresh the session's last-activity stamp, at most once a minute.

        Every write saves the whole session row, so stamping every request made two concurrent
        requests of one customer race, and the later save could undo the earlier one's changes.
        A missing stamp is written at once: `_is_session_expired` reads it as "now", so it must
        not stay missing. Idle expiry can therefore fire up to a minute early, never late.
        """
        now = time.time()
        last_activity = request.session.get("last_activity")
        if last_activity is None or now - last_activity >= self.ACTIVITY_STAMP_INTERVAL_SECONDS:
            request.session["last_activity"] = now

    def _handle_security_violation(self, request: HttpRequest, violation_type: str) -> HttpResponse:
        """🔒 Handle detected security violations"""

        session_key_raw = getattr(request.session, "session_key", "unknown")
        session_key = (session_key_raw or "unknown")[:8]

        # Log security event
        logger.error(
            f"🚨 [Security] Session security violation: {violation_type} "
            f"for session {session_key}... from IP {self._get_client_ip(request)}"
        )

        # Clear potentially compromised session
        unavailable_response = end_session_or_unavailable(request)
        if unavailable_response is not None:
            return unavailable_response

        # Redirect to login with security message
        return redirect("/login/?security=session_security_violation")

    def _handle_session_timeout(self, request: HttpRequest) -> HttpResponse:
        """Handle expired sessions gracefully"""

        # Log timeout
        session_key = (getattr(request.session, "session_key", None) or "unknown")[:8]
        logger.info(f"🕒 [Session] Session timeout for {session_key}...")

        # Clear expired session
        unavailable_response = end_session_or_unavailable(request)
        if unavailable_response is not None:
            return unavailable_response

        # Redirect to login with timeout message
        return redirect("/login/?timeout=session_expired")

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        return get_safe_client_ip(request)


class CSPNonceMiddleware:
    """Generate a per-request CSP nonce for inline scripts/styles.

    Must be placed BEFORE SecurityHeadersMiddleware in MIDDLEWARE.
    """

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        import secrets  # noqa: PLC0415

        request.csp_nonce = secrets.token_urlsafe(32)
        return self.get_response(request)


class SecurityHeadersMiddleware:
    """Enhanced security headers middleware with CSP and comprehensive protections."""

    # Byte-exact current policy (see #104 [M7]). The default profile MUST emit
    # this unchanged so the CSP-hardening rollout never regresses the live header.
    _CURRENT_CSP_PARTS: tuple[str, ...] = (
        "default-src 'self'",
        "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com",
        "style-src 'self' 'unsafe-inline'",
        "img-src 'self' data: https:",
        "font-src 'self'",
        "connect-src 'self' https://api.stripe.com",
        "frame-src 'self' https://js.stripe.com https://*.stripe.com",
        "frame-ancestors 'none'",
        "form-action 'self'",
        "base-uri 'self'",
        "object-src 'none'",
        "media-src 'self'",
    )

    _TARGET_CSP_PROFILES: frozenset[str] = frozenset(
        {
            "phase2-target",
            "phase3-target",
        }
    )

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    @classmethod
    def _build_csp_parts(cls, request: HttpRequest) -> tuple[str, ...]:
        """Build the server-selected CSP, falling back to current when unsafe."""
        profile = str(getattr(settings, "CSP_PROFILE", "current"))

        if profile == "current" or profile not in cls._TARGET_CSP_PROFILES:
            return cls._CURRENT_CSP_PARTS

        nonce = getattr(request, "csp_nonce", None)
        if not isinstance(nonce, str) or not nonce:
            return cls._CURRENT_CSP_PARTS

        if profile == "phase2-target":
            script_src = f"script-src 'self' 'nonce-{nonce}' 'unsafe-eval' https://js.stripe.com"
        else:
            script_src = f"script-src 'self' 'nonce-{nonce}' https://js.stripe.com"

        target_parts = list(cls._CURRENT_CSP_PARTS)
        target_parts[1] = script_src
        target_parts.insert(2, "script-src-attr 'none'")
        return tuple(target_parts)

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Core security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")

        # Strict-Transport-Security is NOT set here. Django's SecurityMiddleware sets it from the
        # SECURE_HSTS_* settings, and only when the header is absent, so a hardcoded value here made
        # those settings dead (staging's one-hour policy included).

        # CSP rollout profiles (#104 [M7]) separate policy qualification from
        # disposition. "current" preserves unsafe-inline until nonce migration
        # is qualified; target profiles inject the per-request nonce and
        # progressively remove unsafe-inline and unsafe-eval. CSP_REPORT_ONLY
        # switches the header name without changing the policy content.
        csp = "; ".join(self._build_csp_parts(request))
        csp_header = (
            "Content-Security-Policy-Report-Only"
            if bool(getattr(settings, "CSP_REPORT_ONLY", False))
            else "Content-Security-Policy"
        )
        response[csp_header] = csp

        # 🔒 SECURITY: Permissions Policy (formerly Feature Policy)
        permissions_policy_parts = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=(self)",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()",
        ]
        response["Permissions-Policy"] = ", ".join(permissions_policy_parts)

        # Portal identification
        response["X-Service"] = "portal"

        return response
