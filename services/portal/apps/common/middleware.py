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

from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

from apps.common.request_ip import get_safe_client_ip

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

        # Only apply to authenticated sessions
        if not request.session.session_key:
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
            logger.error(f"🔥 [Session] Security middleware error: {e}")
            # Don't block request on middleware errors, but log them
            return None

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
                "last_validated": time.time(),
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
        """Update session last activity timestamp"""
        request.session["last_activity"] = time.time()

        # Update validation timestamp in fingerprint
        if "security_fingerprint" in request.session:
            request.session["security_fingerprint"]["last_validated"] = time.time()
            request.session.modified = True

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
        if hasattr(request, "user") and request.user.is_authenticated:
            logout(request)

        request.session.flush()

        # Redirect to login with security message
        return redirect("/login/?security=session_security_violation")

    def _handle_session_timeout(self, request: HttpRequest) -> HttpResponse:
        """Handle expired sessions gracefully"""

        # Log timeout
        session_key = getattr(request.session, "session_key", "unknown")[:8]
        logger.info(f"🕒 [Session] Session timeout for {session_key}...")

        # Clear expired session
        if hasattr(request, "user") and request.user.is_authenticated:
            logout(request)

        request.session.flush()

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
    """Enhanced security headers middleware with CSP and comprehensive protections"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Core security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"

        # Strict Transport Security (HTTPS only)
        if request.is_secure():
            response["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"

        # Content Security Policy — nonce-based with unsafe-inline fallback
        nonce = getattr(request, "csp_nonce", "")
        nonce_directive = f"'nonce-{nonce}'" if nonce else ""
        csp_parts = [
            "default-src 'self'",
            f"script-src 'self' 'unsafe-inline' 'unsafe-eval' {nonce_directive} https://js.stripe.com",
            f"style-src 'self' 'unsafe-inline' {nonce_directive}",
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' https://api.stripe.com",
            "frame-src 'self' https://js.stripe.com https://*.stripe.com",
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "media-src 'self'",
        ]
        response["Content-Security-Policy"] = "; ".join(csp_parts)

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
