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
from django.contrib.sessions.backends.base import SessionBase
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

from apps.common.browser_identity import browser_identity
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
    - Browser binding (family and operating system, stamped at login; never the IP address)
    - Automatic session rotation
    - Session hijacking detection
    """

    # A session's lifetimes are Platform's; PortalAuthenticationMiddleware follows its deadlines.

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

    @staticmethod
    def stamp_fingerprint(session: SessionBase, user_agent: str) -> None:
        """Bind a new session to the browser that signed in (login calls this, ADR-0017 section 5)."""
        session["security_fingerprint"] = {
            "browser": browser_identity(user_agent),
            "user_agent_hash": hashlib.sha256(user_agent.encode()).hexdigest()[:16],
            "created_at": time.time(),
        }

    def _validate_session_integrity(self, request: HttpRequest) -> bool:
        """The session is still in the browser that signed in: same family and operating system.

        A browser update keeps it (the stored user agent is re-stamped); a new network does too. A
        session login did not stamp ends, unless PORTAL_BROWSER_FINGERPRINT_REQUIRED is off (tests
        that build a session by hand), in which case it is bound now.
        """
        session = request.session
        user_agent = request.META.get("HTTP_USER_AGENT", "")
        fingerprint = session.get("security_fingerprint")
        if not isinstance(fingerprint, dict) or "browser" not in fingerprint:
            if getattr(settings, "PORTAL_BROWSER_FINGERPRINT_REQUIRED", True):
                logger.warning(f"🔒 [Session] No browser binding for {(session.session_key or 'unknown')[:8]}...")
                return False
            self.stamp_fingerprint(session, user_agent)
            return True

        if fingerprint["browser"] != browser_identity(user_agent):
            logger.warning(
                f"🔒 [Session] Browser changed for session {(session.session_key or 'unknown')[:8]}... "
                f"(expected: {fingerprint['browser']}, got: {browser_identity(user_agent)})"
            )
            return False

        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        if fingerprint.get("user_agent_hash") != user_agent_hash:
            session["security_fingerprint"] = {**fingerprint, "user_agent_hash": user_agent_hash}  # an update
        return True

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
