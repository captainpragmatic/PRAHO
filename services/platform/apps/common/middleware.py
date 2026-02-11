"""
Common middleware for PRAHO Platform
Security headers, Romanian compliance, and audit logging.
"""

import base64
import hashlib
import hmac
import json
import logging
import os
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

from apps.common.constants import HTTP_CLIENT_ERROR_THRESHOLD
from apps.common.request_ip import get_safe_client_ip

# Security constants
HMAC_TIMESTAMP_WINDOW_SECONDS = 300  # 5 minutes

# Import logging utilities for request ID propagation
from apps.common.logging import clear_request_id, set_request_id

# Import for session security - handle potential circular import gracefully
try:
    from apps.users.services import SessionSecurityService
except ImportError:
    SessionSecurityService = None  # type: ignore[assignment,misc]

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
            request.gdpr_banner_required = True  # type: ignore[attr-defined]
            request.session["gdpr_consent_shown"] = True

        response = self.get_response(request)

        # Add privacy policy header
        response["X-Privacy-Policy"] = "/privacy-policy/"

        return response


# ===============================================================================
# PORTAL SERVICE AUTHENTICATION MIDDLEWARE
# ===============================================================================


class PortalServiceAuthMiddleware:
    """
    🔐 Authentication middleware for portal service API requests.
    
    Validates shared secret and sets up user context for API endpoints.
    Only applies to /api/ endpoints.
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Only process API requests
        if request.path.startswith('/api/'):
            # Check for service authentication header
            service_auth = request.META.get('HTTP_X_SERVICE_AUTH')
            
            if not service_auth:
                return HttpResponse(
                    json.dumps({'error': 'Service authentication required'}),
                    status=401,
                    content_type='application/json'
                )
            
            # Validate shared secret
            expected_secret = getattr(settings, 'PLATFORM_API_SECRET', None)
            if not expected_secret or service_auth != expected_secret:
                logger.warning(f"🔥 [Portal Auth] Invalid service auth from {get_safe_client_ip(request)}")
                return HttpResponse(
                    json.dumps({'error': 'Invalid service authentication'}),
                    status=403,
                    content_type='application/json'
                )
            
            # Extract user context from portal service
            user_id = request.META.get('HTTP_X_USER_ID')
            if user_id:
                try:
                    user_id = int(user_id)
                    # Get user from database
                    user = User.objects.get(id=user_id)
                    # Set user context for API request (don't actually log them in)
                    request.user = user
                    request._portal_authenticated = True  # Mark as portal-authenticated
                    
                    logger.debug(f"✅ [Portal Auth] User context set for API request: {user.email}")
                    
                except (ValueError, User.DoesNotExist):
                    logger.warning(f"🔥 [Portal Auth] Invalid user ID in API request: {user_id}")
                    return HttpResponse(
                        json.dumps({'error': 'Invalid user context'}),
                        status=400,
                        content_type='application/json'
                    )
            
            # Log successful portal service authentication
            logger.info(f"✅ [Portal Auth] API request authenticated from {get_safe_client_ip(request)}")
        
        response = self.get_response(request)
        
        # Add service identification header
        if request.path.startswith('/api/'):
            response['X-Service'] = 'platform'
            response['X-Portal-Auth'] = 'verified' if hasattr(request, '_portal_authenticated') else 'none'
        
        return response


# ===============================================================================
# PORTAL SERVICE HMAC AUTHENTICATION MIDDLEWARE
# ===============================================================================


class PortalServiceHMACMiddleware:
    """
    🔐 HMAC authentication middleware for portal service API requests.
    
    Validates HMAC signatures with nonce deduplication and timestamp validation.
    Only applies to /api/ endpoints. Replaces simple shared secret authentication.
    """
    
    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response
        # Rate limit config (fallbacks if not in settings)
        self._rl_window = int(getattr(settings, 'HMAC_RATE_LIMIT_WINDOW', 60))
        self._rl_max_calls = int(getattr(settings, 'HMAC_RATE_LIMIT_MAX_CALLS', 300))

    def _rate_limited(self, portal_id: str, client_ip: str) -> bool:
        """Simple rate limiting keyed by portal_id and client IP using Django cache."""
        try:
            key = f"hmac_rl:{portal_id}:{client_ip}"
            # Initialize counter if absent
            cache.add(key, 0, timeout=self._rl_window)
            # Increment atomically
            current = cache.incr(key)
        except Exception:
            # Fallback if backend doesn't support incr reliably
            current = (cache.get(key) or 0) + 1
            cache.set(key, current, timeout=self._rl_window)
        return current > self._rl_max_calls
    
    def _validate_hmac_signature(self, request: HttpRequest) -> tuple[bool, str]:  # noqa: C901,PLR0912,PLR0915
        """
        Validate HMAC signature from portal service.
        Returns (is_valid, error_message)
        
        NOTE: High complexity is justified for security-critical HMAC validation.
        Each branch addresses a specific attack vector (replay, tampering, etc.)
        """
        error_msg = ""
        try:
            # Extract HMAC headers
            portal_id = request.META.get('HTTP_X_PORTAL_ID', '')
            nonce = request.META.get('HTTP_X_NONCE', '')
            timestamp = request.META.get('HTTP_X_TIMESTAMP', '')
            body_hash = request.META.get('HTTP_X_BODY_HASH', '')
            signature = request.META.get('HTTP_X_SIGNATURE', '')
            raw_content_type = request.META.get('CONTENT_TYPE', '')

            # Check required headers
            if not all([portal_id, nonce, timestamp, body_hash, signature]):
                error_msg = "Missing HMAC authentication headers"

            # Validate timestamp (5-minute window)
            request_body = b""
            if not error_msg:
                try:
                    request_time = float(timestamp)
                    current_time = time.time()
                    if abs(current_time - request_time) > HMAC_TIMESTAMP_WINDOW_SECONDS:
                        error_msg = "Request timestamp outside allowed window"
                except ValueError:
                    error_msg = "Invalid timestamp format"

            # Check for nonce replay using shared cache with TTL (scoped by portal)
            if not error_msg:
                nonce_key = f"hmac_nonce:{portal_id}:{nonce}"
                # TTL matches timestamp window to mirror freshness guarantees
                added = cache.add(nonce_key, True, timeout=HMAC_TIMESTAMP_WINDOW_SECONDS)
                if not added:
                    error_msg = "Nonce already used (replay attack)"

            # Verify body hash
            if not error_msg:
                request_body = request.body
                computed_body_hash = base64.b64encode(hashlib.sha256(request_body).digest()).decode('ascii')
                if body_hash != computed_body_hash:
                    error_msg = "Body hash mismatch"

            # Get portal secret for this portal ID
            expected_secret = None
            if not error_msg:
                expected_secret = getattr(settings, 'PLATFORM_API_SECRET', None)
                if not expected_secret:
                    error_msg = "Portal authentication not configured"

            # Build canonical string and verify signature
            if not error_msg:
                method = request.method.upper()
                full_path = request.get_full_path()
                parsed = urllib.parse.urlsplit(full_path)
                query_pairs = urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)
                query_pairs.sort(key=lambda kv: (kv[0], kv[1]))
                normalized_query = urllib.parse.urlencode(query_pairs, doseq=True)
                normalized_path = parsed.path + ("?" + normalized_query if normalized_query else "")

                content_type_main = raw_content_type.split(";")[0].strip().lower()

                canonical_new = "\n".join([
                    method,
                    normalized_path,
                    content_type_main,
                    body_hash,
                    portal_id,
                    nonce,
                    timestamp,
                ])

                expected_signature_new = hmac.new(
                    expected_secret.encode(),  # type: ignore[union-attr]
                    canonical_new.encode(),
                    hashlib.sha256,
                ).hexdigest()
                if not hmac.compare_digest(signature, expected_signature_new):
                    error_msg = "HMAC signature verification failed"

            # Enforce timestamp consistency between header and signed body
            if not error_msg:
                try:
                    body_json = json.loads(request_body.decode('utf-8') or '{}')
                    body_ts = body_json.get('timestamp')
                    if body_ts is None or str(body_ts) != str(timestamp):
                        error_msg = "Timestamp mismatch between body and headers"
                except Exception:
                    error_msg = "Invalid JSON body for timestamp validation"

            if not error_msg:
                return True, ""

        except Exception as e:
            logger.error(f"🔥 [HMAC Auth] Signature validation error: {e}")
            error_msg = f"Signature validation error: {e!s}"

        return False, error_msg
    
    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Only process API requests
        if request.path.startswith('/api/'):
            # Skip HMAC validation for authentication endpoints (can't be pre-authenticated)
            auth_exempt_paths = [
                '/api/users/login/',
                '/api/users/register/',  
                '/api/users/password/reset/',
                '/api/users/health/',
                '/api/orders/products/'  # Public product catalog access
            ]
            
            if any(request.path.startswith(path) for path in auth_exempt_paths):
                logger.debug(f"🔓 [HMAC Auth] Skipping HMAC validation for auth endpoint: {request.path}")
                return self.get_response(request)
            
            # Global rate limiting keyed by portal and IP (respects RATELIMIT_ENABLE env var)
            portal_id_for_rl = request.META.get('HTTP_X_PORTAL_ID', 'unknown')
            client_ip = get_safe_client_ip(request)
            if os.environ.get("RATELIMIT_ENABLE", "true").lower() != "false" and self._rate_limited(portal_id_for_rl, client_ip):
                logger.warning(
                    f"🚨 [HMAC Auth] Rate limit exceeded for portal={portal_id_for_rl} ip={client_ip}"
                )
                return HttpResponse(
                    json.dumps({'error': 'Too Many Requests'}),
                    status=429,
                    content_type='application/json'
                )

            # Validate HMAC signature
            is_valid, error_msg = self._validate_hmac_signature(request)
            
            if not is_valid:
                # Allow session-authenticated staff users to access API endpoints.
                # Platform templates (e.g., ticket form) make fetch() calls to /api/
                # using the browser session — these don't carry HMAC headers.
                if getattr(request, 'user', None) and getattr(request.user, 'is_authenticated', False) and getattr(request.user, 'is_staff', False):
                    logger.debug(f"🔓 [HMAC Auth] Allowing session-authenticated staff user {request.user.email} for {request.path}")
                    return self.get_response(request)

                logger.warning(f"🔥 [HMAC Auth] Authentication failed from {get_safe_client_ip(request)}: {error_msg}")
                return HttpResponse(
                    json.dumps({'error': 'HMAC authentication failed'}),
                    status=401,
                    content_type='application/json'
                )
            
            # Mark as portal-authenticated after successful HMAC validation
            request._portal_authenticated = True
            
            # Identity now comes from signed body in API layer; ignore any X-User-Id header
            
            # Mark portal ID for logging
            request._portal_id = request.META.get('HTTP_X_PORTAL_ID', 'unknown')
            
            # Log successful portal service authentication
            logger.info(f"✅ [HMAC Auth] API request authenticated from portal {request._portal_id} at {get_safe_client_ip(request)}")
        
        response = self.get_response(request)
        
        # Add service identification header
        if request.path.startswith('/api/'):
            response['X-Service'] = 'platform'
            response['X-Portal-Auth'] = 'hmac-verified' if hasattr(request, '_portal_authenticated') else 'none'
        
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
            "/users/login/",
            "/users/logout/",
            "/admin/",      # Django admin has its own authentication
            "/api/",        # API has its own authentication via portal service
            "/i18n/",       # Language switching
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
                request, 
                _("❌ Customers cannot access the platform. Please use the customer portal instead.")
            )
            return redirect("users:login")
        
        # Fallback - continue with request  
        return self.get_response(request)
