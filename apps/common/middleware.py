"""
Common middleware for PRAHO Platform
Security headers, Romanian compliance, and audit logging.
"""

import json
import logging
import time
import traceback
import uuid
from collections.abc import Callable
from datetime import datetime, timedelta

from django.conf import settings
from django.contrib.auth import get_user_model
from django.http import HttpRequest, HttpResponse
from django.utils import timezone

from apps.common.constants import HTTP_CLIENT_ERROR_THRESHOLD

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
    """Add unique request ID for tracing and audit logs"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.META['REQUEST_ID'] = request_id

        # Add to response headers for debugging
        response = self.get_response(request)
        response['X-Request-ID'] = request_id

        return response


# ===============================================================================
# SECURITY MIDDLEWARE
# ===============================================================================

class SecurityHeadersMiddleware:
    """Add security headers for Romanian hosting compliance"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Content Security Policy - Enhanced security
        if not response.get('Content-Security-Policy'):
            csp = (
                "default-src 'self'; "
                "style-src 'self' 'unsafe-inline' fonts.googleapis.com; "  # unsafe-inline needed for Tailwind
                "font-src 'self' fonts.gstatic.com; "
                "script-src 'self' 'unsafe-inline'; "  # Removed unsafe-eval for better security
                "img-src 'self' data: https:; "
                "connect-src 'self'; "
                "object-src 'none'; "  # Prevent Flash/Java execution
                "base-uri 'self'; "    # Prevent base tag injection
                "form-action 'self';"  # Restrict form submissions
            )
            response['Content-Security-Policy'] = csp

        # Other security headers
        response['X-Content-Type-Options'] = 'nosniff'
        response['X-Frame-Options'] = 'DENY'
        response['X-XSS-Protection'] = '1; mode=block'
        response['Referrer-Policy'] = 'strict-origin-when-cross-origin'

        # Romanian privacy compliance
        response['X-Powered-By'] = 'PragmaticHost Romania'

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
            'event': 'request',
            'method': request.method,
            'path': request.path,
            'user_id': user_id,
            'ip_address': self._get_client_ip(request),
            'user_agent': request.META.get('HTTP_USER_AGENT', ''),
            'timestamp': time.time(),
        }

        # Don't log sensitive data
        if request.path.startswith('/admin/') or 'password' in request.path.lower():
            audit_data['sensitive'] = True
        else:
            audit_data['query_params'] = dict(request.GET)

        logger.info('audit', extra=audit_data)

    def _log_response(self, request: HttpRequest, response: HttpResponse, duration: float) -> None:
        """Log response"""
        user_id = request.user.id if request.user.is_authenticated else None

        audit_data = {
            'event': 'response',
            'method': request.method,
            'path': request.path,
            'status_code': response.status_code,
            'user_id': user_id,
            'duration_ms': round(duration * 1000, 2),
            'timestamp': time.time(),
        }

        # Log errors with more detail
        if response.status_code >= HTTP_CLIENT_ERROR_THRESHOLD:
            audit_data['error'] = True
            if hasattr(response, 'content'):
                audit_data['response_size'] = len(response.content)

        logger.info('audit', extra=audit_data)

    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        ip = x_forwarded_for.split(',')[0] if x_forwarded_for else request.META.get('REMOTE_ADDR')
        return ip


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
        if request.path.startswith('/api/') and not response.get('Content-Type'):
            response['Content-Type'] = 'application/json'

        return response

    def process_exception(self, request: HttpRequest, exception: Exception) -> HttpResponse:
        """Handle API exceptions as JSON"""
        if request.path.startswith('/api/'):
            error_data = {
                'error': True,
                'message': str(exception),
                'type': exception.__class__.__name__,
            }

            if settings.DEBUG:
                error_data['traceback'] = traceback.format_exc()

            response = HttpResponse(
                json.dumps(error_data),
                content_type='application/json',
                status=500
            )

            # Log API errors
            logger.error(f'API Error: {exception}', extra={
                'path': request.path,
                'method': request.method,
                'user_id': request.user.id if request.user.is_authenticated else None,
            })

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
        if not request.session.get('gdpr_consent_shown'):
            # Mark that GDPR banner should be shown
            request.gdpr_banner_required = True
            request.session['gdpr_consent_shown'] = True

        response = self.get_response(request)

        # Add privacy policy header
        response['X-Privacy-Policy'] = '/privacy-policy/'

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
        if request.user.is_authenticated and hasattr(request, 'session'):
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
                return

            # Update session timeout based on current context
            SessionSecurityService.update_session_timeout(request)

            # Detect and log suspicious activity
            is_suspicious = SessionSecurityService.detect_suspicious_activity(request)

            # Log session activity for important paths
            if self._should_log_activity(request):
                activity_type = self._get_activity_type(request)
                SessionSecurityService.log_session_activity(
                    request,
                    activity_type,
                    is_suspicious=is_suspicious
                )

            # Handle shared device mode expiry
            if request.session.get('shared_device_mode'):
                self._check_shared_device_expiry(request)

        except Exception as e:
            # Don't break the request if session security fails
            logger.error(f"🔥 [SessionSecurityMiddleware] Error processing session security: {e}")

    def _should_log_activity(self, request: HttpRequest) -> bool:
        """Determine if this request should be logged for activity tracking"""
        sensitive_paths = [
            '/users/', '/billing/', '/customers/', '/admin/',
            '/api/', '/settings/', '/tickets/'
        ]
        return any(request.path.startswith(path) for path in sensitive_paths)

    def _get_activity_type(self, request: HttpRequest) -> str:
        """Get activity type based on request path and method"""
        if request.path.startswith('/admin/'):
            return 'admin_access'
        elif request.path.startswith('/billing/'):
            return 'billing_access'
        elif request.path.startswith('/api/'):
            return 'api_access'
        elif request.method in ['POST', 'PUT', 'PATCH', 'DELETE']:
            return 'data_modification'
        else:
            return 'page_access'

    def _check_shared_device_expiry(self, request: HttpRequest) -> None:
        """Check if shared device mode should expire based on inactivity"""
        enabled_at_str = request.session.get('shared_device_enabled_at')
        if not enabled_at_str:
            return

        try:
            enabled_at = datetime.fromisoformat(enabled_at_str)
            max_shared_duration = timedelta(hours=2)  # Max 2 hours in shared mode

            if timezone.now() - enabled_at > max_shared_duration:
                # Auto-disable shared device mode after extended use
                request.session.pop('shared_device_mode', None)
                request.session.pop('shared_device_enabled_at', None)

                if SessionSecurityService is not None:
                    SessionSecurityService.log_session_activity(
                        request,
                        'shared_device_auto_expired',
                        reason='max_duration_exceeded'
                    )

        except Exception as e:
            logger.error(f"🔥 [SessionSecurity] Error checking shared device expiry: {e}")

    def _add_security_headers(self, request: HttpRequest, response: HttpResponse) -> None:
        """Add session security headers to response"""
        # Add session timeout info for client-side warnings
        if hasattr(request, 'session') and request.session.get_expiry_age():
            response['X-Session-Timeout'] = str(request.session.get_expiry_age())

        # Add shared device mode indicator
        if request.session.get('shared_device_mode'):
            response['X-Shared-Device-Mode'] = 'true'
