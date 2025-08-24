"""
Common middleware for PRAHO Platform
Security headers, Romanian compliance, and audit logging.
"""

import json
import logging
import time
import uuid
from typing import Any, Callable

from django.conf import settings
from django.http import HttpRequest, HttpResponse
from django.utils.deprecation import MiddlewareMixin
from django.contrib.auth import get_user_model

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
        if response.status_code >= 400:
            audit_data['error'] = True
            if hasattr(response, 'content'):
                audit_data['response_size'] = len(response.content)
        
        logger.info('audit', extra=audit_data)
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Get real client IP address"""
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            ip = x_forwarded_for.split(',')[0]
        else:
            ip = request.META.get('REMOTE_ADDR')
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
        if request.path.startswith('/api/'):
            if not response.get('Content-Type'):
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
                import traceback
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
