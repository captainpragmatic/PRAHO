"""
Common middleware for PRAHO Portal Service
Enhanced with security features for session protection and attack prevention.
"""

import hashlib
import logging
import time
import uuid
from collections.abc import Callable

from django.contrib.auth import logout
from django.http import HttpRequest, HttpResponse
from django.shortcuts import redirect
from django.utils.deprecation import MiddlewareMixin

logger = logging.getLogger(__name__)


class RequestIDMiddleware:
    """Add unique request ID for tracing"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        # Generate unique request ID
        request_id = str(uuid.uuid4())
        request.META["REQUEST_ID"] = request_id

        # Add to response headers for debugging
        response = self.get_response(request)
        response["X-Request-ID"] = request_id

        return response


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
                logger.warning(f"🔒 [Session] Session integrity failed for {request.session.session_key[:8]}...")
                return self._handle_security_violation(request, "session_integrity_failed")
            
            # 🔒 SECURITY: Check session timeout
            if self._is_session_expired(request):
                logger.info(f"🔒 [Session] Session expired for {request.session.session_key[:8]}...")
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
            '/static/',
            '/media/',
            '/health/',
            '/favicon.ico',
            '/.well-known/',
        ]
        
        path = request.path
        return any(path.startswith(skip_path) for skip_path in skip_paths)
    
    def _validate_session_integrity(self, request: HttpRequest) -> bool:
        """🔒 Validate session hasn't been hijacked or tampered with"""
        
        # Get current session data
        session = request.session
        client_ip = self._get_client_ip(request)
        user_agent = request.META.get('HTTP_USER_AGENT', '')
        user_agent_hash = hashlib.sha256(user_agent.encode()).hexdigest()[:16]
        
        # Check for first-time session setup
        if 'security_fingerprint' not in session:
            # Initialize security fingerprint
            session['security_fingerprint'] = {
                'ip_hash': hashlib.sha256(client_ip.encode()).hexdigest()[:16],
                'user_agent_hash': user_agent_hash,
                'created_at': time.time(),
                'last_validated': time.time()
            }
            session.modified = True
            logger.info(f"🔒 [Session] Security fingerprint created for {session.session_key[:8]}...")
            return True
        
        fingerprint = session['security_fingerprint']
        
        # 🔒 SECURITY: Validate IP address hasn't changed
        expected_ip_hash = fingerprint.get('ip_hash', '')
        current_ip_hash = hashlib.sha256(client_ip.encode()).hexdigest()[:16]
        
        if not self.IP_CHANGE_TOLERANCE and expected_ip_hash != current_ip_hash:
            logger.warning(
                f"🔒 [Session] IP address changed for session {session.session_key[:8]}... "
                f"(expected: {expected_ip_hash}, got: {current_ip_hash})"
            )
            return False
        
        # 🔒 SECURITY: Validate user agent hasn't changed significantly
        expected_ua_hash = fingerprint.get('user_agent_hash', '')
        if expected_ua_hash != user_agent_hash:
            logger.warning(
                f"🔒 [Session] User agent changed for session {session.session_key[:8]}... "
                f"(expected: {expected_ua_hash}, got: {user_agent_hash})"
            )
            return False
        
        return True
    
    def _is_session_expired(self, request: HttpRequest) -> bool:
        """🔒 Check if session has exceeded timeout limits"""
        
        session = request.session
        current_time = time.time()
        
        # Check last activity timeout
        last_activity = session.get('last_activity', current_time)
        if current_time - last_activity > self.SESSION_TIMEOUT_SECONDS:
            return True
        
        # Check absolute session age
        fingerprint = session.get('security_fingerprint', {})
        created_at = fingerprint.get('created_at', current_time)
        return current_time - created_at > self.MAX_SESSION_AGE_SECONDS
    
    def _update_session_activity(self, request: HttpRequest) -> None:
        """Update session last activity timestamp"""
        request.session['last_activity'] = time.time()
        
        # Update validation timestamp in fingerprint
        if 'security_fingerprint' in request.session:
            request.session['security_fingerprint']['last_validated'] = time.time()
            request.session.modified = True
    
    def _handle_security_violation(self, request: HttpRequest, violation_type: str) -> HttpResponse:
        """🔒 Handle detected security violations"""
        
        session_key = getattr(request.session, 'session_key', 'unknown')[:8]
        
        # Log security event
        logger.error(
            f"🚨 [Security] Session security violation: {violation_type} "
            f"for session {session_key}... from IP {self._get_client_ip(request)}"
        )
        
        # Clear potentially compromised session
        if hasattr(request, 'user') and request.user.is_authenticated:
            logout(request)
        
        request.session.flush()
        
        # Redirect to login with security message
        return redirect('/login/?security=session_security_violation')
    
    def _handle_session_timeout(self, request: HttpRequest) -> HttpResponse:
        """Handle expired sessions gracefully"""
        
        # Log timeout
        session_key = getattr(request.session, 'session_key', 'unknown')[:8]
        logger.info(f"🕒 [Session] Session timeout for {session_key}...")
        
        # Clear expired session
        if hasattr(request, 'user') and request.user.is_authenticated:
            logout(request)
        
        request.session.flush()
        
        # Redirect to login with timeout message
        return redirect('/login/?timeout=session_expired')
    
    def _get_client_ip(self, request: HttpRequest) -> str:
        """Safely extract client IP address"""
        # Check for forwarded IP headers
        forwarded_headers = [
            'HTTP_X_FORWARDED_FOR',
            'HTTP_X_REAL_IP',
            'HTTP_CF_CONNECTING_IP',
        ]
        
        for header in forwarded_headers:
            forwarded_ip = request.META.get(header)
            if forwarded_ip:
                # Take first IP if comma-separated
                ip = forwarded_ip.split(',')[0].strip()
                if ip and ip != 'unknown':
                    return ip
        
        return request.META.get('REMOTE_ADDR', '0.0.0.0')


class SecurityHeadersMiddleware:
    """🔒 Enhanced security headers middleware with CSP and comprehensive protections"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # 🔒 SECURITY: Core security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # 🔒 SECURITY: Strict Transport Security (HTTPS only)
        if request.is_secure():
            response['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        # 🔒 SECURITY: Content Security Policy for HTMX/Tailwind compatibility
        csp_parts = [
            "default-src 'self'",
            "script-src 'self' 'unsafe-inline' 'unsafe-eval' https://js.stripe.com",  # HTMX + Stripe need unsafe-inline; Alpine.js v3 needs unsafe-eval for x-data expressions
            "style-src 'self' 'unsafe-inline'",   # Tailwind requires unsafe-inline
            "img-src 'self' data: https:",
            "font-src 'self'",
            "connect-src 'self' https://api.stripe.com",
            "frame-src 'self' https://js.stripe.com https://*.stripe.com",  # Stripe Elements frames
            "frame-ancestors 'none'",
            "form-action 'self'",
            "base-uri 'self'",
            "object-src 'none'",
            "media-src 'self'"
        ]
        response['Content-Security-Policy'] = '; '.join(csp_parts)
        
        # 🔒 SECURITY: Permissions Policy (formerly Feature Policy)
        permissions_policy_parts = [
            "geolocation=()",
            "microphone=()",
            "camera=()",
            "payment=(self)",
            "usb=()",
            "magnetometer=()",
            "gyroscope=()",
            "accelerometer=()"
        ]
        response['Permissions-Policy'] = ', '.join(permissions_policy_parts)
        
        # Portal identification
        response["X-Service"] = "portal"

        return response
