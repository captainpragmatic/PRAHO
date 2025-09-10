"""
Common middleware for PRAHO Portal Service
"""

import uuid
from collections.abc import Callable

from django.http import HttpRequest, HttpResponse


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


class SecurityHeadersMiddleware:
    """Add basic security headers for portal"""

    def __init__(self, get_response: Callable[[HttpRequest], HttpResponse]):
        self.get_response = get_response

    def __call__(self, request: HttpRequest) -> HttpResponse:
        response = self.get_response(request)

        # Basic security headers
        response["X-Content-Type-Options"] = "nosniff"
        response["X-Frame-Options"] = "DENY"
        response["X-XSS-Protection"] = "1; mode=block"
        response["Referrer-Policy"] = "strict-origin-when-cross-origin"
        
        # Portal identification
        response["X-Service"] = "portal"

        return response
