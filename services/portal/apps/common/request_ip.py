"""
IP address utilities for PRAHO Portal Service
"""

from django.http import HttpRequest


def get_safe_client_ip(request: HttpRequest) -> str:
    """
    Get client IP address safely from request.
    Handles proxy headers and provides fallback.
    """
    # Check for forwarded IP first (load balancers, proxies)
    forwarded_for = request.META.get("HTTP_X_FORWARDED_FOR")
    if forwarded_for:
        # Take the first IP in the chain
        ip = forwarded_for.split(",")[0].strip()
        if ip:
            return ip

    # Check other proxy headers
    real_ip = request.META.get("HTTP_X_REAL_IP")
    if real_ip:
        return real_ip

    # Fallback to remote address
    return request.META.get("REMOTE_ADDR", "127.0.0.1")
