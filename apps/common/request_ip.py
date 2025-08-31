"""
Secure client IP detection for PRAHO Platform

This module provides secure IP detection that respects trusted proxy configuration,
preventing IP spoofing attacks that could bypass rate limiting and poison audit logs.

Security approach:
- Uses django-ipware for robust proxy-aware IP detection
- Respects IPWARE_TRUSTED_PROXY_LIST setting for environment-specific configuration
- Falls back safely to prevent complete failures
- Suitable for rate limiting, audit logging, and security controls

Usage:
    from apps.common.request_ip import get_safe_client_ip
    
    def my_view(request):
        client_ip = get_safe_client_ip(request)
        # Use for rate limiting, logging, etc.
"""

import ipaddress
from typing import Any

from django.conf import settings
from django.http import HttpRequest

try:
    from ipware import get_client_ip  # type: ignore[import-untyped]
except ImportError:  # pragma: no cover
    # Fallback if django-ipware is not installed
    def get_client_ip(request: HttpRequest, **kwargs: Any) -> tuple[str, bool]:
        return request.META.get('REMOTE_ADDR', '127.0.0.1'), False


def _is_trusted_proxy(ip: str, trusted_proxies: list[str]) -> bool:
    """Check if an IP address is in the trusted proxy list (supports CIDR)."""
    if not trusted_proxies:
        return False
        
    try:
        ip_addr = ipaddress.ip_address(ip)
        for proxy in trusted_proxies:
            try:
                # Handle both single IPs and CIDR ranges
                if '/' in proxy:
                    network = ipaddress.ip_network(proxy, strict=False)
                    if ip_addr in network:
                        return True
                else:
                    proxy_addr = ipaddress.ip_address(proxy)
                    if ip_addr == proxy_addr:
                        return True
            except (ipaddress.AddressValueError, ValueError):
                continue
    except (ipaddress.AddressValueError, ValueError):
        pass
    return False


def get_safe_client_ip(request: HttpRequest) -> str:
    """
    Get the real client IP address securely, respecting proxy trust configuration.
    
    This function provides secure IP detection that respects trusted proxy configuration,
    preventing IP spoofing attacks that could bypass rate limiting and poison audit logs.
    
    Configuration is done via IPWARE_TRUSTED_PROXY_LIST in Django settings:
    - Dev/Local: [] (empty list - don't trust any proxy headers, use REMOTE_ADDR only)
    - Staging/Prod: ['10.0.0.0/8', '172.16.0.0/12'] (only trust your LB/proxy CIDRs)
    
    Args:
        request: Django HttpRequest object
        
    Returns:
        str: The client IP address. Falls back to '127.0.0.1' if detection fails.
        
    Examples:
        >>> # Development (no trusted proxies)
        >>> # X-Forwarded-For header is ignored, REMOTE_ADDR is used
        >>> ip = get_safe_client_ip(request)
        
        >>> # Production (with trusted load balancer at 10.0.1.5)
        >>> # X-Forwarded-For is trusted only if coming from LB
        >>> ip = get_safe_client_ip(request)
    
    Security Notes:
        - Only headers from IPWARE_TRUSTED_PROXY_LIST are honored
        - Untrusted X-Forwarded-For headers are completely ignored
        - Safe fallback prevents denial of service
        - Suitable for security-critical operations (rate limiting, audit logs)
    """
    # Get trusted proxy list from Django settings
    trusted_proxies = getattr(settings, 'IPWARE_TRUSTED_PROXY_LIST', [])
    
    # Get REMOTE_ADDR (direct connection IP)
    remote_addr = request.META.get('REMOTE_ADDR', '127.0.0.1') or '127.0.0.1'
    
    # If no trusted proxies configured, use REMOTE_ADDR only (development/staging)
    if not trusted_proxies:
        return remote_addr
    
    # Check if the direct connection is from a trusted proxy
    if not _is_trusted_proxy(remote_addr, trusted_proxies):
        # Not from trusted proxy, use REMOTE_ADDR (prevents spoofing)
        return remote_addr
    
    # Connection is from trusted proxy, extract client IP from headers
    try:
        # Check X-Forwarded-For header (most common)
        x_forwarded_for = request.META.get('HTTP_X_FORWARDED_FOR')
        if x_forwarded_for:
            # Get first IP in chain (original client)
            client_ip = x_forwarded_for.split(',')[0].strip()
            if client_ip and _is_valid_ip(client_ip):
                return client_ip
        
        # Check X-Real-IP header (alternative)
        x_real_ip = request.META.get('HTTP_X_REAL_IP')
        if x_real_ip:
            client_ip = x_real_ip.split(',')[0].strip()
            if client_ip and _is_valid_ip(client_ip):
                return client_ip
        
        # No valid proxy headers found, fallback to REMOTE_ADDR
        return remote_addr
        
    except Exception:
        # If header parsing fails, fallback to REMOTE_ADDR for safety
        return remote_addr


def _is_valid_ip(ip: str) -> bool:
    """Check if a string is a valid IP address."""
    try:
        ipaddress.ip_address(ip)
        return True
    except (ipaddress.AddressValueError, ValueError):
        return False

