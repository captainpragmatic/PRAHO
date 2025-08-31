"""
System checks for PRAHO Platform security configuration.

Validates security-critical configurations like IP trust settings
to prevent misconfigurations in production deployments.
"""

import ipaddress
from typing import Any

from django.conf import settings
from django.core.checks import Error, Tags, register
from django.core.checks import Warning as DjangoWarning

# Constants
SSL_HEADER_TUPLE_LENGTH = 2


@register(Tags.security)
def check_ip_trust_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check IP trust configuration for security issues.
    
    Validates IPWARE_TRUSTED_PROXY_LIST setting to ensure proper
    proxy trust configuration in different environments.
    """
    errors = []
    
    # Get trusted proxy list from settings
    trusted_proxies = getattr(settings, 'IPWARE_TRUSTED_PROXY_LIST', None)
    
    # Check if IPWARE_TRUSTED_PROXY_LIST is defined
    if trusted_proxies is None:
        errors.append(
            DjangoWarning(
                'IPWARE_TRUSTED_PROXY_LIST is not defined',
                hint='Set IPWARE_TRUSTED_PROXY_LIST to [] for development or specify proxy CIDRs for production',
                id='security.W030',
            )
        )
        return errors
    
    # Check for production environment with empty trusted proxy list
    if settings.DEBUG is False and not trusted_proxies:
        errors.append(
            DjangoWarning(
                'Production environment with empty IPWARE_TRUSTED_PROXY_LIST',
                hint='Configure trusted proxy CIDRs (e.g., ["10.0.0.0/8"]) for production load balancers',
                id='security.W031',
            )
        )
    
    # Check for development environment with trusted proxies
    if settings.DEBUG is True and trusted_proxies:
        errors.append(
            DjangoWarning(
                'Development environment should use empty IPWARE_TRUSTED_PROXY_LIST',
                hint='Set IPWARE_TRUSTED_PROXY_LIST = [] in development to prevent IP spoofing',
                id='security.W032',
            )
        )
    
    # Validate each proxy entry
    if trusted_proxies:
        for i, proxy in enumerate(trusted_proxies):
            if not isinstance(proxy, str):
                errors.append(
                    Error(
                        f'IPWARE_TRUSTED_PROXY_LIST[{i}] must be a string',
                        hint='Use IP addresses or CIDR notation (e.g., "10.0.0.0/8")',
                        id='security.E030',
                    )
                )
                continue
            
            try:
                # Validate IP address or CIDR range
                if '/' in proxy:
                    ipaddress.ip_network(proxy, strict=False)
                else:
                    ipaddress.ip_address(proxy)
            except (ipaddress.AddressValueError, ValueError):
                errors.append(
                    Error(
                        f'Invalid IP address or CIDR range in IPWARE_TRUSTED_PROXY_LIST: "{proxy}"',
                        hint='Use valid IP addresses (e.g., "10.0.1.5") or CIDR ranges (e.g., "10.0.0.0/8")',
                        id='security.E031',
                    )
                )
    
    # Check for dangerous configurations
    if trusted_proxies:
        # Check for overly broad CIDR ranges
        dangerous_ranges = ['0.0.0.0/0', '::/0']
        for dangerous in dangerous_ranges:
            if dangerous in trusted_proxies:
                errors.append(
                    Error(
                        f'Dangerous IPWARE_TRUSTED_PROXY_LIST entry: "{dangerous}"',
                        hint='This trusts ALL IP addresses. Use specific proxy CIDRs instead.',
                        id='security.E032',
                    )
                )
        
        # Check for public IP ranges that might be suspicious
        public_ranges = ['8.8.8.0/24', '1.1.1.0/24']  # Common public DNS
        for public in public_ranges:
            if public in trusted_proxies:
                errors.append(
                    DjangoWarning(
                        f'Public IP range in IPWARE_TRUSTED_PROXY_LIST: "{public}"',
                        hint='Ensure this public range is actually your load balancer',
                        id='security.W033',
                    )
                )
    
    return errors


@register(Tags.security)
def check_proxy_ssl_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check proxy SSL header configuration.
    
    Ensures SECURE_PROXY_SSL_HEADER is properly configured when
    using trusted proxies in production.
    """
    errors = []
    
    trusted_proxies = getattr(settings, 'IPWARE_TRUSTED_PROXY_LIST', [])
    proxy_ssl_header = getattr(settings, 'SECURE_PROXY_SSL_HEADER', None)
    
    # If using trusted proxies in production, should have SSL header configured
    if not settings.DEBUG and trusted_proxies and not proxy_ssl_header:
        errors.append(
            DjangoWarning(
                'SECURE_PROXY_SSL_HEADER not configured with trusted proxies',
                hint='Set SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") for HTTPS detection',
                id='security.W034',
            )
        )
    
    # Validate SSL header format
    if proxy_ssl_header:
        if not isinstance(proxy_ssl_header, tuple) or len(proxy_ssl_header) != SSL_HEADER_TUPLE_LENGTH:
            errors.append(
                Error(
                    'SECURE_PROXY_SSL_HEADER must be a tuple of (header_name, expected_value)',
                    hint='Example: ("HTTP_X_FORWARDED_PROTO", "https")',
                    id='security.E033',
                )
            )
        elif not proxy_ssl_header[0].startswith('HTTP_'):
            errors.append(
                DjangoWarning(
                    'SECURE_PROXY_SSL_HEADER header name should start with "HTTP_"',
                    hint='Django converts X-Forwarded-Proto to HTTP_X_FORWARDED_PROTO',
                    id='security.W035',
                )
            )
    
    return errors


@register(Tags.security)
def check_security_middleware_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check security middleware configuration.
    
    Ensures SecurityHeadersMiddleware is properly configured and positioned.
    """
    errors = []
    
    middleware = getattr(settings, 'MIDDLEWARE', [])
    
    # Check if SecurityHeadersMiddleware is present
    security_middleware = 'apps.common.middleware.SecurityHeadersMiddleware'
    if security_middleware not in middleware:
        errors.append(
            DjangoWarning(
                'SecurityHeadersMiddleware not found in MIDDLEWARE',
                hint='Add "apps.common.middleware.SecurityHeadersMiddleware" to MIDDLEWARE',
                id='security.W036',
            )
        )
        return errors
    
    # Check middleware positioning
    security_index = middleware.index(security_middleware)
    
    # Should be after SecurityMiddleware but before the end
    django_security = 'django.middleware.security.SecurityMiddleware'
    if django_security in middleware:
        django_security_index = middleware.index(django_security)
        if security_index <= django_security_index:
            errors.append(
                DjangoWarning(
                    'SecurityHeadersMiddleware should be positioned after Django SecurityMiddleware',
                    hint='Move SecurityHeadersMiddleware after django.middleware.security.SecurityMiddleware',
                    id='security.W037',
                )
            )
    
    # Should not be the last middleware
    if security_index == len(middleware) - 1:
        errors.append(
            DjangoWarning(
                'SecurityHeadersMiddleware should not be the last middleware',
                hint='Position SecurityHeadersMiddleware before the last middleware',
                id='security.W038',
            )
        )
    
    return errors
