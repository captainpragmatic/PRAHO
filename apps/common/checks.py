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
MIN_HSTS_SECONDS = 300  # 5 minutes minimum
MAX_SESSION_AGE_HOURS = 86400  # 24 hours in seconds


def _validate_proxy_entries(trusted_proxies: list[str]) -> list[Any]:
    """Validate individual proxy entries for format and security issues."""
    errors = []

    for i, proxy in enumerate(trusted_proxies):
        if not isinstance(proxy, str):
            errors.append(
                Error(
                    f"IPWARE_TRUSTED_PROXY_LIST entry {i} is not a string: {proxy!r}",
                    hint="All proxy entries must be strings (CIDR notation or IP addresses)",
                    id="security.E030",
                )
            )
            continue

        # Validate CIDR format
        try:
            ipaddress.ip_network(proxy, strict=False)
        except ValueError:
            errors.append(
                Error(
                    f'Invalid CIDR format in IPWARE_TRUSTED_PROXY_LIST[{i}]: "{proxy}"',
                    hint='Use valid CIDR notation (e.g., "10.0.0.0/8" or "192.168.1.1/32")',
                    id="security.E031",
                )
            )

    return errors


def _check_dangerous_proxy_ranges(trusted_proxies: list[str]) -> list[Any]:
    """Check for dangerous proxy ranges that trust all IPs."""
    dangerous_ranges = ["0.0.0.0/0", "::/0"]
    return [
        Error(
            f'Dangerous IPWARE_TRUSTED_PROXY_LIST entry: "{dangerous}"',
            hint="This trusts ALL IP addresses. Use specific proxy CIDRs instead.",
            id="security.E032",
        )
        for dangerous in dangerous_ranges
        if dangerous in trusted_proxies
    ]


def _check_public_proxy_ranges(trusted_proxies: list[str]) -> list[Any]:
    """Check for public IP ranges that might be suspicious."""
    
    # Common public IP ranges that are suspicious as proxy headers
    suspicious_public_ranges = ["1.0.0.0/8", "8.8.8.0/24", "8.8.4.0/24"]
    warnings = []
    
    for proxy in trusted_proxies:
        try:
            proxy_network = ipaddress.ip_network(proxy, strict=False)
            for suspicious_range in suspicious_public_ranges:
                suspicious_network = ipaddress.ip_network(suspicious_range)
                
                # Check if ranges overlap (either proxy contains suspicious or vice versa)
                if proxy_network.overlaps(suspicious_network):
                    warnings.append(DjangoWarning(
                        f'Public IP range in IPWARE_TRUSTED_PROXY_LIST: "{proxy}" overlaps with "{suspicious_range}"',
                        hint="Ensure this public range is actually your load balancer",
                        id="security.W033",
                    ))
                    break  # Only warn once per proxy
                    
        except (ipaddress.AddressValueError, ValueError):
            # Skip invalid IP ranges - they'll be caught by other checks
            continue
            
    return warnings


@register(Tags.security)
def check_ip_trust_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check IP trust configuration for security issues.

    Validates IPWARE_TRUSTED_PROXY_LIST setting to ensure proper
    proxy trust configuration in different environments.
    """
    errors = []

    # Get trusted proxy list from settings
    trusted_proxies = getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", None)

    # Check if IPWARE_TRUSTED_PROXY_LIST is defined
    if trusted_proxies is None:
        errors.append(
            DjangoWarning(
                "IPWARE_TRUSTED_PROXY_LIST is not defined",
                hint="Set IPWARE_TRUSTED_PROXY_LIST to [] for development or specify proxy CIDRs for production",
                id="security.W030",
            )
        )
        return errors

    # Check for production environment with empty trusted proxy list
    if settings.DEBUG is False and not trusted_proxies:
        errors.append(
            DjangoWarning(
                "Production environment with empty IPWARE_TRUSTED_PROXY_LIST",
                hint='Configure trusted proxy CIDRs (e.g., ["10.0.0.0/8"]) for production load balancers',
                id="security.W031",
            )
        )

    # Check for development environment with trusted proxies
    if settings.DEBUG is True and trusted_proxies:
        errors.append(
            DjangoWarning(
                "Development environment should use empty IPWARE_TRUSTED_PROXY_LIST",
                hint="Set IPWARE_TRUSTED_PROXY_LIST = [] in development to prevent IP spoofing",
                id="security.W032",
            )
        )

    # Validate proxy entries if they exist
    if trusted_proxies:
        errors.extend(_validate_proxy_entries(trusted_proxies))
        errors.extend(_check_dangerous_proxy_ranges(trusted_proxies))
        errors.extend(_check_public_proxy_ranges(trusted_proxies))

    return errors


@register(Tags.security)
def check_proxy_ssl_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check proxy SSL header configuration.

    Ensures SECURE_PROXY_SSL_HEADER is properly configured when
    using trusted proxies in production.
    """
    errors: list[Any] = []

    trusted_proxies = getattr(settings, "IPWARE_TRUSTED_PROXY_LIST", [])
    proxy_ssl_header = getattr(settings, "SECURE_PROXY_SSL_HEADER", None)

    # If using trusted proxies in production, should have SSL header configured
    if not settings.DEBUG and trusted_proxies and not proxy_ssl_header:
        errors.append(
            DjangoWarning(
                "SECURE_PROXY_SSL_HEADER not configured with trusted proxies",
                hint='Set SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") for HTTPS detection',
                id="security.W034",
            )
        )

    # Validate SSL header format
    if proxy_ssl_header:
        if not isinstance(proxy_ssl_header, tuple) or len(proxy_ssl_header) != SSL_HEADER_TUPLE_LENGTH:
            errors.append(
                Error(
                    "SECURE_PROXY_SSL_HEADER must be a tuple of (header_name, expected_value)",
                    hint='Example: ("HTTP_X_FORWARDED_PROTO", "https")',
                    id="security.E033",
                )
            )
        elif not proxy_ssl_header[0].startswith("HTTP_"):
            errors.append(
                DjangoWarning(
                    'SECURE_PROXY_SSL_HEADER header name should start with "HTTP_"',
                    hint="Django converts X-Forwarded-Proto to HTTP_X_FORWARDED_PROTO",
                    id="security.W035",
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

    middleware = getattr(settings, "MIDDLEWARE", [])

    # Check if SecurityHeadersMiddleware is present
    security_middleware = "apps.common.middleware.SecurityHeadersMiddleware"
    if security_middleware not in middleware:
        errors.append(
            DjangoWarning(
                "SecurityHeadersMiddleware not found in MIDDLEWARE",
                hint='Add "apps.common.middleware.SecurityHeadersMiddleware" to MIDDLEWARE',
                id="security.W036",
            )
        )
        return errors

    # Check middleware positioning
    security_index = middleware.index(security_middleware)

    # Should be after SecurityMiddleware but before the end
    django_security = "django.middleware.security.SecurityMiddleware"
    if django_security in middleware:
        django_security_index = middleware.index(django_security)
        if security_index <= django_security_index:
            errors.append(
                DjangoWarning(
                    "SecurityHeadersMiddleware should be positioned after Django SecurityMiddleware",
                    hint="Move SecurityHeadersMiddleware after django.middleware.security.SecurityMiddleware",
                    id="security.W037",
                )
            )

    # Should not be the last middleware
    if security_index == len(middleware) - 1:
        errors.append(
            DjangoWarning(
                "SecurityHeadersMiddleware should not be the last middleware",
                hint="Position SecurityHeadersMiddleware before the last middleware",
                id="security.W038",
            )
        )

    return errors


def _check_ssl_redirect_configuration() -> list[Any]:
    """Check SSL redirect and proxy header configuration."""
    errors = []
    ssl_redirect = getattr(settings, "SECURE_SSL_REDIRECT", False)
    proxy_ssl_header = getattr(settings, "SECURE_PROXY_SSL_HEADER", None)

    if ssl_redirect and not proxy_ssl_header:
        errors.append(
            Error(
                "SECURE_SSL_REDIRECT enabled but SECURE_PROXY_SSL_HEADER not configured",
                hint='Set SECURE_PROXY_SSL_HEADER = ("HTTP_X_FORWARDED_PROTO", "https") to prevent redirect loops',
                id="security.E040",
            )
        )

    return errors


def _check_secure_cookies_configuration() -> list[Any]:
    """Check secure cookie configuration."""
    errors = []
    ssl_redirect = getattr(settings, "SECURE_SSL_REDIRECT", False)
    session_secure = getattr(settings, "SESSION_COOKIE_SECURE", False)
    csrf_secure = getattr(settings, "CSRF_COOKIE_SECURE", False)

    if ssl_redirect and not session_secure:
        errors.append(
            DjangoWarning(
                "HTTPS enforced but SESSION_COOKIE_SECURE is False",
                hint="Set SESSION_COOKIE_SECURE = True in production to prevent session hijacking",
                id="security.W040",
            )
        )

    if ssl_redirect and not csrf_secure:
        errors.append(
            DjangoWarning(
                "HTTPS enforced but CSRF_COOKIE_SECURE is False",
                hint="Set CSRF_COOKIE_SECURE = True in production to prevent CSRF attacks",
                id="security.W041",
            )
        )

    return errors


def _check_hsts_configuration() -> list[Any]:
    """Check HSTS (HTTP Strict Transport Security) configuration."""
    errors = []
    ssl_redirect = getattr(settings, "SECURE_SSL_REDIRECT", False)
    hsts_seconds = getattr(settings, "SECURE_HSTS_SECONDS", 0)

    if ssl_redirect and hsts_seconds == 0:
        errors.append(
            DjangoWarning(
                "HTTPS enforced but HSTS not configured",
                hint="Set SECURE_HSTS_SECONDS = 31536000 (1 year) to enable HTTP Strict Transport Security",
                id="security.W042",
            )
        )

    if hsts_seconds > 0 and hsts_seconds < MIN_HSTS_SECONDS:
        errors.append(
            DjangoWarning(
                f"HSTS timeout too short: {hsts_seconds} seconds",
                hint="SECURE_HSTS_SECONDS should be at least 300 seconds (5 minutes) for meaningful security",
                id="security.W043",
            )
        )

    return errors


def _check_csrf_origins_configuration() -> list[Any]:
    """Check CSRF trusted origins configuration."""
    errors = []
    ssl_redirect = getattr(settings, "SECURE_SSL_REDIRECT", False)
    csrf_origins = getattr(settings, "CSRF_TRUSTED_ORIGINS", [])

    if ssl_redirect and not csrf_origins:
        errors.append(
            DjangoWarning(
                "HTTPS enforced but CSRF_TRUSTED_ORIGINS not configured",
                hint='Set CSRF_TRUSTED_ORIGINS = ["https://your-domain.com"] for CSRF validation',
                id="security.W045",
            )
        )

    # Validate CSRF origins use HTTPS
    errors.extend(
        [
            DjangoWarning(
                f"CSRF trusted origin uses HTTP in HTTPS-enforced environment: {origin}",
                hint="All CSRF_TRUSTED_ORIGINS should use HTTPS when SECURE_SSL_REDIRECT is enabled",
                id="security.W046",
            )
            for origin in csrf_origins
            if not origin.startswith("https://") and ssl_redirect
        ]
    )

    return errors


@register(Tags.security)
def check_https_security_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check HTTPS security configuration for production deployment.

    Validates SSL settings, secure cookies, and HSTS configuration
    to ensure proper HTTPS security hardening.
    """
    errors = []

    debug = getattr(settings, "DEBUG", False)

    # Production HTTPS security checks
    if not debug:
        errors.extend(_check_ssl_redirect_configuration())
        errors.extend(_check_secure_cookies_configuration())
        errors.extend(_check_hsts_configuration())
        errors.extend(_check_csrf_origins_configuration())

        # Check ALLOWED_HOSTS configuration
        allowed_hosts = getattr(settings, "ALLOWED_HOSTS", [])
        if not allowed_hosts or allowed_hosts == ["*"]:
            errors.append(
                DjangoWarning(
                    "ALLOWED_HOSTS not properly configured for production",
                    hint="Set ALLOWED_HOSTS to specific domain names to prevent Host header attacks",
                    id="security.W044",
                )
            )

        # Check SecurityMiddleware positioning
        middleware = getattr(settings, "MIDDLEWARE", [])
        django_security = "django.middleware.security.SecurityMiddleware"
        if django_security not in middleware:
            errors.append(
                Error(
                    "SecurityMiddleware not found in MIDDLEWARE for production",
                    hint='Add "django.middleware.security.SecurityMiddleware" as first middleware',
                    id="security.E041",
                )
            )
        elif middleware[0] != django_security:
            errors.append(
                DjangoWarning(
                    "SecurityMiddleware must be first in MIDDLEWARE for production",
                    hint='Move "django.middleware.security.SecurityMiddleware" to first position',
                    id="security.W047",
                )
            )

    # Development environment checks
    else:
        # Check development security settings are properly disabled
        ssl_redirect = getattr(settings, "SECURE_SSL_REDIRECT", False)
        if ssl_redirect:
            errors.append(
                DjangoWarning(
                    "SECURE_SSL_REDIRECT enabled in development environment",
                    hint="Set SECURE_SSL_REDIRECT = False in development to avoid redirect loops",
                    id="security.W048",
                )
            )

        hsts_seconds = getattr(settings, "SECURE_HSTS_SECONDS", 0)
        if hsts_seconds > 0:
            errors.append(
                DjangoWarning(
                    "HSTS enabled in development environment",
                    hint="Set SECURE_HSTS_SECONDS = 0 in development to disable HSTS",
                    id="security.W049",
                )
            )

        # Check for secure cookies in development (should be False)
        session_secure = getattr(settings, "SESSION_COOKIE_SECURE", False)
        csrf_secure = getattr(settings, "CSRF_COOKIE_SECURE", False)

        if session_secure:
            errors.append(
                DjangoWarning(
                    "SESSION_COOKIE_SECURE enabled in development environment",
                    hint="Set SESSION_COOKIE_SECURE = False for HTTP development",
                    id="security.W050",
                )
            )

        if csrf_secure:
            errors.append(
                DjangoWarning(
                    "CSRF_COOKIE_SECURE enabled in development environment",
                    hint="Set CSRF_COOKIE_SECURE = False for HTTP development",
                    id="security.W051",
                )
            )

    return errors


@register(Tags.security)
def check_session_security_configuration(app_configs: Any, **kwargs: Any) -> list[Any]:
    """
    Check session security configuration for Romanian hosting compliance.

    Validates session cookie settings and security parameters to ensure
    proper session management security.
    """
    errors = []

    debug = getattr(settings, "DEBUG", False)

    # Session security checks for production
    if not debug:
        # Check session cookie security
        session_httponly = getattr(settings, "SESSION_COOKIE_HTTPONLY", True)
        if not session_httponly:
            errors.append(
                DjangoWarning(
                    "SESSION_COOKIE_HTTPONLY disabled in production",
                    hint="Set SESSION_COOKIE_HTTPONLY = True to prevent XSS attacks",
                    id="security.W052",
                )
            )

        # Check session timeout
        session_age = getattr(settings, "SESSION_COOKIE_AGE", 1209600)  # Django default: 2 weeks
        if session_age > MAX_SESSION_AGE_HOURS:  # More than 24 hours
            errors.append(
                DjangoWarning(
                    f"Session timeout very long for production: {session_age} seconds",
                    hint="Consider shorter session timeout (3600 = 1 hour) for hosting provider security",
                    id="security.W053",
                )
            )

        # Check SameSite setting
        samesite = getattr(settings, "SESSION_COOKIE_SAMESITE", None)
        if samesite not in ["Lax", "Strict"]:
            errors.append(
                DjangoWarning(
                    f"SESSION_COOKIE_SAMESITE not set to secure value: {samesite}",
                    hint='Set SESSION_COOKIE_SAMESITE = "Lax" for CSRF protection with usability',
                    id="security.W054",
                )
            )

        # Check session engine security
        session_engine = getattr(settings, "SESSION_ENGINE", "django.contrib.sessions.backends.db")
        if "cache" in session_engine.lower() and not getattr(settings, "CACHES", {}).get("default"):
            errors.append(
                DjangoWarning(
                    "Cache-based sessions configured but no default cache configured",
                    hint="Configure Redis cache for secure session storage in production",
                    id="security.W055",
                )
            )

    return errors
