"""
🔒 Billing Security Services for PRAHO Platform
Handles URL validation for e-Factura integration and other security concerns.
"""

import re
import urllib.parse

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

# Allowed e-Factura government endpoints
ALLOWED_EFACTURA_DOMAINS = [
    'anaf.ro',
    'mfinante.gov.ro', 
    'efactura.mfinante.ro',
    'webservicesp.anaf.ro'
]

# Blocked internal/private network ranges
BLOCKED_IP_PATTERNS = [
    r'^127\.',           # Loopback
    r'^10\.',           # Private Class A  
    r'^172\.(1[6-9]|2[0-9]|3[0-1])\.',  # Private Class B
    r'^192\.168\.',     # Private Class C
    r'^169\.254\.',     # Link-local
    r'^::1$',           # IPv6 loopback
    r'^fc00:',          # IPv6 private
    r'^fe80:',          # IPv6 link-local
]

# Blocked protocols for SSRF prevention
BLOCKED_PROTOCOLS = [
    'file', 'ftp', 'gopher', 'ldap', 'dict', 'tftp', 'ssh'
]


def validate_efactura_url(url: str) -> str:
    """
    🔒 Validate e-Factura URLs to prevent SSRF attacks.
    Returns the validated URL or raises ValidationError.
    """
    if not url:
        raise ValidationError(_("URL is required for e-Factura integration"))
    
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}") from e
    
    # Check protocol
    if parsed.scheme.lower() not in ['http', 'https']:
        raise ValidationError(f"Protocol '{parsed.scheme}' not allowed. Only HTTP/HTTPS permitted.")
    
    if parsed.scheme.lower() in BLOCKED_PROTOCOLS:
        raise ValidationError(f"Protocol '{parsed.scheme}' is blocked for security reasons")
    
    # Check domain whitelist for e-Factura
    domain = parsed.netloc.lower()
    if not any(allowed_domain in domain for allowed_domain in ALLOWED_EFACTURA_DOMAINS):
        raise ValidationError(
            f"Domain '{domain}' not in allowed e-Factura endpoints: {', '.join(ALLOWED_EFACTURA_DOMAINS)}"
        )
    
    # Check for blocked IP patterns
    hostname = parsed.hostname
    if hostname:
        for pattern in BLOCKED_IP_PATTERNS:
            if re.match(pattern, hostname):
                raise ValidationError(f"Access to IP range '{hostname}' is blocked for security")
    
    # Check for suspicious URL patterns
    if any(suspicious in url.lower() for suspicious in ['localhost', '0.0.0.0', 'metadata']):
        raise ValidationError("URL contains suspicious patterns")
    
    return url


def validate_external_api_url(url: str, allowed_domains: list[str]) -> str:
    """
    🔒 General validation for external API URLs to prevent SSRF.
    """
    if not url:
        raise ValidationError(_("URL is required"))
    
    try:
        parsed = urllib.parse.urlparse(url)
    except Exception as e:
        raise ValidationError(f"Invalid URL format: {e}") from e
    
    # Check protocol
    if parsed.scheme.lower() not in ['http', 'https']:
        raise ValidationError(f"Protocol '{parsed.scheme}' not allowed")
    
    # Check domain whitelist
    domain = parsed.netloc.lower()
    if not any(allowed_domain in domain for allowed_domain in allowed_domains):
        raise ValidationError(f"Domain '{domain}' not in allowed list")
    
    # Check for blocked IPs
    hostname = parsed.hostname
    if hostname:
        for pattern in BLOCKED_IP_PATTERNS:
            if re.match(pattern, hostname):
                raise ValidationError(f"Access to IP range '{hostname}' is blocked")
    
    return url


def sanitize_financial_input(input_str: str, max_length: int = 1000) -> str:
    """
    🔒 Sanitize input for financial operations to prevent injection.
    """
    if not input_str:
        return ""
    
    # Truncate to prevent DoS
    if len(input_str) > max_length:
        input_str = input_str[:max_length]
    
    # Remove potentially dangerous characters
    dangerous_patterns = [
        r'<script.*?</script>',
        r'javascript:',
        r'vbscript:',
        r'onload=',
        r'onerror=',
        r'eval\(',
        r'exec\(',
    ]
    
    for pattern in dangerous_patterns:
        input_str = re.sub(pattern, '', input_str, flags=re.IGNORECASE)
    
    return input_str.strip()
