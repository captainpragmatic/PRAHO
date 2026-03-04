"""
Billing Security Services for PRAHO Platform
Handles URL validation for e-Factura integration and other security concerns.

Delegates SSRF prevention to ``apps.common.outbound_http.validate_and_resolve()``.
"""

from __future__ import annotations

import re

from django.core.exceptions import ValidationError
from django.utils.translation import gettext_lazy as _

from apps.common.outbound_http import OutboundPolicy, OutboundSecurityError, validate_and_resolve

# Allowed e-Factura government endpoints
ALLOWED_EFACTURA_DOMAINS = ["anaf.ro", "mfinante.gov.ro", "efactura.mfinante.ro", "webservicesp.anaf.ro"]

# Policy for e-Factura URL validation
_EFACTURA_POLICY = OutboundPolicy(
    name="efactura_validation",
    require_https=False,
    allowed_schemes=frozenset({"http", "https"}),
    allowed_domains=frozenset(ALLOWED_EFACTURA_DOMAINS),
    check_dns=False,  # Validation only — actual connection handled elsewhere
)


def validate_efactura_url(url: str) -> str:
    """
    Validate e-Factura URLs to prevent SSRF attacks.
    Returns the validated URL or raises ValidationError.
    """
    if not url:
        raise ValidationError(_("URL is required for e-Factura integration"))

    try:
        validate_and_resolve(url, _EFACTURA_POLICY)
    except OutboundSecurityError as exc:
        raise ValidationError(str(exc)) from None

    # Additional e-Factura-specific suspicious pattern check
    if any(suspicious in url.lower() for suspicious in ["localhost", "0.0.0.0", "metadata"]):
        raise ValidationError(_("URL contains suspicious patterns"))

    return url


def validate_external_api_url(url: str, allowed_domains: list[str]) -> str:
    """
    General validation for external API URLs to prevent SSRF.
    """
    if not url:
        raise ValidationError(_("URL is required"))

    policy = OutboundPolicy(
        name="external_api_validation",
        require_https=False,
        allowed_schemes=frozenset({"http", "https"}),
        allowed_domains=frozenset(allowed_domains),
        check_dns=False,
    )

    try:
        validate_and_resolve(url, policy)
    except OutboundSecurityError as exc:
        raise ValidationError(str(exc)) from None

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
        r"<script.*?</script>",
        r"javascript:",
        r"vbscript:",
        r"onload=",
        r"onerror=",
        r"eval\(",
        r"exec\(",
    ]

    for pattern in dangerous_patterns:
        input_str = re.sub(pattern, "", input_str, flags=re.IGNORECASE)

    return input_str.strip()
