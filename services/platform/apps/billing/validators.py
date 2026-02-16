"""
Financial validation functions for PRAHO Platform billing models.
Security-focused validation for financial data to prevent injection attacks.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any

from django.core.exceptions import ValidationError
from django.utils import timezone

from apps.common.validators import log_security_event

logger = logging.getLogger(__name__)

__all__ = [
    "log_security_event",
    "validate_financial_amount",
    "validate_financial_json",
    "validate_financial_text_field",
    "validate_invoice_sequence_increment",
]

# ===============================================================================
# SECURITY VALIDATION CONSTANTS
# ===============================================================================

# Security constants for financial data
MAX_JSON_SIZE_BYTES = 5120  # 5KB limit for financial JSON fields (smaller than products)
MAX_JSON_DEPTH = 5  # Maximum nesting depth for financial data
MAX_FINANCIAL_AMOUNT_CENTS = 10000000000  # 100 million in major currency (reasonable business limit)
MIN_FINANCIAL_AMOUNT_CENTS = -10000000000  # Allow negative for refunds/credits
MAX_DESCRIPTION_LENGTH = 1000  # Maximum for financial descriptions
MAX_ADDRESS_FIELD_LENGTH = 500  # Maximum for address fields

# Dangerous patterns in financial metadata
DANGEROUS_FINANCIAL_PATTERNS = [
    r"eval\s*\(",
    r"exec\s*\(",
    r"__import__",
    r"subprocess",
    r"<script",
    r"javascript:",
    r"data:text/html",
    r"\$\{.*\}",  # Template injection
    r"<%.*%>",  # Template injection
]

# Sensitive keys that shouldn't be in financial metadata
SENSITIVE_FINANCIAL_KEYS = [
    "password",
    "secret",
    "key",
    "token",
    "credential",
    "api_key",
    "card_number",
    "cvv",
    "pin",
    "account_number",
    "routing_number",
    "ssn",
    "social_security",
    "tax_id_internal",
    "bank_account",
]

# ===============================================================================
# VALIDATION FUNCTIONS
# ===============================================================================


def validate_financial_json(data: Any, field_name: str = "Financial JSON field") -> None:
    """🔒 Validate JSON field for financial data security"""
    if not data:
        return

    # Convert to JSON string to check size
    try:
        json_str = json.dumps(data)
    except (TypeError, ValueError) as e:
        raise ValidationError(f"{field_name} contains invalid JSON: {e}") from e

    # Check size limit (smaller for financial data)
    if len(json_str.encode("utf-8")) > MAX_JSON_SIZE_BYTES:
        raise ValidationError(f"{field_name} too large. Maximum size: {MAX_JSON_SIZE_BYTES} bytes for financial data")

    # Check depth
    if _get_financial_json_depth(data) > MAX_JSON_DEPTH:
        raise ValidationError(f"{field_name} too deep. Maximum nesting depth: {MAX_JSON_DEPTH} for financial data")

    # Check for dangerous patterns and sensitive data
    _check_financial_json_security(data, field_name)


def validate_financial_amount(amount_cents: int | None, field_name: str = "Amount") -> None:
    """🔒 Validate financial amounts to prevent overflow/underflow"""
    if amount_cents is None:
        return

    if amount_cents > MAX_FINANCIAL_AMOUNT_CENTS:
        raise ValidationError(
            f"{field_name} too large. Maximum: {MAX_FINANCIAL_AMOUNT_CENTS / 100:,.2f} in major currency units"
        )

    if amount_cents < MIN_FINANCIAL_AMOUNT_CENTS:
        raise ValidationError(
            f"{field_name} too small. Minimum: {MIN_FINANCIAL_AMOUNT_CENTS / 100:,.2f} in major currency units"
        )


def validate_financial_text_field(text: str, field_name: str, max_length: int | None = None) -> None:
    """🔒 Validate text fields in financial documents"""
    if not text:
        return

    max_len = max_length or MAX_DESCRIPTION_LENGTH
    if len(text) > max_len:
        raise ValidationError(f"{field_name} too long. Maximum length: {max_len} characters")

    # Check for dangerous patterns in financial descriptions
    for pattern in DANGEROUS_FINANCIAL_PATTERNS:
        if re.search(pattern, text, re.IGNORECASE):
            raise ValidationError(f"{field_name} contains potentially dangerous pattern")


def validate_invoice_sequence_increment() -> None:
    """🔒 Log critical invoice sequence operations for audit trail"""
    log_security_event(
        event_type="invoice_sequence_increment",
        details={
            "operation": "sequence_number_generated",
            "timestamp": timezone.now().isoformat(),
            "critical_financial_operation": True,
        },
    )


# ===============================================================================
# INTERNAL HELPER FUNCTIONS
# ===============================================================================


def _get_financial_json_depth(data: Any, current_depth: int = 0) -> int:
    """Calculate the maximum depth of financial JSON data"""
    if current_depth > MAX_JSON_DEPTH:
        return current_depth

    if isinstance(data, dict):
        return max([_get_financial_json_depth(v, current_depth + 1) for v in data.values()], default=current_depth)
    elif isinstance(data, list):
        return max([_get_financial_json_depth(item, current_depth + 1) for item in data], default=current_depth)
    else:
        return current_depth


def _check_financial_json_security(data: Any, field_name: str) -> None:
    """Recursively check financial JSON data for security issues"""
    if isinstance(data, dict):
        # Check for sensitive keys
        for key in data:
            if any(sensitive in key.lower() for sensitive in SENSITIVE_FINANCIAL_KEYS):
                raise ValidationError(f"{field_name} contains sensitive financial information in key '{key}'")

        # Check for dangerous patterns in values
        for key, value in data.items():
            if isinstance(value, str):
                for pattern in DANGEROUS_FINANCIAL_PATTERNS:
                    if re.search(pattern, value, re.IGNORECASE):
                        raise ValidationError(f"{field_name} contains potentially dangerous pattern in '{key}'")
            _check_financial_json_security(value, field_name)
    elif isinstance(data, list):
        for item in data:
            _check_financial_json_security(item, field_name)
