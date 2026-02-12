"""
Centralized billing configuration for PRAHO Platform.

All billing-related constants and configuration should be defined here
to ensure DRY compliance and easy maintenance.
"""

import logging
from decimal import Decimal, InvalidOperation

from django.conf import settings

logger = logging.getLogger(__name__)

# ===============================================================================
# HELPER: SAFE VALUE PARSING
# ===============================================================================

def _get_positive_int(setting_name: str, default: int) -> int:
    """Get a positive integer from settings with validation."""
    value = getattr(settings, setting_name, default)
    try:
        result = int(value)
    except (TypeError, ValueError):
        result = default
    return max(1, result)  # Ensure at least 1


def _get_decimal_rate(setting_name: str, default: str) -> Decimal:
    """Get a decimal rate (0-1) from settings with validation."""
    value = getattr(settings, setting_name, default)
    try:
        # Always convert to string first to avoid float precision issues
        result = Decimal(str(value))
    except (TypeError, ValueError, InvalidOperation):
        result = Decimal(default)
    # Clamp to valid rate range
    if result < Decimal("0"):
        return Decimal("0")
    if result > Decimal("1"):
        return Decimal("1")
    return result


# ===============================================================================
# COMPANY & LOCALE DEFAULTS
# ===============================================================================

# Default country for billing (Romania)
DEFAULT_COUNTRY_CODE = getattr(settings, "BILLING_DEFAULT_COUNTRY", "RO") or "RO"

# Default currency
DEFAULT_CURRENCY_CODE = getattr(settings, "BILLING_DEFAULT_CURRENCY", "RON") or "RON"


# ===============================================================================
# TAX CONFIGURATION
# ===============================================================================

# Romanian VAT standard rate (fallback if TaxRule not configured)
DEFAULT_VAT_RATE = _get_decimal_rate("BILLING_DEFAULT_VAT_RATE", "0.21")

# EU countries for VAT purposes
EU_COUNTRY_CODES = frozenset({
    "AT", "BE", "BG", "HR", "CY", "CZ", "DK", "EE", "FI", "FR",
    "DE", "GR", "HU", "IE", "IT", "LV", "LT", "LU", "MT", "NL",
    "PL", "PT", "RO", "SE", "SI", "SK", "ES"
})


# ===============================================================================
# PAYMENT & INVOICE TERMS
# ===============================================================================


def get_invoice_payment_terms_days() -> int:
    """Get invoice payment terms from SettingsService (ADR-0015 cascade)."""
    try:
        from apps.settings.services import SettingsService  # noqa: PLC0415
        return SettingsService.get_integer_setting("billing.invoice_payment_terms_days", 14)
    except Exception:
        logger.warning("Failed to read invoice_payment_terms_days from SettingsService, using fallback", exc_info=True)
        return _get_positive_int("BILLING_PAYMENT_TERMS_DAYS", 14)


# Backward-compatible module-level (for code that reads it at import time)
DEFAULT_PAYMENT_TERMS_DAYS = 14
INVOICE_DUE_DATE_DAYS = DEFAULT_PAYMENT_TERMS_DAYS


# ===============================================================================
# USAGE METERING CONFIGURATION
# ===============================================================================

# Default grace period for accepting late usage events (hours)
DEFAULT_EVENT_GRACE_PERIOD_HOURS = _get_positive_int("BILLING_EVENT_GRACE_PERIOD_HOURS", 24)

# Maximum time drift allowed for future events (minutes)
MAX_FUTURE_EVENT_DRIFT_MINUTES = _get_positive_int("BILLING_MAX_FUTURE_EVENT_MINUTES", 5)


# ===============================================================================
# BATCH PROCESSING CONFIGURATION
# ===============================================================================

# Batch sizes for various operations
BATCH_SIZE_DEFAULT = _get_positive_int("BILLING_BATCH_SIZE_DEFAULT", 100)
BATCH_SIZE_STRIPE_SYNC = _get_positive_int("BILLING_BATCH_SIZE_STRIPE", 100)
BATCH_SIZE_AGGREGATION = _get_positive_int("BILLING_BATCH_SIZE_AGGREGATION", 1000)

# Iterator chunk size for memory-efficient processing
ITERATOR_CHUNK_SIZE = _get_positive_int("BILLING_ITERATOR_CHUNK_SIZE", 100)


# ===============================================================================
# THRESHOLD ALERTS
# ===============================================================================

# Default usage threshold percentages for alerts (immutable tuple)
DEFAULT_USAGE_THRESHOLDS = (
    Decimal("0.50"),  # 50%
    Decimal("0.75"),  # 75%
    Decimal("0.90"),  # 90%
    Decimal("1.00"),  # 100%
)

# Hours between repeat notifications for same threshold
DEFAULT_ALERT_COOLDOWN_HOURS = _get_positive_int("BILLING_ALERT_COOLDOWN_HOURS", 24)


# ===============================================================================
# E-FACTURA (ROMANIAN ELECTRONIC INVOICING)
# ===============================================================================

# Minimum amount for mandatory e-Factura submission (RON)
E_FACTURA_MINIMUM_AMOUNT_CENTS = _get_positive_int("BILLING_EFACTURA_MINIMUM_CENTS", 10000)  # 100 RON


# ===============================================================================
# HELPER FUNCTIONS
# ===============================================================================

def get_vat_rate(country_code: str | None = None, fallback: bool = True) -> Decimal:
    """
    Get VAT rate for a country via centralized TaxService.

    Args:
        country_code: ISO 3166-1 alpha-2 country code. Defaults to DEFAULT_COUNTRY_CODE.
        fallback: If True, use TaxService full fallback chain.
                  If False, return Decimal("0.00") when no active TaxRule exists.

    Returns:
        VAT rate as Decimal (e.g., Decimal("0.21") for 21%)
    """
    from apps.common.tax_service import TaxService
    from .tax_models import TaxRule

    country = (country_code or DEFAULT_COUNTRY_CODE).upper()
    rate = TaxService.get_vat_rate(country, as_decimal=True)

    if fallback:
        return rate

    if TaxRule.get_active_rate(country, "vat") == Decimal("0.00"):
        return Decimal("0.00")

    return rate


def is_eu_country(country_code: str | None) -> bool:
    """
    Check if a country is in the EU.

    Args:
        country_code: ISO 3166-1 alpha-2 country code.

    Returns:
        True if country is in EU, False if not or if country_code is None/empty.
    """
    if not country_code:
        return False
    return country_code.upper() in EU_COUNTRY_CODES


def get_payment_due_date(issue_date=None):
    """
    Calculate payment due date based on issue date and configured terms.

    Args:
        issue_date: Invoice issue date. Defaults to now.

    Returns:
        datetime: Due date
    """
    from datetime import timedelta

    from django.utils import timezone

    if issue_date is None:
        issue_date = timezone.now()

    return issue_date + timedelta(days=get_invoice_payment_terms_days())
