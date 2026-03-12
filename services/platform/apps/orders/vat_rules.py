"""
Order-Specific VAT Rules for PRAHO Platform
Comprehensive EU VAT compliance for Romanian hosting provider.
🔒 Security: Server-computed VAT only with full audit logging.
"""

import logging
import re
from typing import Any

from apps.common.tax_service import CustomerVATInfo, VATCalculationResult, VATScenario

logger = logging.getLogger(__name__)

COUNTRY_CODE_LENGTH = 2
MIN_VAT_NUMBER_LENGTH = 4
MAX_VAT_NUMBER_LENGTH = 15

# Re-export for backward compatibility — consumers can keep importing from here
__all__ = [
    "COUNTRY_CODE_LENGTH",
    "MAX_VAT_NUMBER_LENGTH",
    "MIN_VAT_NUMBER_LENGTH",
    "CustomerVATInfo",
    "OrderVATCalculator",
    "VATCalculationResult",
    "VATScenario",
]


class OrderVATCalculator:
    """
    🔒 Server-authoritative VAT calculator for orders
    Implements Romanian hosting provider VAT rules with EU compliance.

    This class is now a thin facade over TaxService.calculate_vat_for_document().
    All 6-scenario VAT logic lives in TaxConfiguration (accessed via TaxService).
    """

    @classmethod
    def calculate_vat(cls, subtotal_cents: int, customer_info: CustomerVATInfo) -> VATCalculationResult:
        """
        🔒 Calculate VAT for order with full compliance and audit logging.

        Delegates to TaxService.calculate_vat_for_document() which is the
        authoritative implementation of the 6-scenario EU VAT rules.

        Args:
            subtotal_cents: Order subtotal in cents
            customer_info: Customer VAT context (country, business flag, VAT number, overrides)

        Returns:
            VATCalculationResult with full audit trail
        """
        from apps.common.tax_service import TaxService  # noqa: PLC0415  # Deferred: avoids circular import

        return TaxService.calculate_vat_for_document(subtotal_cents, customer_info)

    @classmethod
    def validate_vat_number(cls, vat_number: str, country_code: str) -> bool:
        """
        Basic VAT number format validation.
        Note: For production, integrate with EU VIES system for real validation.
        """
        if not vat_number:
            return False

        # Remove spaces and convert to uppercase
        vat_clean = vat_number.replace(" ", "").upper()

        # Basic format checks by country
        vat_patterns = {
            "RO": r"^RO\d{2,10}$",  # Romania: RO + 2-10 digits
            "DE": r"^DE\d{9}$",  # Germany: DE + 9 digits
            "FR": r"^FR[A-Z0-9]{2}\d{9}$",  # France: FR + 2 chars + 9 digits
            "GB": r"^GB\d{9}(\d{3})?$",  # UK: GB + 9 or 12 digits
            "IT": r"^IT\d{11}$",  # Italy: IT + 11 digits
            # Add more as needed
        }

        pattern = vat_patterns.get(country_code)
        if pattern:
            return bool(re.match(pattern, vat_clean))

        # For countries without specific patterns, basic length check
        return len(vat_clean) >= MIN_VAT_NUMBER_LENGTH and len(vat_clean) <= MAX_VAT_NUMBER_LENGTH

    @classmethod
    def _get_eu_countries(cls) -> set[str]:
        """Get EU countries from centralized TaxService."""
        from apps.common.tax_service import TaxService  # noqa: PLC0415  # Deferred: avoids circular import

        return TaxService.get_eu_countries()

    @classmethod
    def get_vat_rates_for_country(cls, country_code: str) -> dict[str, Any]:
        """Get VAT information for a specific country"""
        from apps.common.tax_service import TaxService  # noqa: PLC0415  # Deferred: avoids circular import

        country_code = country_code.upper()

        return {
            "country_code": country_code,
            "is_eu": country_code in cls._get_eu_countries(),
            "vat_rate": TaxService.get_vat_rate(country_code),
            "requires_vat_number_for_reverse_charge": country_code in cls._get_eu_countries() and country_code != "RO",
        }
