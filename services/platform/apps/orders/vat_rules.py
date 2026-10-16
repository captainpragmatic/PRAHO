"""
Order-Specific VAT Rules for PRAHO Platform
Comprehensive EU VAT compliance for Romanian hosting provider.
🔒 Security: Server-computed VAT only with full audit logging.
"""

import logging
from typing import Any

from apps.common.tax_service import CustomerVATInfo, VATCalculationResult, VATScenario

logger = logging.getLogger(__name__)

COUNTRY_CODE_LENGTH = 2

# Re-export for backward compatibility — consumers can keep importing from here
__all__ = [
    "COUNTRY_CODE_LENGTH",
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
