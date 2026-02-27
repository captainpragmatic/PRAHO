"""
Order-Specific VAT Rules for PRAHO Platform
Comprehensive EU VAT compliance for Romanian hosting provider.
🔒 Security: Server-computed VAT only with full audit logging.
"""

import logging
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum
from typing import Any, TypedDict

from django.utils import timezone

from apps.common.validators import log_security_event

logger = logging.getLogger(__name__)

COUNTRY_CODE_LENGTH = 2
MIN_VAT_NUMBER_LENGTH = 4
MAX_VAT_NUMBER_LENGTH = 15


class VATScenario(Enum):
    """VAT calculation scenarios for audit logging"""

    ROMANIA_B2C = "romania_b2c"  # Romanian consumer
    ROMANIA_B2B = "romania_b2b"  # Romanian business
    EU_B2C = "eu_b2c"  # EU consumer
    EU_B2B_REVERSE_CHARGE = "eu_b2b_reverse"  # EU business (reverse charge)
    NON_EU_ZERO_VAT = "non_eu_zero"  # Non-EU customer
    CUSTOM_RATE_OVERRIDE = "custom_rate_override"  # Per-customer rate override


class CustomerVATInfo(TypedDict, total=False):
    """Customer VAT information for calculation.

    Core fields (always expected):
        country: ISO 2-letter country code
        is_business: Whether customer is a registered business
        vat_number: Customer's VAT number (if business)

    Per-customer overrides (from CustomerTaxProfile):
        is_vat_payer: If False, customer is not VAT-registered → no reverse charge, treated as B2C
        custom_vat_rate: Explicit per-customer rate override (as percentage, e.g. 15.0)
        reverse_charge_eligible: If True + EU country + VAT number → force reverse charge

    Audit context:
        customer_id: For audit logging
        order_id: For audit logging
    """

    country: str
    is_business: bool
    vat_number: str | None
    customer_id: str | None
    order_id: str | None
    # Per-customer overrides from CustomerTaxProfile
    is_vat_payer: bool
    custom_vat_rate: Decimal | None
    reverse_charge_eligible: bool


@dataclass
class VATCalculationResult:
    """Result of VAT calculation with audit trail"""

    scenario: VATScenario
    vat_rate: Decimal
    subtotal_cents: int
    vat_cents: int
    total_cents: int
    country_code: str
    is_business: bool
    vat_number: str | None
    reasoning: str
    audit_data: dict[str, Any]


class OrderVATCalculator:
    """
    🔒 Server-authoritative VAT calculator for orders
    Implements Romanian hosting provider VAT rules with EU compliance.
    """

    # IMPORTANT: VAT rates are now managed centrally via TaxService
    # This provides a single source of truth for all tax calculations

    @classmethod
    def _get_vat_rate(cls, country_code: str) -> Decimal:
        """Get VAT rate from centralized TaxService."""
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        return TaxService.get_vat_rate(country_code, as_decimal=False)

    @classmethod
    def _get_eu_countries(cls) -> set[str]:
        """Get EU countries from centralized TaxService."""
        from apps.common.tax_service import TaxService  # noqa: PLC0415

        return TaxService.get_eu_countries()

    @classmethod
    def calculate_vat(cls, subtotal_cents: int, customer_info: CustomerVATInfo) -> VATCalculationResult:
        """
        🔒 Calculate VAT for order with full compliance and audit logging.

        Args:
            subtotal_cents: Order subtotal in cents
            customer_country: ISO 2-letter country code
            is_business: Whether customer is a business
            vat_number: Customer's VAT number (if business)
            customer_id: For audit logging
            order_id: For audit logging

        Returns:
            VATCalculationResult with full audit trail
        """
        # Extract customer information
        country_raw = customer_info.get("country") or "RO"
        country_code = country_raw.upper()
        is_business = customer_info.get("is_business", False)
        vat_number = customer_info.get("vat_number")
        customer_id = customer_info.get("customer_id")
        order_id = customer_info.get("order_id")

        # Determine VAT scenario (passes full customer_info for per-customer overrides).
        # Returns effective is_business/vat_number which may differ from inputs
        # (e.g. is_vat_payer=False downgrades to B2C).
        scenario, vat_rate, is_business, vat_number = cls._determine_vat_scenario(
            country_code, is_business, vat_number, customer_info=customer_info
        )

        # Calculate VAT amounts
        if vat_rate == Decimal("0.0"):
            vat_cents = 0
        else:
            # Calculate VAT: subtotal * (vat_rate / 100)
            vat_amount = Decimal(subtotal_cents) * (vat_rate / Decimal("100"))
            # Use banker's rounding (round half to even) for financial consistency
            vat_cents = int(vat_amount.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))

        total_cents = subtotal_cents + vat_cents

        # Generate reasoning for audit
        reasoning = cls._generate_vat_reasoning(scenario, country_code, is_business, vat_number, vat_rate)

        # Create audit data
        audit_data = {
            "scenario": scenario.value,
            "country_code": country_code,
            "is_business": is_business,
            "vat_number": vat_number,
            "vat_rate_percent": str(vat_rate),
            "subtotal_cents": subtotal_cents,
            "vat_cents": vat_cents,
            "total_cents": total_cents,
            "customer_id": customer_id,
            "order_id": order_id,
            "calculated_at": timezone.now().isoformat(),
            "reasoning": reasoning,
        }

        result = VATCalculationResult(
            scenario=scenario,
            vat_rate=vat_rate,
            subtotal_cents=subtotal_cents,
            vat_cents=vat_cents,
            total_cents=total_cents,
            country_code=country_code,
            is_business=is_business,
            vat_number=vat_number,
            reasoning=reasoning,
            audit_data=audit_data,
        )

        # 🔒 SECURITY: Log VAT calculation for audit compliance
        cls._audit_vat_calculation(result)

        return result

    @classmethod
    def _determine_vat_scenario(  # noqa: PLR0911, PLR0912
        cls,
        country_code: str,
        is_business: bool,
        vat_number: str | None,
        customer_info: CustomerVATInfo | None = None,
    ) -> tuple[VATScenario, Decimal, bool, str | None]:
        """
        Determine VAT scenario and rate - CONSERVATIVE APPROACH
        Default to Romanian VAT when uncertain for compliance.

        Returns:
            (scenario, vat_rate, effective_is_business, effective_vat_number)
            The effective values may differ from inputs when overrides apply
            (e.g. is_vat_payer=False downgrades is_business to False).

        Per-customer overrides (from CustomerTaxProfile) are checked FIRST:
        1. is_vat_payer=False → disable reverse charge, treat as B2C consumer
        2. custom_vat_rate set → use that rate (CUSTOM_RATE_OVERRIDE scenario)
        3. reverse_charge_eligible + EU + VAT number → force reverse charge
        """

        # Normalize and validate country code
        country_code = country_code.upper().strip() if country_code else "RO"

        # ── Per-customer overrides (checked BEFORE country-based logic) ──

        if customer_info:
            # 1. Non-VAT-registered: disable reverse charge, treat as B2C consumer.
            #    A non-plătitor de TVA still gets charged VAT — they just can't
            #    participate in EU B2B reverse charge or reclaim input VAT.
            if customer_info.get("is_vat_payer") is False:
                logger.info(
                    f"💰 [VAT] Customer is_vat_payer=False → B2C treatment, "
                    f"no reverse charge (customer_id={customer_info.get('customer_id')})"
                )
                is_business = False
                vat_number = None
                # Fall through to standard country-based logic below
            else:
                # 2. Explicit per-customer rate override
                custom_rate = customer_info.get("custom_vat_rate")
                if custom_rate is not None:
                    logger.info(
                        f"💰 [VAT] Custom rate override: {custom_rate}% "
                        f"(customer_id={customer_info.get('customer_id')})"
                    )
                    return VATScenario.CUSTOM_RATE_OVERRIDE, Decimal(str(custom_rate)), is_business, vat_number

                # 3. Reverse charge via profile flag (EU B2B shortcut)
                if (
                    customer_info.get("reverse_charge_eligible")
                    and vat_number
                    and country_code in cls._get_eu_countries()
                    and country_code != "RO"
                ):
                    return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal("0.0"), is_business, vat_number

        # ── Standard country-based logic ──

        # Romania (home country) - always apply Romanian VAT
        if country_code == "RO" or country_code in ["ROMANIA", "ROMÂNIA"]:
            vat_rate = cls._get_vat_rate("RO")
            if is_business:
                return VATScenario.ROMANIA_B2B, vat_rate, is_business, vat_number
            else:
                return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

        # EU member states with valid codes
        elif country_code in cls._get_eu_countries():
            if is_business and vat_number:
                # B2B EU: Reverse charge (0% VAT, customer pays in their country)
                return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal("0.0"), is_business, vat_number
            else:
                # B2C EU: Apply customer country VAT rate
                vat_rate = cls._get_vat_rate(country_code)
                return VATScenario.EU_B2C, vat_rate, is_business, vat_number

        # Unknown/Invalid country codes - DEFAULT TO ROMANIAN VAT for compliance
        elif not country_code or len(country_code) != COUNTRY_CODE_LENGTH:
            # Apply Romanian VAT when country is unclear
            vat_rate = cls._get_vat_rate("RO")
            return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

        # Non-EU countries — delegate to TaxService for the rate.
        # Countries seeded in TaxRule with rate=0.00 (US, GB, CH, etc.) get 0%.
        # Unknown countries with no TaxRule → TaxService fails safe to Romanian VAT.
        else:
            vat_rate = cls._get_vat_rate(country_code)
            if vat_rate == Decimal("0.0"):
                return VATScenario.NON_EU_ZERO_VAT, Decimal("0.0"), is_business, vat_number
            else:
                # Unknown country got Romanian default from TaxService → fail-safe
                return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

    @classmethod
    def _generate_vat_reasoning(  # noqa: PLR0911
        cls,
        scenario: VATScenario,
        country_code: str,
        is_business: bool,
        vat_number: str | None,
        vat_rate: Decimal = Decimal("0.0"),
    ) -> str:
        """Generate human-readable reasoning for VAT calculation"""

        if scenario == VATScenario.CUSTOM_RATE_OVERRIDE:
            return f"Per-customer rate override: {vat_rate}% applied"

        if scenario == VATScenario.ROMANIA_B2C:
            if country_code in ["RO", "ROMANIA", "ROMÂNIA"]:
                return f"Romanian consumer - apply Romanian VAT {cls._get_vat_rate('RO')}%"
            else:
                return f"Unknown/Invalid country ({country_code}) - default to Romanian VAT {cls._get_vat_rate('RO')}% for compliance"

        elif scenario == VATScenario.ROMANIA_B2B:
            return f"Romanian business - apply Romanian VAT {cls._get_vat_rate('RO')}%"

        elif scenario == VATScenario.EU_B2C:
            eu_rate = cls._get_vat_rate(country_code)
            return f"EU consumer ({country_code}) - apply destination country VAT {eu_rate}%"

        elif scenario == VATScenario.EU_B2B_REVERSE_CHARGE:
            return f"EU business ({country_code}) with VAT number {vat_number} - reverse charge 0%"

        elif scenario == VATScenario.NON_EU_ZERO_VAT:
            return f"Non-EU country ({country_code}) - export, 0% VAT"

    @classmethod
    def _audit_vat_calculation(cls, result: VATCalculationResult) -> None:
        """🔒 Log VAT calculation for compliance audit"""

        try:
            log_security_event(
                event_type="order_vat_calculation",
                details={
                    "scenario": result.scenario.value,
                    "reasoning": result.reasoning,
                    **result.audit_data,
                },
            )

            logger.info(
                f"💰 [VAT] {result.scenario.value}: "
                f"{result.subtotal_cents}¢ + {result.vat_cents}¢ VAT = {result.total_cents}¢ "
                f"({result.country_code}, business={result.is_business})"
            )

        except Exception as e:
            # Don't fail order on audit logging error, but log it
            logger.error(f"🔥 [VAT] Audit logging failed: {e}")

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
            import re  # noqa: PLC0415

            return bool(re.match(pattern, vat_clean))

        # For countries without specific patterns, basic length check
        return len(vat_clean) >= MIN_VAT_NUMBER_LENGTH and len(vat_clean) <= MAX_VAT_NUMBER_LENGTH

    @classmethod
    def get_vat_rates_for_country(cls, country_code: str) -> dict[str, Any]:
        """Get VAT information for a specific country"""

        country_code = country_code.upper()

        return {
            "country_code": country_code,
            "is_eu": country_code in cls._get_eu_countries(),
            "vat_rate": cls._get_vat_rate(country_code),
            "requires_vat_number_for_reverse_charge": country_code in cls._get_eu_countries() and country_code != "RO",
        }
