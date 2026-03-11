"""
Centralized Tax Service for PRAHO Platform

Single source of truth for all VAT/tax calculations and configurations.
Provides configurable tax rates with caching and audit trail.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass
from decimal import ROUND_HALF_EVEN, Decimal
from enum import Enum
from typing import Any, ClassVar, TypedDict

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


class VATScenario(Enum):
    """VAT calculation scenarios for audit logging"""

    ROMANIA_B2C = "romania_b2c"  # Romanian consumer
    ROMANIA_B2B = "romania_b2b"  # Romanian business
    EU_B2C = "eu_b2c"  # EU consumer
    EU_B2B_REVERSE_CHARGE = "eu_b2b_reverse"  # EU business (reverse charge)
    NON_EU_ZERO_VAT = "non_eu_zero"  # Non-EU customer
    CUSTOM_RATE_OVERRIDE = "custom_rate_override"  # Per-customer rate override


class VATResult(TypedDict):
    """Result of a simple VAT calculation via TaxConfiguration.calculate_vat()."""

    vat_cents: int
    total_cents: int
    vat_rate_percent: Decimal


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


class TaxConfiguration:
    """
    Centralized tax configuration manager.

    This is the SINGLE SOURCE OF TRUTH for all tax rates across the platform.
    Rates can be configured via Django admin or settings.
    """

    # Cache configuration
    CACHE_KEY_PREFIX: ClassVar[str] = "tax_rate"
    CACHE_TIMEOUT: ClassVar[int] = 3600  # 1 hour cache

    # ISO 3166-1 alpha-2 country code length
    COUNTRY_CODE_LENGTH: ClassVar[int] = 2

    # Default VAT rates (can be overridden via settings or database)
    DEFAULT_VAT_RATES: ClassVar[dict[str, Decimal]] = {
        # Romania - Primary market (updated Aug 2025)
        "RO": Decimal("21.0"),
        # EU Countries
        "AT": Decimal("20.0"),  # Austria
        "BE": Decimal("21.0"),  # Belgium
        "BG": Decimal("20.0"),  # Bulgaria
        "HR": Decimal("25.0"),  # Croatia
        "CY": Decimal("19.0"),  # Cyprus
        "CZ": Decimal("21.0"),  # Czech Republic
        "DK": Decimal("25.0"),  # Denmark
        "EE": Decimal("22.0"),  # Estonia
        "FI": Decimal("24.0"),  # Finland
        "FR": Decimal("20.0"),  # France
        "DE": Decimal("19.0"),  # Germany
        "GR": Decimal("24.0"),  # Greece
        "HU": Decimal("27.0"),  # Hungary (highest in EU)
        "IE": Decimal("23.0"),  # Ireland
        "IT": Decimal("22.0"),  # Italy
        "LV": Decimal("21.0"),  # Latvia
        "LT": Decimal("21.0"),  # Lithuania
        "LU": Decimal("17.0"),  # Luxembourg
        "MT": Decimal("18.0"),  # Malta
        "NL": Decimal("21.0"),  # Netherlands
        "PL": Decimal("23.0"),  # Poland
        "PT": Decimal("23.0"),  # Portugal
        "SK": Decimal("20.0"),  # Slovakia
        "SI": Decimal("22.0"),  # Slovenia
        "ES": Decimal("21.0"),  # Spain
        "SE": Decimal("25.0"),  # Sweden
    }

    @classmethod
    def get_vat_rate(cls, country_code: str, as_decimal: bool = False) -> Decimal:
        """
        Get VAT rate for a country.

        Args:
            country_code: ISO 2-letter country code
            as_decimal: If True, return as decimal (0.21), else as percentage (21.0)

        Returns:
            VAT rate as Decimal
        """
        # Normalize country code
        country_code = country_code.upper().strip() if country_code else "RO"

        # Special handling for Romanian variations
        if country_code in ["ROMANIA", "ROMÂNIA"]:
            country_code = "RO"

        # Check cache first
        cache_key = f"{cls.CACHE_KEY_PREFIX}:{country_code}"
        cached_rate = cache.get(cache_key)

        if cached_rate is not None:
            return Decimal(cached_rate) / 100 if as_decimal else Decimal(cached_rate)

        # Try to get from database (if model exists)
        rate = cls._get_rate_from_database(country_code)

        # Fall back to settings
        if rate is None:
            rate = cls._get_rate_from_settings(country_code)

        # Fall back to defaults
        if rate is None:
            rate = cls.DEFAULT_VAT_RATES.get(country_code)

        # Unknown country code → default to Romanian rate (conservative / fail-safe).
        # Non-EU countries that should get 0% (US, GB, CH, etc.) are seeded in the DB
        # via setup_tax_rules. If a country has no TaxRule, no settings entry, and no
        # DEFAULT_VAT_RATES entry, it's safest to charge Romanian VAT. This avoids
        # tax leakage from typos like "R0" or "ZZ" silently getting 0%.
        if rate is None:
            logger.warning(f"⚠️ [TaxService] No rate found for {country_code!r}, defaulting to Romanian VAT (fail-safe)")
            rate = cls.DEFAULT_VAT_RATES["RO"]

        # Cache the rate
        cache.set(cache_key, str(rate), cls.CACHE_TIMEOUT)
        logger.info(f"💰 [TaxService] Loaded rate for {country_code}: {rate}%")

        return rate / 100 if as_decimal else rate

    @classmethod
    def _get_rate_from_database(cls, country_code: str) -> Decimal | None:
        """Get VAT rate from TaxRule model as percentage (e.g., 21.0)."""
        try:
            from apps.billing.tax_models import (  # noqa: PLC0415  # Deferred: avoids circular import
                TaxRule,  # Circular: cross-app  # Deferred: avoids circular import
            )

            today = timezone.now().date()
            rule = (
                TaxRule.objects.filter(country_code=country_code.upper(), tax_type="vat", valid_from__lte=today)
                .filter(models.Q(valid_to__isnull=True) | models.Q(valid_to__gte=today))
                .order_by("-valid_from", "-created_at")
                .first()
            )

            if rule:
                return (rule.rate * Decimal("100")).quantize(Decimal("0.01"))

        except Exception as e:
            logger.debug(f"Database tax rules not available: {e}")

        return None

    @classmethod
    def _get_rate_from_settings(cls, country_code: str) -> Decimal | None:
        """Get rate from Django settings.

        Always converts to Decimal via str() to avoid float precision issues.
        """
        # Check for country-specific setting
        setting_name = f"VAT_RATE_{country_code}"
        if hasattr(settings, setting_name):
            value = getattr(settings, setting_name)
            if isinstance(value, float):
                logger.warning(
                    f"⚠️ [TaxService] Setting {setting_name} is a float ({value}); "
                    f"use Decimal or str to avoid precision issues"
                )
            return Decimal(str(value))

        # Check for general VAT rates dictionary
        if hasattr(settings, "VAT_RATES"):
            rates = getattr(settings, "VAT_RATES", {})
            if country_code in rates:
                value = rates[country_code]
                if isinstance(value, float):
                    logger.warning(
                        f"⚠️ [TaxService] VAT_RATES[{country_code}] is a float ({value}); "
                        f"use Decimal or str to avoid precision issues"
                    )
                return Decimal(str(value))

        return None

    @classmethod
    def calculate_vat(
        cls, amount_cents: int, country_code: str = "RO", is_business: bool = False, vat_number: str | None = None
    ) -> VATResult:
        """
        Calculate VAT for an amount using proper rounding.

        Args:
            amount_cents: Amount in cents
            country_code: Country for VAT rate
            is_business: Whether customer is a business (for EU reverse charge)
            vat_number: VAT number for reverse charge checking

        Returns:
            VATResult with vat_cents, total_cents, and vat_rate_percent
        """
        country_code = country_code.upper().strip() if country_code else "RO"

        # EU B2B reverse charge: 0% VAT when business has valid VAT number
        # and is in an EU country other than Romania (provider's home country)
        if is_business and vat_number and cls.is_eu_country(country_code) and country_code != "RO":
            logger.info(f"💰 [TaxService] EU B2B reverse charge: {country_code} VAT {vat_number} → 0% VAT")
            return VATResult(
                vat_cents=0,
                total_cents=amount_cents,
                vat_rate_percent=Decimal("0.0"),
            )

        # Get VAT rate as decimal (e.g., 0.21 for 21%)
        vat_rate = cls.get_vat_rate(country_code, as_decimal=True)

        # Calculate VAT with banker's rounding
        vat_amount = Decimal(amount_cents) * vat_rate
        vat_cents = int(vat_amount.quantize(Decimal("1"), rounding=ROUND_HALF_EVEN))

        return VATResult(vat_cents=vat_cents, total_cents=amount_cents + vat_cents, vat_rate_percent=vat_rate * 100)

    @classmethod
    def invalidate_cache(cls, country_code: str | None = None) -> None:
        """Invalidate tax rate cache."""
        if country_code:
            cache_key = f"{cls.CACHE_KEY_PREFIX}:{country_code.upper()}"
            cache.delete(cache_key)
            logger.info(f"🔄 [TaxService] Invalidated cache for {country_code}")
        else:
            # Build union of DEFAULT_VAT_RATES keys and all country codes stored in
            # TaxRule rows (non-EU countries such as US, GB, CH are only in the DB).
            # NOTE: cache.keys() with wildcards is NOT supported by Django's
            # DatabaseCache backend — only Redis/Memcached support it.
            country_codes: set[str] = set(cls.DEFAULT_VAT_RATES.keys())
            try:
                from apps.billing.tax_models import (  # noqa: PLC0415  # Deferred: avoids circular import
                    TaxRule,  # Circular: cross-app  # Deferred: avoids circular import
                )

                db_codes = TaxRule.objects.values_list("country_code", flat=True).distinct()
                country_codes.update(db_codes)
            except Exception as e:
                logger.debug(f"Could not fetch TaxRule country codes for cache invalidation: {e}")

            keys = [f"{cls.CACHE_KEY_PREFIX}:{cc}" for cc in country_codes]
            cache.delete_many(keys)
            logger.info("🔄 [TaxService] Invalidated all tax rate caches")

    @classmethod
    def get_eu_countries(cls) -> set[str]:
        """Get set of EU country codes."""
        return set(cls.DEFAULT_VAT_RATES.keys())

    @classmethod
    def is_eu_country(cls, country_code: str) -> bool:
        """Check if country is in EU."""
        return country_code.upper() in cls.get_eu_countries()

    # ── VAT Document Calculation (moved from OrderVATCalculator) ──────────────

    @classmethod
    def calculate_vat_for_document(cls, subtotal_cents: int, customer_info: CustomerVATInfo) -> VATCalculationResult:
        """
        Calculate VAT for a document (order/invoice) with full compliance and audit logging.

        This is the authoritative implementation of the 6-scenario EU VAT logic for
        Romanian hosting providers. OrderVATCalculator.calculate_vat() delegates here.

        Args:
            subtotal_cents: Document subtotal in cents
            customer_info: Customer VAT context (country, business flag, VAT number, overrides)

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
    def _determine_vat_scenario(  # Complexity: order processing pipeline  # noqa: PLR0911, PLR0912  # Complexity: multi-step business logic
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
                    and country_code in cls.get_eu_countries()
                    and country_code != "RO"
                ):
                    return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal("0.0"), is_business, vat_number

        # ── Standard country-based logic ──

        # Romania (home country) - always apply Romanian VAT
        if country_code == "RO" or country_code in ["ROMANIA", "ROMÂNIA"]:
            vat_rate = cls.get_vat_rate("RO")
            if is_business:
                return VATScenario.ROMANIA_B2B, vat_rate, is_business, vat_number
            else:
                return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

        # EU member states with valid codes
        elif country_code in cls.get_eu_countries():
            if is_business and vat_number:
                # B2B EU: Reverse charge (0% VAT, customer pays in their country)
                return VATScenario.EU_B2B_REVERSE_CHARGE, Decimal("0.0"), is_business, vat_number
            else:
                # B2C EU: Apply customer country VAT rate
                vat_rate = cls.get_vat_rate(country_code)
                return VATScenario.EU_B2C, vat_rate, is_business, vat_number

        # Unknown/Invalid country codes - DEFAULT TO ROMANIAN VAT for compliance
        elif not country_code or len(country_code) != cls.COUNTRY_CODE_LENGTH:
            # Apply Romanian VAT when country is unclear
            vat_rate = cls.get_vat_rate("RO")
            return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

        # Non-EU countries — delegate to TaxService for the rate.
        # Countries seeded in TaxRule with rate=0.00 (US, GB, CH, etc.) get 0%.
        # Unknown countries with no TaxRule → TaxService fails safe to Romanian VAT.
        else:
            vat_rate = cls.get_vat_rate(country_code)
            if vat_rate == Decimal("0.0"):
                return VATScenario.NON_EU_ZERO_VAT, Decimal("0.0"), is_business, vat_number
            else:
                # Unknown country got Romanian default from TaxService → fail-safe
                return VATScenario.ROMANIA_B2C, vat_rate, is_business, vat_number

    @classmethod
    def _generate_vat_reasoning(  # Complexity: order processing pipeline  # noqa: PLR0911  # Complexity: multi-step business logic
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
                return f"Romanian consumer - apply Romanian VAT {cls.get_vat_rate('RO')}%"
            else:
                return f"Unknown/Invalid country ({country_code}) - default to Romanian VAT {cls.get_vat_rate('RO')}% for compliance"

        if scenario == VATScenario.ROMANIA_B2B:
            return f"Romanian business - apply Romanian VAT {cls.get_vat_rate('RO')}%"

        if scenario == VATScenario.EU_B2C:
            eu_rate = cls.get_vat_rate(country_code)
            return f"EU consumer ({country_code}) - apply destination country VAT {eu_rate}%"

        if scenario == VATScenario.EU_B2B_REVERSE_CHARGE:
            return f"EU business ({country_code}) with VAT number {vat_number} - reverse charge 0%"

        # VATScenario.NON_EU_ZERO_VAT (and any future scenarios)
        return f"Non-EU country ({country_code}) - export, 0% VAT"

    @classmethod
    def _audit_vat_calculation(cls, result: VATCalculationResult) -> None:
        """Log VAT calculation for compliance audit"""
        from apps.common.validators import (  # noqa: PLC0415  # Deferred: avoids circular import
            log_security_event,
        )

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


# Export main service class
TaxService = TaxConfiguration
