"""
Centralized Tax Service for PRAHO Platform

Single source of truth for all VAT/tax calculations and configurations.
Provides configurable tax rates with caching and audit trail.
"""

from __future__ import annotations

import logging
from decimal import ROUND_HALF_EVEN, Decimal
from typing import ClassVar

from django.conf import settings
from django.core.cache import cache
from django.db import models
from django.utils import timezone

logger = logging.getLogger(__name__)


class TaxConfiguration:
    """
    Centralized tax configuration manager.

    This is the SINGLE SOURCE OF TRUTH for all tax rates across the platform.
    Rates can be configured via Django admin or settings.
    """

    # Cache configuration
    CACHE_KEY_PREFIX: ClassVar[str] = "tax_rate"
    CACHE_TIMEOUT: ClassVar[int] = 3600  # 1 hour cache

    # Default VAT rates (can be overridden via settings or database)
    DEFAULT_VAT_RATES: ClassVar[dict[str, Decimal]] = {
        # Romania - Primary market (updated Aug 2025)
        'RO': Decimal('21.0'),

        # EU Countries
        'AT': Decimal('20.0'),  # Austria
        'BE': Decimal('21.0'),  # Belgium
        'BG': Decimal('20.0'),  # Bulgaria
        'HR': Decimal('25.0'),  # Croatia
        'CY': Decimal('19.0'),  # Cyprus
        'CZ': Decimal('21.0'),  # Czech Republic
        'DK': Decimal('25.0'),  # Denmark
        'EE': Decimal('22.0'),  # Estonia
        'FI': Decimal('24.0'),  # Finland
        'FR': Decimal('20.0'),  # France
        'DE': Decimal('19.0'),  # Germany
        'GR': Decimal('24.0'),  # Greece
        'HU': Decimal('27.0'),  # Hungary (highest in EU)
        'IE': Decimal('23.0'),  # Ireland
        'IT': Decimal('22.0'),  # Italy
        'LV': Decimal('21.0'),  # Latvia
        'LT': Decimal('21.0'),  # Lithuania
        'LU': Decimal('17.0'),  # Luxembourg
        'MT': Decimal('18.0'),  # Malta
        'NL': Decimal('21.0'),  # Netherlands
        'PL': Decimal('23.0'),  # Poland
        'PT': Decimal('23.0'),  # Portugal
        'SK': Decimal('20.0'),  # Slovakia
        'SI': Decimal('22.0'),  # Slovenia
        'ES': Decimal('21.0'),  # Spain
        'SE': Decimal('25.0'),  # Sweden
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
        country_code = country_code.upper().strip() if country_code else 'RO'

        # Special handling for Romanian variations
        if country_code in ['ROMANIA', 'ROMÂNIA']:
            country_code = 'RO'

        # Check cache first
        cache_key = f"{cls.CACHE_KEY_PREFIX}:{country_code}"
        cached_rate = cache.get(cache_key)

        if cached_rate is not None:
            logger.debug(f"💰 [TaxService] Using cached rate for {country_code}: {cached_rate}%")
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
            logger.warning(
                f"⚠️ [TaxService] No rate found for {country_code!r}, "
                f"defaulting to Romanian VAT (fail-safe)"
            )
            rate = cls.DEFAULT_VAT_RATES['RO']

        # Cache the rate
        cache.set(cache_key, str(rate), cls.CACHE_TIMEOUT)
        logger.info(f"💰 [TaxService] Loaded rate for {country_code}: {rate}%")

        return rate / 100 if as_decimal else rate

    @classmethod
    def _get_rate_from_database(cls, country_code: str) -> Decimal | None:
        """Get VAT rate from TaxRule model as percentage (e.g., 21.0)."""
        try:
            from apps.billing.tax_models import TaxRule

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
        if hasattr(settings, 'VAT_RATES'):
            rates = getattr(settings, 'VAT_RATES', {})
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
    def calculate_vat(cls, amount_cents: int, country_code: str = 'RO',
                     is_business: bool = False, vat_number: str | None = None) -> dict[str, int]:
        """
        Calculate VAT for an amount using proper rounding.

        Args:
            amount_cents: Amount in cents
            country_code: Country for VAT rate
            is_business: Whether customer is a business (for EU reverse charge)
            vat_number: VAT number for reverse charge checking

        Returns:
            Dict with vat_cents and total_cents
        """
        country_code = country_code.upper().strip() if country_code else 'RO'

        # EU B2B reverse charge: 0% VAT when business has valid VAT number
        # and is in an EU country other than Romania (provider's home country)
        if (
            is_business
            and vat_number
            and cls.is_eu_country(country_code)
            and country_code != 'RO'
        ):
            logger.info(
                f"💰 [TaxService] EU B2B reverse charge: {country_code} "
                f"VAT {vat_number} → 0% VAT"
            )
            return {
                'vat_cents': 0,
                'total_cents': amount_cents,
                'vat_rate_percent': Decimal('0.0'),
            }

        # Get VAT rate as decimal (e.g., 0.21 for 21%)
        vat_rate = cls.get_vat_rate(country_code, as_decimal=True)

        # Calculate VAT with banker's rounding
        vat_amount = Decimal(amount_cents) * vat_rate
        vat_cents = int(vat_amount.quantize(Decimal('1'), rounding=ROUND_HALF_EVEN))

        return {
            'vat_cents': vat_cents,
            'total_cents': amount_cents + vat_cents,
            'vat_rate_percent': vat_rate * 100
        }

    @classmethod
    def invalidate_cache(cls, country_code: str | None = None) -> None:
        """Invalidate tax rate cache."""
        if country_code:
            cache_key = f"{cls.CACHE_KEY_PREFIX}:{country_code.upper()}"
            cache.delete(cache_key)
            logger.info(f"🔄 [TaxService] Invalidated cache for {country_code}")
        else:
            # Clear all known tax rate caches by iterating DEFAULT_VAT_RATES keys.
            # NOTE: cache.keys() with wildcards is NOT supported by Django's
            # DatabaseCache backend — only Redis/Memcached support it.
            keys = [f"{cls.CACHE_KEY_PREFIX}:{cc}" for cc in cls.DEFAULT_VAT_RATES]
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


# Export main service class
TaxService = TaxConfiguration
