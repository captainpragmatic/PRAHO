# ===============================================================================
# CONSTANTS & CONFIGURATION CONSISTENCY TESTS
# ===============================================================================
"""
Guardrail tests to prevent configuration sprawl from recurring.

Verifies:
1. No VAT rate defined in constants.py (ADR-0005/0015)
2. Billing term defaults match between constants.py and SettingsService
3. Page size consistent between constants.py and REST_FRAMEWORK
4. Dead constants stay removed
5. calculate_romanian_vat() reads from TaxService (not hardcoded)
6. Context processor reads VAT rate from TaxService
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.test import TestCase

from apps.common.constants import (
    DEFAULT_PAGE_SIZE,
    INVOICE_DUE_DAYS_DEFAULT,
    PAYMENT_GRACE_PERIOD_DAYS,
    PROFORMA_VALIDITY_DAYS,
)
from apps.settings.services import SettingsService


class ConstantsVATGuardTest(TestCase):
    """Verify constants.py contains no VAT rate definitions."""

    def test_no_romanian_vat_rate_in_constants(self) -> None:
        """constants.py must not define ROMANIAN_VAT_RATE."""
        constants_file = Path(__file__).resolve().parent.parent.parent / "apps" / "common" / "constants.py"
        content = constants_file.read_text()

        for line_num, line in enumerate(content.splitlines(), 1):
            stripped = line.strip()
            if stripped.startswith("#"):
                continue
            if stripped.startswith("ROMANIAN_VAT_RATE"):
                self.fail(f"constants.py:{line_num} defines ROMANIAN_VAT_RATE — use TaxService instead")


class BillingTermDefaultsConsistencyTest(TestCase):
    """Verify constants.py billing term defaults match SettingsService defaults."""

    def test_proforma_validity_days_matches(self) -> None:
        """PROFORMA_VALIDITY_DAYS must match SettingsService default."""
        settings_default = SettingsService.DEFAULT_SETTINGS["billing.proforma_validity_days"]
        self.assertEqual(
            PROFORMA_VALIDITY_DAYS,
            settings_default,
            f"constants.PROFORMA_VALIDITY_DAYS ({PROFORMA_VALIDITY_DAYS}) != "
            f"SettingsService default ({settings_default})",
        )

    def test_invoice_due_days_matches(self) -> None:
        """INVOICE_DUE_DAYS_DEFAULT must match SettingsService default."""
        settings_default = SettingsService.DEFAULT_SETTINGS["billing.invoice_payment_terms_days"]
        self.assertEqual(
            INVOICE_DUE_DAYS_DEFAULT,
            settings_default,
            f"constants.INVOICE_DUE_DAYS_DEFAULT ({INVOICE_DUE_DAYS_DEFAULT}) != "
            f"SettingsService default ({settings_default})",
        )

    def test_payment_grace_period_matches(self) -> None:
        """PAYMENT_GRACE_PERIOD_DAYS must match SettingsService default."""
        settings_default = SettingsService.DEFAULT_SETTINGS["billing.payment_grace_period_days"]
        self.assertEqual(
            PAYMENT_GRACE_PERIOD_DAYS,
            settings_default,
            f"constants.PAYMENT_GRACE_PERIOD_DAYS ({PAYMENT_GRACE_PERIOD_DAYS}) != "
            f"SettingsService default ({settings_default})",
        )


class PageSizeConsistencyTest(TestCase):
    """Verify page size is consistent across constants and DRF config."""

    def test_page_size_matches_drf(self) -> None:
        """DEFAULT_PAGE_SIZE must match REST_FRAMEWORK['PAGE_SIZE']."""
        drf_page_size = settings.REST_FRAMEWORK.get("PAGE_SIZE")
        self.assertEqual(
            DEFAULT_PAGE_SIZE,
            drf_page_size,
            f"constants.DEFAULT_PAGE_SIZE ({DEFAULT_PAGE_SIZE}) != "
            f"REST_FRAMEWORK.PAGE_SIZE ({drf_page_size})",
        )


class DeadConstantsTest(TestCase):
    """Verify that removed constants stay removed."""

    def test_no_password_reset_token_validity(self) -> None:
        """PASSWORD_RESET_TOKEN_VALIDITY_HOURS must not exist in constants."""
        import apps.common.constants as constants_mod
        self.assertFalse(
            hasattr(constants_mod, "PASSWORD_RESET_TOKEN_VALIDITY_HOURS"),
            "PASSWORD_RESET_TOKEN_VALIDITY_HOURS should be removed — Django's PASSWORD_RESET_TIMEOUT is authoritative",
        )

    def test_no_email_send_rate_per_hour(self) -> None:
        """EMAIL_SEND_RATE_PER_HOUR must not exist in constants."""
        import apps.common.constants as constants_mod
        self.assertFalse(
            hasattr(constants_mod, "EMAIL_SEND_RATE_PER_HOUR"),
            "EMAIL_SEND_RATE_PER_HOUR should be removed — EMAIL_RATE_LIMIT.MAX_PER_HOUR is authoritative",
        )


class CalculateRomanianVATTaxServiceTest(TestCase):
    """Verify calculate_romanian_vat() reads from TaxService, not a constant."""

    def setUp(self) -> None:
        cache.clear()

    def test_uses_current_tax_service_rate(self) -> None:
        """calculate_romanian_vat() returns the rate from TaxService defaults."""
        from apps.common.types import calculate_romanian_vat

        result = calculate_romanian_vat(10000, include_vat=False)

        # With default TaxService rate of 21%, VAT on 10000 should be 2100
        self.assertEqual(result["vat_amount"], 2100)
        self.assertAlmostEqual(result["vat_rate"], 0.21)

    def test_responds_to_db_rate_change(self) -> None:
        """When TaxRule changes the rate, calculate_romanian_vat() reflects it."""
        from apps.billing.tax_models import TaxRule
        from apps.common.tax_service import TaxService
        from apps.common.types import calculate_romanian_vat

        # Seed a TaxRule with 25% rate
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2500"),
            valid_from=date(2020, 1, 1),
            valid_to=None,
            is_eu_member=True,
        )
        TaxService.invalidate_cache("RO")

        result = calculate_romanian_vat(10000, include_vat=False)

        # With 25% rate, VAT on 10000 should be 2500
        self.assertEqual(result["vat_amount"], 2500)
        self.assertAlmostEqual(result["vat_rate"], 0.25)


class ContextProcessorVATTest(TestCase):
    """Verify context processor reads VAT rate from TaxService."""

    def setUp(self) -> None:
        cache.clear()

    def test_vat_rate_from_tax_service_default(self) -> None:
        """Context processor returns 21 (int) from TaxService defaults."""
        from django.test import RequestFactory

        from apps.common.context_processors import romanian_business_context

        request = RequestFactory().get("/")
        context = romanian_business_context(request)

        self.assertEqual(context["vat_rate"], 21)

    def test_vat_rate_responds_to_db_change(self) -> None:
        """Context processor reflects TaxRule changes."""
        from django.test import RequestFactory

        from apps.billing.tax_models import TaxRule
        from apps.common.context_processors import romanian_business_context
        from apps.common.tax_service import TaxService

        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2500"),
            valid_from=date(2020, 1, 1),
            valid_to=None,
            is_eu_member=True,
        )
        TaxService.invalidate_cache("RO")

        request = RequestFactory().get("/")
        context = romanian_business_context(request)

        self.assertEqual(context["vat_rate"], 25)
