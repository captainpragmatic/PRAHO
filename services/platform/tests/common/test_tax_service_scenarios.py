"""
Tests for TaxService.calculate_vat_for_document() — all 6 VAT scenarios.

Verifies that the 6-scenario EU VAT logic in TaxConfiguration is correct
when called directly via TaxService (i.e. bypassing OrderVATCalculator).

Scenarios:
1. Romania B2C — apply Romanian VAT
2. Romania B2B — apply Romanian VAT (same rate, different scenario tag)
3. EU B2C — apply destination country VAT
4. EU B2B reverse charge — 0% VAT
5. Non-EU — 0% VAT (requires seeded TaxRule)
6. Custom rate override — per-customer rate
"""

from __future__ import annotations

from datetime import date
from decimal import Decimal

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.billing.tax_models import TaxRule
from apps.common.tax_service import CustomerVATInfo, TaxService, VATCalculationResult, VATScenario

LOCMEM_TEST_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM_TEST_CACHE)
class TaxServiceScenarioTests(TestCase):
    """Test TaxService.calculate_vat_for_document() for all 6 VAT scenarios."""

    def setUp(self) -> None:
        cache.clear()

    # ── Scenario 1: Romania B2C ──────────────────────────────────────────────

    def test_romania_b2c_applies_romanian_vat(self) -> None:
        """Romanian consumer: standard 21% VAT applied."""
        info: CustomerVATInfo = {"country": "RO", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertIsInstance(result, VATCalculationResult)
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)
        self.assertEqual(result.total_cents, 12100)
        self.assertEqual(result.subtotal_cents, 10000)

    def test_romania_b2c_lowercase_country(self) -> None:
        """Country code is normalised to uppercase."""
        info: CustomerVATInfo = {"country": "ro", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.country_code, "RO")

    # ── Scenario 2: Romania B2B ──────────────────────────────────────────────

    def test_romania_b2b_applies_romanian_vat(self) -> None:
        """Romanian business: 21% VAT (same rate, different scenario tag)."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2B)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)
        self.assertEqual(result.total_cents, 12100)

    def test_romania_b2b_without_vat_number_still_b2b(self) -> None:
        """Romanian business without VAT number still gets ROMANIA_B2B scenario."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": None,
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2B)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    # ── Scenario 3: EU B2C ───────────────────────────────────────────────────

    def test_eu_b2c_applies_destination_country_rate(self) -> None:
        """EU consumer: destination country VAT rate (Germany 19%)."""
        info: CustomerVATInfo = {"country": "DE", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))
        self.assertEqual(result.vat_cents, 1900)
        self.assertEqual(result.total_cents, 11900)

    def test_eu_b2c_business_without_vat_number_treated_as_b2c(self) -> None:
        """EU business WITHOUT VAT number: treated as B2C (destination rate)."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": None,
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        # Without VAT number, reverse charge cannot be applied
        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))

    def test_eu_b2c_hungary_highest_rate(self) -> None:
        """Hungary has the highest EU rate (27%)."""
        info: CustomerVATInfo = {"country": "HU", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("27.0"))
        self.assertEqual(result.vat_cents, 2700)

    # ── Scenario 4: EU B2B Reverse Charge ───────────────────────────────────

    def test_eu_b2b_reverse_charge_zero_vat(self) -> None:
        """EU business with VAT number: reverse charge — 0% VAT."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)
        self.assertEqual(result.total_cents, 10000)

    def test_eu_b2b_reverse_charge_preserves_vat_number(self) -> None:
        """Reverse charge result retains the VAT number for audit."""
        info: CustomerVATInfo = {
            "country": "FR",
            "is_business": True,
            "vat_number": "FR12345678901",
        }
        result = TaxService.calculate_vat_for_document(5000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_number, "FR12345678901")
        self.assertEqual(result.vat_cents, 0)

    # ── Scenario 5: Non-EU Zero VAT ──────────────────────────────────────────

    def test_non_eu_zero_vat_with_seeded_rule(self) -> None:
        """Non-EU customer with seeded TaxRule(rate=0): 0% VAT (export)."""
        TaxRule.objects.create(
            country_code="US",
            tax_type="vat",
            rate=Decimal("0.0000"),
            valid_from=date(2020, 1, 1),
            is_eu_member=False,
        )
        info: CustomerVATInfo = {"country": "US", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.NON_EU_ZERO_VAT)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)
        self.assertEqual(result.total_cents, 10000)

    def test_non_eu_unknown_country_fails_safe_to_romanian(self) -> None:
        """Non-EU country with no TaxRule fails safe to Romanian VAT (not 0%)."""
        info: CustomerVATInfo = {"country": "ZZ", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        # Fail-safe: unknown country → Romanian VAT (not 0% to prevent tax leakage)
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)

    # ── Scenario 6: Custom Rate Override ────────────────────────────────────

    def test_custom_rate_override_applied(self) -> None:
        """Per-customer rate override bypasses country-based logic."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "custom_vat_rate": Decimal("15.0"),
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.CUSTOM_RATE_OVERRIDE)
        self.assertEqual(result.vat_rate, Decimal("15.0"))
        self.assertEqual(result.vat_cents, 1500)
        self.assertEqual(result.total_cents, 11500)

    def test_custom_rate_override_zero_percent(self) -> None:
        """Custom rate of 0% is valid (e.g. diplomatic exemptions)."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "custom_vat_rate": Decimal("0.0"),
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.CUSTOM_RATE_OVERRIDE)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)

    # ── Edge cases ───────────────────────────────────────────────────────────

    def test_empty_country_defaults_to_romanian_vat(self) -> None:
        """Empty/invalid country codes default to Romanian rate (conservative)."""
        info: CustomerVATInfo = {"country": "", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_none_country_defaults_to_romanian_vat(self) -> None:
        """None country value defaults to Romanian rate."""
        info = {"country": None, "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)  # type-safe: tested at runtime

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_missing_country_key_defaults_to_romanian_vat(self) -> None:
        """Missing country key in CustomerVATInfo defaults to Romanian rate."""
        info = {"is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)  # type-safe: tested at runtime

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_bankers_rounding_half_to_even(self) -> None:
        """VAT calculation uses ROUND_HALF_EVEN (banker's rounding)."""
        # 10050 * 21% = 2110.5 → rounds to 2110 (nearest even)
        info: CustomerVATInfo = {"country": "RO", "is_business": False}
        result = TaxService.calculate_vat_for_document(10050, info)
        self.assertEqual(result.vat_cents, 2110)

    def test_audit_data_included(self) -> None:
        """Every calculation includes audit data for compliance."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": False,
            "customer_id": "CUST-001",
            "order_id": "ORD-001",
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertIn("scenario", result.audit_data)
        self.assertIn("calculated_at", result.audit_data)
        self.assertIn("reasoning", result.audit_data)
        self.assertEqual(result.audit_data["customer_id"], "CUST-001")
        self.assertEqual(result.audit_data["order_id"], "ORD-001")

    def test_result_is_vat_calculation_result_instance(self) -> None:
        """Result is always a VATCalculationResult dataclass."""
        info: CustomerVATInfo = {"country": "RO", "is_business": False}
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertIsInstance(result, VATCalculationResult)
        self.assertIsInstance(result.scenario, VATScenario)
        self.assertIsInstance(result.vat_rate, Decimal)
        self.assertIsInstance(result.vat_cents, int)
        self.assertIsInstance(result.total_cents, int)

    def test_is_vat_payer_false_disables_reverse_charge(self) -> None:
        """is_vat_payer=False downgrades EU B2B to B2C treatment."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "is_vat_payer": False,
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        # Should NOT be reverse charge — treated as B2C
        self.assertNotEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))

    def test_reverse_charge_eligible_flag_forces_reverse_charge(self) -> None:
        """reverse_charge_eligible=True forces EU B2B reverse charge."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "reverse_charge_eligible": True,
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_cents, 0)

    def test_reverse_charge_not_applied_for_romania(self) -> None:
        """reverse_charge_eligible does NOT apply to Romania (home country)."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
            "reverse_charge_eligible": True,
        }
        result = TaxService.calculate_vat_for_document(10000, info)

        # Romania is always charged Romanian VAT — reverse charge doesn't apply
        self.assertNotEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
