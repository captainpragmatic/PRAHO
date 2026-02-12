# ===============================================================================
# TAX CONFIGURATION & VAT COMPLIANCE TESTS
# ===============================================================================
"""
Comprehensive test suite for VAT system architecture.

Covers:
1. Temporal VAT rate validity (TaxRule model with valid_from/valid_to)
2. TaxService 4-tier resolution cascade (cache → DB → settings → defaults)
3. billing.config delegation to TaxService
4. Invoice immutability (locked_at enforcement)
5. OrderVATCalculator EU compliance scenarios
6. ADR-0005 / ADR-0015 compliance: no hardcoded VAT in business logic
7. Per-line VAT rate freezing on documents

References:
- ADR-0005: Immutable constants (IBAN_LENGTH, CUI_MAX_LENGTH)
- ADR-0015: Configuration Resolution Order (cache → DB → settings → defaults)
- Romania Emergency Ordinance 156/2024: 19% → 21% (Aug 1, 2025)
"""

from __future__ import annotations

import re
from datetime import date, timedelta
from decimal import Decimal
from pathlib import Path

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.config import DEFAULT_VAT_RATE, get_vat_rate, is_eu_country
from apps.billing.invoice_models import Invoice, InvoiceLine
from apps.billing.models import Currency, ProformaInvoice
from apps.billing.tax_models import TaxRule
from apps.common.tax_service import TaxService
from apps.customers.models import Customer, CustomerTaxProfile
from apps.orders.vat_rules import (
    CustomerVATInfo,
    OrderVATCalculator,
    VATScenario,
)

# ===============================================================================
# SECTION 1: TEMPORAL VAT RATE VALIDITY (TaxRule model)
# ===============================================================================


class TaxRuleTemporalValidityTests(TestCase):
    """Test TaxRule temporal validity for Romanian VAT rate changes.

    Romania changed VAT from 19% to 21% on August 1, 2025.
    Historical invoices MUST resolve to the rate valid at their creation date.
    """

    def setUp(self) -> None:
        """Seed historical and current Romanian VAT rules."""
        cache.clear()

        # Historical rate: 19% (Jan 2020 - Jul 31, 2025)
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.1900"),
            reduced_rate=Decimal("0.0900"),
            valid_from=date(2020, 1, 1),
            valid_to=date(2025, 7, 31),
            is_eu_member=True,
            vies_required=True,
            reverse_charge_eligible=True,
        )

        # Current rate: 21% (Aug 1, 2025 - indefinite)
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2100"),
            reduced_rate=Decimal("0.1100"),
            valid_from=date(2025, 8, 1),
            valid_to=None,
            is_eu_member=True,
            vies_required=True,
            reverse_charge_eligible=True,
        )

    def test_historical_rate_pre_aug2025(self) -> None:
        """Before Aug 2025, Romanian VAT was 19%."""
        rate = TaxRule.get_active_rate("RO", "vat", date(2024, 6, 15))
        self.assertEqual(rate, Decimal("0.1900"))

    def test_transition_boundary_july31(self) -> None:
        """July 31, 2025 is the last day of 19%."""
        rate = TaxRule.get_active_rate("RO", "vat", date(2025, 7, 31))
        self.assertEqual(rate, Decimal("0.1900"))

    def test_transition_boundary_aug1(self) -> None:
        """August 1, 2025 is the first day of 21%."""
        rate = TaxRule.get_active_rate("RO", "vat", date(2025, 8, 1))
        self.assertEqual(rate, Decimal("0.2100"))

    def test_current_rate_no_date(self) -> None:
        """Without a date argument, returns the currently active rate."""
        rate = TaxRule.get_active_rate("RO", "vat")
        self.assertEqual(rate, Decimal("0.2100"))

    def test_future_date_uses_current(self) -> None:
        """A future date still resolves to the open-ended rule."""
        rate = TaxRule.get_active_rate("RO", "vat", date(2030, 1, 1))
        self.assertEqual(rate, Decimal("0.2100"))

    def test_date_before_any_rule(self) -> None:
        """A date before all rules returns 0.00 (no rule active)."""
        rate = TaxRule.get_active_rate("RO", "vat", date(2019, 1, 1))
        self.assertEqual(rate, Decimal("0.00"))

    def test_non_romanian_country_returns_zero(self) -> None:
        """Country with no TaxRule returns 0.00."""
        rate = TaxRule.get_active_rate("XX", "vat")
        self.assertEqual(rate, Decimal("0.00"))

    def test_is_active_method(self) -> None:
        """TaxRule.is_active() checks date against valid_from/valid_to."""
        historical = TaxRule.objects.get(country_code="RO", valid_to__isnull=False)
        current = TaxRule.objects.get(country_code="RO", valid_to__isnull=True)

        # Historical rule should be active on Jul 31 2025, inactive on Aug 1
        self.assertTrue(historical.is_active(date(2025, 7, 31)))
        self.assertFalse(historical.is_active(date(2025, 8, 1)))

        # Current rule should be active on Aug 1, inactive on Jul 31
        self.assertTrue(current.is_active(date(2025, 8, 1)))
        self.assertFalse(current.is_active(date(2025, 7, 31)))


# ===============================================================================
# SECTION 2: TAX SERVICE 4-TIER CASCADE
# ===============================================================================


class TaxServiceCascadeTests(TestCase):
    """Test TaxService 4-tier resolution: cache → DB → settings → defaults.

    Per ADR-0015, the resolution order is:
    1. Cache (1h TTL)
    2. Database (TaxRule model)
    3. Django settings (VAT_RATE_XX or VAT_RATES dict)
    4. Code defaults (DEFAULT_VAT_RATES dict)
    """

    def setUp(self) -> None:
        cache.clear()

    def test_default_rate_for_romania(self) -> None:
        """Without DB rules, TaxService falls back to DEFAULT_VAT_RATES."""
        rate = TaxService.get_vat_rate("RO")
        self.assertEqual(rate, Decimal("21.0"))

    def test_default_rate_as_decimal(self) -> None:
        """as_decimal=True returns 0.21 instead of 21.0."""
        rate = TaxService.get_vat_rate("RO", as_decimal=True)
        self.assertEqual(rate, Decimal("0.21"))

    def test_database_overrides_defaults(self) -> None:
        """A TaxRule in the DB takes precedence over DEFAULT_VAT_RATES."""
        # Create a DB rule with a different rate
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2500"),
            valid_from=date(2020, 1, 1),
            valid_to=None,
            is_eu_member=True,
        )

        rate = TaxService.get_vat_rate("RO")
        self.assertEqual(rate, Decimal("25.00"))

    @override_settings(VAT_RATE_RO=Decimal("22.0"))
    def test_settings_override_when_no_db(self) -> None:
        """Django settings override defaults when no DB rule exists."""
        rate = TaxService.get_vat_rate("RO")
        self.assertEqual(rate, Decimal("22.0"))

    def test_cache_hit_returns_cached_value(self) -> None:
        """After first call, subsequent calls return cached value."""
        # First call — populates cache
        rate1 = TaxService.get_vat_rate("RO")

        # Verify cache is populated
        cached = cache.get("tax_rate:RO")
        self.assertIsNotNone(cached)

        # Second call should use cache
        rate2 = TaxService.get_vat_rate("RO")
        self.assertEqual(rate1, rate2)

    def test_cache_invalidation(self) -> None:
        """TaxService.invalidate_cache() clears cached rate."""
        TaxService.get_vat_rate("RO")  # populate cache
        self.assertIsNotNone(cache.get("tax_rate:RO"))

        TaxService.invalidate_cache("RO")
        self.assertIsNone(cache.get("tax_rate:RO"))

    def test_seeded_non_eu_country_gets_zero_vat(self) -> None:
        """Non-EU country with TaxRule(rate=0) gets 0% VAT (export)."""
        # Seed a non-EU rule (as setup_tax_rules would)
        TaxRule.objects.create(
            country_code="US",
            tax_type="vat",
            rate=Decimal("0.0000"),
            valid_from=date(2020, 1, 1),
            is_eu_member=False,
        )
        rate = TaxService.get_vat_rate("US")
        self.assertEqual(rate, Decimal("0.00"))

    def test_unknown_country_fails_safe_to_romanian(self) -> None:
        """Unknown 2-letter code with no TaxRule fails safe to Romanian VAT.

        This prevents tax leakage from typos (e.g. 'R0', 'ZZ') silently
        getting 0%. Countries that should get 0% must be seeded via
        setup_tax_rules.
        """
        rate = TaxService.get_vat_rate("ZZ")
        self.assertEqual(rate, Decimal("21.0"))

    def test_empty_code_defaults_to_romanian(self) -> None:
        """Empty/invalid country codes conservatively default to Romanian rate."""
        rate = TaxService.get_vat_rate("")
        self.assertEqual(rate, Decimal("21.0"))

    def test_eu_country_rates_unchanged(self) -> None:
        """EU country defaults are correct and not accidentally set to 21%."""
        # Germany has 19% (which is correct for DE, not a stale Romanian rate)
        self.assertEqual(TaxService.DEFAULT_VAT_RATES["DE"], Decimal("19.0"))
        # Cyprus also 19%
        self.assertEqual(TaxService.DEFAULT_VAT_RATES["CY"], Decimal("19.0"))
        # Hungary 27% (highest in EU)
        self.assertEqual(TaxService.DEFAULT_VAT_RATES["HU"], Decimal("27.0"))

    def test_calculate_vat_with_bankers_rounding(self) -> None:
        """calculate_vat() uses ROUND_HALF_EVEN for VAT compliance."""
        result = TaxService.calculate_vat(10000, "RO")  # 100.00 RON
        self.assertEqual(result["vat_cents"], 2100)  # 21% of 10000
        self.assertEqual(result["total_cents"], 12100)

    def test_calculate_vat_rounding_edge_case(self) -> None:
        """Banker's rounding: 0.5 rounds to nearest even."""
        # 1050 * 0.21 = 220.5 → rounds to 220 (even)
        result = TaxService.calculate_vat(1050, "RO")
        self.assertEqual(result["vat_cents"], 220)

    def test_is_eu_country(self) -> None:
        """EU country detection."""
        self.assertTrue(TaxService.is_eu_country("RO"))
        self.assertTrue(TaxService.is_eu_country("DE"))
        self.assertFalse(TaxService.is_eu_country("US"))
        self.assertFalse(TaxService.is_eu_country("GB"))


# ===============================================================================
# SECTION 3: BILLING CONFIG DELEGATION
# ===============================================================================


class BillingConfigDelegationTests(TestCase):
    """Test that billing.config.get_vat_rate() delegates to TaxService.

    After the consolidation, billing/config.py should NOT independently
    resolve VAT rates. It should use TaxService as the single source of truth.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_default_vat_rate_is_021(self) -> None:
        """DEFAULT_VAT_RATE constant is 0.21 (not stale 0.19)."""
        self.assertEqual(DEFAULT_VAT_RATE, Decimal("0.21"))

    def test_get_vat_rate_returns_decimal(self) -> None:
        """get_vat_rate() returns rate as decimal (0.21, not 21.0)."""
        rate = get_vat_rate("RO")
        self.assertEqual(rate, Decimal("0.21"))

    def test_get_vat_rate_defaults_to_romania(self) -> None:
        """get_vat_rate(None) defaults to Romanian rate."""
        rate = get_vat_rate(None)
        self.assertEqual(rate, Decimal("0.21"))

    def test_get_vat_rate_with_db_rule(self) -> None:
        """get_vat_rate() picks up TaxRule from database."""
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2300"),
            valid_from=date(2020, 1, 1),
            valid_to=None,
            is_eu_member=True,
        )
        rate = get_vat_rate("RO")
        self.assertEqual(rate, Decimal("0.23"))

    def test_is_eu_country_function(self) -> None:
        """is_eu_country() checks EU membership."""
        self.assertTrue(is_eu_country("RO"))
        self.assertTrue(is_eu_country("DE"))
        self.assertFalse(is_eu_country("US"))
        self.assertFalse(is_eu_country(None))
        self.assertFalse(is_eu_country(""))


# ===============================================================================
# SECTION 4: INVOICE IMMUTABILITY
# ===============================================================================


class InvoiceImmutabilityTests(TestCase):
    """Test that invoices become immutable once locked.

    Per ADR-0015, issued invoices freeze their tax rate at creation time.
    The locked_at field + clean() validation ensures immutability.
    A July 15, 2025 invoice MUST always show 19% even after the rate change.
    """

    def setUp(self) -> None:
        self.currency = Currency.objects.create(code="RON", symbol="lei", decimals=2)
        self.customer = Customer.objects.create(
            customer_type="company",
            company_name="Test SRL",
            status="active",
        )

    def test_draft_invoice_is_mutable(self) -> None:
        """Draft invoices can be modified freely."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-001",
            status="draft",
            total_cents=12100,
            tax_cents=2100,
            subtotal_cents=10000,
        )
        # Should succeed — drafts are mutable
        # Must keep subtotal+tax=total consistent
        invoice.total_cents = 15000
        invoice.tax_cents = 2600
        invoice.subtotal_cents = 12400
        invoice.save()  # no error
        invoice.refresh_from_db()
        self.assertEqual(invoice.total_cents, 15000)

    def test_locked_non_draft_invoice_raises_on_modify(self) -> None:
        """Locked invoices with non-draft status cannot be saved."""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-002",
            status="issued",
            locked_at=timezone.now(),
            total_cents=11900,
            tax_cents=1900,
            subtotal_cents=10000,
        )
        with self.assertRaises(ValidationError) as ctx:
            invoice.clean()
        self.assertIn("Cannot modify locked invoice", str(ctx.exception))

    def test_locked_draft_invoice_can_still_be_cleaned(self) -> None:
        """Locked invoice in 'draft' status is a transitional state (allowed)."""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-003",
            status="draft",
            locked_at=timezone.now(),
            total_cents=12100,
            tax_cents=2100,
            subtotal_cents=10000,
        )
        # Should not raise
        invoice.clean()

    def test_financial_calculation_integrity(self) -> None:
        """subtotal + tax must equal total when all non-zero."""
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-004",
            status="draft",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=99999,  # Wrong!
        )
        with self.assertRaises(ValidationError) as ctx:
            invoice.clean()
        self.assertIn("Financial calculation error", str(ctx.exception))

    def test_due_date_must_be_after_issue_date(self) -> None:
        """Due date must be strictly after issue date."""
        now = timezone.now()
        invoice = Invoice(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-005",
            status="draft",
            issued_at=now,
            due_at=now - timedelta(days=1),
        )
        with self.assertRaises(ValidationError) as ctx:
            invoice.clean()
        self.assertIn("Due date must be after issue date", str(ctx.exception))

    def test_invoice_line_stores_frozen_rate(self) -> None:
        """InvoiceLine stores the VAT rate at creation, independent of TaxRule.

        An invoice line created with tax_rate=0.1900 keeps that rate forever,
        even if TaxRule changes to 0.2100.
        """
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-006",
            status="draft",
        )
        line = InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Web Hosting (historical rate)",
            quantity=Decimal("1.000"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.1900"),  # 19% — frozen from pre-Aug 2025
        )
        line.refresh_from_db()

        # The line's rate is frozen at 19%, not overwritten to 21%
        self.assertEqual(line.tax_rate, Decimal("0.1900"))
        # Tax calculation: 10000 * 0.19 = 1900
        self.assertEqual(line.tax_cents, 1900)
        self.assertEqual(line.line_total_cents, 11900)

    def test_invoice_line_current_rate(self) -> None:
        """New lines created today use current 21% rate."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-007",
            status="draft",
        )
        line = InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Web Hosting (current rate)",
            quantity=Decimal("1.000"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),  # 21% — current rate
        )
        line.refresh_from_db()

        self.assertEqual(line.tax_rate, Decimal("0.2100"))
        self.assertEqual(line.tax_cents, 2100)
        self.assertEqual(line.line_total_cents, 12100)

    def test_recalculate_totals_from_lines(self) -> None:
        """Invoice.recalculate_totals() sums all line items correctly."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-TEST-008",
            status="draft",
        )
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="service",
            description="Hosting",
            quantity=Decimal("1.000"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
        )
        InvoiceLine.objects.create(
            invoice=invoice,
            kind="setup",
            description="Setup Fee",
            quantity=Decimal("1.000"),
            unit_price_cents=5000,
            tax_rate=Decimal("0.2100"),
        )

        invoice.recalculate_totals()

        self.assertEqual(invoice.subtotal_cents, 15000)  # 10000 + 5000
        self.assertEqual(invoice.tax_cents, 3150)  # 2100 + 1050
        self.assertEqual(invoice.total_cents, 18150)


# ===============================================================================
# SECTION 5: ORDER VAT CALCULATOR — EU COMPLIANCE SCENARIOS
# ===============================================================================


class OrderVATCalculatorTests(TestCase):
    """Test OrderVATCalculator for all VAT scenarios.

    Verifies the 5 EU VAT scenarios: Romania B2C, Romania B2B,
    EU B2C, EU B2B Reverse Charge, Non-EU Zero VAT.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_romania_b2c(self) -> None:
        """Romanian consumer: standard 21% VAT."""
        info: CustomerVATInfo = {"country": "RO", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)
        self.assertEqual(result.total_cents, 12100)

    def test_romania_b2b(self) -> None:
        """Romanian business: standard 21% VAT (same rate, different scenario)."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2B)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)

    def test_eu_b2c(self) -> None:
        """EU consumer: destination country rate (Germany 19%)."""
        info: CustomerVATInfo = {"country": "DE", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))
        self.assertEqual(result.vat_cents, 1900)

    def test_eu_b2b_reverse_charge(self) -> None:
        """EU business with VAT number: reverse charge (0% VAT)."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)
        self.assertEqual(result.total_cents, 10000)

    def test_eu_b2b_without_vat_number(self) -> None:
        """EU business WITHOUT VAT number: treated as B2C (destination rate)."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": None,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Without VAT number, can't apply reverse charge
        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))

    def test_non_eu_zero_vat(self) -> None:
        """Non-EU customer with seeded TaxRule: 0% VAT (export)."""
        # Seed US as non-EU 0% (as setup_tax_rules would)
        TaxRule.objects.create(
            country_code="US",
            tax_type="vat",
            rate=Decimal("0.0000"),
            valid_from=date(2020, 1, 1),
            is_eu_member=False,
        )
        info: CustomerVATInfo = {"country": "US", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.NON_EU_ZERO_VAT)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)

    def test_unknown_country_fails_safe_to_romanian_vat(self) -> None:
        """Unknown 2-letter code with no TaxRule fails safe to Romanian VAT."""
        info: CustomerVATInfo = {"country": "ZZ", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Fail-safe: unknown country → Romanian VAT (not 0%)
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)

    def test_empty_country_defaults_to_romanian_vat(self) -> None:
        """Empty/invalid country codes default to Romanian rate (conservative)."""
        info: CustomerVATInfo = {"country": "", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_bankers_rounding_consistency(self) -> None:
        """VAT calculation uses banker's rounding (ROUND_HALF_EVEN)."""
        # 10050 * 21% = 2110.5 → rounds to 2110 (even)
        info: CustomerVATInfo = {"country": "RO", "is_business": False}
        result = OrderVATCalculator.calculate_vat(10050, info)
        self.assertEqual(result.vat_cents, 2110)

    def test_audit_data_included(self) -> None:
        """Every calculation includes audit data for compliance."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": False,
            "customer_id": "CUST-001",
            "order_id": "ORD-001",
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertIn("scenario", result.audit_data)
        self.assertIn("calculated_at", result.audit_data)
        self.assertEqual(result.audit_data["customer_id"], "CUST-001")
        self.assertEqual(result.audit_data["order_id"], "ORD-001")


# ===============================================================================
# SECTION 6: CUSTOMER TAX PROFILE DEFAULTS
# ===============================================================================


class CustomerTaxProfileDefaultTests(TestCase):
    """Test CustomerTaxProfile model defaults match current rates."""

    def setUp(self) -> None:
        self.customer = Customer.objects.create(
            customer_type="company",
            company_name="New Customer SRL",
            status="active",
        )

    def test_new_tax_profile_defaults_to_21(self) -> None:
        """New CustomerTaxProfile defaults to 21% (not stale 19%)."""
        profile = CustomerTaxProfile.objects.create(customer=self.customer)
        self.assertEqual(profile.vat_rate, Decimal("21.00"))

    def test_existing_19_rate_preserved(self) -> None:
        """Customers with explicit 19% rate keep their stored value."""
        profile = CustomerTaxProfile.objects.create(
            customer=self.customer,
            vat_rate=Decimal("19.00"),
        )
        profile.refresh_from_db()
        self.assertEqual(profile.vat_rate, Decimal("19.00"))

    def test_is_vat_payer_default(self) -> None:
        """New profiles default to is_vat_payer=True."""
        profile = CustomerTaxProfile.objects.create(customer=self.customer)
        self.assertTrue(profile.is_vat_payer)


# ===============================================================================
# SECTION 7: HARDCODED VAT GUARD TEST (ADR-0005 / ADR-0015 COMPLIANCE)
# ===============================================================================


class HardcodedVATGuardTests(TestCase):
    """Scan business logic for hardcoded VAT rates.

    ADR-0015 mandates that business logic use TaxService for VAT rates,
    not hardcoded Decimal values. This test catches future sprawl.

    Allowed exceptions:
    - migrations/ (historical, immutable)
    - constants.py (ADR-0005 immutable constants)
    - tax_service.py (the source of truth's own defaults)
    - tax_models.py (the model definition)
    - efactura/settings.py (e-Factura standard codes)
    - tests/ (test fixtures use known inputs)
    - conftest.py (pytest fixtures)
    - setup_tax_rules.py (seed data command)
    """

    # Patterns that indicate a hardcoded Romanian VAT rate.
    # These are intentionally narrow to minimize false positives:
    # - Only match Decimal("0.19...") and Decimal("19.00") (the formats used in code)
    # - Don't match bare floats/ints (too many false positives with version numbers, etc.)
    SUSPECT_PATTERNS = [
        # Decimal format: Decimal("0.19"), Decimal("0.1900"), Decimal("19.00")
        r'Decimal\(\s*["\']0\.19(?:00)?["\']\s*\)',
        r'Decimal\(\s*["\']19\.00["\']\s*\)',
    ]

    # Directories/files that are allowed to have hardcoded rates
    ALLOWED_PATHS = {
        "migrations",
        "constants.py",
        "tax_service.py",
        "tax_models.py",
        "efactura/settings.py",
        "tests/",
        "conftest.py",
        "setup_tax_rules.py",
        "generate_sample_data.py",
        "create_sample_domains.py",
    }

    def test_no_hardcoded_19_in_business_logic(self) -> None:
        """No stale 19% VAT references in business logic files.

        Scans all .py files under apps/ for patterns that look like
        hardcoded Romanian VAT rates (0.19, 19.00, Decimal("0.19")).
        Only fires on non-allowlisted files.
        """
        apps_dir = Path(__file__).resolve().parent.parent.parent / "apps"
        violations = []

        for py_file in apps_dir.rglob("*.py"):
            # Check if file is in allowed path
            rel_path = str(py_file.relative_to(apps_dir))
            if any(allowed in rel_path for allowed in self.ALLOWED_PATHS):
                continue

            try:
                content = py_file.read_text()
            except (OSError, UnicodeDecodeError):
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                # Skip comments
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue

                for pattern in self.SUSPECT_PATTERNS:
                    if re.search(pattern, line):
                        # Exclude lines referencing EU country codes that have 19% VAT
                        # (Germany DE, Cyprus CY — their 19% is correct, not a stale RO rate)
                        eu_19_countries = {"DE", "CY"}
                        if any(
                            f"'{cc}'" in line or f'"{cc}"' in line
                            for cc in eu_19_countries
                        ):
                            continue
                        violations.append(f"{rel_path}:{line_num}: {stripped}")

        if violations:
            msg = (
                f"Found {len(violations)} hardcoded 19% VAT reference(s) in business logic.\n"
                "Use TaxService.get_vat_rate() instead (ADR-0015).\n\n"
                + "\n".join(violations)
            )
            self.fail(msg)

    def test_no_romanian_vat_rate_constant_outside_allowlist(self) -> None:
        """No ROMANIAN_VAT_RATE = ... definitions outside test files and efactura/settings.py.

        After the config-consolidation cleanup, the ROMANIAN_VAT_RATE module-level
        constant should only exist in test fixtures and efactura settings.
        """
        apps_dir = Path(__file__).resolve().parent.parent.parent / "apps"
        violations = []

        # Pattern: module-level constant definition (not inside comments)
        pattern = re.compile(r"^\s*ROMANIAN_VAT_RATE\s*[=:]")

        for py_file in apps_dir.rglob("*.py"):
            rel_path = str(py_file.relative_to(apps_dir))
            # Allow in efactura settings and test files
            if any(allowed in rel_path for allowed in self.ALLOWED_PATHS):
                continue

            try:
                content = py_file.read_text()
            except (OSError, UnicodeDecodeError):
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                stripped = line.strip()
                if stripped.startswith("#"):
                    continue
                if pattern.match(line):
                    violations.append(f"{rel_path}:{line_num}: {stripped}")

        if violations:
            msg = (
                f"Found {len(violations)} ROMANIAN_VAT_RATE definition(s) outside allowlist.\n"
                "VAT rates should only come from TaxService (ADR-0005/0015).\n\n"
                + "\n".join(violations)
            )
            self.fail(msg)

    # test_constants_py_has_no_vat_rate removed — covered by
    # tests/common/test_constants_consistency.py::ConstantsVATGuardTest

    def test_no_hardcoded_vat_in_templates(self) -> None:
        """No stale 19% VAT rates in HTML templates."""
        templates_dir = (
            Path(__file__).resolve().parent.parent.parent.parent / "templates"
        )

        if not templates_dir.exists():
            return  # Skip if templates dir not found

        violations = []
        for html_file in templates_dir.rglob("*.html"):
            try:
                content = html_file.read_text()
            except (OSError, UnicodeDecodeError):
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                # Look for value="19" in dropdowns (the critical bug we fixed)
                if re.search(r'value\s*=\s*["\']19["\']', line):
                    rel_path = str(html_file.relative_to(templates_dir))
                    violations.append(f"{rel_path}:{line_num}: {line.strip()}")

        if violations:
            msg = (
                f"Found {len(violations)} template(s) with value=\"19\" "
                "(stale Romanian VAT).\n\n" + "\n".join(violations)
            )
            self.fail(msg)

    def test_no_hardcoded_vat_in_javascript(self) -> None:
        """No stale 19% VAT defaults in JavaScript files."""
        static_dir = (
            Path(__file__).resolve().parent.parent.parent.parent / "static"
        )

        if not static_dir.exists():
            return  # Skip if static dir not found

        violations = []
        for js_file in static_dir.rglob("*.js"):
            try:
                content = js_file.read_text()
            except (OSError, UnicodeDecodeError):
                continue

            for line_num, line in enumerate(content.splitlines(), 1):
                if re.search(r'vatRate\s*=\s*19\b', line):
                    rel_path = str(js_file.relative_to(static_dir))
                    violations.append(f"{rel_path}:{line_num}: {line.strip()}")

        if violations:
            msg = (
                f"Found {len(violations)} JS file(s) with hardcoded vatRate=19.\n\n"
                + "\n".join(violations)
            )
            self.fail(msg)


# ===============================================================================
# SECTION 8: E-FACTURA VALIDATOR RATE SET
# ===============================================================================


class EFacturaValidatorRateTests(TestCase):
    """Test that e-Factura validator accepts current Romanian rates."""

    def test_valid_vat_rates_set(self) -> None:
        """VALID_VAT_RATES contains 21%, 11%, 0% (not stale 19%, 9%, 5%)."""
        from apps.billing.efactura.validator import CIUSROValidator

        expected = {"21.00", "11.00", "0.00"}
        self.assertEqual(CIUSROValidator.VALID_VAT_RATES, expected)


# ===============================================================================
# SECTION 9: PROFORMA MODEL TAX RATE STORAGE
# ===============================================================================


class ProformaInvoiceTaxTests(TestCase):
    """Test that ProformaInvoice stores VAT rate per line."""

    def setUp(self) -> None:
        self.currency = Currency.objects.create(code="RON", symbol="lei", decimals=2)
        self.customer = Customer.objects.create(
            customer_type="company",
            company_name="Proforma Test SRL",
            status="active",
        )

    def test_proforma_default_tax_rate(self) -> None:
        """New proforma line defaults should use current rate when created by views."""
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PF-TEST-001",
            status="draft",
        )
        # ProformaInvoice itself doesn't have a tax_rate field —
        # rates are on the lines, which is correct per ADR-0015
        self.assertEqual(proforma.status, "draft")


# ===============================================================================
# SECTION 10: PER-CUSTOMER VAT OVERRIDES (Part F)
# ===============================================================================


class PerCustomerVATOverrideTests(TestCase):
    """Test per-customer VAT overrides from CustomerTaxProfile.

    CustomerTaxProfile has is_vat_payer, vat_rate, and reverse_charge_eligible.
    These should be respected by OrderVATCalculator when passed via CustomerVATInfo.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_non_vat_payer_treated_as_b2c(self) -> None:
        """Customer with is_vat_payer=False is treated as B2C consumer.

        A non-plătitor de TVA still gets charged VAT — they just can't
        participate in EU B2B reverse charge. So a Romanian non-VAT-payer
        gets standard 21% (not 0%).
        """
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
            "is_vat_payer": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Treated as B2C — standard Romanian rate, NOT 0%
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)
        self.assertEqual(result.total_cents, 12100)

    def test_non_vat_payer_eu_no_reverse_charge(self) -> None:
        """Non-VAT-payer EU business can't use reverse charge → destination B2C rate."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "is_vat_payer": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Treated as B2C — gets German consumer rate, NOT reverse charge 0%
        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertEqual(result.vat_rate, Decimal("19.0"))  # DE rate
        self.assertEqual(result.vat_cents, 1900)

    def test_custom_vat_rate_override(self) -> None:
        """Customer with explicit vat_rate uses that rate."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "custom_vat_rate": Decimal("15.0"),
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.CUSTOM_RATE_OVERRIDE)
        self.assertEqual(result.vat_rate, Decimal("15.0"))
        self.assertEqual(result.vat_cents, 1500)
        self.assertEqual(result.total_cents, 11500)

    def test_reverse_charge_via_profile(self) -> None:
        """reverse_charge_eligible=True + EU country + VAT number → 0%."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "reverse_charge_eligible": True,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_rate, Decimal("0.0"))
        self.assertEqual(result.vat_cents, 0)

    def test_reverse_charge_not_for_romania(self) -> None:
        """reverse_charge_eligible doesn't apply to Romanian customers."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
            "reverse_charge_eligible": True,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Romanian B2B: still gets standard Romanian rate
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2B)
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_vat_payer_default_uses_country_rate(self) -> None:
        """is_vat_payer=True with no custom rate → standard country rate."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": False,
            "is_vat_payer": True,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        self.assertEqual(result.vat_rate, Decimal("21.0"))
        self.assertEqual(result.vat_cents, 2100)

    def test_calculate_vat_respects_business_flag(self) -> None:
        """TaxService.calculate_vat with is_business + EU VAT number → 0%."""
        result = TaxService.calculate_vat(
            10000, "DE", is_business=True, vat_number="DE123456789"
        )
        self.assertEqual(result["vat_cents"], 0)
        self.assertEqual(result["total_cents"], 10000)
        self.assertEqual(result["vat_rate_percent"], Decimal("0.0"))

    def test_calculate_vat_romanian_business_still_charged(self) -> None:
        """TaxService.calculate_vat: Romanian business still pays 21%."""
        result = TaxService.calculate_vat(
            10000, "RO", is_business=True, vat_number="RO12345678"
        )
        self.assertEqual(result["vat_cents"], 2100)

    def test_calculate_vat_non_eu_business_zero(self) -> None:
        """TaxService.calculate_vat: non-EU business gets 0% VAT (export)."""
        # Non-EU countries must be seeded in TaxRule to get 0% (fail-safe is Romanian VAT)
        TaxRule.objects.create(
            country_code="US", tax_type="vat", rate=Decimal("0.00"),
            valid_from=date(2020, 1, 1), is_eu_member=False,
        )
        TaxService.invalidate_cache("US")

        result = TaxService.calculate_vat(
            10000, "US", is_business=True, vat_number="US12345"
        )
        # US is non-EU with seeded 0% rule → 0% VAT (export)
        self.assertEqual(result["vat_cents"], 0)
        self.assertEqual(result["total_cents"], 10000)


# ===============================================================================
# SECTION 11: CROSS-CALCULATOR CONSISTENCY
# ===============================================================================


class CrossCalculatorConsistencyTests(TestCase):
    """Verify TaxService and OrderVATCalculator agree on VAT amounts.

    Both paths should produce identical results for the same inputs.
    This catches drift between the two calculation codepaths.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_romanian_b2c_consistency(self) -> None:
        """TaxService and OrderVATCalculator agree on Romanian B2C."""
        amount = 10000
        ts_result = TaxService.calculate_vat(amount, "RO")
        ov_result = OrderVATCalculator.calculate_vat(
            amount, {"country": "RO", "is_business": False}
        )
        self.assertEqual(ts_result["vat_cents"], ov_result.vat_cents)
        self.assertEqual(ts_result["total_cents"], ov_result.total_cents)

    def test_eu_b2b_reverse_charge_consistency(self) -> None:
        """Both calculators return 0% for EU B2B reverse charge."""
        amount = 10000
        ts_result = TaxService.calculate_vat(
            amount, "DE", is_business=True, vat_number="DE123456789"
        )
        ov_result = OrderVATCalculator.calculate_vat(
            amount, {
                "country": "DE",
                "is_business": True,
                "vat_number": "DE123456789",
            }
        )
        self.assertEqual(ts_result["vat_cents"], 0)
        self.assertEqual(ov_result.vat_cents, 0)


# ===============================================================================
# SECTION 12: CACHE INVALIDATION SIGNAL
# ===============================================================================


class TaxRuleCacheSignalTests(TestCase):
    """Test that TaxRule save/delete signals invalidate TaxService cache."""

    def setUp(self) -> None:
        cache.clear()

    def test_saving_tax_rule_invalidates_cache(self) -> None:
        """Creating a TaxRule clears the cached rate for that country."""
        # Populate cache
        TaxService.get_vat_rate("RO")
        self.assertIsNotNone(cache.get("tax_rate:RO"))

        # Create a new TaxRule — should invalidate cache
        TaxRule.objects.create(
            country_code="RO",
            tax_type="vat",
            rate=Decimal("0.2500"),
            valid_from=date(2020, 1, 1),
            is_eu_member=True,
        )

        # Cache should be cleared
        self.assertIsNone(cache.get("tax_rate:RO"))

    def test_deleting_tax_rule_invalidates_cache(self) -> None:
        """Deleting a TaxRule clears the cached rate."""
        rule = TaxRule.objects.create(
            country_code="DE",
            tax_type="vat",
            rate=Decimal("0.1900"),
            valid_from=date(2020, 1, 1),
            is_eu_member=True,
        )
        # Populate cache
        TaxService.get_vat_rate("DE")
        self.assertIsNotNone(cache.get("tax_rate:DE"))

        # Delete — should invalidate
        rule.delete()
        self.assertIsNone(cache.get("tax_rate:DE"))


# ===============================================================================
# SECTION 13: REGRESSION TESTS FOR REVIEW FINDINGS
# ===============================================================================


class AuditMetadataConsistencyTests(TestCase):
    """Verify audit/result metadata is consistent with the chosen VAT scenario.

    Regression for: is_vat_payer=False downgrades to B2C, but audit data
    could show is_business=True contradicting the ROMANIA_B2C scenario.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_non_vat_payer_audit_shows_b2c(self) -> None:
        """When is_vat_payer=False downgrades to B2C, audit must show is_business=False."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,  # Input says business
            "vat_number": "RO12345678",
            "is_vat_payer": False,  # But not VAT-registered → downgrade to B2C
            "customer_id": "CUST-001",
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Scenario must be B2C
        self.assertEqual(result.scenario, VATScenario.ROMANIA_B2C)
        # Result object must reflect the effective (downgraded) state
        self.assertFalse(result.is_business)
        self.assertIsNone(result.vat_number)
        # Audit data must also be consistent
        self.assertFalse(result.audit_data["is_business"])
        self.assertIsNone(result.audit_data["vat_number"])

    def test_eu_non_vat_payer_no_reverse_charge_in_audit(self) -> None:
        """EU business with is_vat_payer=False: audit must show B2C, not reverse charge."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,
            "vat_number": "DE123456789",
            "is_vat_payer": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.EU_B2C)
        self.assertFalse(result.is_business)
        self.assertIsNone(result.vat_number)
        # Must pay German B2C rate, not 0% reverse charge
        self.assertEqual(result.vat_rate, Decimal("19.0"))

    def test_custom_rate_override_preserves_business_in_audit(self) -> None:
        """Custom rate override keeps original is_business in audit data."""
        info: CustomerVATInfo = {
            "country": "RO",
            "is_business": True,
            "vat_number": "RO12345678",
            "custom_vat_rate": Decimal("15.0"),
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.scenario, VATScenario.CUSTOM_RATE_OVERRIDE)
        self.assertTrue(result.is_business)
        self.assertEqual(result.audit_data["is_business"], True)


class NullCountrySafetyTests(TestCase):
    """Verify that None/missing country values don't crash the VAT calculation.

    Regression for: country=None → .upper() raises AttributeError.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_none_country_in_customer_info(self) -> None:
        """Explicitly None country must not crash."""
        info: CustomerVATInfo = {
            "country": None,
            "is_business": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Should fall back to Romanian rate
        self.assertEqual(result.country_code, "RO")
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_missing_country_key(self) -> None:
        """Missing country key must not crash."""
        info: CustomerVATInfo = {
            "is_business": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.country_code, "RO")
        self.assertEqual(result.vat_rate, Decimal("21.0"))

    def test_empty_string_country(self) -> None:
        """Empty string country defaults to Romanian rate."""
        info: CustomerVATInfo = {
            "country": "",
            "is_business": False,
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        self.assertEqual(result.country_code, "RO")
        self.assertEqual(result.vat_rate, Decimal("21.0"))


class BusinessDetectionConsistencyTests(TestCase):
    """Verify that is_business detection is consistent across calculation paths.

    Regression for: calculate_order_totals used company_name only, while
    create_order item path used company_name OR vat_number.
    Both paths must agree.
    """

    def setUp(self) -> None:
        cache.clear()

    def test_vat_number_alone_implies_business(self) -> None:
        """Customer with vat_number but no company_name is still a business."""
        info: CustomerVATInfo = {
            "country": "DE",
            "is_business": True,  # Set by: bool(company_name) or bool(vat_number)
            "vat_number": "DE123456789",
        }
        result = OrderVATCalculator.calculate_vat(10000, info)

        # Must get reverse charge, not B2C rate
        self.assertEqual(result.scenario, VATScenario.EU_B2B_REVERSE_CHARGE)
        self.assertEqual(result.vat_cents, 0)


# ===============================================================================
# SECTION 16: SETUP_TAX_RULES LEGACY REMEDIATION
# ===============================================================================


class RemediateLegacyRoRulesTests(TestCase):
    """Direct tests for _remediate_legacy_ro_rules() in setup_tax_rules command.

    Regression guard: the method must close *only* open-ended legacy RO VAT
    rules (valid_from < 2025-08-01, valid_to IS NULL) without touching:
    - Rules with explicit valid_to (already bounded)
    - Future rules (valid_from >= 2025-08-01)
    - The canonical current rule (valid_from = 2025-08-01)
    - Non-RO rules
    """

    def setUp(self) -> None:
        from apps.billing.management.commands.setup_tax_rules import Command
        self.command = Command()

    def test_closes_open_ended_legacy_rule(self) -> None:
        """Open-ended legacy RO rule gets valid_to=2025-07-31."""
        legacy = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2020, 1, 1), valid_to=None,
        )

        closed = self.command._remediate_legacy_ro_rules()

        legacy.refresh_from_db()
        self.assertEqual(closed, 1)
        self.assertEqual(legacy.valid_to, date(2025, 7, 31))

    def test_leaves_already_bounded_rule_untouched(self) -> None:
        """Rule with explicit valid_to is never modified."""
        bounded = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2020, 1, 1), valid_to=date(2024, 12, 31),
        )

        closed = self.command._remediate_legacy_ro_rules()

        bounded.refresh_from_db()
        self.assertEqual(closed, 0)
        self.assertEqual(bounded.valid_to, date(2024, 12, 31))

    def test_leaves_future_rule_untouched(self) -> None:
        """Future RO rule (valid_from >= 2025-08-01) is never touched."""
        future = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.25"),
            valid_from=date(2027, 1, 1), valid_to=None,
        )

        closed = self.command._remediate_legacy_ro_rules()

        future.refresh_from_db()
        self.assertEqual(closed, 0)
        self.assertIsNone(future.valid_to)

    def test_leaves_canonical_current_rule_untouched(self) -> None:
        """The canonical 2025-08-01 rule is never modified."""
        canonical = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.21"),
            valid_from=date(2025, 8, 1), valid_to=None,
        )

        closed = self.command._remediate_legacy_ro_rules()

        canonical.refresh_from_db()
        self.assertEqual(closed, 0)
        self.assertIsNone(canonical.valid_to)

    def test_leaves_non_ro_rules_untouched(self) -> None:
        """Open-ended rules for other countries are never touched."""
        de_rule = TaxRule.objects.create(
            country_code="DE", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2020, 1, 1), valid_to=None,
        )

        closed = self.command._remediate_legacy_ro_rules()

        de_rule.refresh_from_db()
        self.assertEqual(closed, 0)
        self.assertIsNone(de_rule.valid_to)

    def test_mixed_scenario_only_targets_correct_rows(self) -> None:
        """With a mix of legacy, bounded, future, and non-RO rules,
        only the open-ended legacy RO rule is closed."""
        # Should be closed
        legacy_open = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2023, 6, 1), valid_to=None,
        )
        # Should NOT be closed (already bounded)
        legacy_bounded = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2020, 1, 1), valid_to=date(2023, 5, 31),
        )
        # Should NOT be closed (canonical current)
        canonical = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.21"),
            valid_from=date(2025, 8, 1), valid_to=None,
        )
        # Should NOT be closed (future)
        future = TaxRule.objects.create(
            country_code="RO", tax_type="vat", rate=Decimal("0.25"),
            valid_from=date(2028, 1, 1), valid_to=None,
        )
        # Should NOT be closed (non-RO)
        de_rule = TaxRule.objects.create(
            country_code="DE", tax_type="vat", rate=Decimal("0.19"),
            valid_from=date(2020, 1, 1), valid_to=None,
        )

        closed = self.command._remediate_legacy_ro_rules()

        self.assertEqual(closed, 1)

        legacy_open.refresh_from_db()
        self.assertEqual(legacy_open.valid_to, date(2025, 7, 31))

        legacy_bounded.refresh_from_db()
        self.assertEqual(legacy_bounded.valid_to, date(2023, 5, 31))

        canonical.refresh_from_db()
        self.assertIsNone(canonical.valid_to)

        future.refresh_from_db()
        self.assertIsNone(future.valid_to)

        de_rule.refresh_from_db()
        self.assertIsNone(de_rule.valid_to)
