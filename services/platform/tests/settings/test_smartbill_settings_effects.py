"""The two `critical=True` settings whose effect nothing asserted.

An audit of all 262 catalog keys found 53 with an effect test - a test that writes the key and
then observes a DIFFERENT app's behaviour change. Two of the five keys flagged `critical=True`
were not among them: `integrations.smartbill_invoice_series` and
`integrations.smartbill_tax_names`. Both were merely mentioned in tests, never driven.

`tests/billing/test_smartbill_mapper.py` covers the mapper thoroughly, but it constructs
`SmartBillAccountConfig` directly. That proves the mapper; it cannot prove the settings, because
nothing between the stored value and the mapper is exercised. This closes that span:
setting -> `_config_from_settings()` -> `build_invoice_payload`.

The effect being asserted is the one that matters. Neither setting is decorative - each decides
whether an invoice may be sent to SmartBill at all, and a wrong tax name would put a legally
incorrect VAT description on a Romanian fiscal document. `tax_names` is operator-configured
rather than derived precisely because two configured rates can share a percentage with different
fiscal meaning, so selecting by percentage alone is unsafe.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Currency, Invoice
from apps.billing.issuers.smartbill.issuer import _config_from_settings
from apps.billing.issuers.smartbill.mapper import build_invoice_payload
from apps.settings.services import SettingsService
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

SERIES_KEY = "integrations.smartbill_invoice_series"
TAX_NAMES_KEY = "integrations.smartbill_tax_names"
MEASURING_UNIT_KEY = "integrations.smartbill_measuring_unit"
UNIT_FROM_SETTINGS = "ora"  # distinct from the catalog default "buc"
SERIES_REFUSAL = "No SmartBill invoice series configured"
TAX_NAME_REFUSAL = "No SmartBill tax name configured"


class SmartBillSettingEffectTests(TestCase):
    """Each test drives the stored value and asserts what the mapper then does."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        # A fully valid invoice, so the only refusals that can appear are the configured ones.
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-EFFECT-0001",
            status="issued",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_tax_id="RO12345678",
            bill_to_address1="Str. Exemplu 1",
            bill_to_city="Sector 1",
            bill_to_region="Bucuresti",
            bill_to_country="RO",
            vat_evidence={
                "version": 1,
                "scenario": "romania_b2b",
                "category": "S",
                "country_code": "RO",
                "is_business": True,
                "vat_rate_percent": "0.21",
            },
        )
        InvoiceLineFactory(
            invoice=self.invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
            tax_category_code="S",
        )
        # A measuring unit is required independently, so it must be set or every assertion below
        # would be masked by that refusal. Deliberately NOT the catalog default "buc": writing a
        # value a setting already has earns the key an effect credit while proving nothing about it,
        # and `test_the_configured_series_is_what_reaches_the_payload` asserts this one lands too.
        SettingsService.update_setting(MEASURING_UNIT_KEY, UNIT_FROM_SETTINGS)

    def _refusals(self) -> tuple[str, ...]:
        result = build_invoice_payload(self.invoice, _config_from_settings())
        return tuple(result.error) if result.is_err() else ()

    # --- integrations.smartbill_invoice_series -------------------------------------

    def test_an_unset_series_refuses_the_invoice(self) -> None:
        SettingsService.update_setting(SERIES_KEY, "")
        SettingsService.update_setting(TAX_NAMES_KEY, {"S:21.00": "Normala"})

        self.assertIn(SERIES_REFUSAL, self._refusals())

    def test_a_configured_series_removes_that_refusal(self) -> None:
        SettingsService.update_setting(SERIES_KEY, "FCT")
        SettingsService.update_setting(TAX_NAMES_KEY, {"S:21.00": "Normala"})

        self.assertNotIn(SERIES_REFUSAL, self._refusals())

    def test_the_configured_series_is_what_reaches_the_payload(self) -> None:
        """Not merely "a series was set": the value that travels must be the one stored."""
        SettingsService.update_setting(SERIES_KEY, "SERIES-FROM-SETTINGS")
        SettingsService.update_setting(TAX_NAMES_KEY, {"S:21.00": "Normala"})

        result = build_invoice_payload(self.invoice, _config_from_settings())

        self.assertTrue(result.is_ok(), result.error if result.is_err() else "")
        payload = result.unwrap().payload
        self.assertEqual(payload["seriesName"], "SERIES-FROM-SETTINGS")
        for product in payload["products"]:
            self.assertEqual(product["measuringUnitName"], UNIT_FROM_SETTINGS)

    # --- integrations.smartbill_tax_names ------------------------------------------

    def test_an_unmapped_vat_rate_refuses_the_invoice(self) -> None:
        """Selecting a rate by percentage alone is unsafe, so an absent mapping must refuse."""
        SettingsService.update_setting(SERIES_KEY, "FCT")
        SettingsService.update_setting(TAX_NAMES_KEY, {})

        refusals = self._refusals()

        self.assertTrue(
            any(TAX_NAME_REFUSAL in refusal for refusal in refusals),
            f"an unmapped 21% rate should refuse; got {refusals}",
        )

    def test_the_configured_tax_name_is_what_reaches_the_payload(self) -> None:
        SettingsService.update_setting(SERIES_KEY, "FCT")
        SettingsService.update_setting(TAX_NAMES_KEY, {"S:21.00": "NAME-FROM-SETTINGS"})

        result = build_invoice_payload(self.invoice, _config_from_settings())

        self.assertTrue(result.is_ok(), result.error if result.is_err() else "")
        # The field, not the payload's repr. Searching the whole structure would also pass if the
        # name landed in `measuringUnitName` or a description, which is a different bug entirely.
        products = result.unwrap().payload["products"]
        self.assertTrue(products)
        for product in products:
            self.assertEqual(product["taxName"], "NAME-FROM-SETTINGS")

    def test_a_mapping_for_a_different_rate_does_not_satisfy_this_one(self) -> None:
        """The mapping is keyed on category and rate together, which is the point of it."""
        SettingsService.update_setting(SERIES_KEY, "FCT")
        SettingsService.update_setting(TAX_NAMES_KEY, {"S:11.00": "Redusa"})

        refusals = self._refusals()

        self.assertTrue(
            any(TAX_NAME_REFUSAL in refusal for refusal in refusals),
            f"an 11% mapping must not satisfy a 21% line; got {refusals}",
        )
