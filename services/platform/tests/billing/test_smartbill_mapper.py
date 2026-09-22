"""Mapping a PRAHO invoice to SmartBill, and refusing when it cannot be done.

Most of these are refusals, deliberately. SmartBill's API models commercial
invoicing; e-Factura models legal invoicing. A 0% rate answers "how much" but never
"why", and for a reverse charge the "why" is the mandatory part. Anything whose
fiscal meaning cannot be carried is refused rather than approximated.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import Currency, Invoice
from apps.billing.issuers.smartbill.mapper import (
    SUPPORTED_TAX_CATEGORIES,
    SmartBillAccountConfig,
    build_invoice_payload,
)
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory

CONFIG = SmartBillAccountConfig(
    invoice_series="TEST",
    tax_names={"S:21.00": "Normala", "S:11.00": "Redusa"},
    company_vat_code="RO12345678",
)


def _currency(code: str = "RON") -> Currency:
    obj, _ = Currency.objects.get_or_create(code=code, defaults={"symbol": "L", "decimals": 2})
    return obj


class MapperTestBase(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = _currency()
        self._counter = 0

    def _invoice(self, **kwargs: object) -> Invoice:
        self._counter += 1
        defaults: dict[str, object] = {
            "customer": self.customer,
            "currency": self.currency,
            "number": f"INV-MAP-{self._counter:04d}",
            "status": "issued",
            "issued_at": timezone.now(),
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": 12100,
            "bill_to_name": "Test Company SRL",
            "bill_to_tax_id": "RO12345678",
            "bill_to_address1": "Str. Exemplu 1",
            "bill_to_city": "Sector 1",
            "bill_to_region": "Bucuresti",
            "bill_to_country": "RO",
            # The frozen VAT decision. isTaxPayer is read from here, never inferred
            # from the presence of a tax ID.
            "vat_evidence": {
                "version": 1,
                "scenario": "romania_b2b",
                "category": "S",
                "country_code": "RO",
                "is_business": True,
                "vat_rate_percent": "0.21",
            },
        }
        defaults.update(kwargs)
        return Invoice.objects.create(**defaults)

    def _line(self, invoice: Invoice, **kwargs: object) -> None:
        defaults: dict[str, object] = {
            "invoice": invoice,
            "description": "Hosting",
            "quantity": Decimal("1"),
            "unit_price_cents": 10000,
            "tax_rate": Decimal("0.2100"),
            "tax_cents": 2100,
            "line_total_cents": 12100,
            "tax_category_code": "S",
        }
        defaults.update(kwargs)
        InvoiceLineFactory(**defaults)


class HappyPathTests(MapperTestBase):
    def test_a_standard_romanian_invoice_maps(self) -> None:
        invoice = self._invoice()
        self._line(invoice)

        result = build_invoice_payload(invoice, CONFIG)

        self.assertTrue(result.is_ok(), msg=result.error if result.is_err() else "")
        mapped = result.unwrap()
        self.assertEqual(mapped.expected_total_cents, 12100)
        self.assertEqual(mapped.tax_name, "Normala")

    def test_account_coupled_strings_come_from_configuration(self) -> None:
        """`seriesName`, `taxName` and `measuringUnitName` are never invented."""
        invoice = self._invoice()
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload

        self.assertEqual(payload["seriesName"], "TEST")
        self.assertEqual(payload["products"][0]["taxName"], "Normala")
        self.assertEqual(payload["products"][0]["measuringUnitName"], "buc")

    def test_praho_keeps_delivery_and_the_nomenclature_stays_empty(self) -> None:
        invoice = self._invoice()
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload

        self.assertFalse(payload["sendEmail"])
        self.assertFalse(payload["client"]["saveToDb"])
        self.assertFalse(payload["products"][0]["saveToDb"])

    def test_prices_are_explicitly_vat_exclusive(self) -> None:
        """SmartBill defaults to exclusive; relying on a default is how it drifts."""
        invoice = self._invoice()
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload
        self.assertIs(payload["products"][0]["isTaxIncluded"], False)

    def test_a_vat_registered_buyer_is_marked_as_one(self) -> None:
        """`isTaxPayer` defaults to false, which misrepresents a registered company."""
        invoice = self._invoice()
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload
        self.assertIs(payload["client"]["isTaxPayer"], True)


class DiscountTests(MapperTestBase):
    def test_a_document_discount_becomes_one_trailing_line(self) -> None:
        invoice = self._invoice(discount_cents=1000, subtotal_cents=9000, tax_cents=1890, total_cents=10890)
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload
        discount = payload["products"][-1]

        self.assertTrue(discount["isDiscount"])
        self.assertEqual(discount["discountType"], 1)

    def test_number_of_items_is_set(self) -> None:
        """Omitting it makes SmartBill IGNORE the discount, return 200, and issue
        the document at the unreduced total."""
        invoice = self._invoice(discount_cents=1000, subtotal_cents=9000, tax_cents=1890, total_cents=10890)
        self._line(invoice)

        discount = build_invoice_payload(invoice, CONFIG).unwrap().payload["products"][-1]
        self.assertEqual(discount["numberOfItems"], 1)

    def test_the_discount_value_is_negative(self) -> None:
        """A positive value is accepted and INCREASES the total instead."""
        invoice = self._invoice(discount_cents=1000, subtotal_cents=9000, tax_cents=1890, total_cents=10890)
        self._line(invoice)

        discount = build_invoice_payload(invoice, CONFIG).unwrap().payload["products"][-1]
        self.assertLess(discount["discountValue"], 0)


class RefusalTests(MapperTestBase):
    """Each of these would produce a legally wrong document if approximated."""

    def _errors(self, invoice: Invoice) -> tuple[str, ...]:
        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_err(), msg="expected a refusal")
        return result.error

    def test_reverse_charge_is_refused(self) -> None:
        """AE needs BT-151 and an exemption reason; the API carries neither."""
        invoice = self._invoice(bill_to_country="DE")
        self._line(invoice, tax_rate=Decimal("0.0000"), tax_cents=0, tax_category_code="AE")

        self.assertTrue(any("BT-151" in e for e in self._errors(invoice)))

    def test_out_of_scope_is_refused(self) -> None:
        invoice = self._invoice(bill_to_country="US")
        self._line(invoice, tax_rate=Decimal("0.0000"), tax_cents=0, tax_category_code="O")

        self.assertTrue(any("cannot be expressed" in e for e in self._errors(invoice)))

    def test_zero_rated_is_refused(self) -> None:
        invoice = self._invoice()
        self._line(invoice, tax_rate=Decimal("0.0000"), tax_cents=0, tax_category_code="Z")

        self.assertTrue(any("cannot be expressed" in e for e in self._errors(invoice)))

    def test_only_category_s_is_supported(self) -> None:
        """Pins the fail-closed list so widening it is a deliberate act."""
        self.assertEqual(SUPPORTED_TAX_CATEGORIES, frozenset({"S"}))

    def test_a_multi_rate_document_is_refused(self) -> None:
        """A single document discount cannot be split across rates faithfully."""
        invoice = self._invoice(subtotal_cents=20000, tax_cents=3200, total_cents=23200)
        self._line(invoice)
        self._line(invoice, tax_rate=Decimal("0.1100"), tax_cents=1100, line_total_cents=11100)

        self.assertTrue(any("Multiple VAT rates" in e for e in self._errors(invoice)))

    def test_a_line_level_discount_is_refused(self) -> None:
        invoice = self._invoice()
        self._line(invoice, discount_amount_cents=500)

        self.assertTrue(any("Line-level discounts" in e for e in self._errors(invoice)))

    def test_a_zero_quantity_is_refused(self) -> None:
        """SmartBill accepts 0 and negative quantities without error."""
        invoice = self._invoice()
        self._line(invoice, quantity=Decimal("0"))

        self.assertTrue(any("quantity" in e for e in self._errors(invoice)))

    def test_bucharest_without_a_sector_is_refused(self) -> None:
        """Otherwise the e-Factura fails SPV validation after it has been issued."""
        invoice = self._invoice(bill_to_city="Bucuresti", bill_to_region="Bucuresti")
        self._line(invoice)

        self.assertTrue(any("Sector 1..6" in e for e in self._errors(invoice)))

    def test_a_missing_tax_name_is_refused_rather_than_guessed(self) -> None:
        """Two configured rates can share a percentage with different meaning."""
        invoice = self._invoice(subtotal_cents=10000, tax_cents=1900, total_cents=11900)
        self._line(invoice, tax_rate=Decimal("0.1900"), tax_cents=1900, line_total_cents=11900)

        self.assertTrue(any("No SmartBill tax name configured" in e for e in self._errors(invoice)))

    def test_an_invoice_with_no_lines_is_refused(self) -> None:
        self.assertTrue(any("no lines" in e for e in self._errors(self._invoice())))

    def test_every_refusal_is_reported_at_once(self) -> None:
        """One problem per attempt is a bad trade against a provider that charges a
        fiscal number for each one."""
        invoice = self._invoice(bill_to_name="", bill_to_city="Bucuresti", bill_to_region="Bucuresti")
        self._line(invoice, quantity=Decimal("0"))

        self.assertGreaterEqual(len(self._errors(invoice)), 3)


class ArithmeticTests(MapperTestBase):
    """SmartBill recomputes totals and will not accept ours."""

    def test_a_divergence_from_the_ledger_is_refused(self) -> None:
        """Issuing anyway would make the legal document disagree with our record.

        The invoice is internally consistent; the LINE prices are not what its
        totals describe, which is exactly the drift this check exists to catch.
        """
        invoice = self._invoice()
        self._line(invoice, unit_price_cents=50000, line_total_cents=60500, tax_cents=10500)

        result = build_invoice_payload(invoice, CONFIG)

        self.assertTrue(result.is_err())
        self.assertTrue(any("disagree" in e for e in result.error))

    def test_fractional_quantities_still_reconcile(self) -> None:
        invoice = self._invoice(subtotal_cents=1234, tax_cents=259, total_cents=1493)
        self._line(
            invoice,
            quantity=Decimal("1.234"),
            unit_price_cents=1000,
            tax_cents=259,
            line_total_cents=1493,
        )

        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_ok(), msg=result.error if result.is_err() else "")


class ForeignCurrencyTests(MapperTestBase):
    def test_the_frozen_bnr_rate_is_sent_at_document_level(self) -> None:
        """Romanian law wants the BNR rate of the day before the tax point, and
        PRAHO froze it. Per-line rates are omitted: they can disagree."""
        eur = _currency("EUR")
        invoice = self._invoice(currency=eur, exchange_to_ron=Decimal("4.9772"))
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload

        self.assertEqual(payload["currency"], "EUR")
        self.assertAlmostEqual(payload["exchangeRate"], 4.9772, places=4)
        self.assertNotIn("exchangeRate", payload["products"][0])

    def test_a_foreign_invoice_without_a_frozen_rate_is_refused(self) -> None:
        eur = _currency("EUR")
        invoice = self._invoice(currency=eur, exchange_to_ron=None)
        self._line(invoice)

        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_err())
        self.assertTrue(any("exchange rate" in e for e in result.error))


class FiscalFactTests(MapperTestBase):
    """Facts are read from the document, never invented when absent."""

    def test_a_non_vat_registered_company_is_not_marked_as_registered(self) -> None:
        """A Romanian company can hold a CUI without being VAT-registered.

        Inferring `isTaxPayer` from the presence of a tax ID would misstate it.
        """
        invoice = self._invoice(
            vat_evidence={"version": 1, "scenario": "romania_b2c", "category": "S", "is_business": False},
        )
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload
        self.assertIs(payload["client"]["isTaxPayer"], False)
        self.assertTrue(payload["client"]["vatCode"], msg="the tax ID is still sent")

    def test_an_invoice_without_frozen_evidence_is_refused(self) -> None:
        invoice = self._invoice(vat_evidence={})
        self._line(invoice)

        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_err())
        self.assertTrue(any("VAT evidence" in e for e in result.error))

    def test_a_line_without_a_tax_category_is_refused(self) -> None:
        """Defaulting an absent category to 'S' would invent a fiscal fact."""
        invoice = self._invoice()
        self._line(invoice, tax_category_code="")

        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_err())
        self.assertTrue(any("no EN16931 tax category" in e for e in result.error))

    def test_a_missing_billing_country_is_refused(self) -> None:
        invoice = self._invoice(bill_to_country="", bill_to_city="Cluj", bill_to_region="Cluj")
        self._line(invoice)

        result = build_invoice_payload(invoice, CONFIG)
        self.assertTrue(result.is_err())
        self.assertTrue(any("bill_to_country" in e for e in result.error))


class ComponentTotalsTests(MapperTestBase):
    def test_a_matching_grand_total_is_not_enough(self) -> None:
        """Net 10001 + VAT 2099 and net 10000 + VAT 2100 both total 12100.

        They are different documents for VAT reporting, so all three components
        are compared, not just the sum.
        """
        invoice = self._invoice(subtotal_cents=10001, tax_cents=2099, total_cents=12100)
        self._line(invoice)

        result = build_invoice_payload(invoice, CONFIG)

        self.assertTrue(result.is_err(), msg="a shifted taxable base must not pass")
        joined = " ".join(result.error)
        self.assertIn("net", joined)
        self.assertIn("VAT", joined)


class CurrencyDenominationTests(MapperTestBase):
    def test_product_prices_carry_the_document_currency(self) -> None:
        """`products[].currency` defaults to RON INDEPENDENTLY of the document
        currency, so omitting it prices a EUR invoice in RON."""
        eur = _currency("EUR")
        invoice = self._invoice(currency=eur, exchange_to_ron=Decimal("4.9772"))
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload

        self.assertEqual(payload["currency"], "EUR")
        self.assertEqual(payload["products"][0]["currency"], "EUR")

    def test_the_discount_line_is_denominated_too(self) -> None:
        eur = _currency("EUR")
        invoice = self._invoice(
            currency=eur,
            exchange_to_ron=Decimal("4.9772"),
            discount_cents=1000,
            subtotal_cents=9000,
            tax_cents=1890,
            total_cents=10890,
        )
        self._line(invoice)

        payload = build_invoice_payload(invoice, CONFIG).unwrap().payload
        self.assertEqual(payload["products"][-1]["currency"], "EUR")


class PrecisionTests(MapperTestBase):
    def test_an_uncertified_precision_is_refused(self) -> None:
        """SmartBill's VAT calculation method is account-configurable (per-line vs
        document total) and untested here beyond 2 decimals."""
        invoice = self._invoice()
        self._line(invoice)

        config = SmartBillAccountConfig(
            invoice_series="TEST",
            tax_names={"S:21.00": "Normala"},
            company_vat_code="RO12345678",
            precision=4,
        )
        result = build_invoice_payload(invoice, config)

        self.assertTrue(result.is_err())
        self.assertTrue(any("precision" in e for e in result.error))
