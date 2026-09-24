"""The customer-facing document has to show the correction it describes.

The PDF derives the document discount exactly as the XML builder does, so it inherited
the same signed value - and the same three `> 0` guards that then discarded it. On a
credit note that means: no discount row at all, a VAT base taken from the gross lines
instead of the discounted net (so the PDF and the e-Factura XML state different taxable
amounts for one document), and a Subtotal falling through a `gross > 0` test written for
LINE-LESS documents into the net header.

The label is the fourth: `"Discount: -{amount}"` hardcodes the minus, so a negative
discount renders as a double negative. What the row means is the adjustment APPLIED to
the subtotal above it, which is `-discount` in both directions.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase, override_settings
from django.utils import timezone

from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.billing.issuers.service import _get_or_create_credit_note
from apps.billing.pdf_generators import RomanianInvoicePDFGenerator
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


@override_settings(COMPANY_NAME="Test Company SRL", EFACTURA_COMPANY_CUI="12345678")
class CreditNoteTotalsBlockTests(TestCase):
    """Lines gross 100.00, document discount 10.00, header net 90.00, VAT 21%."""

    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _discounted_original(self, number: str = "FCT-000800") -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=9000,
            tax_cents=1890,
            total_cents=10890,
            discount_cents=1000,
            bill_to_name="Customer SRL",
            bill_to_country="RO",
            bill_to_tax_id="RO87654321",
            issuer_provider=ISSUER_SMARTBILL,
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=1890,
            line_total_cents=11890,
        )
        return invoice

    def _issued_reversal(self, original: Invoice) -> Invoice:
        credit_note = _get_or_create_credit_note(original)
        Invoice.objects.filter(pk=credit_note.pk).update(number="CN-000800", issued_at=timezone.now())
        return Invoice.objects.get(pk=credit_note.pk)

    def _totals_rows(self, document: Invoice) -> list[str]:
        """Every string the totals block actually draws on the page."""
        generator = RomanianInvoicePDFGenerator(document)
        with patch.object(generator.canvas, "drawString") as drawn:
            generator._render_totals_section()
        return [call.args[2] for call in drawn.call_args_list]

    def test_the_credit_note_shows_the_discount_it_reverses(self) -> None:
        rows = self._totals_rows(self._issued_reversal(self._discounted_original()))

        discount_rows = [row for row in rows if "Discount" in row]
        self.assertTrue(discount_rows, f"the correction must state what it reverses; drew {rows}")
        self.assertNotIn("--", discount_rows[0], f"double negative: {discount_rows[0]}")
        self.assertIn("10.00", discount_rows[0])

    def test_the_credit_note_subtotal_is_the_line_gross(self) -> None:
        """`gross > 0` is a line-less-document fallback, not a sign test."""
        rows = self._totals_rows(self._issued_reversal(self._discounted_original("FCT-000801")))

        subtotal = next(row for row in rows if "Subtotal" in row)

        self.assertIn("-100.00", subtotal, f"got {subtotal}")

    def test_the_credit_note_vat_base_matches_the_xml(self) -> None:
        """The XML emits TaxableAmount -90.00; the PDF must not state -100.00."""
        rows = self._totals_rows(self._issued_reversal(self._discounted_original("FCT-000802")))

        vat = next(row for row in rows if "baza" in row)

        self.assertIn("-90.00", vat, f"got {vat}")

    def test_the_credit_note_is_not_stamped_unpaid(self) -> None:
        """`issued` is a credit note's terminal status, so `!= "paid"` never clears.

        Nothing is owed on a correction, and it has no due date, so the customer's copy
        read "Unpaid invoice - Due: undefined" - permanently, on every one of them. The
        interaction only appears once a credit note is kept out of `paid`, which is why
        no test caught it before.
        """
        rows = self._totals_rows(self._issued_reversal(self._discounted_original("FCT-000804")))

        self.assertFalse([row for row in rows if "Unpaid" in row], f"drew {rows}")

    def test_an_unpaid_ordinary_invoice_is_still_stamped(self) -> None:
        """The regression guard: the notice still has to appear where it belongs."""
        rows = self._totals_rows(self._discounted_original("FCT-000805"))

        self.assertTrue([row for row in rows if "Unpaid" in row], f"drew {rows}")

    def test_a_discounted_ordinary_invoice_is_unchanged(self) -> None:
        """The regression guard for all four sites at once."""
        rows = self._totals_rows(self._discounted_original("FCT-000803"))

        subtotal = next(row for row in rows if "Subtotal" in row)
        discount = next(row for row in rows if "Discount" in row)
        vat = next(row for row in rows if "baza" in row)

        self.assertIn("100.00", subtotal)
        self.assertIn("-10.00", discount, f"a deduction still reads as negative; got {discount}")
        self.assertIn("90.00", vat)
