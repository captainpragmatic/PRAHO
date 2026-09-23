"""A reversal of a discounted invoice must stay internally consistent.

`Invoice.subtotal_cents` is stored NET of `discount_cents` while `InvoiceLine`
amounts are GROSS, so the ledger invariant is `gross - discount == subtotal`. The
reversal mirrored the lines but dropped the discount, leaving a document whose header
contradicted its own lines: the derivation that both the e-Factura XML and the PDF use
to recover the discount clamps a negative to zero, so the allowance vanished and the
document no longer added up.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.efactura.xml_builder import UBLInvoiceBuilder
from apps.billing.invoice_models import (
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from apps.billing.issuers.service import _get_or_create_credit_note
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory


class DiscountedReversalTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _discounted_original(self) -> Invoice:
        """Lines gross 10000, document discount 1000, so the header subtotal is 9000."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-000600",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=9000,
            tax_cents=1890,
            total_cents=10890,
            discount_cents=1000,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
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

    def _reverse(self, original: Invoice) -> Invoice:
        return _get_or_create_credit_note(original)

    def test_the_credit_note_carries_the_discount_negated(self) -> None:
        original = self._discounted_original()

        credit_note = self._reverse(original)

        self.assertEqual(credit_note.discount_cents, -original.discount_cents)

    def test_the_ledger_invariant_holds_in_both_directions(self) -> None:
        """`gross - discount == subtotal` is what every reader relies on."""
        original = self._discounted_original()
        credit_note = self._reverse(original)

        original_gross = sum(line.subtotal_cents for line in original.lines.all())
        credit_gross = sum(line.subtotal_cents for line in credit_note.lines.all())

        self.assertEqual(original_gross - original.discount_cents, original.subtotal_cents)
        self.assertEqual(
            credit_gross - credit_note.discount_cents,
            credit_note.subtotal_cents,
            "the reversal must satisfy the same invariant as the document it reverses",
        )

    def test_the_discount_survives_the_derivation_the_pdf_and_xml_share(self) -> None:
        """Both recover the discount as `line gross - header subtotal`.

        Clamped at zero that yields no allowance for a credit note, so the document
        silently loses the discount it was supposed to reverse.
        """
        original = self._discounted_original()
        credit_note = self._reverse(original)

        derived = UBLInvoiceBuilder(credit_note)._get_document_discount()

        self.assertNotEqual(derived, Decimal("0"), "the allowance must not be clamped away")
        self.assertEqual(abs(derived), Decimal("10.00"))

    def test_an_undiscounted_reversal_is_unchanged(self) -> None:
        """The regression guard: nothing here may disturb the ordinary case."""
        original = self._discounted_original()
        original.discount_cents = 0
        original.subtotal_cents = 10000
        original.tax_cents = 2100
        original.total_cents = 12100
        original.save()

        credit_note = self._reverse(original)

        self.assertEqual(credit_note.discount_cents, 0)
        self.assertEqual(credit_note.total_cents, -12100)
