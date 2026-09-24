"""Revenue must not subtract a refunded invoice twice.

A credit note only ever exists for an invoice that is ALREADY `refunded`:
`_storno_refusal_reason` refuses to reverse anything else, because SmartBill's storno
carries no amount and reverses the whole document. A refunded invoice has already left
the `paid` filter, so counting the credit note on top removes the same money a second
time - a fully refunded 500 RON invoice reported -500 instead of zero.

The earlier version of this test left the original `paid`, which the real flow never
does, so it asserted a state the system cannot reach and missed the double subtraction
entirely.
"""

from __future__ import annotations

from decimal import Decimal

from django.test import TestCase
from django.urls import reverse
from django.utils import timezone

from apps.billing.invoice_models import DOCUMENT_KIND_CREDIT_NOTE, Currency, Invoice
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.factories.core_factories import create_admin_user
from tests.helpers.fsm_helpers import force_status


class RevenueNetsAnIssuedReversalTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.client.force_login(create_admin_user(username="revenue_admin"))

    def _paid_invoice(self, number: str, total: int) -> Invoice:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=number,
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=total,
            tax_cents=0,
            total_cents=total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )
        InvoiceLineFactory(
            invoice=invoice,
            description="Hosting",
            quantity=Decimal("1"),
            unit_price_cents=total,
            tax_rate=Decimal("0"),
            tax_cents=0,
            line_total_cents=total,
        )
        force_status(invoice, "issued")
        force_status(invoice, "paid")
        return invoice

    def _issued_credit_note(self, original: Invoice, total: int) -> Invoice:
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"STORNO-{original.number}",
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-total,
            tax_cents=0,
            total_cents=-total,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )
        force_status(credit_note, "issued")
        return credit_note

    def _total_revenue(self) -> int:
        response = self.client.get(reverse("billing:reports"))
        self.assertEqual(response.status_code, 200)
        return response.context["total_revenue"] or 0

    def test_a_refunded_invoice_and_its_reversal_net_to_zero(self) -> None:
        """The whole lifecycle, in the order the system actually produces it."""
        baseline = self._total_revenue()

        original = self._paid_invoice("FCT-REV-1", 50000)
        self.assertEqual(self._total_revenue(), baseline + 50000, "a collected invoice is revenue")

        force_status(original, "refunded")
        after_refund = self._total_revenue()
        self.assertEqual(after_refund, baseline, "refunding it takes the money back out")

        self._issued_credit_note(original, 50000)

        self.assertEqual(
            self._total_revenue(),
            baseline,
            "the credit note is the fiscal record of a refund already reflected here; "
            "counting it too subtracts the same money twice",
        )

    def test_an_uncollected_invoice_is_not_revenue(self) -> None:
        """The regression guard on the other side: only collected money counts."""
        baseline = self._total_revenue()

        invoice = self._paid_invoice("FCT-REV-2", 12100)
        force_status(invoice, "refunded")

        self.assertEqual(self._total_revenue(), baseline)
