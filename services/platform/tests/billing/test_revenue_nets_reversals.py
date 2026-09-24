"""Revenue and VAT must agree about a reversal.

The design's bet is that a correction is a negative Invoice row, so "reporting that
sums invoice rows sees the correction without needing to know this integration exists"
(`issue_storno_for_invoice`). The VAT report honours that - it sums `issued` and `paid`.
The revenue report sums `paid` only, and a credit note's life ends at `issued` because
there is nothing to collect. Same event, two staff screens, two different numbers.
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

    def test_revenue_subtracts_a_reversal(self) -> None:
        original = self._paid_invoice("FCT-REV-1", 50000)
        before = self._total_revenue()

        self._issued_credit_note(original, 50000)

        self.assertEqual(
            self._total_revenue(),
            before - 50000,
            "a reversal the VAT report already nets must not be invisible to revenue",
        )

    def test_revenue_still_counts_ordinary_paid_invoices(self) -> None:
        """The regression guard."""
        self._paid_invoice("FCT-REV-2", 30000)

        self.assertEqual(self._total_revenue(), 30000)

    def test_an_unissued_reversal_is_not_counted(self) -> None:
        """A draft credit note is not yet a document."""
        original = self._paid_invoice("FCT-REV-3", 40000)
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            subtotal_cents=-40000,
            tax_cents=0,
            total_cents=-40000,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

        self.assertEqual(self._total_revenue(), 40000)
