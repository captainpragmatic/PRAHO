"""A credit note must not be presented to the customer as a bill.

A reversal is an issued document with a negative total, so it satisfies every
"invoice was created" and "invoice was issued" check. Left unguarded the customer
receives the seeded receivable copy - "Factura noua ... Termen de plata" - for a
document that owes them money, twice, and the first send happens inline inside the
transaction that is still deciding whether the reversal may proceed at all.
"""

from __future__ import annotations

from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.fsm_helpers import force_status


class CreditNotesAreNotEmailedAsInvoicesTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]

    def _original(self) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-000800",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )

    def _credit_note(self, original: Invoice) -> Invoice:
        return Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=None,
            status="draft",
            document_kind=DOCUMENT_KIND_CREDIT_NOTE,
            reverses_invoice=original,
            issuer_provider=ISSUER_SMARTBILL,
            subtotal_cents=-10000,
            tax_cents=-2100,
            total_cents=-12100,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )

    def test_creating_a_credit_note_emails_nobody(self) -> None:
        original = self._original()

        with patch("apps.billing.signals._send_invoice_created_email") as sender:
            self._credit_note(original)

        sender.assert_not_called()

    def test_issuing_a_credit_note_emails_nobody(self) -> None:
        original = self._original()
        credit_note = self._credit_note(original)
        credit_note.number = "STORNO-000801"

        with patch("apps.billing.signals._send_invoice_issued_email") as sender:
            credit_note.issue()
            credit_note.save()

        sender.assert_not_called()

    def test_an_ordinary_invoice_is_still_announced(self) -> None:
        """The regression guard: this must not silence real invoices."""
        with patch("apps.billing.signals._send_invoice_created_email") as sender:
            self._original()

        sender.assert_called_once()

    def test_an_ordinary_invoice_is_still_announced_when_issued(self) -> None:
        invoice = self._original()

        with patch("apps.billing.signals._send_invoice_issued_email") as sender:
            force_status(invoice, "issued")

        sender.assert_called_once()
