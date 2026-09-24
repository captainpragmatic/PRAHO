"""A credit note is complete when issued. It is never paid.

Its remaining amount clamps to zero because there is nothing to collect, not because
anyone settled it — so every "fully settled" check reads true and the document walks
into the paid lifecycle: a payment-received email, payment history credited, pending
services activated. `paid` carries collection semantics a reversal does not have.

The guard belongs on the transition rather than at its callers. Four sites can move an
invoice to paid, and a caller-side guard leaves the invariant breakable at the other
three.
"""

from __future__ import annotations

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from django_fsm import TransitionNotAllowed

from apps.billing import signals
from apps.billing.invoice_models import (
    DOCUMENT_KIND_CREDIT_NOTE,
    ISSUER_SMARTBILL,
    Currency,
    Invoice,
)
from tests.factories.billing_factories import CustomerFactory, InvoiceLineFactory
from tests.helpers.fsm_helpers import force_status


class CreditNoteIsNeverPaidTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self._seq = 0

    def _original(self) -> Invoice:
        self._seq += 1
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"FCT-0020{self._seq}",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
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
            tax_cents=2100,
            line_total_cents=12100,
        )
        return invoice

    def _issued_credit_note(self) -> Invoice:
        original = self._original()
        credit_note = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"STORNO-0020{self._seq}",
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
        force_status(credit_note, "issued")
        return credit_note

    def test_the_transition_itself_refuses_a_credit_note(self) -> None:
        """The invariant lives here, so no caller can break it."""
        credit_note = self._issued_credit_note()

        with self.assertRaises(TransitionNotAllowed):
            credit_note.mark_as_paid()

    def test_convergence_treats_it_as_inapplicable_not_as_a_failure(self) -> None:
        """Its balance clamps to zero, so convergence would otherwise call the transition
        and log a warning about a document that was never going to be paid."""
        credit_note = self._issued_credit_note()

        with patch("apps.billing.invoice_models.logger") as log:
            credit_note.update_status_from_payments()

        credit_note.refresh_from_db()
        self.assertEqual(credit_note.status, "issued", "issued is where a reversal ends")
        log.warning.assert_not_called()

    def test_no_payment_side_effects_fire_for_a_credit_note(self) -> None:
        """The handler does more than email: payment history and service activation too."""
        credit_note = self._issued_credit_note()

        with (
            patch.object(signals, "_send_payment_received_email") as email,
            patch.object(signals, "_update_customer_payment_history") as history,
            patch.object(signals, "_activate_pending_services") as activate,
        ):
            signals._handle_invoice_paid(credit_note)

        email.assert_not_called()
        history.assert_not_called()
        activate.assert_not_called()

    def test_an_ordinary_invoice_still_converges_and_notifies(self) -> None:
        """The regression guard, including the zero-value case a totals-based guard breaks."""
        invoice = self._original()
        force_status(invoice, "issued")

        with patch.object(signals, "_send_payment_received_email") as email:
            signals._handle_invoice_paid(invoice)

        email.assert_called_once()

    def test_a_zero_value_invoice_still_reaches_paid(self) -> None:
        """Discriminating on totals rather than document kind would strand this one."""
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-ZERO-1",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=0,
            tax_cents=0,
            total_cents=0,
            bill_to_name="Test Company SRL",
            bill_to_country="RO",
        )
        force_status(invoice, "issued")

        invoice.update_status_from_payments()

        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "paid")
