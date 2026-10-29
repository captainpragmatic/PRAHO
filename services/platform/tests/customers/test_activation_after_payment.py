"""A paid invoice moves a prospect to active and an inactive customer back to active (ADR-0066).

The move runs after the payment commits, in its own transaction, so it can never undo or block the
payment. A suspended customer stays suspended: unsuspending is a staff decision.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing import signals
from apps.billing.invoice_models import ISSUER_SMARTBILL, Currency, Invoice
from apps.customers.customer_service import activate_customer_after_payment
from apps.customers.models import Customer
from tests.factories.billing_factories import CustomerFactory
from tests.helpers.fsm_helpers import force_status

EMAIL = "apps.notifications.services.EmailService.send_template_email"


class ActivationAfterPaymentTests(TestCase):
    def setUp(self) -> None:
        self.customer = CustomerFactory()
        self.currency = Currency.objects.get_or_create(code="RON", defaults={"symbol": "L", "decimals": 2})[0]
        self.invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="FCT-ACT-1",
            status="draft",
            issued_at=timezone.now(),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            bill_to_name="Paying SRL",
            bill_to_country="RO",
            issuer_provider=ISSUER_SMARTBILL,
        )
        force_status(self.invoice, "issued")

    def _set_status(self, status: str) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(status=status)
        self.assertEqual(self._status(), status)

    def _status(self) -> str:
        return Customer.objects.get(pk=self.customer.pk).status

    def _invoice_paid(self) -> Any:
        """The handler a paid invoice runs, with its post-commit work executed."""
        with patch(EMAIL) as email, self.captureOnCommitCallbacks(execute=True):
            signals._handle_invoice_paid(self.invoice)
        return email

    def test_a_paid_invoice_activates_a_prospect(self) -> None:
        self._set_status("prospect")
        email = self._invoice_paid()
        self.assertEqual(self._status(), "active")
        self.assertIn("customer_activated", [call.kwargs["template_key"] for call in email.call_args_list])

    def test_a_paid_invoice_reactivates_an_inactive_customer(self) -> None:
        self._set_status("inactive")
        self._invoice_paid()
        self.assertEqual(self._status(), "active")

    def test_a_suspended_customer_stays_suspended(self) -> None:
        self._set_status("suspended")
        self._invoice_paid()
        self.assertEqual(self._status(), "suspended")

    def test_an_active_customer_is_left_as_it_is(self) -> None:
        self._set_status("active")
        email = self._invoice_paid()
        self.assertEqual(self._status(), "active")
        self.assertNotIn("customer_activated", [call.kwargs["template_key"] for call in email.call_args_list])

    def test_a_failed_activation_never_reaches_the_payment(self) -> None:
        self._set_status("prospect")
        with patch("apps.customers.models.Customer.activate", side_effect=RuntimeError("database went away")) as activate:
            self._invoice_paid()  # must not raise
        activate.assert_called_once()  # the failing path really ran
        self.assertEqual(self._status(), "prospect")

    def test_a_second_run_changes_nothing_and_sends_nothing(self) -> None:
        self._set_status("prospect")
        with patch(EMAIL) as email, self.captureOnCommitCallbacks(execute=True):
            activate_customer_after_payment(self.customer.pk, self.invoice.pk)
            activate_customer_after_payment(self.customer.pk, self.invoice.pk)
        self.assertEqual(self._status(), "active")
        sent = [call.kwargs["template_key"] for call in email.call_args_list]
        self.assertEqual(sent.count("customer_activated"), 1)
