"""
Tests for payment-method-aware order-timeout cancellation (#222).

`_handle_order_timeout` cancelled ANY awaiting_payment order 24h after creation, including
bank-transfer / manual orders whose wire legitimately settles over 1-3 business days — cancelling
paying customers and expiring the proforma the customer was still holding.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice
from apps.customers.models import Customer
from apps.orders.models import Order
from apps.orders.tasks import process_pending_orders
from tests.helpers.fsm_helpers import force_status


class OrderTimeoutTestCase(TestCase):
    """#222: the auto-cancel deadline must depend on payment method, not a flat 24h."""

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Timeout Test SRL",
            customer_type="company",
            status="active",
            primary_email="timeout@test.ro",
        )

    def _order(self, *, payment_method: str, hours_old: float, with_proforma_valid_days: int | None = None) -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            payment_method=payment_method,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={},
        )
        force_status(order, "awaiting_payment")

        if with_proforma_valid_days is not None:
            proforma = ProformaInvoice.objects.create(
                customer=self.customer,
                currency=self.currency,
                number=f"PRO-{uuid.uuid4().hex[:8]}",
                total_cents=12100,
                valid_until=timezone.now() + timedelta(days=with_proforma_valid_days),
            )
            order.proforma = proforma
            order.save(update_fields=["proforma"])

        # created_at is auto_now_add, so push it into the past via an update.
        Order.objects.filter(pk=order.pk).update(created_at=timezone.now() - timedelta(hours=hours_old))
        order.refresh_from_db()
        return order

    def _run(self) -> None:
        # The cancellation email fires on transaction commit.
        with self.captureOnCommitCallbacks(execute=True):
            process_pending_orders()

    def _status(self, order: Order) -> str:
        order.refresh_from_db()
        return order.status

    # --- card / immediate methods: unchanged 24h behaviour ---

    def test_card_order_past_24h_is_cancelled(self) -> None:
        """Non-regression: card orders still time out at 24h."""
        order = self._order(payment_method="card", hours_old=25)

        self._run()

        self.assertEqual(self._status(order), "cancelled")

    def test_card_order_under_24h_is_not_cancelled(self) -> None:
        order = self._order(payment_method="card", hours_old=1)

        self._run()

        self.assertEqual(self._status(order), "awaiting_payment")

    def test_paypal_crypto_wallet_keep_the_24h_card_path(self) -> None:
        for method in ("paypal", "crypto", "wallet"):
            with self.subTest(method=method):
                order = self._order(payment_method=method, hours_old=25)

                self._run()

                self.assertEqual(self._status(order), "cancelled")

    # --- bank_transfer / manual: the #222 fix ---

    def test_bank_transfer_order_is_not_cancelled_at_25h(self) -> None:
        """The #222 bug: a bank-transfer wire in flight must not be cancelled at 25h."""
        order = self._order(payment_method="bank_transfer", hours_old=25, with_proforma_valid_days=30)

        self._run()

        self.assertEqual(self._status(order), "awaiting_payment")

    def test_bank_transfer_order_is_cancelled_past_its_proforma_validity(self) -> None:
        """Offline orders still time out — just at the proforma window the customer was given."""
        order = self._order(payment_method="bank_transfer", hours_old=1)
        # A proforma that already expired.
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{uuid.uuid4().hex[:8]}",
            total_cents=12100,
            valid_until=timezone.now() - timedelta(hours=1),
        )
        order.proforma = proforma
        order.save(update_fields=["proforma"])

        self._run()

        self.assertEqual(self._status(order), "cancelled")

    def test_bank_transfer_missing_proforma_gets_one_and_is_not_cancelled_at_73h(self) -> None:
        """process_pending_orders self-heals a missing proforma before the timeout check, so an
        offline order is judged against that fresh (30-day) window — not cancelled at 73h."""
        order = self._order(payment_method="bank_transfer", hours_old=73)

        self._run()

        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")
        self.assertIsNotNone(order.proforma, "a missing proforma should have been created")

    def test_bank_transfer_fallback_deadline_used_when_no_proforma_can_be_anchored(self) -> None:
        """Helper-level: when an offline order genuinely has no proforma, the deadline is the 72h
        fallback rather than the 24h card window."""
        from apps.orders.tasks import _order_timeout_deadline  # noqa: PLC0415

        order = self._order(payment_method="bank_transfer", hours_old=1)
        self.assertIsNone(order.proforma)

        deadline, basis = _order_timeout_deadline(order)

        self.assertEqual(basis, "bank_transfer_fallback")
        self.assertEqual(deadline, order.created_at + timedelta(hours=72))

    def test_empty_payment_method_is_treated_as_offline(self) -> None:
        """An unknown method is fail-open: never cancel a possible payer at 25h."""
        order = self._order(payment_method="", hours_old=25)

        self._run()

        self.assertEqual(self._status(order), "awaiting_payment")
