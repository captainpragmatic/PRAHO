"""A payment and a customer suspension cannot interleave into hosting for a suspended customer.

The payment path checks the customer's suspension and then restores the Service. A suspension that
committed between that check and the restore would be missed twice: the payment decided on the old
status, and the suspension cascade skipped the Service, which was still off for non-payment when it
ran. The check therefore locks the customer row, customer before Service as billing locks them, and
the restore re-reads the Service under its own lock. Row locks are real only on PostgreSQL, so this
runs there (CI's PostgreSQL step) and skips on SQLite.
"""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from decimal import Decimal
from types import SimpleNamespace
from typing import Any, cast

from django.db import close_old_connections, connection, transaction
from django.test import TransactionTestCase

from apps.billing.models import Currency
from apps.billing.payment_models import Payment
from apps.billing.signals import _activate_payment_services
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan

# Long enough for an unblocked payment to finish, short enough to keep the test quick.
_HOLD_SECONDS = 2.0


class PaymentActivationSuspensionRaceTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row-lock guarantees require PostgreSQL")
        self.customer = Customer.objects.create(
            name="Race SRL", customer_type="company", status="active", primary_email="race@example.com"
        )
        currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Race Hosting", plan_type="shared_hosting", price_monthly=Decimal("10"))
        self.service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=currency,
            service_name="race.example.com",
            domain="race.example.com",
            username="race",
            billing_cycle="monthly",
            price=Decimal("10.00"),
            status="active",
        )
        # Off for non-payment: the state a paid invoice restores.
        Service.objects.filter(pk=self.service.pk).update(status="suspended", suspension_reason="payment_overdue")

    def _payment(self) -> Payment:
        """The order graph the loop reads, built around the real Service row; loading it is not under test."""
        service = Service.objects.get(pk=self.service.pk)
        item = SimpleNamespace(service=service)
        order: Any = SimpleNamespace(status="completed", items=SimpleNamespace(filter=lambda **_kw: [item]))
        invoice = SimpleNamespace(number="INV-RACE", orders=SimpleNamespace(all=lambda: [order]))
        return cast("Payment", SimpleNamespace(invoice_id=1, invoice=invoice))

    def test_a_customer_suspension_in_flight_is_seen_by_the_payment(self) -> None:
        suspension_locked = threading.Event()
        payment_done = threading.Event()

        def suspend_customer_and_hold() -> None:
            close_old_connections()
            try:
                with transaction.atomic():
                    # The customer's suspension, uncommitted and holding the customer row.
                    Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
                    suspension_locked.set()
                    # Unblocked, the payment finishes inside this window and reads the old status.
                    # Locking the customer first, it waits here until this commits.
                    payment_done.wait(timeout=_HOLD_SECONDS)
            finally:
                connection.close()

        def pay() -> None:
            close_old_connections()
            try:
                suspension_locked.wait(timeout=10)
                _activate_payment_services(self._payment())
            finally:
                payment_done.set()
                connection.close()

        with ThreadPoolExecutor(max_workers=2) as executor:
            holder = executor.submit(suspend_customer_and_hold)
            paying = executor.submit(pay)
            holder.result(timeout=30)
            paying.result(timeout=30)

        self.service.refresh_from_db()
        self.assertEqual(self.service.status, "suspended", "the payment restored hosting for a suspended customer")
        # And the suspension now owns it, so unsuspending resumes it.
        self.assertEqual(self.service.suspension_reason, "customer_suspended")
