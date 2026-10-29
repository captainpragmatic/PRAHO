"""A suspended customer may pay, but gets no new or restored hosting until staff unsuspend it (ADR-0066).

Platform no longer refuses a suspended customer's API calls, so the hold lives where hosting is
turned on: order fulfilment and the two payment paths that start or restore a service.
"""

from __future__ import annotations

from typing import cast

from apps.billing.payment_models import Payment
from apps.billing.signals import _activate_payment_services, _activate_pending_services
from apps.customers.models import Customer
from apps.orders.hosting_fulfilment import fulfil_hosting_line
from apps.orders.models import Order
from apps.provisioning.models import Service
from tests.helpers.fsm_helpers import force_status
from tests.orders._hosting_workflow_case import HostingWorkflowCase


class SuspendedCustomerHoldTests(HostingWorkflowCase):
    def _order_with_service(self) -> Order:
        return self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "setup_cents": 0,
                    "billing_period": "monthly",
                    "description": self.product.name,
                    "domain_name": "held-shop.ro",
                }
            ]
        )

    def _invoice_for(self, order: Order):
        from apps.billing.models import Invoice  # noqa: PLC0415

        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, number=f"INV-{order.pk.hex[:8]}")
        Order.objects.filter(pk=order.pk).update(invoice=invoice)
        return invoice

    def _suspend_customer(self) -> None:
        Customer.objects.filter(pk=self.customer.pk).update(status="suspended")
        self.assertEqual(Customer.objects.get(pk=self.customer.pk).status, "suspended")

    def test_a_suspended_customer_s_paid_line_is_held_and_moves_once_unsuspended(self) -> None:
        order = self._order_with_service()
        force_status(order, "provisioning")
        line = order.items.get()
        self.assertEqual(line.provisioning_status, "pending")
        self._suspend_customer()

        self.assertEqual(fulfil_hosting_line(line.pk).unwrap(), "held")
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")
        self.assertEqual(Service.objects.get().status, "pending")

        Customer.objects.filter(pk=self.customer.pk).update(status="active")
        self.assertNotEqual(fulfil_hosting_line(line.pk).unwrap(), "held")
        line.refresh_from_db()
        self.assertNotEqual(line.provisioning_status, "pending")

    def test_a_line_already_started_is_held_too(self) -> None:
        # Suspension can land after fulfilment started the line: the service must not come on then either.
        order = self._order_with_service()
        force_status(order, "provisioning")
        line = order.items.get()
        line.start_provisioning()
        line.save(update_fields=["provisioning_status", "updated_at"])
        service = Service.objects.get()
        force_status(service, "provisioning")
        self._suspend_customer()

        self.assertEqual(fulfil_hosting_line(line.pk).unwrap(), "held")
        service.refresh_from_db()
        self.assertEqual(service.status, "provisioning")

    def test_unsuspending_dispatches_every_held_line_again(self) -> None:
        # Recovery never re-picks a started line whose account is not finished, so without this
        # dispatch a line held mid-way would stay stuck after the customer is unsuspended.
        from unittest.mock import patch  # noqa: PLC0415

        from apps.customers.signals import _handle_customer_unsuspension  # noqa: PLC0415

        line, service = self._started_line()
        self._suspend_customer()
        self.assertEqual(fulfil_hosting_line(line.pk).unwrap(), "held")

        Customer.objects.filter(pk=self.customer.pk).update(status="active")
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            _handle_customer_unsuspension(Customer.objects.get(pk=self.customer.pk))
        dispatched = [call.args[1] for call in enqueue.call_args_list if call.args[0] == "apps.orders.tasks.provision_order_item"]
        self.assertEqual(dispatched, [str(line.pk)])
        # And the dispatched work turns the hosting on.
        fulfil_hosting_line(line.pk)
        service.refresh_from_db()
        self.assertEqual(service.status, "active")

    def _started_line(self, domain: str = "held-shop.ro"):
        """A paid line fulfilment started: the line in progress, its Service waiting to be activated."""
        order = self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "setup_cents": 0,
                    "billing_period": "monthly",
                    "description": self.product.name,
                    "domain_name": domain,
                }
            ]
        )
        force_status(order, "provisioning")
        line = order.items.get()
        line.start_provisioning()
        line.save(update_fields=["provisioning_status", "updated_at"])
        service = Service.objects.get(pk=line.service_id)
        force_status(service, "provisioning")
        self.assertEqual((line.provisioning_status, service.status), ("in_progress", "provisioning"))
        return line, service

    def test_recovery_moves_a_started_line_held_past_its_unsuspension(self) -> None:
        # If queueing failed when the customer was unsuspended, recovery must still find the line.
        from datetime import timedelta  # noqa: PLC0415

        from django.utils import timezone  # noqa: PLC0415

        from apps.orders.hosting_fulfilment import DISPATCH_LOST_AFTER, recover_hosting_lines  # noqa: PLC0415
        from apps.orders.models import OrderItem  # noqa: PLC0415

        line, service = self._started_line()
        OrderItem.objects.filter(pk=line.pk).update(updated_at=timezone.now() - DISPATCH_LOST_AFTER - timedelta(minutes=1))
        recover_hosting_lines()
        service.refresh_from_db()
        self.assertEqual(service.status, "active")

    def test_manual_lines_cannot_starve_recovery(self) -> None:
        # A manual line (no automatic provisioning) stays "provisioning" for staff and is never moved by
        # fulfilment, so recovery must not keep selecting it ahead of hosting it can recover.
        from datetime import timedelta  # noqa: PLC0415

        from django.utils import timezone  # noqa: PLC0415

        from apps.orders.hosting_fulfilment import DISPATCH_LOST_AFTER, recover_hosting_lines  # noqa: PLC0415
        from apps.orders.models import OrderItem  # noqa: PLC0415
        from apps.provisioning.models import ServicePlan  # noqa: PLC0415

        manual, manual_service = self._started_line("manual-ssl.ro")
        ssl = ServicePlan.objects.create(name="SSL", plan_type="ssl", price_monthly=10)
        Service.objects.filter(pk=manual_service.pk).update(service_plan=ssl)
        hosting, hosting_service = self._started_line("recoverable.ro")
        old = timezone.now() - DISPATCH_LOST_AFTER - timedelta(minutes=1)
        OrderItem.objects.filter(pk=manual.pk).update(updated_at=old - timedelta(minutes=5))  # older: first in line
        OrderItem.objects.filter(pk=hosting.pk).update(updated_at=old)

        recover_hosting_lines(limit=1)

        hosting_service.refresh_from_db()
        self.assertEqual(hosting_service.status, "active")

    def test_one_failed_dispatch_does_not_stop_the_others(self) -> None:
        from unittest.mock import patch  # noqa: PLC0415

        from apps.orders.hosting_fulfilment import dispatch_held_lines  # noqa: PLC0415

        first, _ = self._started_line("first-held.ro")
        second, _ = self._started_line("second-held.ro")
        queued: list[str] = []

        def enqueue(_func: str, item_id: str, **_kwargs: object) -> None:
            if item_id == str(first.pk):
                raise RuntimeError("queue unavailable")
            queued.append(item_id)

        with patch("django_q.tasks.async_task", side_effect=enqueue):
            dispatch_held_lines(self.customer.pk)
        self.assertEqual(queued, [str(second.pk)])

    def test_a_paid_invoice_does_not_start_a_suspended_customer_s_pending_service(self) -> None:
        order = self._order_with_service()
        force_status(order, "provisioning")  # the state in which payment would start it
        invoice = self._invoice_for(order)
        self._suspend_customer()

        _activate_pending_services(invoice)

        self.assertEqual(Service.objects.get().status, "pending")

    def test_a_payment_hands_a_suspended_customer_s_overdue_service_to_the_unsuspension(self) -> None:
        order = self._order_with_service()
        invoice = self._invoice_for(order)
        service = Service.objects.get()
        force_status(service, "suspended")
        Service.objects.filter(pk=service.pk).update(suspension_reason="payment_overdue")
        self._suspend_customer()

        payment = type("PaymentStub", (), {"invoice_id": invoice.pk, "invoice": invoice})()
        _activate_payment_services(cast("Payment", payment))

        service.refresh_from_db()
        self.assertEqual((service.status, service.suspension_reason), ("suspended", "customer_suspended"))
        customer = Customer.objects.get(pk=self.customer.pk)
        with self.captureOnCommitCallbacks(execute=True):  # the real unsuspension, and its cascade
            customer.unsuspend()
            customer.save()
        service.refresh_from_db()
        self.assertEqual(service.status, "active")

    def test_a_payment_still_restores_an_active_customer_s_service(self) -> None:
        order = self._order_with_service()
        invoice = self._invoice_for(order)
        service = Service.objects.get()
        force_status(service, "suspended")
        Service.objects.filter(pk=service.pk).update(suspension_reason="payment_overdue")

        payment = type("PaymentStub", (), {"invoice_id": invoice.pk, "invoice": invoice})()
        _activate_payment_services(cast("Payment", payment))

        service.refresh_from_db()
        self.assertEqual(service.status, "active")
