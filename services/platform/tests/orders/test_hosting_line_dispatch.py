"""Each paid service line has one way forward: confirmation queues its fulfilment, once.

Before this, a paid hosting order stayed in provisioning for good and a free one queued a task that
failed. These tests run the real queue: every task the order's path enqueues is executed, twice over,
with only the Virtualmin node itself replaced.
"""

from __future__ import annotations

from typing import Any, cast
from unittest.mock import patch

from django.test import override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.audit.models import AuditEvent
from apps.billing.payment_models import Payment
from apps.billing.signals import _activate_pending_services
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.orders.services import OrderPaymentConfirmationService, OrderService, StatusChangeData
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from tests.helpers.fsm_helpers import force_status
from tests.orders._hosting_workflow_case import HostingWorkflowCase

FULFIL = "apps.orders.tasks.provision_order_item"
CREATE = "apps.provisioning.virtualmin_tasks.provision_virtualmin_account"


def _node_creates_the_account(params: Any, **_kwargs: Any) -> dict[str, Any]:
    """The Virtualmin node, replaced: the account comes up and its create job completes."""
    service_id = (params if isinstance(params, dict) else params.decrypt())["service_id"]
    service = Service.objects.get(pk=service_id)
    if VirtualminAccount.objects.filter(service=service).exists():
        return {"success": True, "message": "Account already exists"}
    server = VirtualminServer.objects.get()
    account = VirtualminAccount.objects.create(
        domain=service.domain,
        service=service,
        server=server,
        virtualmin_username=service.username,
        template_name="Default",
        status="active",
        praho_customer_id=service.customer_id,
        praho_service_id=service.pk,
    )
    job = VirtualminProvisioningJob.objects.create(
        server=server,
        account=account,
        operation="create_domain",
        correlation_id=f"create-{account.pk}",
        started_at=timezone.now(),
    )
    job.mark_completed({"domain": account.domain})
    return {"success": True, "account_id": str(account.pk)}


@override_settings(VIRTUALMIN_AUTO_PROVISIONING_ENABLED=True)
class HostingLineDispatchTests(HostingWorkflowCase):
    def setUp(self) -> None:
        super().setUp()
        OrmQ.objects.all().delete()
        VirtualminServer.objects.create(
            name="Node A",
            hostname="node-a.example.test",
            api_username="api",
            api_port=10000,
            status="active",
            max_domains=100,
        )
        self.ran: list[str] = []
        self.enterContext(patch(CREATE, side_effect=_node_creates_the_account))

    def _items(self, price: int = 10000) -> list[dict[str, object]]:
        return [
            {
                "product_id": self.product.pk,
                "quantity": 1,
                "unit_price_cents": price,
                "setup_cents": 0,
                "billing_period": "monthly",
                "description": self.product.name,
                "domain_name": "dispatch-shop.ro",
            }
        ]

    def _drain(self) -> None:
        """Run every queued task, and what they queue, until the queue is empty."""
        for _ in range(50):
            row = OrmQ.objects.order_by("pk").first()
            if row is None:
                return
            package = cast("dict[str, Any]", SignedPackage.loads(row.payload))
            row.delete()
            self.ran.append(package["func"])
            with self.captureOnCommitCallbacks(execute=True):
                import_string(package["func"])(*package["args"], **package["kwargs"])
        self.fail("the queue never emptied")

    def _assert_fulfilled_once(self, order: Order) -> None:
        for _ in range(2):
            self._drain()
        order.refresh_from_db()
        line = order.items.get()
        service = Service.objects.get()
        self.assertEqual((order.status, line.provisioning_status, service.status), ("completed", "completed", "active"))
        self.assertEqual(VirtualminAccount.objects.filter(service=service, status="active").count(), 1)
        self.assertEqual(
            AuditEvent.objects.filter(action="provisioning_completed", object_id=str(service.pk)).count(), 1
        )
        self.assertEqual(OrderStatusHistory.objects.filter(order=order, new_status="completed").count(), 1)
        self.assertEqual(self.ran.count(CREATE), 1)

    def test_paid_hosting_line_reaches_completed_exactly_once(self) -> None:
        order = self.create_order(items=self._items())
        self.pay(order)
        order.refresh_from_db()
        self.assertEqual(order.status, "provisioning")
        self.assertNotIn(CREATE, [SignedPackage.loads(row.payload)["func"] for row in OrmQ.objects.all()])
        self._assert_fulfilled_once(order)
        # Once by confirmation, once by the create job's completion.
        self.assertEqual(self.ran.count(FULFIL), 2)

    def test_free_hosting_line_reaches_completed_exactly_once(self) -> None:
        order = self.create_order(items=self._items(price=0))
        self.assertEqual(order.total_cents, 0)
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(OrderPaymentConfirmationService.confirm_order(order).is_ok())
        self._assert_fulfilled_once(order)


class DispatchEntryPointTests(HostingWorkflowCase):
    def _review_order(self) -> tuple[Order, OrderItem]:
        order = self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "setup_cents": 0,
                    "billing_period": "monthly",
                    "description": self.product.name,
                    "domain_name": "review-shop.ro",
                }
            ]
        )
        force_status(order, "in_review")
        return order, order.items.get()

    def test_review_approval_dispatches_once(self) -> None:
        order, line = self._review_order()
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            approved = OrderService.update_order_status(order, StatusChangeData(new_status="provisioning"))
        self.assertTrue(approved.is_ok(), approved)
        dispatched = [call.args[1] for call in enqueue.call_args_list if call.args[0] == FULFIL]
        self.assertEqual(dispatched, [str(line.pk)])

    def test_review_rejection_dispatches_nothing(self) -> None:
        order, _line = self._review_order()
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            OrderService.update_order_status(order, StatusChangeData(new_status="cancelled"))
        self.assertNotIn(FULFIL, [call.args[0] for call in enqueue.call_args_list])

    def test_payment_does_not_activate_a_new_orders_pending_service(self) -> None:
        order = self.create_order(items=self._items_with_service())
        invoice = self._invoice_for(order)
        service = Service.objects.get()
        self.assertEqual(service.status, "pending")
        _activate_pending_services(invoice)
        service.refresh_from_db()
        self.assertEqual(service.status, "pending")

    def test_payment_still_reactivates_a_suspended_service(self) -> None:
        order = self.create_order(items=self._items_with_service())
        invoice = self._invoice_for(order)
        service = Service.objects.get()
        force_status(service, "suspended")
        from apps.billing.signals import _activate_payment_services  # noqa: PLC0415

        payment = type("PaymentStub", (), {"invoice_id": invoice.pk, "invoice": invoice})()
        _activate_payment_services(cast("Payment", payment))
        service.refresh_from_db()
        self.assertEqual(service.status, "active")

    def _items_with_service(self) -> list[dict[str, object]]:
        return [
            {
                "product_id": self.product.pk,
                "quantity": 1,
                "unit_price_cents": 10000,
                "setup_cents": 0,
                "billing_period": "monthly",
                "description": self.product.name,
                "domain_name": "paying-shop.ro",
            }
        ]

    def _invoice_for(self, order: Order):
        from apps.billing.models import Invoice  # noqa: PLC0415

        invoice = Invoice.objects.create(
            customer=self.customer, currency=self.currency, number=f"INV-{order.pk.hex[:8]}"
        )
        Order.objects.filter(pk=order.pk).update(invoice=invoice)
        return invoice
