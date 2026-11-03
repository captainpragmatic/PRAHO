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
from apps.common.types import Retriability
from apps.orders.hosting_fulfilment import retry_line_for_staff
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.orders.services import OrderPaymentConfirmationService, OrderService, StatusChangeData
from apps.provisioning.models import Service
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.users.models import CustomerMembership, User
from tests.helpers.fsm_helpers import force_status
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin
from tests.helpers.portal_session import BoundSessionMixin
from tests.helpers.task_queue import run_queued
from tests.orders import test_confirm_order_service_identity as identity
from tests.orders._hosting_workflow_case import HostingWorkflowCase

FULFIL = "apps.orders.tasks.provision_order_item"
CREATE = "apps.provisioning.virtualmin_tasks.provision_virtualmin_account"


def _node_creates_the_account(params: Any, *, failed: bool = False, **_kwargs: Any) -> dict[str, Any]:
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
        status="error" if failed else "active",
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
    if failed:
        job.retry_count = job.max_retries
        job.save(update_fields=["retry_count"])
        job.mark_failed("quota refused", retriability=Retriability.RETRIABLE)
        return {"success": False, "error": "quota refused"}
    job.mark_completed({"domain": account.domain})
    return {"success": True, "account_id": str(account.pk)}


@override_settings(VIRTUALMIN_AUTO_PROVISIONING_ENABLED=True)
class HostingLineDispatchTests(BoundSessionMixin, HMACTestMixin, HostingWorkflowCase):
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

    @override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
    def test_signed_confirmation_and_duplicate_delivery_create_one_native_account(self) -> None:
        self.owner = User.objects.create_user(email="dispatch-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        order = self.create_order(items=self._items())
        service_id = order.items.get().service_id
        identity.ConfirmOrderServiceIdentityTests.prepare_payment(self, order)
        with self.captureOnCommitCallbacks(execute=True):
            response = identity.ConfirmOrderServiceIdentityTests.request_confirmation(self, order, billing_first=True)
        self.assertEqual(response.status_code, 200, response.content)
        line = order.items.get()
        self.assertEqual(line.service_id, service_id)
        self.assertEqual(Service.objects.count(), 1)
        self._assert_fulfilled_once(order)
        # Replay the actual line payload, as duplicate delivery/recovery would.
        from apps.orders.tasks import provision_order_item  # noqa: PLC0415

        provision_order_item(str(line.pk))
        replay = identity.ConfirmOrderServiceIdentityTests.request_confirmation(self, order)
        self.assertEqual(replay.status_code, 200, replay.content)
        self._assert_fulfilled_once(order)
        self.assertEqual(Service.objects.get().pk, service_id)
        self.assertEqual(VirtualminAccount.objects.count(), 1)
        self.assertNotIn("apps.provisioning.tasks.provision_service_task", self.ran)

    @override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE)
    def test_signed_confirmation_keeps_failed_create_recoverable_on_its_line(self) -> None:
        self.owner = User.objects.create_user(email="recoverable-owner@example.test")
        CustomerMembership.objects.create(customer=self.customer, user=self.owner, role="owner", is_primary=True)
        order = self.create_order(items=self._items())
        service_id = order.items.get().service_id
        identity.ConfirmOrderServiceIdentityTests.prepare_payment(self, order)
        with self.captureOnCommitCallbacks(execute=True):
            response = identity.ConfirmOrderServiceIdentityTests.request_confirmation(self, order)
        self.assertEqual(response.status_code, 200, response.content)
        with patch(CREATE, side_effect=lambda params, **kw: _node_creates_the_account(params, failed=True, **kw)):
            self._drain()
        line = order.items.get()
        self.assertEqual((line.service_id, line.provisioning_status), (service_id, "failed"))
        job = VirtualminProvisioningJob.objects.get(account__service_id=service_id)
        self.assertEqual((job.status, job.retry_count), ("failed", job.max_retries))
        with self.captureOnCommitCallbacks(execute=True):
            self.assertEqual(retry_line_for_staff(line.pk, actor=self.admin).unwrap(), "retried")
        with self.captureOnCommitCallbacks(execute=True):
            run_queued(FULFIL)
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")
        # The retried node operation succeeds; its completion wakes the same line.
        VirtualminAccount.objects.filter(pk=job.account_id).update(status="active")
        with self.captureOnCommitCallbacks(execute=True):
            job.mark_completed({"domain": line.domain_name})
        with self.captureOnCommitCallbacks(execute=True):
            run_queued(FULFIL)
        order.refresh_from_db()
        line.refresh_from_db()
        self.assertEqual((order.status, line.provisioning_status), ("completed", "completed"))
        self.assertEqual(Service.objects.get().pk, service_id)
        self.assertEqual(VirtualminAccount.objects.count(), 1)


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


class PaidInvoiceQueuesNoDirectCreateTests(HostingWorkflowCase):
    def test_a_paid_invoice_never_queues_a_virtualmin_create_directly(self) -> None:
        """Only line fulfilment, through the Service's activation, leads to an account create.

        The invoice-paid hook used to queue provision_virtualmin_account itself, beside the line dispatch,
        so two creates could race for one Service on a direct-invoice order.
        """
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.billing.signals import _handle_invoice_paid  # noqa: PLC0415

        order = self.create_order(
            items=[
                {
                    "product_id": self.product.pk,
                    "quantity": 1,
                    "unit_price_cents": 10000,
                    "setup_cents": 0,
                    "billing_period": "monthly",
                    "description": self.product.name,
                    "domain_name": "direct-shop.ro",
                }
            ]
        )
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, number="DIRECT-1")
        Order.objects.filter(pk=order.pk).update(invoice=invoice)
        Service.objects.filter(pk=order.items.get().service_id).update(status="provisioning")
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            _handle_invoice_paid(invoice)
        self.assertNotIn(CREATE, [call.args[0] for call in enqueue.call_args_list])
