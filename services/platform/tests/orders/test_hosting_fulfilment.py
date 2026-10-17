"""A paid hosting line follows its Service and its Virtualmin account, from one idempotent function.

No production code moved a hosting line out of pending: the order stayed in provisioning, the Service
in provisioning, and the account was never created. fulfil_hosting_line is the one place that does it.
"""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal
from unittest.mock import patch

from django.db import transaction
from django.test import TestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.billing.models import Currency
from apps.common.types import Err, Retriability
from apps.customers.models import Customer
from apps.orders.hosting_fulfilment import fulfil_hosting_line, recover_hosting_lines
from apps.orders.models import Order, OrderItem, OrderStatusHistory
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from tests.helpers.fsm_helpers import force_status

ACTIVATE = "apps.provisioning.provisioning_service.ProvisioningService.activate_service"


class HostingLineCase(TestCase):
    """An order paid and in provisioning, with one hosting line and its Service still provisioning."""

    plan_type = "shared_hosting"
    domain = "hosted.example.test"

    def setUp(self) -> None:
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            name="Hosting Buyer",
            company_name="Hosting Buyer SRL",
            customer_type="company",
            primary_email="hosting-buyer@example.test",
            status="active",
        )
        self.plan = ServicePlan.objects.create(
            name=f"{self.plan_type} plan", plan_type=self.plan_type, price_monthly=Decimal("29.99")
        )
        self.product = Product.objects.create(
            slug=f"{self.plan_type}-product",
            name="Hosting",
            product_type=self.plan_type,
            default_service_plan=self.plan,
        )
        self.order = self._order()
        self.service, self.line = self._line(self.order, self.domain)
        self.server = VirtualminServer.objects.create(
            name="Node A",
            hostname="node-a.example.test",
            api_username="api",
            api_port=10000,
            status="active",
            max_domains=100,
        )

    def _order(self, status: str = "provisioning") -> Order:
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            billing_address={},
            subtotal_cents=2999,
            total_cents=2999,
        )
        force_status(order, status)
        return order

    def _line(self, order: Order, domain: str) -> tuple[Service, OrderItem]:
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=domain,
            domain=domain,
            username=f"u{Service.objects.count()}",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="provisioning",
        )
        line = OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name="Hosting",
            product_type=self.plan_type,
            quantity=1,
            unit_price_cents=2999,
            line_total_cents=2999,
            service=service,
            domain_name=domain,
            config={"billing_period": "monthly"},
        )
        return service, line

    def _account(self, status: str = "active") -> VirtualminAccount:
        return VirtualminAccount.objects.create(
            domain=self.service.domain,
            service=self.service,
            server=self.server,
            virtualmin_username=self.service.username,
            template_name="Default",
            status=status,
            praho_customer_id=self.customer.id,
            praho_service_id=self.service.id,
        )

    def _job(self, account: VirtualminAccount) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=account,
            operation="create_domain",
            correlation_id=f"create-{account.pk}",
            started_at=timezone.now() - timedelta(seconds=1),
        )

    def _reload(self) -> None:
        self.line.refresh_from_db()
        self.service.refresh_from_db()
        self.order.refresh_from_db()

    def _audits(self, action: str) -> int:
        # Provisioning events are recorded against the line's Service.
        return AuditEvent.objects.filter(action=action, object_id=str(self.service.pk)).count()


class HostingFulfilmentTests(HostingLineCase):
    def test_pending_line_in_provisioning_order_moves_in_progress_and_activates_service_once(self) -> None:
        for _ in range(2):
            self.assertTrue(fulfil_hosting_line(self.line.pk).is_ok())
        self._reload()
        self.assertEqual(self.line.provisioning_status, "in_progress")
        self.assertEqual(self.service.status, "active")
        activated = AuditEvent.objects.filter(action="service_activated", object_id=str(self.service.pk))
        self.assertEqual(activated.count(), 1)

    def test_line_completes_once_when_initial_create_job_completed(self) -> None:
        fulfil_hosting_line(self.line.pk)
        account = self._account(status="provisioning")
        job = self._job(account)
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "in_progress")
        job.mark_completed({"domain": account.domain})
        VirtualminAccount.objects.filter(pk=account.pk).update(status="active")
        for _ in range(2):
            fulfil_hosting_line(self.line.pk)
        self._reload()
        self.assertEqual(self.line.provisioning_status, "completed")
        self.assertIsNotNone(self.line.provisioned_at)
        self.assertEqual(self._audits("provisioning_completed"), 1)
        self.assertEqual(self.order.status, "completed")
        self.assertEqual(OrderStatusHistory.objects.filter(order=self.order, new_status="completed").count(), 1)

    def test_retryable_create_failure_keeps_line_in_progress_then_completes_on_retry(self) -> None:
        fulfil_hosting_line(self.line.pk)
        account = self._account(status="error")
        job = self._job(account)
        job.mark_failed("node busy", retriability=Retriability.RETRIABLE)
        self.assertIsNotNone(job.next_retry_at)
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "in_progress")
        self._reload()
        self.assertEqual(self.line.provisioning_status, "in_progress")
        job.mark_completed({"domain": account.domain})
        VirtualminAccount.objects.filter(pk=account.pk).update(status="active")
        fulfil_hosting_line(self.line.pk)
        self._reload()
        self.assertEqual(self.line.provisioning_status, "completed")

    def test_retry_exhaustion_fails_line_once(self) -> None:
        for terminal in ("exhausted", "attention"):
            with self.subTest(terminal=terminal):
                order = self._order()
                self.service, self.line = self._line(order, f"{terminal}.example.test")
                fulfil_hosting_line(self.line.pk)
                job = self._job(self._account(status="error"))
                if terminal == "exhausted":
                    job.retry_count = job.max_retries
                    job.mark_failed("quota refused", retriability=Retriability.RETRIABLE)
                    self.assertIsNone(job.next_retry_at)
                else:
                    job.mark_attention("lost the node's answer")
                for _ in range(2):
                    fulfil_hosting_line(self.line.pk)
                self._reload()
                self.assertEqual(self.line.provisioning_status, "failed")
                self.assertEqual(self._audits("provisioning_failed"), 1)
                self.assertNotIn("quota", self.line.provisioning_notes)

    def test_already_active_service_is_treated_as_activated(self) -> None:
        Service.objects.filter(pk=self.service.pk).update(status="active", activated_at=timezone.now())
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "in_progress")
        self._reload()
        self.assertEqual(self.line.provisioning_status, "in_progress")
        self.assertFalse(AuditEvent.objects.filter(action="service_activated", object_id=str(self.service.pk)).exists())

    def test_line_with_active_account_completes_on_first_call(self) -> None:
        self._account(status="active")
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "completed")
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("completed", "active"))

    def test_activation_err_rolls_back_line_to_pending(self) -> None:
        with patch(ACTIVATE, return_value=Err("node refused")):
            self.assertTrue(fulfil_hosting_line(self.line.pk).is_err())
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("pending", "provisioning"))

    def test_cancelled_order_is_never_fulfilled(self) -> None:
        for status in ("cancelled", "in_review", "paid", "awaiting_payment"):
            with self.subTest(status=status):
                Order.objects.filter(pk=self.order.pk).update(status=status)
                self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "noop")
                self._reload()
                self.assertEqual((self.line.provisioning_status, self.service.status), ("pending", "provisioning"))

    def test_domain_line_is_left_to_its_registrar(self) -> None:
        OrderItem.objects.filter(pk=self.line.pk).update(product_type="domain")
        self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "noop")
        self._reload()
        self.assertEqual(self.line.provisioning_status, "pending")

    def test_service_ready_email_not_sent_when_completion_rolls_back(self) -> None:
        force_status(self.line, "in_progress", field_name="provisioning_status")
        Service.objects.filter(pk=self.service.pk).update(status="active")
        with (
            patch("apps.notifications.services.EmailService.send_template_email") as send,
            self.captureOnCommitCallbacks(execute=True),
        ):
            try:
                with transaction.atomic():
                    line = OrderItem.objects.get(pk=self.line.pk)
                    line.complete_provisioning()
                    line.save(update_fields=["provisioning_status", "provisioned_at", "updated_at"])
                    raise RuntimeError("the completing transaction failed")
            except RuntimeError:
                pass
        send.assert_not_called()


class StaffHandledLineTests(HostingLineCase):
    """A line that needs no hosting account is started, then left for staff to activate and complete.

    PRAHO provisions nothing for SSL, email, backup, maintenance or cloud products itself.
    """

    plan_type = "ssl"

    def test_non_hosting_line_is_left_for_staff(self) -> None:
        for _ in range(2):
            self.assertEqual(fulfil_hosting_line(self.line.pk).unwrap(), "left_for_staff")
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("in_progress", "provisioning"))
        self.assertEqual(self.order.status, "provisioning")


class RecoverySweepTests(HostingLineCase):
    def test_sweep_heals_a_line_whose_dispatch_was_lost(self) -> None:
        OrderItem.objects.filter(pk=self.line.pk).update(updated_at=timezone.now() - timedelta(minutes=11))
        _fresh_service, fresh = self._line(self.order, "fresh.example.test")
        self.assertEqual(recover_hosting_lines(), {"lines": 1, "orders": 0})
        self._reload()
        fresh.refresh_from_db()
        self.assertEqual(self.line.provisioning_status, "in_progress")
        self.assertEqual(fresh.provisioning_status, "pending")

    def test_sweep_completes_a_line_whose_completion_was_lost(self) -> None:
        force_status(self.line, "in_progress", field_name="provisioning_status")
        Service.objects.filter(pk=self.service.pk).update(status="active")
        self._account(status="active")
        self.assertEqual(recover_hosting_lines()["lines"], 1)
        self._reload()
        self.assertEqual(self.line.provisioning_status, "completed")

    def test_sweep_completes_order_whose_lines_all_completed(self) -> None:
        # update(), not save(): a saved completion completes the order itself; this is the lost one.
        OrderItem.objects.filter(pk=self.line.pk).update(provisioning_status="completed")
        self.assertEqual(recover_hosting_lines()["orders"], 1)
        self._reload()
        self.assertEqual(self.order.status, "completed")

    def test_sweep_is_bounded(self) -> None:
        OrderItem.objects.filter(pk=self.line.pk).update(updated_at=timezone.now() - timedelta(minutes=11))
        for index in range(3):
            _service, line = self._line(self.order, f"more{index}.example.test")
            OrderItem.objects.filter(pk=line.pk).update(updated_at=timezone.now() - timedelta(minutes=11))
        self.assertEqual(recover_hosting_lines(limit=2)["lines"], 2)


class ProvisionOrderItemTaskTests(HostingLineCase):
    def test_the_queued_task_fulfils_the_line(self) -> None:
        from apps.orders.tasks import provision_order_item  # noqa: PLC0415

        result = provision_order_item(str(self.line.pk))
        self.assertTrue(result["success"], result)
        self._reload()
        self.assertEqual((self.line.provisioning_status, self.service.status), ("in_progress", "active"))


class CreateJobTriggerTests(HostingLineCase):
    def test_create_job_terminal_state_enqueues_line_fulfilment(self) -> None:
        job = self._job(self._account(status="provisioning"))
        force_status(self.line, "in_progress", field_name="provisioning_status")
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            job.mark_completed({"domain": self.service.domain})
        calls = [call.args for call in enqueue.call_args_list]
        self.assertIn(("apps.orders.tasks.provision_order_item", str(self.line.pk)), calls)

    def test_fulfilment_enqueue_failure_never_breaks_the_job(self) -> None:
        account = self._account(status="active")
        job = self._job(account)
        with (
            patch("django_q.tasks.async_task", side_effect=RuntimeError("queue down")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            job.mark_completed({"domain": account.domain})
        job.refresh_from_db()
        account.refresh_from_db()
        self.assertEqual((job.status, account.status), ("completed", "active"))

    def test_other_operations_do_not_enqueue_fulfilment(self) -> None:
        job = self._job(self._account(status="active"))
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(operation="suspend_domain")
        job.refresh_from_db()
        with patch("django_q.tasks.async_task") as enqueue, self.captureOnCommitCallbacks(execute=True):
            job.mark_completed({})
        self.assertNotIn("apps.orders.tasks.provision_order_item", [c.args[0] for c in enqueue.call_args_list])
