"""Order → domains wiring: paid orders actually process their domain items.

process_domain_order_items existed without a live caller — the domain commerce
pipeline (validated items, ownership re-checks, idempotency tokens) was built but
connected to nothing. The orders service now enqueues a Django-Q2 task on the
transition into provisioning (on_commit, because the registrar call is network
I/O and must never run inside the order transaction), and the task delegates to
DomainOrderService.
"""

from __future__ import annotations

import uuid
from unittest.mock import patch

from django.test import TestCase

from apps.common.types import Ok
from apps.domains import tasks as domain_tasks
from apps.domains.models import Domain
from apps.domains.services import DomainOrderService
from apps.orders.services import OrderService, OrderServiceCreationService, StatusChangeData

from .test_domain_service_logic import DomainFixtureMixin


class OrderDomainProcessingTaskTests(DomainFixtureMixin, TestCase):
    def test_task_processes_the_orders_domain_items(self) -> None:
        domain = Domain.objects.create(
            name="task-owned.ro",
            tld=self.ro,
            registrar=self.ro_registrar,
            customer=self.customer,
            status="active",
        )

        with patch.object(
            DomainOrderService, "process_domain_order_items", return_value=[domain]
        ) as mock_process:
            result = domain_tasks.process_order_domain_items(str(self.order.pk))

        mock_process.assert_called_once()
        self.assertEqual(mock_process.call_args.args[0], self.order)
        self.assertTrue(result["success"])
        self.assertEqual(result["processed"], 1)
        self.assertEqual(result["domains"], ["task-owned.ro"])

    def test_task_reports_failure_when_paid_items_remain_unprocessed(self) -> None:
        """A registrar outage that rejects every item must NOT record a successful
        task — Django-Q2's success flag is the only durable signal that paid items
        remain unfulfilled."""
        DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="unfulfilled.ro", action="register", years=1
        )

        with patch.object(DomainOrderService, "process_domain_order_items", return_value=[]):
            result = domain_tasks.process_order_domain_items(str(self.order.pk))

        self.assertFalse(result["success"])
        self.assertEqual(result["processed"], 0)
        self.assertEqual(result["items_total"], 1)

    def test_task_handles_missing_order_without_raising(self) -> None:
        with patch.object(DomainOrderService, "process_domain_order_items") as mock_process:
            result = domain_tasks.process_order_domain_items(str(uuid.uuid4()))

        mock_process.assert_not_called()
        self.assertFalse(result["success"])


class OrderProvisioningEnqueuesDomainProcessingTests(DomainFixtureMixin, TestCase):
    """The transition into provisioning enqueues domain processing on commit."""

    def setUp(self) -> None:
        super().setUp()
        # Bypass the FSM guard to stage the precondition state directly.
        type(self.order).objects.filter(pk=self.order.pk).update(status="paid")
        self.order.refresh_from_db()

    def _transition_to_provisioning(self) -> object:
        # Enrollment is a sibling concern with its own coverage; isolate the wiring.
        with patch.object(
            OrderServiceCreationService,
            "update_service_status_on_payment",
            return_value=Ok([]),
        ):
            return OrderService.update_order_status(self.order, StatusChangeData(new_status="provisioning"))

    def test_provisioning_transition_enqueues_domain_processing(self) -> None:
        self._owned_domain = Domain.objects.create(
            name="enqueue-me.ro",
            tld=self.ro,
            registrar=self.ro_registrar,
            customer=self.customer,
            status="active",
        )
        created, item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="enqueue-me.ro", action="renew", years=1
        )
        self.assertTrue(created, item)

        with (
            patch("django_q.tasks.async_task") as mock_async,
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self._transition_to_provisioning()

        self.assertTrue(result.is_ok(), result)
        mock_async.assert_called_once_with(
            "apps.domains.tasks.process_order_domain_items",
            str(self.order.pk),
        )

    def test_no_domain_items_means_no_enqueue(self) -> None:
        with (
            patch("django_q.tasks.async_task") as mock_async,
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = self._transition_to_provisioning()

        self.assertTrue(result.is_ok(), result)
        mock_async.assert_not_called()


class AutomaticPaymentConfirmationEnqueuesDomainProcessingTests(DomainFixtureMixin, TestCase):
    """The AUTOMATIC payment path (confirm_order auto-advance, used by payment
    signals/tasks) bypasses update_order_status entirely — it must enqueue domain
    processing too, or the normal customer flow never registers anything."""

    def setUp(self) -> None:
        super().setUp()
        type(self.order).objects.filter(pk=self.order.pk).update(status="awaiting_payment")
        self.order.refresh_from_db()

    def test_auto_advance_confirmation_enqueues_domain_processing(self) -> None:
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        Domain.objects.create(
            name="auto-confirm.ro",
            tld=self.ro,
            registrar=self.ro_registrar,
            customer=self.customer,
            status="active",
        )
        created, item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="auto-confirm.ro", action="renew", years=1
        )
        self.assertTrue(created, item)

        with (
            patch("django_q.tasks.async_task") as mock_async,
            patch.object(
                OrderServiceCreationService,
                "update_service_status_on_payment",
                return_value=Ok([]),
            ),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = OrderPaymentConfirmationService.confirm_order(self.order)

        self.assertTrue(result.is_ok(), result)
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, "provisioning")
        mock_async.assert_called_once_with(
            "apps.domains.tasks.process_order_domain_items",
            str(self.order.pk),
        )
