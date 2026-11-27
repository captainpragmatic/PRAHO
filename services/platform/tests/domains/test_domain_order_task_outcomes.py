"""The domain-order task reports each paid line from its recorded state, not from this run alone (#442).

A line is sent to the registrar at most once: a claimed line is refused a second time, and a renewal
replays its intent. So a repeated run (a retried task, or the sweep re-queuing an order for one line
that never started) dispatches nothing new for the lines already done. The task's success flag is
the durable signal that paid lines remain unfulfilled, so it must count those finished lines too,
instead of reporting them as unprocessed.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from unittest.mock import patch

from django.db import transaction
from django.test import TransactionTestCase
from django.utils import timezone

from apps.common.types import Ok
from apps.domains import tasks as domain_tasks
from apps.domains.gateways.base import DomainInfoResult
from apps.domains.models import Domain, DomainOperation, DomainOrderItem
from apps.domains.operation_services import DomainOperationService
from apps.domains.services import DomainOrderService
from apps.orders.models import OrderItem

from .test_domain_order_flow import ALERT, REGISTER, DomainOrderLineFixture, _domain_line


def _registered() -> tuple[bool, dict[str, object]]:
    return True, {"registrar_domain_id": "outcome", "expires_at": timezone.now() + timedelta(days=365)}


def _outcome(domain: str, action: str, outcome: str) -> dict[str, str]:
    return {"domain": domain, "action": action, "outcome": outcome}


class DomainOrderTaskOutcomeTests(DomainOrderLineFixture, TransactionTestCase):
    def test_a_repeated_run_reports_finished_lines_as_done_and_sends_nothing(self) -> None:
        order, line = self._domain_order()
        with patch(REGISTER, return_value=_registered()) as register:
            first = domain_tasks.process_order_domain_items(str(order.pk))
            line.refresh_from_db()
            self.assertEqual(line.provisioning_status, "completed")  # precondition: the line is done
            with self.assertNoLogs("apps.domains.tasks", level="ERROR"):
                second = domain_tasks.process_order_domain_items(str(order.pk))

        register.assert_called_once()
        self.assertTrue(first["success"], first)
        self.assertTrue(second["success"], second)
        self.assertEqual(second["outcomes"], [_outcome("flow.ro", "register", "completed")])

    def test_a_sweep_rerun_counts_the_line_already_done_and_the_one_it_finishes(self) -> None:
        price = DomainOrderService.quote_order_line("first.ro", "register", "RON").unwrap().total_cents
        order = self._create_order(
            _domain_line(self.domain_product, "first.ro", price), _domain_line(self.domain_product, "second.ro", price)
        )
        type(order).objects.filter(pk=order.pk).update(status="provisioning")
        order.refresh_from_db()
        first_line, second_line = order.items.order_by("domain_name")

        # The first run reached only the first line (its worker died before the second was claimed).
        with patch(REGISTER, return_value=_registered()):
            DomainOrderService._process_paid_line(order, first_line.domain_order_item)
        first_line.refresh_from_db()
        second_line.refresh_from_db()
        self.assertEqual((first_line.provisioning_status, second_line.provisioning_status), ("completed", "pending"))

        with patch(REGISTER, return_value=_registered()) as register:
            result = domain_tasks.process_order_domain_items(str(order.pk))

        register.assert_called_once()  # only the second line is sent
        self.assertTrue(result["success"], result)
        self.assertCountEqual(
            result["outcomes"],
            [_outcome("first.ro", "register", "completed"), _outcome("second.ro", "register", "completed")],
        )

    def test_a_failed_line_fails_the_task_and_is_named(self) -> None:
        order, line = self._domain_order()
        crash = patch(
            "apps.domains.services.DomainLifecycleService._build_registrant_data", side_effect=RuntimeError("db down")
        )
        with crash, patch(REGISTER) as register, patch(ALERT):
            result = domain_tasks.process_order_domain_items(str(order.pk))

        register.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        self.assertFalse(result["success"], result)
        self.assertEqual(result["outcomes"], [_outcome("flow.ro", "register", "failed")])

    def test_a_cancelled_line_is_reported_and_not_held_against_the_task(self) -> None:
        order, line = self._domain_order()
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="cancelled")

        with patch(REGISTER) as register:
            result = domain_tasks.process_order_domain_items(str(order.pk))

        register.assert_not_called()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["outcomes"], [_outcome("flow.ro", "register", "cancelled")])

    def test_a_renewal_is_in_progress_until_confirmed_then_completed_without_a_second_charge(self) -> None:
        domain = Domain.objects.create(
            name="renewed-outcome.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer, status="active"
        )
        domain.expires_at = datetime(2028, 1, 1, tzinfo=UTC)
        domain.registrar_domain_id = domain.name
        domain.save()
        created, _item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name=domain.name, action="renew", years=1
        )
        self.assertTrue(created)
        info = DomainInfoResult(domain.name, domain.name, "active", domain.expires_at, [])
        with (
            patch("apps.domains.services.DomainRegistrarGateway.get_domain_info", return_value=Ok(info)),
            patch(
                "apps.domains.services.DomainRegistrarGateway.renew_domain", return_value=(True, {"pending": True})
            ) as renew,
        ):
            waiting = domain_tasks.process_order_domain_items(str(self.order.pk))
            self.assertFalse(waiting["success"], waiting)
            self.assertIn(_outcome(domain.name, "renew", "in_progress"), waiting["outcomes"])
            operation = DomainOperation.objects.get(domain=domain, operation_type="renew")
            self.assertTrue(DomainOperationService.confirm_renewal(operation, datetime(2029, 1, 1, tzinfo=UTC)))
            confirmed = domain_tasks.process_order_domain_items(str(self.order.pk))

        self.assertEqual(renew.call_count, 1)
        self.assertIn(_outcome(domain.name, "renew", "completed"), confirmed["outcomes"])

    def test_a_cancelled_transfer_with_its_code_cleared_is_cancelled_not_waiting(self) -> None:
        order, line = self._domain_order()
        # What cancelling a pending transfer leaves: the line cancelled and the transfer code cleared.
        DomainOrderItem.objects.filter(order_item=line).update(action="transfer", epp_code="")
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="cancelled")

        outcomes = DomainOrderService.order_item_outcomes(order)

        self.assertEqual(outcomes, [_outcome("flow.ro", "transfer", "cancelled")])

    def test_a_registration_without_an_order_line_stays_completed_after_its_domain_changes(self) -> None:
        created, item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="legacy-done.ro", action="register", years=1
        )
        self.assertTrue(created, item)
        self.assertIsNone(item.order_item_id)  # precondition: an item with no order line
        domain = Domain.objects.create(
            name="legacy-done.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer,
            status="suspended", registered_at=timezone.now() - timedelta(days=30),
        )
        DomainOrderItem.objects.filter(pk=item.pk).update(domain=domain)

        outcomes = DomainOrderService.order_item_outcomes(self.order)

        self.assertIn(_outcome("legacy-done.ro", "register", "completed"), outcomes)

    def test_a_registration_confirmed_by_webhook_is_completed(self) -> None:
        """Every confirmation path records registered_at; the webhook did not (#442 review)."""
        from apps.domains.webhooks import RegistrarWebhookView  # noqa: PLC0415

        created, item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="webhook-done.ro", action="register", years=1
        )
        self.assertTrue(created, item)
        domain = Domain.objects.create(
            name="webhook-done.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer,
            status="pending", expires_at=timezone.now() + timedelta(days=365),
        )
        DomainOrderItem.objects.filter(pk=item.pk).update(domain=domain)
        self.assertIsNone(domain.registered_at)  # precondition

        with patch("apps.domains.signals.sync_domain_to_virtualmin"), transaction.atomic():
            ok, reason = RegistrarWebhookView()._handle_domain_registered(domain, {}, "198.51.100.7")

        self.assertTrue(ok, reason)
        domain.refresh_from_db()
        self.assertEqual(domain.status, "active")
        self.assertIsNotNone(domain.registered_at)
        self.assertIn(
            _outcome("webhook-done.ro", "register", "completed"), DomainOrderService.order_item_outcomes(self.order)
        )

    def test_a_registration_without_a_line_that_is_active_but_unstamped_is_completed(self) -> None:
        """A row confirmed before every path stamped registered_at still reads as completed."""
        created, item = DomainOrderService.create_domain_order_item(
            order=self.order, domain_name="unstamped.ro", action="register", years=1
        )
        self.assertTrue(created, item)
        domain = Domain.objects.create(
            name="unstamped.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer, status="active"
        )
        DomainOrderItem.objects.filter(pk=item.pk).update(domain=domain)
        self.assertIsNone(domain.registered_at)  # precondition

        self.assertIn(
            _outcome("unstamped.ro", "register", "completed"), DomainOrderService.order_item_outcomes(self.order)
        )
