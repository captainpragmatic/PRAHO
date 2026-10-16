"""A paid domain line survives what goes wrong between the request and the registrar's answer.

The registrar it was sold with is the one asked; a refusal never deletes a domain something else
confirmed meanwhile; a lost completion, a lost enqueue or a killed worker is picked up by the sweep;
an error's text never reaches the logs or the staff alert, only its kind.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import Mock, patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.common.types import Err, Retriability
from apps.domains.gateways import RegistrarAPIError, RegistrarErrorCode
from apps.domains.models import Domain, DomainOrderItem, Registrar, TLDRegistrarAssignment
from apps.domains.order_fulfilment import (
    claim_order_line,
    fail_order_line,
    fulfil_order_item_for_domain,
    sweep_domain_order_lines,
)
from apps.domains.services import DomainLifecycleService, DomainOrderService
from apps.orders import signals as order_signals
from apps.orders.models import Order, OrderItem

from .test_domain_order_flow import ALERT, REGISTER, DomainOrderLineFixture, _domain_line


def _activate_without_callbacks(domain: Domain) -> None:
    """What a crash between the activation commit and its completion callback leaves behind."""
    Domain.objects.filter(pk=domain.pk).update(status="active", expires_at=timezone.now() + timedelta(days=365))


class QuotedRegistrarTests(DomainOrderLineFixture, TransactionTestCase):
    def test_the_domain_item_factory_records_its_registrar_for_older_callers_too(self) -> None:
        order, _line = self._domain_order()
        created, item = DomainOrderService.create_domain_order_item(order, "factory.ro", "register")

        self.assertTrue(created)
        self.assertIsInstance(item, DomainOrderItem)
        self.assertEqual(item.registrar, self.ro_registrar)

    def test_a_paid_line_without_its_quoted_registrar_is_not_sent_to_a_substitute(self) -> None:
        order, line = self._domain_order()
        DomainOrderItem.objects.filter(order_item=line).update(registrar=None)

        with patch(REGISTER) as register, patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)

        register.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        alert.assert_called_once()

    def test_a_paid_registration_goes_to_the_registrar_it_was_sold_with(self) -> None:
        order, _line = self._domain_order()
        newcomer = Registrar.objects.create(
            name="newcomer", display_name="Newcomer", website_url="https://new.example.test",
            api_endpoint="https://api.gandi.net/v5",
        )
        TLDRegistrarAssignment.objects.filter(tld=self.ro).update(is_primary=False)
        TLDRegistrarAssignment.objects.create(tld=self.ro, registrar=newcomer, is_primary=True, is_active=True)

        with patch(REGISTER, return_value=(True, {"pending": True})) as register:
            DomainOrderService.process_domain_order_items(order)

        self.assertEqual(register.call_args.args[0], self.ro_registrar)

    def test_a_registrar_that_no_longer_offers_the_extension_fails_the_line_instead_of_a_substitute(self) -> None:
        order, line = self._domain_order()
        backup = Registrar.objects.create(
            name="backup", display_name="Backup", website_url="https://backup.example.test",
            api_endpoint="https://api.gandi.net/v5",
        )
        TLDRegistrarAssignment.objects.create(tld=self.ro, registrar=backup, is_primary=False, is_active=True)
        TLDRegistrarAssignment.objects.filter(tld=self.ro, registrar=self.ro_registrar).update(is_active=False)

        with patch(REGISTER) as register, patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)

        register.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        alert.assert_called_once()


class LateRefusalTests(DomainOrderLineFixture, TransactionTestCase):
    def _refusal_after_activation(self) -> Err[RegistrarAPIError]:
        # A webhook (or staff) confirmed the domain while this request was still waiting.
        Domain.objects.filter(name="late.ro").update(status="active")
        return Err(
            RegistrarAPIError("refused", code=RegistrarErrorCode.INVALID_REGISTRANT_DATA),
            retriability=Retriability.NOT_RETRIABLE,
        )

    def test_a_contact_refusal_keeps_a_domain_confirmed_meanwhile(self) -> None:
        with patch(
            "apps.domains.gateways.gandi.GandiGateway.prepare_registration_contact",
            side_effect=lambda _data: self._refusal_after_activation(),
        ):
            result = DomainLifecycleService.create_domain_registration(self.customer, "late.ro")

        self.assertTrue(result.is_err())
        self.assertEqual(Domain.objects.get(name="late.ro").status, "active")

    def test_a_transfer_refusal_keeps_a_domain_confirmed_meanwhile(self) -> None:
        with patch(
            "apps.domains.gateways.gandi.GandiGateway.initiate_transfer",
            side_effect=lambda *_args, **_kwargs: self._refusal_after_activation(),
        ):
            result = DomainLifecycleService.initiate_transfer("late.ro", "CODE-1", self.customer, self.ro_registrar)

        self.assertTrue(result.is_err())
        self.assertEqual(Domain.objects.get(name="late.ro").status, "active")


class SweepTests(DomainOrderLineFixture, TransactionTestCase):
    def test_a_line_whose_domain_is_active_completes_when_its_completion_was_lost(self) -> None:
        order, line = self._domain_order()
        with patch(REGISTER, return_value=(True, {"pending": True})):
            DomainOrderService.process_domain_order_items(order)
        _activate_without_callbacks(Domain.objects.get(name="flow.ro"))

        sweep_domain_order_lines()

        line.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual((line.provisioning_status, order.status), ("completed", "completed"))

    def test_a_line_claimed_but_never_sent_fails_for_staff_after_an_hour(self) -> None:
        _order, line = self._domain_order()
        self.assertTrue(claim_order_line(line.domain_order_item))
        OrderItem.objects.filter(pk=line.pk).update(updated_at=timezone.now() - timedelta(minutes=30))

        with patch(ALERT) as alert:
            sweep_domain_order_lines()
            line.refresh_from_db()
            self.assertEqual(line.provisioning_status, "in_progress")
            OrderItem.objects.filter(pk=line.pk).update(updated_at=timezone.now() - timedelta(hours=2))
            sweep_domain_order_lines()

        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "failed")
        alert.assert_called_once()

    def test_a_paid_line_never_picked_up_is_queued_again(self) -> None:
        order, _line = self._domain_order()
        Order.objects.filter(pk=order.pk).update(updated_at=timezone.now() - timedelta(hours=2))

        with patch("django_q.tasks.async_task") as enqueue:
            sweep_domain_order_lines()

        enqueue.assert_called_once_with("apps.domains.tasks.process_order_domain_items", str(order.pk))

    def test_a_renewal_is_never_completed_by_an_active_domain(self) -> None:
        _order, line = self._domain_order()
        domain_item = line.domain_order_item
        DomainOrderItem.objects.filter(pk=domain_item.pk).update(action="renew")
        domain = Domain.objects.create(
            name="flow.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer, status="active"
        )
        DomainOrderItem.objects.filter(pk=domain_item.pk).update(domain=domain)
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")

        sweep_domain_order_lines()
        self.assertEqual(fulfil_order_item_for_domain(domain.pk), 0)

        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")

        # The sweep must also leave a renewal intent without a linked domain alone.
        DomainOrderItem.objects.filter(pk=domain_item.pk).update(domain=None)
        OrderItem.objects.filter(pk=line.pk).update(updated_at=timezone.now() - timedelta(hours=2))
        with patch(ALERT) as alert:
            sweep_domain_order_lines()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")
        alert.assert_not_called()

    def test_the_reconciliation_task_runs_the_sweep(self) -> None:
        from apps.domains import tasks  # noqa: PLC0415

        with (
            patch.object(tasks.DomainReconciliationService, "reconcile") as reconcile,
            patch("apps.domains.tasks.sweep_domain_order_lines") as sweep,
        ):
            tasks.reconcile_pending_domain_operations()

        reconcile.assert_called_once()
        sweep.assert_called_once()


class FailLineTests(DomainOrderLineFixture, TestCase):
    def test_a_line_with_a_domain_at_the_registrar_is_not_failed(self) -> None:
        _order, line = self._domain_order()
        domain_item = line.domain_order_item
        OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
        domain = Domain.objects.create(name="flow.ro", tld=self.ro, registrar=self.ro_registrar, customer=self.customer)
        DomainOrderItem.objects.filter(pk=domain_item.pk).update(domain=domain)

        with patch(ALERT) as alert:
            self.assertFalse(fail_order_line(domain_item, "stalled"))

        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")
        alert.assert_not_called()


class OrderLockTests(DomainOrderLineFixture, TestCase):
    def test_claim_fail_and_fulfil_lock_the_order_before_the_line(self) -> None:
        for action in ("claim", "fail", "fulfil"):
            with self.subTest(action):
                _order, line = self._domain_order(f"{action}.ro")
                domain_item = line.domain_order_item
                if action != "claim":
                    OrderItem.objects.filter(pk=line.pk).update(provisioning_status="in_progress")
                if action == "fulfil":
                    domain = Domain.objects.create(
                        name=domain_item.domain_name, tld=self.ro, registrar=self.ro_registrar,
                        customer=self.customer, status="active",
                    )
                    DomainOrderItem.objects.filter(pk=domain_item.pk).update(domain=domain)
                locks = Mock()
                with (
                    patch.object(Order.objects, "select_for_update", wraps=Order.objects.select_for_update) as order_lock,
                    patch.object(OrderItem.objects, "select_for_update", wraps=OrderItem.objects.select_for_update) as line_lock,
                    patch(ALERT),
                ):
                    locks.attach_mock(order_lock, "order")
                    locks.attach_mock(line_lock, "line")
                    if action == "claim":
                        self.assertTrue(claim_order_line(domain_item))
                    elif action == "fail":
                        self.assertTrue(fail_order_line(domain_item, "refused"))
                    else:
                        self.assertEqual(fulfil_order_item_for_domain(domain.pk), 1)

                self.assertEqual([call[0] for call in locks.mock_calls][:2], ["order", "line"])

    def test_a_claim_reloads_a_cancelled_order_instead_of_using_the_callers_snapshot(self) -> None:
        order, line = self._domain_order()
        domain_item = line.domain_order_item
        self.assertEqual(order.status, "provisioning")
        Order.objects.filter(pk=order.pk).update(status="cancelled")

        self.assertFalse(claim_order_line(domain_item))

        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")

    def test_the_last_of_two_completed_lines_completes_the_order_in_either_order(self) -> None:
        for reverse in (False, True):
            with self.subTest(reverse=reverse):
                names = [f"first-{int(reverse)}.ro", f"second-{int(reverse)}.ro"]
                price = DomainOrderService.quote_order_line(names[0], "register", "RON").unwrap().total_cents
                order = self._create_order(*(_domain_line(self.domain_product, name, price) for name in names))
                Order.objects.filter(pk=order.pk).update(status="provisioning")
                OrderItem.objects.filter(order=order).update(provisioning_status="in_progress")
                for line in order.items.all():
                    domain = Domain.objects.create(
                        name=line.domain_name, tld=self.ro, registrar=self.ro_registrar,
                        customer=self.customer, status="active",
                    )
                    DomainOrderItem.objects.filter(order_item=line).update(domain=domain)
                domains = list(Domain.objects.filter(name__in=names).order_by("name"))
                if reverse:
                    domains.reverse()

                self.assertEqual(fulfil_order_item_for_domain(domains[0].pk), 1)
                order.refresh_from_db()
                self.assertEqual(order.status, "provisioning")
                with patch.object(order_signals, "Order", wraps=Order) as signal_order:
                    self.assertEqual(fulfil_order_item_for_domain(domains[1].pk), 1)

                signal_order.objects.select_for_update.assert_called_once_with(of=("self",))
                order.refresh_from_db()
                self.assertEqual(order.status, "completed")


class SentryOptionsTests(TestCase):
    def test_reports_carry_no_frame_locals_and_secrets_are_scrubbed_at_any_depth(self) -> None:
        from config.settings.sentry import sentry_options  # noqa: PLC0415

        options = sentry_options("https://key@sentry.example.test/1", release="1.0")
        scrubber = options["event_scrubber"]

        self.assertIs(options["include_local_variables"], False)
        self.assertTrue(scrubber.recursive)
        for key in ("cnp", "cnp_fiscal_code", "epp_code", "auth_code", "authorization_key", "transfer_code"):
            self.assertIn(key, scrubber.denylist)
