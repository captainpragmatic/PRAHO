"""Paid transfers keep their code until dispatch and complete only on activation."""
from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.core.cache import cache
from django.db import transaction
from django.db.models import Model, QuerySet
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.customers.models import Customer
from apps.domains.gateways import DomainTransferResult, RegistrarAPIError
from apps.domains.gateways.errors import RegistrarErrorCode
from apps.domains.models import Domain, DomainOperation, DomainOrderItem, TLDRegistrarAssignment, TLDRetailPrice
from apps.domains.operation_services import DomainOperationService
from apps.domains.order_fulfilment import claim_order_line, sweep_domain_order_lines
from apps.domains.services import DomainOrderService
from apps.domains.transfer_codes import clear_terminal_transfer_code
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderService, StatusChangeData

from .test_domain_order_flow import ALERT, DomainOrderLineFixture, _domain_line

TRANSFER = "apps.domains.gateways.gandi.GandiGateway._do_initiate_transfer"

class TransferLineFixture(DomainOrderLineFixture):
    def setUp(self) -> None:
        super().setUp()
        Customer.objects.filter(pk=self.customer.pk).update(status="active")
        self.customer.refresh_from_db()

    def _transfer_order(self, name: str = "transfer.ro") -> tuple[Order, OrderItem]:
        quote = DomainOrderService.quote_order_line(name, "transfer", "RON").unwrap()
        data = _domain_line(self.domain_product, name, quote.total_cents)
        data["meta"] = {"domain_mode": "transfer"}
        order = self._create_order(data)
        Order.objects.filter(pk=order.pk).update(status="provisioning")
        order.refresh_from_db()
        return order, order.items.get()

    def _code(self, line: OrderItem, value: str = "Transfer-Secret!123") -> str:
        item = DomainOrderItem.objects.get(order_item=line)
        item.set_encrypted_epp_code(value)
        item.save(update_fields=["epp_code", "updated_at"])
        return item.epp_code

@override_settings(
    REGISTRAR_ADAPTERS_VERIFIED=True,
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "paid-transfers"}},
)
class PaidTransferTests(TransferLineFixture, TransactionTestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()

    def test_a_transfer_without_a_code_is_not_claimed(self) -> None:
        order, line = self._transfer_order()
        with patch(TRANSFER) as transfer:
            DomainOrderService.process_domain_order_items(order)
        transfer.assert_not_called()
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "pending")
        self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_claim_refuses_a_missing_code_or_a_linked_domain_and_refreshes_a_replaced_code(self) -> None:
        _order, line = self._transfer_order()
        item = line.domain_order_item
        self.assertFalse(claim_order_line(item))
        self._code(line, "old-code")
        stale = DomainOrderItem.objects.get(pk=item.pk)
        self._code(line, "new-code")
        domain = Domain.objects.create(name=line.domain_name, tld=self.ro, registrar=self.ro_registrar, customer=self.customer)
        DomainOrderItem.objects.filter(pk=item.pk).update(domain=domain)
        self.assertFalse(claim_order_line(stale))
        DomainOrderItem.objects.filter(pk=item.pk).update(domain=None)
        self.assertTrue(claim_order_line(stale))
        self.assertEqual(stale.get_decrypted_epp_code(), "new-code")
        line.refresh_from_db()
        self.assertEqual(line.provisioning_status, "in_progress")

    def test_creation_and_dispatch_keep_the_order_line_item_domain_operation_lock_order(self) -> None:
        order, line = self._transfer_order()
        self._code(line)
        original_fetch = QuerySet._fetch_all
        locks: list[type[Model]] = []

        def observe(queryset: QuerySet[Model]) -> None:
            if queryset.query.select_for_update and queryset.model in (Order, OrderItem, DomainOrderItem, Domain, DomainOperation):
                locks.append(queryset.model)
            original_fetch(queryset)

        with patch.object(QuerySet, "_fetch_all", new=observe), patch(TRANSFER, return_value=Ok(DomainTransferResult(transfer_id="locked", status="pending"))):
            DomainOrderService.process_domain_order_items(order)
        self.assertEqual(locks, [Order, OrderItem, DomainOrderItem] * 3 + [Domain, DomainOperation])

    def test_terminal_cleanup_rechecks_state_and_waits_until_the_line_save_commits(self) -> None:
        _order, line = self._transfer_order()
        encrypted = self._code(line)
        clear_terminal_transfer_code(line.pk)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, encrypted)
        with self.assertRaises(RuntimeError), transaction.atomic():
            line.start_provisioning()
            line.complete_provisioning()
            line.save()
            raise RuntimeError("rollback")
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, encrypted)
        line.refresh_from_db()
        with transaction.atomic():
            line.start_provisioning()
            line.complete_provisioning()
            line.save()
            self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, encrypted)
        self.assertEqual(DomainOrderItem.objects.get(order_item=line).epp_code, "")

    def test_dispatch_links_the_paid_domain_and_takes_the_code_immediately_before_submission(self) -> None:
        order, line = self._transfer_order()
        paid_terms = {**line.domain_order_item.renewal_terms, "whois_privacy": True}
        DomainOrderItem.objects.filter(order_item=line).update(whois_privacy=True, auto_renew=False, renewal_terms=paid_terms)
        self.assertEqual(TLDRetailPrice.objects.filter(tld=self.ro, currency_id="RON").update(renewal_price_cents=9999), 1)
        self._code(line)
        sent: list[str] = []

        def submit(name: str, code: str, registrant_data: dict[str, object] | None = None) -> Ok[DomainTransferResult]:
            item = DomainOrderItem.objects.get(order_item=line)
            self.assertEqual(item.epp_code, "")
            self.assertIsNotNone(item.domain_id)
            self.assertEqual(DomainOperation.objects.get(domain=item.domain).state, "submitted")
            sent.append(code)
            return Ok(DomainTransferResult(transfer_id="transfer-1", status="pending"))

        with patch(TRANSFER, side_effect=submit) as transfer:
            DomainOrderService.process_domain_order_items(order)
            DomainOrderService.process_domain_order_items(order)
        transfer.assert_called_once()
        self.assertEqual(sent, ["Transfer-Secret!123"])
        domain = Domain.objects.get(name=line.domain_name)
        line.refresh_from_db()
        self.assertEqual((domain.status, line.provisioning_status), ("transfer_in", "in_progress"))
        self.assertEqual((domain.registrar, domain.whois_privacy, domain.auto_renew), (self.ro_registrar, True, False))
        self.assertEqual(domain.billing_currency_id, "RON")
        self.assertEqual(domain.renewal_unit_price_cents, paid_terms["unit_price_cents"])
        with transaction.atomic():
            domain.activate()
            domain.save()
        line.refresh_from_db()
        order.refresh_from_db()
        self.assertEqual((line.provisioning_status, order.status), ("completed", "completed"))

    def test_a_submitted_operation_cannot_take_the_code_or_dispatch_again(self) -> None:
        order, line = self._transfer_order()
        self._code(line)
        with patch(TRANSFER, return_value=Ok(DomainTransferResult(transfer_id="once", status="pending"))):
            DomainOrderService.process_domain_order_items(order)
        item = DomainOrderItem.objects.get(order_item=line)
        operation = DomainOperation.objects.get(domain=item.domain)
        with patch.object(DomainOperation, "mark_submitted", side_effect=AssertionError("Duplicate dispatch")) as submit:
            self.assertFalse(DomainOperationService.dispatch(operation, order_item=item))
        submit.assert_not_called()
        operation.refresh_from_db()
        self.assertEqual(operation.state, "submitted")

    def test_crashes_before_dispatch_keep_the_code_and_never_quote_it_in_logs_or_alerts(self) -> None:
        for boundary in ("apps.domains.services.DomainLifecycleService._build_registrant_data", "apps.domains.operation_services.DomainOperationService._can_create_domain"):
            with self.subTest(boundary=boundary):
                suffix = "contact" if boundary.endswith("_build_registrant_data") else "records"
                order, line = self._transfer_order(f"crash-{suffix}.ro")
                code = f"Crash-Secret-{suffix}!123"
                encrypted = self._code(line, code)
                with patch(boundary, side_effect=RuntimeError(f"{code}/{encrypted}")), patch(TRANSFER) as transfer, patch(ALERT) as alert, self.assertLogs("apps", level="DEBUG") as logs:
                    DomainOrderService.process_domain_order_items(order)
                transfer.assert_not_called()
                line.refresh_from_db()
                self.assertEqual((line.provisioning_status, line.domain_order_item.epp_code), ("failed", encrypted))
                alert.assert_called_once()
                evidence = "\n".join(logs.output) + repr(alert.call_args_list)
                self.assertIn("RuntimeError", evidence)
                self.assertNotIn(code, evidence)
                self.assertNotIn(encrypted, evidence)

    @override_settings(REGISTRAR_ADAPTERS_VERIFIED=False)
    def test_an_unverified_adapter_refuses_before_dispatch_and_keeps_the_code_for_staff(self) -> None:
        order, line = self._transfer_order()
        encrypted = self._code(line)
        with patch(TRANSFER) as transfer, patch(ALERT) as alert:
            DomainOrderService.process_domain_order_items(order)
        transfer.assert_not_called()
        alert.assert_called_once()
        line.refresh_from_db()
        self.assertEqual((line.provisioning_status, line.domain_order_item.epp_code), ("failed", encrypted))
        self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_an_open_breaker_refuses_before_dispatch_and_keeps_the_code(self) -> None:
        order, line = self._transfer_order()
        encrypted = self._code(line)
        refusal = Err(RegistrarAPIError("Breaker open", code=RegistrarErrorCode.OPERATION_PENDING), retriability=Retriability.RETRIABLE)
        with patch("apps.domains.gateways.gandi.GandiGateway._check_circuit_breaker", return_value=refusal), patch(TRANSFER) as transfer, patch(ALERT):
            DomainOrderService.process_domain_order_items(order)
        transfer.assert_not_called()
        line.refresh_from_db()
        self.assertEqual((line.provisioning_status, line.domain_order_item.epp_code), ("failed", encrypted))
        self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_a_cancelled_order_and_a_changed_registrar_assignment_cannot_dispatch(self) -> None:
        for state in ("cancelled", "unassigned"):
            with self.subTest(state=state):
                order, line = self._transfer_order(f"refused-{state}.ro")
                self._code(line)
                if state == "cancelled":
                    Order.objects.filter(pk=order.pk).update(status="cancelled")
                else:
                    TLDRegistrarAssignment.objects.filter(registrar=self.ro_registrar).update(is_active=False)
                with patch(TRANSFER) as transfer, patch(ALERT):
                    DomainOrderService.process_domain_order_items(order)
                transfer.assert_not_called()
                line.refresh_from_db()
                self.assertEqual(line.provisioning_status, "pending" if state == "cancelled" else "failed")
                self.assertTrue(line.domain_order_item.epp_code)
                self.assertFalse(Domain.objects.filter(name=line.domain_name).exists())

    def test_rejection_fails_the_line_but_an_unknown_answer_keeps_its_domain_and_never_resends(self) -> None:
        for outcome in (Retriability.NOT_RETRIABLE, Retriability.UNKNOWN):
            with self.subTest(outcome=outcome):
                order, line = self._transfer_order(f"outcome-{outcome.value.replace('_', '-')}.ro")
                self._code(line)
                result = Err(RegistrarAPIError("Transfer refused", code=RegistrarErrorCode.INVALID_REGISTRANT_DATA), retriability=outcome)
                with patch(TRANSFER, return_value=result) as transfer, patch(ALERT):
                    DomainOrderService.process_domain_order_items(order)
                    DomainOrderService.process_domain_order_items(order)
                transfer.assert_called_once()
                line.refresh_from_db()
                self.assertEqual(line.domain_order_item.epp_code, "")
                self.assertEqual(line.provisioning_status, "failed" if outcome == Retriability.NOT_RETRIABLE else "in_progress")
                self.assertEqual(Domain.objects.filter(name=line.domain_name).exists(), outcome == Retriability.UNKNOWN)

    def test_cancelling_a_pending_transfer_clears_its_code_but_preserves_an_in_flight_line(self) -> None:
        for in_flight in (False, True):
            with self.subTest(in_flight=in_flight):
                order, line = self._transfer_order(f"cancel-{in_flight}.ro")
                self._code(line)
                if in_flight:
                    with patch(TRANSFER, return_value=Ok(DomainTransferResult(transfer_id="accepted", status="pending"))):
                        DomainOrderService.process_domain_order_items(order)
                result = OrderService.update_order_status(order, StatusChangeData(new_status="cancelled"))
                self.assertTrue(result.is_ok(), result)
                line.refresh_from_db()
                self.assertEqual(line.provisioning_status, "in_progress" if in_flight else "cancelled")
                self.assertEqual(line.domain_order_item.epp_code, "")

    def test_the_sweep_requeues_only_pending_transfers_holding_a_code(self) -> None:
        order, line = self._transfer_order()
        Order.objects.filter(pk=order.pk).update(updated_at=timezone.now() - timedelta(hours=2))
        with patch("django_q.tasks.async_task") as enqueue:
            sweep_domain_order_lines()
        enqueue.assert_not_called()
        self._code(line)
        with patch("django_q.tasks.async_task") as enqueue:
            sweep_domain_order_lines()
        enqueue.assert_called_once_with("apps.domains.tasks.process_order_domain_items", str(order.pk))
