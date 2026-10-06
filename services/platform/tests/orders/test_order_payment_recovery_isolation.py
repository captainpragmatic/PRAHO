"""Order recovery, deadline visibility, and optional-effect isolation."""

from __future__ import annotations

from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from decimal import Decimal
from threading import Event
from typing import cast
from unittest.mock import patch

from django.contrib.auth.models import AnonymousUser
from django.core.cache import cache
from django.db import DatabaseError, close_old_connections, connection, transaction
from django.template.loader import render_to_string
from django.test import RequestFactory, TestCase, TransactionTestCase, override_settings
from django.utils import timezone
from django.utils.translation import override

from apps.audit.services import BusinessEventData
from apps.billing.models import Currency, Invoice, Payment
from apps.billing.payment_convergence import PaymentSuccessService
from apps.billing.proforma_models import ProformaInvoice
from apps.billing.proforma_service import ProformaService, send_proforma_email
from apps.billing.services import ProformaConversionService
from apps.common.types import Err, Result
from apps.common.utils import format_romanian_date
from apps.customers.models import Customer
from apps.notifications.services import EmailResult
from apps.orders import signals
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderPaymentConfirmationService, OrderService, StatusChangeData
from apps.orders.tasks import OrderProcessingResults, _order_timeout_deadline, process_pending_orders
from apps.products.models import Product
from apps.provisioning.models import Service, ServicePlan
from apps.settings.services import SettingsService
from tests.helpers.fsm_helpers import force_status


def prepare_case(case: TestCase | TransactionTestCase) -> tuple[Customer, Currency]:
    delivery = patch("django_q.tasks.async_task", return_value="test-job")
    delivery.start()
    case.addCleanup(delivery.stop)
    cache.clear()
    case.addCleanup(cache.clear)
    customer = Customer.objects.create(name="Order isolation", primary_email="order-isolation@example.com")
    currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    return customer, currency


def make_order(customer: Customer, currency: Currency, *, method: str = "card") -> Order:
    order = Order.objects.create(
        customer=customer,
        currency=currency,
        customer_email=customer.primary_email,
        customer_name=customer.name,
        payment_method=method,
        total_cents=12100,
    )
    force_status(order, "awaiting_payment")
    return order


def make_timeout_payment_case(customer: Customer, currency: Currency) -> tuple[Order, Invoice, Payment]:
    order = make_order(customer, currency)
    proforma = ProformaInvoice.objects.create(
        customer=customer,
        currency=currency,
        number="PRO-TIMEOUT-RACE",
        total_cents=12100,
        valid_until=timezone.now() + timedelta(days=1),
    )
    invoice = Invoice.objects.create(customer=customer, currency=currency, number="TIMEOUT-RACE", total_cents=12100)
    force_status(invoice, "issued")
    order.proforma = proforma
    order.invoice = invoice
    order.save(update_fields=["proforma", "invoice"])
    Order.objects.filter(pk=order.pk).update(created_at=timezone.now() - timedelta(hours=25))
    order.refresh_from_db()
    payment = Payment.objects.create(
        customer=customer,
        currency=currency,
        invoice=invoice,
        amount_cents=12100,
        payment_method="stripe",
        gateway_txn_id="pi_timeout_race",
    )
    return order, invoice, payment


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class OrderRecoveryIsolationTests(TestCase):
    def setUp(self) -> None:
        self.customer, self.currency = prepare_case(self)

    def test_paid_orders_past_deadline_are_confirmed_with_siblings(self) -> None:
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, total_cents=12100)
        force_status(invoice, "paid")
        paid_orders = [make_order(self.customer, self.currency) for _ in range(2)]
        unpaid = make_order(self.customer, self.currency)
        for order in [*paid_orders, unpaid]:
            Order.objects.filter(pk=order.pk).update(created_at=timezone.now() - timedelta(hours=25))
        for order in paid_orders:
            order.invoice = invoice
            order.save(update_fields=["invoice"])

        result = process_pending_orders()

        for order in paid_orders:
            order.refresh_from_db()
            self.assertEqual(order.status, "provisioning")
            self.assertEqual(
                list(order.status_history.order_by("created_at").values_list("old_status", "new_status")),
                [("awaiting_payment", "paid"), ("paid", "provisioning")],
            )
        unpaid.refresh_from_db()
        self.assertEqual(unpaid.status, "cancelled")
        self.assertEqual(result["results"]["confirmed_orders"], 2)
        self.assertEqual(result["results"]["timed_out_orders"], 1)

    def test_paid_confirmation_failure_does_not_expire_the_order(self) -> None:
        order = make_order(self.customer, self.currency)
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, total_cents=12100)
        force_status(invoice, "paid")
        order.invoice = invoice
        order.save(update_fields=["invoice"])
        Order.objects.filter(pk=order.pk).update(created_at=timezone.now() - timedelta(hours=25))
        with patch(
            "apps.orders.services.OrderServiceCreationService.update_service_status_on_payment",
            return_value=Err("enrollment unavailable"),
        ):
            result = process_pending_orders()
        order.refresh_from_db()
        self.assertEqual(order.status, "awaiting_payment")
        self.assertFalse(order.status_history.exists())
        self.assertEqual(order.meta["paid_order_confirmation"]["attempts"], 1)
        self.assertEqual(result["results"]["timed_out_orders"], 0)
        self.assertEqual(result["results"]["failed_orders"], 1)

    def test_failed_confirmation_rolls_back_one_order_and_confirms_sibling(self) -> None:
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, total_cents=12100)
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-ISOLATION",
            valid_until=timezone.now() + timedelta(days=1),
        )
        sibling = make_order(self.customer, self.currency)
        failing = make_order(self.customer, self.currency)
        for order in (sibling, failing):
            order.proforma = proforma
            order.save(update_fields=["proforma"])
        confirm = OrderPaymentConfirmationService.confirm_order

        def fail_first(order: Order, invoice: Invoice | None = None) -> Result[Order, str]:
            if order.pk == failing.pk:
                Currency.objects.create(code="XOF", symbol="partial confirmation")
                raise RuntimeError("confirmation failed")
            return confirm(order, invoice=invoice)

        with (
            patch.object(OrderPaymentConfirmationService, "confirm_order", side_effect=fail_first),
            self.captureOnCommitCallbacks(execute=True),
        ):
            transaction.on_commit(
                lambda: signals._handle_proforma_payment_received(
                    sender=ProformaService, proforma=proforma, invoice=invoice, payment=None
                )
            )

        sibling.refresh_from_db()
        failing.refresh_from_db()
        self.assertEqual(sibling.status, "provisioning")
        self.assertEqual(failing.status, "awaiting_payment")
        self.assertFalse(Currency.objects.filter(code="XOF").exists())
        self.assertEqual(sibling.status_history.count(), 2)
        self.assertFalse(failing.status_history.exists())

    def test_order_audit_failure_rolls_back_optional_writes_only(self) -> None:
        order = make_order(self.customer, self.currency)

        def fail_audit(_event: BusinessEventData) -> None:
            Currency.objects.create(code="XOA", symbol="partial audit")
            raise RuntimeError("audit failed")

        with patch.object(signals.OrdersAuditService, "log_order_event", side_effect=fail_audit):
            result = OrderService.update_order_status(order, StatusChangeData(new_status="cancelled"))

        self.assertFalse(Currency.objects.filter(code="XOA").exists())
        self.assertTrue(result.is_ok(), str(result))
        order.refresh_from_db()
        self.assertEqual(order.status, "cancelled")
        self.assertEqual(order.status_history.get().new_status, "cancelled")

    def test_failed_refund_suspension_rolls_back_partial_write_and_continues(self) -> None:
        invoice = Invoice.objects.create(customer=self.customer, currency=self.currency, total_cents=12100)
        order = make_order(self.customer, self.currency)
        order.invoice = invoice
        order.save(update_fields=["invoice"])
        plan = ServicePlan.objects.create(name="Refund plan", plan_type="vps", price_monthly=Decimal("100"))
        services = [
            Service.objects.create(
                customer=self.customer,
                currency=self.currency,
                service_plan=plan,
                service_name=name,
                username=name,
                price=Decimal("100"),
            )
            for name in ("refund-failing", "refund-sibling")
        ]
        product = Product.objects.create(name="Refund product", slug="refund-product", product_type="vps")
        for service in services:
            force_status(service, "active")
            OrderItem.objects.create(
                order=order, product=product, service=service, product_name=service.service_name, unit_price_cents=10000
            )
        suspend = Service.suspend

        def fail_suspension(service: Service, reason: str = "") -> None:
            if service.pk == services[0].pk:
                Currency.objects.create(code="XRS", symbol="partial suspension")
                raise RuntimeError("suspension failed")
            suspend(service, reason=reason)

        with patch.object(Service, "suspend", new=fail_suspension):
            signals._handle_invoice_refunded(sender=Invoice, invoice=invoice, refund_type="full")

        self.assertFalse(Currency.objects.filter(code="XRS").exists())
        for service, status in zip(services, ("active", "suspended"), strict=True):
            service.refresh_from_db()
            self.assertEqual(service.status, status)
            self.assertFalse(service.auto_renew)


class OrderTimeoutPaymentRaceTests(TestCase):
    def setUp(self) -> None:
        self.customer, self.currency = prepare_case(self)
        self.order, self.invoice, self.payment = make_timeout_payment_case(self.customer, self.currency)

    def _pay_invoice(self) -> None:
        result = PaymentSuccessService.converge_local_paid_document(self.payment.pk)
        self.assertTrue(result.is_ok(), str(result))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")

    def _sweep_after(self, payment_effect: Callable[[], None]) -> OrderProcessingResults:
        deadline = _order_timeout_deadline

        def pay_after_read(candidate: Order) -> tuple[datetime, str]:
            self.assertEqual(candidate.status, "awaiting_payment")
            if candidate.invoice is not None:
                self.assertEqual(candidate.invoice.status, "issued")
            else:
                assert candidate.proforma is not None
                self.assertEqual(candidate.proforma.status, "draft")
            payment_effect()
            return deadline(candidate)

        with patch("apps.orders.tasks._order_timeout_deadline", side_effect=pay_after_read):
            outcome = process_pending_orders()
        self.assertTrue(outcome["success"], str(outcome))
        return cast(OrderProcessingResults, outcome["results"])

    def _assert_not_cancelled(self, expected_status: str, results: OrderProcessingResults) -> None:
        self.order.refresh_from_db()
        self.assertEqual(self.order.status, expected_status)
        self.assertFalse(self.order.status_history.filter(new_status="cancelled").exists())
        self.assertEqual(results["timed_out_orders"], 0)

    def test_payment_confirmation_after_sweep_read_preserves_provisioning(self) -> None:
        def confirm_payment() -> None:
            self._pay_invoice()
            result = OrderPaymentConfirmationService.confirm_order(self.order, invoice=self.invoice)
            self.assertTrue(result.is_ok(), str(result))
            self.assertEqual(result.unwrap().status, "provisioning")

        results = self._sweep_after(confirm_payment)

        self._assert_not_cancelled("provisioning", results)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertEqual(
            list(self.order.status_history.order_by("created_at").values_list("old_status", "new_status")),
            [("awaiting_payment", "paid"), ("paid", "provisioning")],
        )

    def test_paid_invoice_after_sweep_read_preserves_awaiting_payment(self) -> None:
        # Proforma-linked orders are confirmed separately after settlement.
        results = self._sweep_after(self._pay_invoice)

        self._assert_not_cancelled("awaiting_payment", results)
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")

    def test_converted_proforma_after_sweep_read_is_not_cancelled(self) -> None:
        def convert_proforma() -> None:
            result = ProformaConversionService.convert_to_invoice(str(self.order.proforma_id))
            self.assertTrue(result.is_ok(), str(result))

        results = self._sweep_after(convert_proforma)

        self._assert_not_cancelled("awaiting_payment", results)
        assert self.order.proforma is not None
        self.assertEqual(self.order.proforma.status, "converted")

    def test_succeeded_proforma_payment_after_sweep_read_is_not_cancelled(self) -> None:
        self.order.invoice = None
        self.order.save(update_fields=["invoice"])
        self.payment.invoice = None
        self.payment.proforma = self.order.proforma
        self.payment.save(update_fields=["invoice", "proforma"])

        def confirm_gateway_payment() -> None:
            assert self.payment.gateway_txn_id is not None
            result = PaymentSuccessService.converge_gateway_success(
                self.payment.gateway_txn_id, {"amount_received": 12100, "currency": "ron"}
            )
            self.assertTrue(result.is_ok(), str(result))

        results = self._sweep_after(confirm_gateway_payment)

        self._assert_not_cancelled("awaiting_payment", results)
        self.payment.refresh_from_db()
        self.assertEqual(self.payment.status, "succeeded")
        assert self.order.proforma is not None
        self.assertEqual(self.order.proforma.status, "converted")
        assert self.order.invoice is not None
        self.assertEqual(self.order.invoice.status, "paid")


class BankTransferDeadlineTests(TestCase):
    def setUp(self) -> None:
        self.customer, self.currency = prepare_case(self)

    def set_value(self, key: str, value: int) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), str(result))

    def create_proforma(self, method: str, now: datetime) -> tuple[Order, ProformaInvoice]:
        order = make_order(self.customer, self.currency, method=method)
        Order.objects.filter(pk=order.pk).update(created_at=now - timedelta(hours=1))
        order.refresh_from_db()
        with patch("apps.billing.proforma_service.timezone.now", return_value=now):
            result = ProformaService.create_from_order(order)
        self.assertTrue(result.is_ok(), str(result))
        return order, cast(ProformaInvoice, result.unwrap())

    def test_bank_transfer_uses_earlier_limit_without_capping_other_methods(self) -> None:
        now = timezone.now()
        self.set_value("orders.bank_transfer_timeout_hours", 72)
        for days, method, hours in (
            (30, "bank_transfer", 71),
            (1, "bank_transfer", 24),
            (30, "card", 720),
            (30, "manual", 720),
            (30, "sepa_debit", 720),
            (30, "", 720),
        ):
            with self.subTest(days=days, method=method):
                self.set_value("billing.proforma_validity_days", days)
                order, proforma = self.create_proforma(method, now)
                self.assertEqual(proforma.valid_until, now + timedelta(hours=hours))
                if method == "bank_transfer":
                    self.assertEqual(_order_timeout_deadline(order), (proforma.valid_until, "proforma_valid_until"))
                elif method == "card":
                    self.assertEqual(
                        _order_timeout_deadline(order), (order.created_at + timedelta(hours=24), "card_timeout")
                    )

    def test_displayed_and_emailed_validity_equals_effective_bank_deadline(self) -> None:
        now = timezone.now()
        self.set_value("orders.bank_transfer_timeout_hours", 72)
        self.set_value("billing.proforma_validity_days", 30)
        order, proforma = self.create_proforma("bank_transfer", now)
        deadline = order.created_at + timedelta(hours=72)
        expected_date = format_romanian_date(deadline)
        request = RequestFactory().get("/billing/proformas/")
        request.user = AnonymousUser()
        with override("en"):
            html = render_to_string(
                "billing/proforma_detail.html",
                {"proforma": proforma, "lines": proforma.lines.all()},
                request=request,
            )
            with (
                patch("reportlab.rl_config.pageCompression", 0),
                patch(
                    "apps.notifications.services.EmailService.send_email", return_value=EmailResult(success=True)
                ) as send,
            ):
                self.assertTrue(send_proforma_email(proforma))
        attachments = cast(list[tuple[str, bytes, str]], send.call_args.kwargs["attachments"])
        self.assertIn(expected_date, html)
        self.assertIn(f"Valid until: {expected_date}".encode(), attachments[0][1])
        self.assertEqual(proforma.valid_until, deadline)
        self.assertEqual(_order_timeout_deadline(order)[0], deadline)


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class OrderAuditPostgresIsolationTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("statement-aborts-transaction behavior requires PostgreSQL")
        self.customer, self.currency = prepare_case(self)

    def test_order_and_status_rows_commit_after_audit_statement_failure(self) -> None:
        failed_events: list[str] = []

        def fail_sql(event: BusinessEventData) -> None:
            failed_events.append(event.event_type)
            with connection.cursor() as cursor:
                cursor.execute("SELECT 1/0")

        order = Order(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            status="awaiting_payment",
            total_cents=12100,
        )
        result: Result[Order, str] | None = None
        try:
            with (
                patch.object(signals.OrdersAuditService, "log_order_event", side_effect=fail_sql),
                transaction.atomic(),
            ):
                order.save()
                result = OrderService.update_order_status(order, StatusChangeData(new_status="cancelled"))
        except DatabaseError:
            pass

        self.assertTrue(Order.objects.filter(pk=order.pk, status="cancelled").exists())
        self.assertIsNotNone(result)
        assert result is not None
        self.assertTrue(result.is_ok(), str(result))
        order.refresh_from_db()
        self.assertEqual(order.status, "cancelled")
        self.assertEqual(order.status_history.get().new_status, "cancelled")
        self.assertIn("order_created", failed_events)
        self.assertIn("order_updated", failed_events)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_confirmation_commits_between_sweep_read_and_timeout_cancellation(self) -> None:
        order, invoice, payment = make_timeout_payment_case(self.customer, self.currency)
        candidate_read = Event()
        resume_timeout = Event()
        deadline = _order_timeout_deadline

        def park_after_read(candidate: Order) -> tuple[datetime, str]:
            self.assertEqual(candidate.status, "awaiting_payment")
            assert candidate.invoice is not None
            self.assertEqual(candidate.invoice.status, "issued")
            candidate_read.set()
            if not resume_timeout.wait(timeout=10):
                raise AssertionError("Payment confirmation did not release the timeout sweep")
            return deadline(candidate)

        def sweep() -> OrderProcessingResults:
            close_old_connections()
            try:
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '3s'")
                    cursor.execute("SET statement_timeout = '5s'")
                outcome = process_pending_orders()
                self.assertTrue(outcome["success"], str(outcome))
                return cast(OrderProcessingResults, outcome["results"])
            finally:
                connection.close()

        with (
            patch("apps.orders.tasks._order_timeout_deadline", side_effect=park_after_read),
            ThreadPoolExecutor(max_workers=1) as executor,
        ):
            pending = executor.submit(sweep)
            try:
                self.assertTrue(candidate_read.wait(timeout=10), "Sweep did not read the unpaid candidate")
                with transaction.atomic():
                    settled = PaymentSuccessService.converge_local_paid_document(payment.pk)
                    self.assertTrue(settled.is_ok(), str(settled))
                    confirmed = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
                    self.assertTrue(confirmed.is_ok(), str(confirmed))
                    self.assertEqual(confirmed.unwrap().status, "provisioning")
                # The payment and confirmation have committed on the other connection.
            finally:
                resume_timeout.set()
            results = pending.result(timeout=10)

        order.refresh_from_db()
        invoice.refresh_from_db()
        payment.refresh_from_db()
        self.assertEqual(order.status, "provisioning")
        self.assertEqual(invoice.status, "paid")
        self.assertEqual(payment.status, "succeeded")
        self.assertFalse(order.status_history.filter(new_status="cancelled").exists())
        self.assertEqual(results["timed_out_orders"], 0)
