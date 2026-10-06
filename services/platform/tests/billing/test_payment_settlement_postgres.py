"""PostgreSQL settlement savepoints and concurrent staff/gateway convergence."""

from __future__ import annotations

import threading
from concurrent.futures import ThreadPoolExecutor
from unittest.mock import patch

from django.db import DatabaseError, close_old_connections, connection, transaction
from django.db.models import Sum
from django.test import TransactionTestCase, override_settings

from apps.audit.services import BusinessEventData
from apps.billing import signals
from apps.billing.models import Currency, Invoice, Payment
from apps.billing.payment_convergence import PaymentSuccessService
from apps.promotions import locking
from apps.users.models import User
from tests.billing.test_payment_settlement_isolation import offline_request, prepare_case


def fail_sql(_event: BusinessEventData) -> None:
    if connection.vendor == "postgresql":
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1/0")
    else:
        Currency.objects.create(code="RON", symbol="duplicate")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class PaymentSettlementPostgresTests(TransactionTestCase):
    def setUp(self) -> None:
        self.customer, self.currency, self.invoice, self.staff = prepare_case(self)

    def test_payment_audit_sql_failure_keeps_outer_rows_committed(self) -> None:
        status: int | None = None
        try:
            with (
                transaction.atomic(),
                patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_sql),
            ):
                response = offline_request(self.invoice, self.staff)
                self.customer.company_name = "Outer transaction committed"
                self.customer.save(update_fields=["company_name"])
                status = response.status_code
        except DatabaseError:
            pass
        self.assertEqual(status, 200, "an optional failed audit must not abort the staff payment")
        self.invoice.refresh_from_db()
        self.customer.refresh_from_db()
        self.assertEqual(self.invoice.status, "paid")
        self.assertEqual(self.customer.company_name, "Outer transaction committed")
        self.assertEqual(Payment.objects.get(invoice=self.invoice).status, "succeeded")

    @staticmethod
    def _gateway(gateway_id: str) -> bool:
        close_old_connections()
        try:
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '3s'")
                    cursor.execute("SET statement_timeout = '5s'")
            result = PaymentSuccessService.converge_gateway_success(
                gateway_id, {"amount_received": 5000, "currency": "ron"}
            )
            return result.is_ok()
        finally:
            connection.close()

    @staticmethod
    def _offline(invoice_id: int, staff_id: object, started: threading.Event) -> int:
        close_old_connections()
        try:
            if connection.vendor == "postgresql":
                with connection.cursor() as cursor:
                    cursor.execute("SET lock_timeout = '3s'")
                    cursor.execute("SET statement_timeout = '5s'")
            invoice = Invoice.objects.get(pk=invoice_id)
            staff = User.objects.get(pk=staff_id)
            started.set()
            return offline_request(invoice, staff, "50.00").status_code
        finally:
            connection.close()

    def test_gateway_and_staff_race_settles_once_despite_failed_audit(self) -> None:
        payment = Payment.objects.create(
            customer=self.customer,
            invoice=self.invoice,
            currency=self.currency,
            amount_cents=5000,
            payment_method="stripe",
            gateway_txn_id="pi_wp13_race",
        )
        document_locked = threading.Event()
        release_gateway = threading.Event()
        staff_started = threading.Event()
        first_lock = threading.Lock()
        parked = False
        original_lock = locking.lock_document_context

        def park_first(document: Invoice, *, gift_code: str = "") -> None:
            nonlocal parked
            original_lock(document, gift_code=gift_code)
            with first_lock:
                first = not parked
                parked = True
            if first:
                document_locked.set()
                if not release_gateway.wait(timeout=10):
                    raise AssertionError("gateway convergence was not released")

        def fail_success_audit(event: BusinessEventData) -> None:
            if event.event_type == "payment_succeeded":
                fail_sql(event)

        if connection.vendor == "postgresql":
            with (
                patch.object(locking, "lock_document_context", side_effect=park_first),
                patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_success_audit),
                ThreadPoolExecutor(max_workers=2) as executor,
            ):
                gateway = executor.submit(self._gateway, "pi_wp13_race")
                try:
                    self.assertTrue(document_locked.wait(timeout=10), "gateway never reached document convergence")
                    offline = executor.submit(self._offline, self.invoice.pk, self.staff.pk, staff_started)
                    self.assertTrue(staff_started.wait(timeout=10), "staff payment never started")
                finally:
                    release_gateway.set()
                self.assertTrue(gateway.result(timeout=15), "gateway convergence failed or deadlocked")
                self.assertEqual(offline.result(timeout=15), 200)

        else:
            # SQLite cannot reproduce row-lock waits; exercise the same winning order.
            with patch.object(signals.BillingAuditService, "log_payment_event", side_effect=fail_success_audit):
                self.assertTrue(self._gateway("pi_wp13_race"))
                self.assertEqual(self._offline(self.invoice.pk, self.staff.pk, staff_started), 200)

        self.invoice.refresh_from_db()
        paid_at = self.invoice.paid_at
        self.assertEqual(self.invoice.status, "paid")
        self.assertIsNotNone(paid_at)
        payments = Payment.objects.filter(invoice=self.invoice, status="succeeded")
        self.assertEqual(payments.count(), 2)
        self.assertEqual(payments.aggregate(total=Sum("amount_cents"))["total"], self.invoice.total_cents)
        replay = PaymentSuccessService.converge_local_paid_document(payment.pk)
        self.assertTrue(replay.is_ok(), str(replay))
        self.invoice.refresh_from_db()
        self.assertEqual(self.invoice.paid_at, paid_at)
        self.assertEqual(Payment.objects.filter(invoice=self.invoice).count(), 2)
