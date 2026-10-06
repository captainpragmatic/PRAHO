"""Regression proofs for invoice signal failures using real failed database operations."""

from collections.abc import Callable
from contextlib import nullcontext
from datetime import timedelta
from typing import Any
from unittest.mock import MagicMock, patch
from uuid import uuid4

from django.db import DatabaseError, IntegrityError, connection, transaction
from django.test import SimpleTestCase, TestCase, TransactionTestCase, override_settings
from django.utils import timezone

from apps.billing import signals
from apps.billing.invoice_models import ISSUER_BUILTIN
from apps.billing.issuers.models import ProviderIssuance
from apps.billing.models import Currency, Invoice
from apps.common.types import Ok, Result
from apps.customers.models import Customer
from tests.billing import _fiscal_correction_helpers as h
from tests.factories.billing_factories import CurrencyFactory, CustomerFactory


def _quiet_delivery(test: SimpleTestCase) -> MagicMock:
    from apps.settings.models import SystemSetting  # noqa: PLC0415

    SystemSetting.objects.update_or_create(
        key="efactura.enabled",
        defaults={"name": "e-Factura", "data_type": "boolean", "value": True, "default_value": False},
    )
    for target in ("django_q.tasks.async_task", "apps.notifications.services.EmailService.send_template_email"):
        delivery = patch(target, return_value="test-job")
        delivery.start()
        test.addCleanup(delivery.stop)
    queued = patch("apps.billing.efactura.tasks.queue_efactura_submission", return_value="efactura-job")
    result = queued.start()
    test.addCleanup(queued.stop)
    return result


def _draft(customer: Customer, currency: Currency) -> Invoice:
    return Invoice.objects.create(
        customer=customer,
        currency=currency,
        number=f"SIG-{uuid4().hex}",
        status="draft",
        subtotal_cents=10000,
        total_cents=10000,
        bill_to_name="Isolation SRL",
        bill_to_country="RO",
        issuer_provider=ISSUER_BUILTIN,
        due_at=timezone.now() + timedelta(days=14),
    )


def _fail_write(*args: object, **kwargs: object) -> None:
    # A real save_base failure sets needs_rollback on SQLite as well as PostgreSQL.
    Currency.objects.create(code="RON", symbol="duplicate")


def _fail_sql(*args: object, **kwargs: object) -> None:
    with connection.cursor() as cursor:
        cursor.execute("SELECT 1 / 0")


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class InvoiceCreationPersistenceTests(TransactionTestCase):
    def setUp(self) -> None:
        self.queued = _quiet_delivery(self)
        self.customer = CustomerFactory()
        self.currency = CurrencyFactory()

    def _assert_creation_survives(self, *, caller_atomic: bool) -> None:
        with patch.object(signals, "_update_customer_billing_stats", side_effect=_fail_write) as failed:
            with transaction.atomic() if caller_atomic else nullcontext():
                invoice = _draft(self.customer, self.currency)
            failed.assert_called_once()
        self.assertTrue(Invoice.objects.filter(pk=invoice.pk).exists())
        invoice.refresh_from_db()
        self.assertEqual(invoice.status, "draft")

    def test_create_without_caller_atomic_survives_failed_stats_write(self) -> None:
        self._assert_creation_survives(caller_atomic=False)

    def test_create_inside_caller_atomic_survives_failed_stats_write(self) -> None:
        self._assert_creation_survives(caller_atomic=True)


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class InvoiceMutableSavePersistenceTests(TransactionTestCase):
    def test_paid_at_write_failure_without_caller_atomic_rolls_back_status(self) -> None:
        _quiet_delivery(self)
        customer = CustomerFactory()
        currency = CurrencyFactory()
        invoice = _draft(customer, currency)
        invoice.issue()
        invoice.save()
        invoice.mark_as_paid()
        invoice.paid_at = None
        failed = MagicMock(side_effect=_fail_write)

        def fail_paid_at(
            execute: Callable[..., object], sql: str, params: object, many: bool, context: dict[str, object]
        ) -> object:
            if sql.startswith(f'UPDATE "{Invoice._meta.db_table}"') and '"paid_at"' in sql:
                failed()
            return execute(sql, params, many, context)

        self.assertTrue(connection.get_autocommit())
        self.assertFalse(connection.in_atomic_block)
        with connection.execute_wrapper(fail_paid_at), self.assertRaises(IntegrityError):
            invoice.save(update_fields=["status"])
        failed.assert_called_once()
        self.assertTrue(connection.get_autocommit())
        self.assertFalse(connection.needs_rollback)
        persisted = Invoice.objects.get(pk=invoice.pk)
        self.assertEqual(persisted.status, "issued")
        self.assertIsNone(persisted.paid_at)


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class InvoiceSignalIsolationTests(TestCase):
    def setUp(self) -> None:
        self.queued = _quiet_delivery(self)
        self.customer = CustomerFactory()
        self.currency = CurrencyFactory()

    def test_service_activation_savepoint_entry_error_propagates(self) -> None:
        failure = DatabaseError("savepoint entry failed")
        with (
            patch.object(connection, "savepoint", side_effect=failure),
            self.assertRaises(DatabaseError) as raised,
        ):
            signals._activate_pending_services(Invoice())
        self.assertIs(raised.exception, failure)

    def test_required_receivable_read_error_propagates_from_save_unchanged(self) -> None:
        invoice = _draft(self.customer, self.currency)
        invoice.issue()
        invoice.save()
        invoice.mark_as_paid()
        failure = DatabaseError("receivable lookup failed")
        with (
            patch.object(signals, "_is_receivable", side_effect=failure) as failed,
            self.assertRaises(DatabaseError) as raised,
            transaction.atomic(),
        ):
            invoice.save(update_fields=["status"])
        self.assertIs(raised.exception, failure)
        failed.assert_called_once_with(invoice)
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")

    def test_required_paid_at_write_failure_propagates_from_save_and_rolls_back_status(self) -> None:
        invoice = _draft(self.customer, self.currency)
        invoice.issue()
        invoice.save()
        invoice.mark_as_paid()
        # Exercise the handler's fallback for a paid document lacking its timestamp.
        invoice.paid_at = None
        failed = MagicMock(side_effect=_fail_write)

        def fail_paid_at(
            execute: Callable[..., Any], sql: str, params: Any, many: bool, context: dict[str, Any]
        ) -> Any:
            if sql.startswith(f'UPDATE "{Invoice._meta.db_table}"') and '"paid_at"' in sql:
                failed()
            return execute(sql, params, many, context)

        with (
            connection.execute_wrapper(fail_paid_at),
            self.assertRaises(IntegrityError),
            transaction.atomic(),
        ):
            invoice.save(update_fields=["status"])
        failed.assert_called_once()
        self.assertFalse(connection.needs_rollback)
        persisted = Invoice.objects.get(pk=invoice.pk)
        self.assertEqual(persisted.status, "issued")
        self.assertIsNone(persisted.paid_at)

    def test_lifecycle_audit_failed_orm_write_preserves_invoice_save(self) -> None:
        with transaction.atomic():
            invoice = _draft(self.customer, self.currency)
            with patch.object(signals.AuditService, "log_event", side_effect=_fail_write) as failed:
                signals._log_billing_model_event(
                    event_type="invoice_isolation_probe",
                    instance=invoice,
                    description=f"Invoice {invoice.pk} audit probe",
                )
                failed.assert_called_once()
            self.assertFalse(connection.needs_rollback)
            invoice.meta = {"audit_probe": "saved"}
            invoice.save(update_fields=["meta"])
        persisted = Invoice.objects.get(pk=invoice.pk)
        self.assertEqual(persisted.status, "draft")
        self.assertEqual(persisted.meta, {"audit_probe": "saved"})

    def test_compliance_failure_preserves_issued_invoice_and_efactura_callback(self) -> None:
        invoice = _draft(self.customer, self.currency)
        issued_compliance = MagicMock(side_effect=_fail_write)

        def fail_issued_compliance(request: signals.ComplianceEventRequest) -> None:
            # Number allocation uses the same compliance_type; only fail the issued handler.
            if request.description.startswith("Invoice issued:"):
                issued_compliance(request)

        with (
            patch.object(signals.AuditService, "log_compliance_event", side_effect=fail_issued_compliance),
            patch.object(signals, "_send_invoice_issued_email") as issued_email,
        ):
            with self.captureOnCommitCallbacks(execute=True) as callbacks:
                with transaction.atomic():
                    invoice.issue()
                    invoice.save()
                self.queued.assert_not_called()
            issued_compliance.assert_called_once()
        self.assertTrue(callbacks)
        self.queued.assert_called_once_with(str(invoice.pk))
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")
        issued_email.assert_called_once_with(invoice)

    def test_specialized_audit_failure_does_not_skip_issuance_effects(self) -> None:
        invoice = _draft(self.customer, self.currency)
        with (
            patch.object(signals.BillingAuditService, "log_invoice_event", side_effect=_fail_write) as failed,
            patch.object(signals, "_send_invoice_issued_email") as issued_email,
            patch.object(signals, "_schedule_payment_reminders") as reminders,
            self.captureOnCommitCallbacks(execute=True),
        ):
            invoice.issue()
            invoice.save()
            failed.assert_called_once()
        issued_email.assert_called_once_with(invoice)
        reminders.assert_called_once_with(invoice)
        self.queued.assert_called_once_with(str(invoice.pk))
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")

    def test_original_lookup_propagates_database_error_and_clears_stale_values(self) -> None:
        invoice = _draft(self.customer, self.currency)
        invoice._original_invoice_values = {"status": "paid"}
        failure = DatabaseError("original lookup failed")
        with patch.object(Invoice.objects, "get", side_effect=failure), self.assertRaises(DatabaseError) as raised:
            invoice.save(update_fields=["meta"])
        self.assertIs(raised.exception, failure)
        self.assertEqual(invoice._original_invoice_values, {})
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "draft")

    def test_created_email_write_failure_preserves_invoice_and_independent_stats(self) -> None:
        with (
            patch("apps.notifications.services.EmailService.send_template_email", side_effect=_fail_write) as failed,
            patch.object(signals, "_update_customer_billing_stats") as stats,
        ):
            invoice = _draft(self.customer, self.currency)
            failed.assert_called_once()
            stats.assert_called_once_with(self.customer)
        self.assertTrue(Invoice.objects.filter(pk=invoice.pk).exists())

    def test_reminder_enqueue_failure_preserves_issuance_and_efactura(self) -> None:
        invoice = _draft(self.customer, self.currency)
        with (
            patch("django_q.tasks.async_task", side_effect=_fail_write) as failed,
            self.captureOnCommitCallbacks(execute=True),
        ):
            invoice.issue()
            invoice.save()
            failed.assert_called_once()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")
        self.queued.assert_called_once_with(str(invoice.pk))

    def test_analytics_false_result_rolls_back_bundle_and_still_invalidates_cache(self) -> None:
        invoice = _draft(self.customer, self.currency)

        def failed_metrics(*args: object, **kwargs: object) -> dict[str, object]:
            Currency.objects.create(code="XOP", symbol="optional")
            return {"success": False, "error": "metrics unavailable"}

        with (
            patch("apps.billing.services.BillingAnalyticsService.update_invoice_metrics", side_effect=failed_metrics),
            patch("apps.billing.services.BillingAnalyticsService.update_customer_metrics") as customer_metrics,
            patch.object(signals, "_invalidate_billing_dashboard_cache") as invalidate,
        ):
            signals._update_billing_analytics(invoice, created=False)
        self.assertFalse(Currency.objects.filter(code="XOP").exists())
        customer_metrics.assert_not_called()
        invalidate.assert_called_once_with(self.customer.pk)

    def test_refund_analytics_false_result_rolls_back_both_writes(self) -> None:
        invoice = _draft(self.customer, self.currency)

        def refund_metrics(*args: object, **kwargs: object) -> dict[str, object]:
            Currency.objects.create(code="XOP", symbol="optional")
            return {"success": True}

        def failed_ltv(*args: object, **kwargs: object) -> dict[str, object]:
            Currency.objects.create(code="XLT", symbol="optional")
            return {"success": False, "error": "LTV unavailable"}

        with (
            patch("apps.billing.services.BillingAnalyticsService.record_invoice_refund", side_effect=refund_metrics),
            patch("apps.billing.services.BillingAnalyticsService.adjust_customer_ltv", side_effect=failed_ltv),
        ):
            signals._update_billing_refund_metrics(invoice)
        self.assertFalse(Currency.objects.filter(code__in=["XOP", "XLT"]).exists())

    def test_provider_audit_failure_preserves_attempt_record(self) -> None:
        invoice = _draft(self.customer, self.currency)
        with patch.object(signals.AuditService, "log_simple_event", side_effect=_fail_write) as failed:
            with transaction.atomic():
                issuance = ProviderIssuance.objects.create(invoice=invoice, provider="smartbill")
            failed.assert_called_once()
        self.assertTrue(ProviderIssuance.objects.filter(pk=issuance.pk).exists())

    def test_provider_snapshot_failure_preserves_attempt_update(self) -> None:
        invoice = _draft(self.customer, self.currency)
        issuance = ProviderIssuance.objects.create(invoice=invoice, provider="smartbill")
        with patch.object(ProviderIssuance.objects, "get", side_effect=_fail_write) as failed:
            with transaction.atomic():
                issuance.attempts = 1
                issuance.save(update_fields=["attempts"])
            failed.assert_called_once()
        self.assertEqual(ProviderIssuance.objects.get(pk=issuance.pk).attempts, 1)

    def test_order_failure_does_not_skip_the_next_order(self) -> None:
        invoice = _draft(self.customer, self.currency)
        h.order_for(invoice, status="awaiting_payment")
        h.order_for(invoice, status="awaiting_payment")
        calls = 0

        def confirm(*args: object, **kwargs: object) -> Result[bool, str]:
            nonlocal calls
            calls += 1
            if calls == 1:
                Currency.objects.create(code="XOF", symbol="first")
                _fail_write()
            Currency.objects.create(code="XOR", symbol="second")
            return Ok(True)

        with patch(
            "apps.orders.services.OrderPaymentConfirmationService.confirm_order", side_effect=confirm
        ) as confirm_order:
            with transaction.atomic():
                signals._sync_orders_on_invoice_status_change(invoice, "issued", "paid")
                self.assertFalse(connection.needs_rollback)
                # This write is outside every per-order savepoint.
                Currency.objects.create(code="XOK", symbol="outer")
            self.assertEqual(confirm_order.call_count, 2)
        self.assertFalse(Currency.objects.filter(code="XOF").exists())
        self.assertTrue(Currency.objects.filter(code="XOR").exists())
        self.assertTrue(Currency.objects.filter(code="XOK").exists())

    def _assert_refund_callbacks_survive(self, failing_target: str) -> None:
        invoice = _draft(self.customer, self.currency)
        seen: list[str] = []
        with (
            patch(failing_target, side_effect=_fail_write) as failed,
            patch.object(signals, "_send_invoice_refund_confirmation", side_effect=lambda inv: seen.append("email")),
            patch.object(signals, "_handle_efactura_refund_reporting", side_effect=lambda inv: seen.append("report")),
            patch(
                "apps.billing.custom_signals.invoice_refunded.send", side_effect=lambda **kwargs: seen.append("signal")
            ),
            self.captureOnCommitCallbacks(execute=True),
        ):
            with transaction.atomic():
                signals._handle_invoice_refund_completion(invoice)
            failed.assert_called_once()
        self.assertEqual(seen, ["email", "report", "signal"])
        self.assertTrue(Invoice.objects.filter(pk=invoice.pk).exists())

    def test_refund_history_failure_preserves_independent_callbacks_in_order(self) -> None:
        self._assert_refund_callbacks_survive("apps.customers.services.CustomerAnalyticsService.record_invoice_event")

    def test_refund_threshold_failure_preserves_independent_callbacks_in_order(self) -> None:
        self._assert_refund_callbacks_survive("apps.billing.config.get_large_refund_threshold_cents")

    def test_rolled_back_deletion_preserves_files_and_cache(self) -> None:
        invoice = _draft(self.customer, self.currency)
        invoice_id = invoice.pk
        with (
            patch.object(signals, "default_storage") as storage,
            patch.object(signals.cache, "delete_many") as delete_cache,
            self.captureOnCommitCallbacks(execute=True),
        ):
            with self.assertRaises(RuntimeError), transaction.atomic():
                invoice.delete()
                raise RuntimeError("caller rollback")
            storage.exists.assert_not_called()
            storage.delete.assert_not_called()
            delete_cache.assert_not_called()
        self.assertTrue(Invoice.objects.filter(pk=invoice_id).exists())


@override_settings(DISABLE_AUDIT_SIGNALS=False)
class InvoiceSignalPostgresTests(TransactionTestCase):
    def setUp(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("statement-aborts-transaction behavior requires PostgreSQL")
        self.queued = _quiet_delivery(self)
        self.customer = CustomerFactory()
        self.currency = CurrencyFactory()

    def test_required_paid_at_sql_error_surfaces_to_caller_and_rolls_back_status(self) -> None:
        invoice = _draft(self.customer, self.currency)
        invoice.issue()
        invoice.save()
        invoice.mark_as_paid()
        # Exercise the handler's fallback for a paid document lacking its timestamp.
        invoice.paid_at = None
        failed = MagicMock(side_effect=_fail_sql)

        def fail_paid_at(
            execute: Callable[..., Any], sql: str, params: Any, many: bool, context: dict[str, Any]
        ) -> Any:
            if sql.startswith(f'UPDATE "{Invoice._meta.db_table}"') and '"paid_at"' in sql:
                failed()
            return execute(sql, params, many, context)

        with (
            connection.execute_wrapper(fail_paid_at),
            self.assertRaises(DatabaseError) as raised,
            transaction.atomic(),
        ):
            invoice.save(update_fields=["status"])
        failed.assert_called_once()
        self.assertEqual(getattr(raised.exception.__cause__, "sqlstate", None), "22012")
        self.assertFalse(connection.needs_rollback)
        persisted = Invoice.objects.get(pk=invoice.pk)
        self.assertEqual(persisted.status, "issued")
        self.assertIsNone(persisted.paid_at)
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            self.assertEqual(cursor.fetchone(), (1,))

    def test_create_without_caller_atomic_commits_after_failed_sql(self) -> None:
        with patch.object(signals, "_update_customer_billing_stats", side_effect=_fail_sql) as failed:
            invoice = _draft(self.customer, self.currency)
            failed.assert_called_once()
        invoice.refresh_from_db()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "draft")

    def test_create_inside_caller_atomic_keeps_transaction_usable_and_commits(self) -> None:
        with patch.object(signals, "_update_customer_billing_stats", side_effect=_fail_sql) as failed:
            with transaction.atomic():
                invoice = _draft(self.customer, self.currency)
                self.assertTrue(Invoice.objects.filter(pk=invoice.pk).exists())
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    self.assertEqual(cursor.fetchone(), (1,))
            failed.assert_called_once()
        invoice.refresh_from_db()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "draft")

    def test_issue_inside_caller_atomic_persists_status_and_efactura_after_failed_sql(self) -> None:
        invoice = _draft(self.customer, self.currency)
        issued_compliance = MagicMock(side_effect=_fail_sql)

        def fail_issued_compliance(request: signals.ComplianceEventRequest) -> None:
            # Keep the critical number-allocation event outside the injected failure.
            if request.description.startswith("Invoice issued:"):
                issued_compliance(request)

        with patch.object(signals.AuditService, "log_compliance_event", side_effect=fail_issued_compliance):
            with transaction.atomic():
                invoice.issue()
                invoice.save()
                with connection.cursor() as cursor:
                    cursor.execute("SELECT 1")
                    self.assertEqual(cursor.fetchone(), (1,))
                self.queued.assert_not_called()
            issued_compliance.assert_called_once()
        self.assertEqual(Invoice.objects.get(pk=invoice.pk).status, "issued")
        self.queued.assert_called_once_with(str(invoice.pk))
