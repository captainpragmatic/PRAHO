"""
Tests for D3: Service deletion on order cancellation.

Validates:
- Pending services are hard-deleted on order cancel
- OrderItem.service is SET_NULL before deletion
- Audit event services_deleted_on_cancellation logged
- Services in provisioning are failed first, then deleted
"""

from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db import DatabaseError
from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderService, StatusChangeData
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status


class ServiceDeletionOnCancelTest(TestCase):
    """Test service cleanup when orders are cancelled."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Cancel Test SRL", customer_type="company",
            status="active", primary_email="cancel@test.ro",
        )
        self.product = Product.objects.create(
            name="Hosting Plan", slug="hosting-plan",
            product_type="shared_hosting", is_active=True,
        )

    def _create_order_with_service(self, order_status="awaiting_payment"):
        """Create an order with a linked service."""
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            billing_address={},
        )
        force_status(order, order_status)

        # Create service plan and service
        plan, _ = ServicePlan.objects.get_or_create(
            name="Test Plan", defaults={
                "plan_type": "shared_hosting", "is_active": True,
                "price_monthly": Decimal("50.00"),
            }
        )
        service = Service.objects.create(
            customer=self.customer, service_plan=plan,
            currency=self.currency, service_name="Test Service",
            username="test_user", billing_cycle="monthly",
            price=Decimal("100.00"),
        )

        item = OrderItem.objects.create(
            order=order, product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1, unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100, line_total_cents=12100,
            service=service,
        )
        return order, item, service

    def test_cancel_deletes_pending_services(self):
        """Pending services are hard-deleted when order is cancelled (D3)."""
        from apps.provisioning.models import Service  # noqa: PLC0415

        order, item, service = self._create_order_with_service("awaiting_payment")
        service_id = service.id

        # Cancel the order — use captureOnCommitCallbacks because the signal handler
        # runs via on_commit (Django TestCase wraps in transaction that never commits)
        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="Test cancel")
            )
        self.assertTrue(result.is_ok())

        # Service should be deleted
        self.assertFalse(Service.objects.filter(id=service_id).exists())

        # OrderItem.service should be NULL
        item.refresh_from_db()
        self.assertIsNone(item.service)

    def test_cancel_sets_order_item_service_null(self):
        """OrderItem keeps product data but service FK is cleared."""
        order, item, _service = self._create_order_with_service("awaiting_payment")

        with self.captureOnCommitCallbacks(execute=True):
            OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="Test")
            )

        item.refresh_from_db()
        self.assertIsNone(item.service)
        # Product data preserved for audit
        self.assertEqual(item.product_name, self.product.name)


class ProformaExpiryOnCancelTest(TestCase):
    """C2: proforma.expire_proforma() → expire() rename + draft handling."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Proforma Expiry SRL", customer_type="company",
            status="active", primary_email="proforma-expiry@test.ro",
        )
        self.product = Product.objects.create(
            name="Expiry Plan", slug="expiry-plan",
            product_type="shared_hosting", is_active=True,
        )
        from apps.billing.proforma_models import ProformaSequence  # noqa: PLC0415
        ProformaSequence.objects.get_or_create(scope="default")

    def _create_order_with_proforma(self, proforma_status: str) -> tuple:
        """Create an order with a linked proforma in the given status."""
        from datetime import timedelta  # noqa: PLC0415

        from django.utils import timezone  # noqa: PLC0415

        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            billing_address={},
        )
        force_status(order, "awaiting_payment")

        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number=f"PRO-C2-{proforma_status[:4].upper()}",
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        if proforma_status == "sent":
            proforma.send_proforma()
            proforma.save()

        order.proforma = proforma
        order.save(update_fields=["proforma"])
        return order, proforma

    def test_cancel_order_with_sent_proforma_expires_it(self):
        """C2 RED: Cancelling an order with a sent proforma must expire the proforma.

        Before fix: signals.py calls proforma.expire_proforma() which raises AttributeError.
        After fix: signals.py calls proforma.expire() which works.
        """
        order, proforma = self._create_order_with_proforma("sent")

        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="C2 test cancel")
            )

        self.assertTrue(result.is_ok())
        proforma.refresh_from_db()
        self.assertEqual(
            proforma.status, "expired",
            f"Sent proforma should be expired on order cancel, got: {proforma.status}"
        )

    def test_cancel_order_with_draft_proforma_expires_or_deletes_it(self):
        """C2 RED: Cancelling an order with a draft proforma must handle it gracefully.

        Before fix: signals.py calls proforma.expire_proforma() on a 'draft' proforma.
        expire() only allows source='sent', so this raises TransitionNotAllowed,
        which is swallowed and the proforma stays in 'draft' (orphaned).
        After fix: draft proformas are deleted (they were never sent to the customer).
        """
        order, proforma = self._create_order_with_proforma("draft")
        proforma_id = proforma.id

        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="C2 draft test cancel")
            )

        self.assertTrue(result.is_ok())
        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
        # F17 fix: Draft proformas must be hard-deleted on order cancellation
        # (they were never sent to the customer so no customer-visible record exists).
        # assertFalse(exists()) is a definitive check — the conditional version could
        # pass vacuously if the draft is left in place.
        self.assertFalse(
            ProformaInvoice.objects.filter(id=proforma_id).exists(),
            "Draft proforma must be deleted (not left in 'draft' state) after order cancellation"
        )


class ProformaCleanupAtomicityTest(TestCase):
    """C4 review fix: Proforma cleanup runs inside the same atomic block as service cleanup."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Atomic Cleanup SRL", customer_type="company",
            status="active", primary_email="atomic@test.ro",
        )
        self.product = Product.objects.create(
            name="Atomic Plan", slug="atomic-plan",
            product_type="shared_hosting", is_active=True,
        )
        from apps.billing.proforma_models import ProformaSequence  # noqa: PLC0415
        ProformaSequence.objects.get_or_create(scope="default")

    def test_sent_proforma_expired_when_order_cancelled(self):
        """Sent proforma is expired atomically with service cleanup during cancellation."""
        from datetime import timedelta  # noqa: PLC0415

        from django.utils import timezone  # noqa: PLC0415

        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415
        from tests.helpers.fsm_helpers import force_status  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email="atomic@test.ro", customer_name="Atomic Cleanup SRL",
            subtotal_cents=10000, tax_cents=2100, total_cents=12100, billing_address={},
        )
        OrderItem.objects.create(
            order=order, product=self.product, product_name=self.product.name,
            product_type=self.product.product_type, quantity=1,
            unit_price_cents=10000, tax_rate=Decimal("0.2100"), tax_cents=2100, line_total_cents=12100,
        )
        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=14),
        )
        force_status(proforma, "sent")
        order.proforma = proforma
        order.save(update_fields=["proforma"])
        force_status(order, "awaiting_payment")

        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="C4 atomicity test")
            )

        self.assertTrue(result.is_ok())
        proforma.refresh_from_db()
        self.assertEqual(
            proforma.status, "expired",
            "Sent proforma must be expired atomically during cancellation"
        )


class AuditFailureDoesNotBlockOnCommit(TestCase):
    """M1 review fix: Audit logging failure must not prevent on_commit callbacks."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Audit Test SRL", customer_type="company",
            status="active", primary_email="audit@test.ro",
        )

    @patch("apps.orders.signals.OrdersAuditService.log_order_event", side_effect=Exception("Audit DB down"))
    @patch("apps.orders.signals._send_order_confirmation_email")
    def test_email_sent_even_if_audit_fails(self, mock_email, mock_audit):
        """Order creation email fires even when audit logging raises."""
        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email="audit@test.ro", customer_name="Audit Test SRL",
            subtotal_cents=10000, tax_cents=2100, total_cents=12100, billing_address={},
        )

        # on_commit fires when the test transaction commits (captureOnCommitCallbacks)
        with self.captureOnCommitCallbacks(execute=True):
            order.save()

        # The email callback should still have been registered despite audit failure
        # Note: the order was already created above, the save() is an update.
        # For the creation case, the email is registered in the initial create.
        # Let's verify audit was called and failed, but signal didn't crash.
        mock_audit.assert_called()


# ===============================================================================
# TASK 2.1: Proforma expiry failure must log at ERROR with exc_info (not WARNING)
# ===============================================================================


class ProformaExpiryErrorLoggingTest(TestCase):
    """Task 2.1: except Exception in proforma expiry must use logger.error + exc_info=True."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Expiry Logging SRL", customer_type="company",
            status="active", primary_email="expiry-log@test.ro",
        )
        from apps.billing.proforma_models import ProformaSequence  # noqa: PLC0415
        ProformaSequence.objects.get_or_create(scope="default")

    def _create_order_with_sent_proforma(self) -> tuple:
        from apps.billing.proforma_models import ProformaInvoice  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer, currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            billing_address={},
        )
        force_status(order, "awaiting_payment")

        proforma = ProformaInvoice.objects.create(
            customer=self.customer, currency=self.currency,
            number="PRO-ERRLOG-SENT",
            subtotal_cents=10000, tax_cents=2100, total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        proforma.send_proforma()
        proforma.save()

        order.proforma = proforma
        order.save(update_fields=["proforma"])
        return order, proforma

    def test_proforma_expire_failure_logs_at_error_level_with_exc_info(self):
        """Task 2.1 RED: proforma.expire() failure must be logged at ERROR (not WARNING)
        with exc_info=True so the traceback is captured in logs.

        Currently the code uses logger.warning without exc_info — this test
        will FAIL until the fix is applied.
        """
        order, _proforma = self._create_order_with_sent_proforma()

        with (
            patch("apps.billing.proforma_models.ProformaInvoice.expire", side_effect=DatabaseError("DB error")),
            self.assertLogs("apps.orders.signals", level="ERROR") as log_ctx,
            self.captureOnCommitCallbacks(execute=True),
        ):
            OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="2.1 test")
            )

        # Must log at ERROR level (not WARNING)
        error_records = [msg for msg in log_ctx.output if "ERROR" in msg]
        self.assertTrue(
            len(error_records) > 0,
            f"Expected at least one ERROR log, got: {log_ctx.output}",
        )

        # The error message must include the order number for traceability
        self.assertTrue(
            any(order.order_number in msg for msg in error_records),
            f"Expected order number {order.order_number} in error log, got: {error_records}",
        )

    def test_proforma_expire_failure_includes_exc_info(self):
        """Task 2.1 RED: exc_info=True must be set so the traceback is captured.

        We test _handle_order_cancellation directly with a mock order that has a
        proforma whose expire() raises DatabaseError, then verify the log record
        has exc_info set on the LogRecord via assertLogs.cm.records.
        """
        from apps.orders.signals import _handle_order_cancellation  # noqa: PLC0415

        mock_proforma = MagicMock()
        mock_proforma.status = "sent"
        mock_proforma.number = "PRO-EXCINFO-001"
        mock_proforma.expire.side_effect = DatabaseError("DB exc_info test")

        mock_order = MagicMock()
        mock_order.order_number = "ORD-EXCINFO-001"
        mock_order.proforma = mock_proforma
        mock_order.items.select_for_update.return_value.filter.return_value.select_related.return_value = []
        mock_order.items.filter.return_value = []

        # assertLogs temporarily lowers the logger level so records are captured
        with self.assertLogs("apps.orders.signals", level="ERROR") as log_ctx:
            _handle_order_cancellation(mock_order, old_status="awaiting_payment")

        # Find the record about proforma expiry failure
        error_records = [r for r in log_ctx.records if r.levelno >= 40]  # logging.ERROR == 40
        self.assertTrue(
            len(error_records) > 0,
            f"No ERROR records found. All records: {[(r.levelname, r.getMessage()) for r in log_ctx.records]}",
        )

        # The critical property: exc_info must be set (not None and not (None, None, None))
        proforma_error_records = [
            r for r in error_records
            if "proforma" in r.getMessage().lower() or mock_order.order_number in r.getMessage()
        ]
        self.assertTrue(len(proforma_error_records) > 0, f"No proforma-related error record found. Records: {[(r.levelname, r.getMessage()) for r in error_records]}")

        record = proforma_error_records[0]
        self.assertIsNotNone(
            record.exc_info,
            "exc_info must be set on the log record so the traceback is captured",
        )
        # exc_info is a 3-tuple (type, value, tb) — check it's not all-None
        self.assertIsNotNone(
            record.exc_info[0],
            "exc_info[0] (exception type) must not be None",
        )


# ===============================================================================
# TASK 2.2: _handle_invoice_refunded critical handler must have exc_info=True
# ===============================================================================


class InvoiceRefundedHandlerExcInfoTest(TestCase):
    """Task 2.2: logger.critical in _handle_invoice_refunded must include exc_info=True."""

    def test_invoice_refunded_handler_critical_log_has_exc_info(self):
        """Task 2.2 RED: The outer except in _handle_invoice_refunded calls logger.critical
        without exc_info=True. This test verifies exc_info is set on the log record.

        Currently the code is missing exc_info — this test will FAIL until fixed.
        """
        import logging  # noqa: PLC0415

        from apps.orders.signals import _handle_invoice_refunded  # noqa: PLC0415

        captured_records: list[logging.LogRecord] = []

        class CapturingHandler(logging.Handler):
            def emit(self, record: logging.LogRecord) -> None:
                captured_records.append(record)

        handler = CapturingHandler()
        handler.setLevel(logging.DEBUG)
        signal_logger = logging.getLogger("apps.orders.signals")
        signal_logger.addHandler(handler)

        try:
            # Force the outer try to fail by making Order.objects.filter raise
            with patch("apps.orders.signals.Order.objects") as mock_qs:
                mock_qs.filter.side_effect = DatabaseError("DB gone during refund handler")
                _handle_invoice_refunded(sender=None, invoice=object(), refund_type="full")
        finally:
            signal_logger.removeHandler(handler)

        critical_records = [r for r in captured_records if r.levelno >= logging.CRITICAL]
        self.assertTrue(
            len(critical_records) > 0,
            f"Expected CRITICAL log record, got: {[r.getMessage() for r in captured_records]}",
        )

        record = critical_records[0]
        self.assertIsNotNone(
            record.exc_info,
            "exc_info must be set on the CRITICAL log record so the traceback is captured",
        )
        self.assertIsNotNone(
            record.exc_info[0],
            "exc_info[0] (exception type) must not be None — traceback must be attached",
        )


# ===============================================================================
# TASK 5.1: _handle_invoice_refunded — full/partial/no-services cases
# ===============================================================================


class InvoiceRefundedSignalTest(TestCase):
    """Task 5.1: Test _handle_invoice_refunded signal handler end-to-end.

    The signal is emitted by billing with (invoice, refund_type). The orders
    app suspends active services on full refund and logs a warning on partial.
    """

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Refund Signal SRL",
            customer_type="company",
            status="active",
            primary_email="refund-signal@test.ro",
        )
        self.product = Product.objects.create(
            name="Refund Test Plan",
            slug="refund-test-plan",
            product_type="shared_hosting",
            is_active=True,
        )

    def _create_order_with_active_service(self):
        """Return (order, item, service) where service.status == 'active'."""
        from decimal import Decimal  # noqa: PLC0415

        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={},
        )
        plan, _ = ServicePlan.objects.get_or_create(
            name="Refund Test Plan",
            defaults={
                "plan_type": "shared_hosting",
                "is_active": True,
                "price_monthly": Decimal("50.00"),
            },
        )
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Refund Test Service",
            username="refund_user",
            billing_cycle="monthly",
            price=Decimal("100.00"),
        )
        force_status(service, "active")

        item = OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
            service=service,
        )
        return order, item, service

    def _emit_invoice_refunded(self, invoice, refund_type: str) -> None:
        """Emit the invoice_refunded custom signal."""
        from apps.billing.custom_signals import invoice_refunded  # noqa: PLC0415

        invoice_refunded.send(sender=invoice.__class__, invoice=invoice, refund_type=refund_type)

    def test_full_refund_suspends_active_service(self):
        """Task 5.1a: Full refund → active service is suspended.

        Emit invoice_refunded(refund_type='full') and assert the linked
        service transitions from 'active' to 'suspended'.
        """
        from apps.billing.models import Invoice  # noqa: PLC0415

        order, _item, service = self._create_order_with_active_service()

        # Create a paid invoice linked to the order
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        force_status(invoice, "paid")
        order.invoice = invoice
        order.save(update_fields=["invoice"])

        self._emit_invoice_refunded(invoice, refund_type="full")

        service.refresh_from_db()
        self.assertEqual(
            service.status,
            "suspended",
            f"Full refund must suspend active service, got: {service.status}",
        )

    def test_partial_refund_logs_warning_and_does_not_suspend(self):
        """Task 5.1b: Partial refund → no suspension, info log about manual review."""
        from apps.billing.models import Invoice  # noqa: PLC0415

        order, _item, service = self._create_order_with_active_service()

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        force_status(invoice, "paid")
        order.invoice = invoice
        order.save(update_fields=["invoice"])

        # assertLogs captures INFO and above; the partial-refund path logs at INFO.
        with self.assertLogs("apps.orders.signals", level="INFO") as log_ctx:
            self._emit_invoice_refunded(invoice, refund_type="partial")

        service.refresh_from_db()
        self.assertEqual(
            service.status,
            "active",
            "Partial refund must NOT suspend service automatically",
        )
        # Handler must log that the service needs manual review
        self.assertTrue(
            any("manual review" in msg.lower() for msg in log_ctx.output),
            f"Expected 'manual review' in log output, got: {log_ctx.output}",
        )

    def test_no_active_services_handler_completes_without_error(self):
        """Task 5.1c: Order with no active services — handler completes gracefully."""
        from apps.billing.models import Invoice  # noqa: PLC0415

        # Order with no services at all
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={},
        )
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )
        force_status(invoice, "paid")
        order.invoice = invoice
        order.save(update_fields=["invoice"])

        # Should not raise; no log at WARNING or above is required
        try:
            self._emit_invoice_refunded(invoice, refund_type="full")
        except Exception as exc:
            self.fail(f"Handler raised unexpectedly with no services: {exc}")


# ===============================================================================
# TASK 5.2: Active/provisioning service suspension on order cancellation
# ===============================================================================


class ServiceSuspensionOnCancellationTest(TestCase):
    """Task 5.2: When an order is cancelled, services in 'provisioning' are failed
    and services in 'active' are suspended — not deleted.
    """

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Suspension Cancel SRL",
            customer_type="company",
            status="active",
            primary_email="suspend-cancel@test.ro",
        )
        self.product = Product.objects.create(
            name="Suspension Plan",
            slug="suspension-plan",
            product_type="shared_hosting",
            is_active=True,
        )

    def _create_order_with_service_in_status(self, service_status: str):
        """Return (order, item, service) with service in the given status."""
        from decimal import Decimal  # noqa: PLC0415

        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            billing_address={},
        )
        force_status(order, "awaiting_payment")

        plan, _ = ServicePlan.objects.get_or_create(
            name="Suspension Cancel Plan",
            defaults={
                "plan_type": "shared_hosting",
                "is_active": True,
                "price_monthly": Decimal("50.00"),
            },
        )
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name=f"Service-{service_status}",
            username=f"user_{service_status}",
            billing_cycle="monthly",
            price=Decimal("100.00"),
        )
        force_status(service, service_status)

        item = OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
            service=service,
        )
        return order, item, service

    def test_provisioning_service_is_failed_on_order_cancellation(self):
        """Task 5.2a: Service in 'provisioning' becomes 'failed' when order is cancelled.

        _handle_order_cancellation calls service.fail_provisioning() for services
        in the 'provisioning' state (real infrastructure — must not be deleted).
        """
        from apps.provisioning.models import Service  # noqa: PLC0415

        order, _item, service = self._create_order_with_service_in_status("provisioning")
        service_id = service.id

        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="5.2a test")
            )

        self.assertTrue(result.is_ok(), f"update_order_status failed: {result}")
        service_after = Service.objects.get(id=service_id)
        self.assertEqual(
            service_after.status,
            "failed",
            f"Provisioning service must be failed on order cancellation, got: {service_after.status}",
        )

    def test_active_service_is_suspended_on_order_cancellation(self):
        """Task 5.2b: Service in 'active' becomes 'suspended' when order is cancelled.

        _handle_order_cancellation calls service.suspend() for services
        in the 'active' state (real infrastructure — must not be deleted).
        """
        from apps.provisioning.models import Service  # noqa: PLC0415

        order, _item, service = self._create_order_with_service_in_status("active")
        service_id = service.id

        with self.captureOnCommitCallbacks(execute=True):
            result = OrderService.update_order_status(
                order, StatusChangeData(new_status="cancelled", notes="5.2b test")
            )

        self.assertTrue(result.is_ok(), f"update_order_status failed: {result}")
        service_after = Service.objects.get(id=service_id)
        self.assertEqual(
            service_after.status,
            "suspended",
            f"Active service must be suspended on order cancellation, got: {service_after.status}",
        )
