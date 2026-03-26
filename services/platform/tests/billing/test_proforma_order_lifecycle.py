"""
Tests for Phase B: Proforma Lifecycle (Order-Proforma-Invoice lifecycle).

Validates:
- ProformaService.create_from_order() — sync DB creation
- ProformaPaymentService.record_payment_and_convert() — convergence point
- proforma_payment_received signal — unidirectional billing→orders coupling
- OrderPaymentConfirmationService.confirm_order() — atomic double-transition
- Idempotency: already-converted proforma returns Ok
- Order.proforma FK and Payment.proforma FK
"""

from datetime import timedelta
from decimal import Decimal

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency
from apps.billing.proforma_models import ProformaInvoice, ProformaSequence
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.products.models import Product
from apps.users.models import User
from tests.helpers.fsm_helpers import force_status


class ProformaLifecycleTestBase(TestCase):
    """Base test case with common setup for proforma lifecycle tests."""

    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            status="active",
            primary_email="test@example.ro",
            company_name="Test Company SRL",
        )
        self.product = Product.objects.create(
            name="Shared Hosting Basic",
            slug="shared-hosting-basic",
            product_type="shared_hosting",
            is_active=True,
        )
        self.user = User.objects.create_user(
            email="admin@pragmatichost.com",
            password="testpass123",
            is_staff=True,
        )
        # Ensure proforma sequence exists
        ProformaSequence.objects.get_or_create(scope="default")

    def _create_order_with_items(self, total_cents=12100, **kwargs):
        defaults = {
            "customer": self.customer,
            "currency": self.currency,
            "customer_email": self.customer.primary_email,
            "customer_name": self.customer.name,
            "subtotal_cents": 10000,
            "tax_cents": 2100,
            "total_cents": total_cents,
            "billing_address": {"company_name": "Test SRL", "country": "RO"},
        }
        defaults.update(kwargs)
        order = Order.objects.create(**defaults)
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=10000,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=12100,
        )
        return order


class TestOrderProformaFK(ProformaLifecycleTestBase):
    """Test Order.proforma FK exists and works."""

    def test_order_has_proforma_field(self):
        """Order model has a nullable FK to ProformaInvoice."""
        order = self._create_order_with_items()
        self.assertTrue(hasattr(order, "proforma"))
        self.assertIsNone(order.proforma)

    def test_order_proforma_fk_accepts_proforma(self):
        """Order.proforma can be set to a ProformaInvoice instance."""
        order = self._create_order_with_items()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-000001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order.proforma = proforma
        order.save(update_fields=["proforma"])
        order.refresh_from_db()
        self.assertEqual(order.proforma, proforma)

    def test_proforma_orders_reverse_relation(self):
        """ProformaInvoice.orders reverse relation works."""
        order = self._create_order_with_items()
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-000002",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        order.proforma = proforma
        order.save(update_fields=["proforma"])
        self.assertEqual(proforma.orders.count(), 1)
        self.assertEqual(proforma.orders.first(), order)


class TestPaymentProformaFK(ProformaLifecycleTestBase):
    """Test Payment.proforma FK exists."""

    def test_payment_has_proforma_field(self):
        """Payment model has a nullable FK to ProformaInvoice."""
        from apps.billing.payment_models import Payment  # noqa: PLC0415

        payment = Payment.objects.create(
            customer=self.customer,
            currency=self.currency,
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(hasattr(payment, "proforma"))
        self.assertIsNone(payment.proforma)


class TestCreateFromOrder(ProformaLifecycleTestBase):
    """Test ProformaService.create_from_order()."""

    def test_creates_proforma_with_correct_totals(self):
        """create_from_order produces proforma matching order financial totals."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        self.assertTrue(result.is_ok(), f"Expected Ok, got: {result}")
        proforma = result.unwrap()

        self.assertEqual(proforma.customer, self.customer)
        self.assertEqual(proforma.total_cents, order.total_cents)
        self.assertEqual(proforma.currency, self.currency)
        self.assertIn("PRO-", proforma.number)

    def test_creates_proforma_lines_from_order_items(self):
        """Each OrderItem produces a corresponding ProformaLine."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()

        self.assertEqual(proforma.lines.count(), 1)
        line = proforma.lines.first()
        self.assertEqual(line.unit_price_cents, 10000)
        self.assertEqual(line.quantity, Decimal("1.000"))

    def test_sets_valid_until_from_settings(self):
        """Proforma valid_until uses billing.proforma_validity_days setting (default 30)."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()

        # H1 fix: default is 30 days from SettingsService, not hardcoded 7
        expected_min = timezone.now() + timedelta(days=29)
        expected_max = timezone.now() + timedelta(days=31)
        self.assertGreater(proforma.valid_until, expected_min)
        self.assertLess(proforma.valid_until, expected_max)

    def test_sets_bill_to_from_order(self):
        """Proforma bill_to fields populated from order billing_address."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items(
            billing_address={
                "company_name": "Acme SRL",
                "country": "RO",
                "city": "Bucharest",
            }
        )
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()

        self.assertEqual(proforma.bill_to_name, "Acme SRL")
        self.assertEqual(proforma.bill_to_country, "RO")

    def test_discount_preserved_in_proforma_totals(self):
        """Proforma total_cents reflects discount — regression guard for recalculate_totals overwrite."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        # Create order with items first (triggers post_save recalculation),
        # THEN apply discount (which changes totals but not line items).
        order = self._create_order_with_items()
        # Apply discount AFTER item creation to avoid post_save overwrite
        order.discount_cents = 2000
        # Recalculate: subtotal stays 10000, but total = 10000 - 2000 + VAT(8000)
        order.total_cents = order.total_cents - 2000  # Subtract discount from total
        order.save(update_fields=["discount_cents", "total_cents"])
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        self.assertTrue(result.is_ok(), f"Expected Ok, got: {result}")
        proforma = result.unwrap()

        # Proforma must reflect discounted totals, NOT full-price line totals
        full_price_total = 10000 + 2100  # 12100 without discount
        self.assertLess(
            proforma.total_cents,
            full_price_total,
            "Proforma total should be less than full price — discount must be applied",
        )

    def test_links_proforma_to_order(self):
        """create_from_order sets order.proforma FK."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()

        order.refresh_from_db()
        self.assertEqual(order.proforma, proforma)

    def test_sets_currency_from_order(self):
        """Proforma currency matches order currency (F10)."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()
        self.assertEqual(proforma.currency, order.currency)


class TestRecordPaymentAndConvert(ProformaLifecycleTestBase):
    """Test ProformaPaymentService.record_payment_and_convert()."""

    def _create_sent_proforma(self, total_cents=12100):
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-{ProformaSequence.objects.get(scope='default').last_value + 1:06d}",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=total_cents,
            valid_until=timezone.now() + timedelta(days=7),
        )
        proforma.send_proforma()
        proforma.save()
        return proforma

    def test_creates_payment_and_converts_proforma(self):
        """record_payment_and_convert creates Payment, converts proforma to invoice."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
            created_by=self.user,
        )
        self.assertTrue(result.is_ok(), f"Expected Ok, got: {result}")
        invoice = result.unwrap()

        proforma.refresh_from_db()
        self.assertEqual(proforma.status, "converted")
        self.assertEqual(invoice.status, "paid")
        self.assertGreater(invoice.total_cents, 0)

    def test_rejects_partial_payment(self):
        """Only full payment accepted (amount must equal proforma total)."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma(total_cents=12100)

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=5000,  # Less than total
            payment_method="bank",
        )
        self.assertTrue(result.is_err())

    def test_rejects_expired_proforma(self):
        """Cannot record payment on expired proforma."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()
        # Force expiry by updating valid_until
        ProformaInvoice.objects.filter(pk=proforma.pk).update(
            valid_until=timezone.now() - timedelta(days=1)
        )

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result.is_err())

    def test_idempotent_already_converted(self):
        """Already-converted proforma returns Ok with existing invoice (M9)."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()

        # First conversion
        result1 = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result1.is_ok())

        # Second call — should return Ok, not Err
        result2 = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result2.is_ok())

    def test_emits_signal_via_on_commit(self):
        """proforma_payment_received signal emitted via on_commit (F2).

        Django TestCase wraps tests in transactions that never commit, so on_commit
        callbacks don't fire. We use captureOnCommitCallbacks to capture and run them.
        """
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()
        signal_received = []

        from apps.billing.custom_signals import proforma_payment_received  # noqa: PLC0415

        def handler(sender, proforma, invoice, payment, **kwargs):
            signal_received.append({"proforma": proforma, "invoice": invoice})

        proforma_payment_received.connect(handler)
        try:
            with self.captureOnCommitCallbacks(execute=True):
                result = ProformaPaymentService.record_payment_and_convert(
                    proforma_id=str(proforma.id),
                    amount_cents=12100,
                    payment_method="bank",
                )
            self.assertTrue(result.is_ok())
            # Signal fires when on_commit callbacks are executed
            self.assertEqual(len(signal_received), 1)
            self.assertEqual(signal_received[0]["proforma"].id, proforma.id)
        finally:
            proforma_payment_received.disconnect(handler)


class TestOrderPaymentConfirmationService(ProformaLifecycleTestBase):
    """Test OrderPaymentConfirmationService.confirm_order()."""

    def test_confirms_order_awaiting_payment_to_paid(self):
        """confirm_order transitions awaiting_payment → paid."""
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        # Should be paid or provisioning (depends on review gate threshold)
        self.assertIn(order.status, ["paid", "provisioning", "in_review"])

    def test_idempotent_already_paid(self):
        """confirm_order on already-paid order returns Ok."""
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "paid")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())

    def test_links_invoice_to_order(self):
        """confirm_order sets order.invoice when invoice provided."""
        from apps.billing.models import Invoice, InvoiceSequence  # noqa: PLC0415
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        seq, _ = InvoiceSequence.objects.get_or_create(scope="default")
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=seq.get_next_number("INV"),
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
        )

        result = OrderPaymentConfirmationService.confirm_order(order, invoice=invoice)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.invoice, invoice)


class TestProformaPaymentReceivedSignal(ProformaLifecycleTestBase):
    """Test that the proforma_payment_received signal exists and can be connected."""

    def test_signal_exists(self):
        """proforma_payment_received signal is importable."""
        from apps.billing.custom_signals import proforma_payment_received  # noqa: PLC0415
        self.assertIsNotNone(proforma_payment_received)

    def test_signal_can_connect_and_send(self):
        """Signal can be connected and sent."""
        from apps.billing.custom_signals import proforma_payment_received  # noqa: PLC0415

        received = []

        def handler(sender, **kwargs):
            received.append(kwargs)

        proforma_payment_received.connect(handler)
        try:
            proforma_payment_received.send(
                sender=self.__class__,
                proforma=None,
                invoice=None,
                payment=None,
            )
            self.assertEqual(len(received), 1)
        finally:
            proforma_payment_received.disconnect(handler)


class TestProformaPaymentEdgeCases(ProformaLifecycleTestBase):
    """H8: Missing tests for edge cases in ProformaPaymentService."""

    def _create_sent_proforma(self, customer=None, total_cents=12100):
        """Create a sent proforma for testing."""
        cust = customer or self.customer
        proforma = ProformaInvoice.objects.create(
            customer=cust, currency=self.currency,
            number=f"PRO-EDGE-{ProformaInvoice.objects.count() + 1:03d}",
            subtotal_cents=total_cents - 2100, tax_cents=2100, total_cents=total_cents,
            valid_until=timezone.now() + timedelta(days=7),
        )
        proforma.send_proforma()
        proforma.save()
        return proforma

    def test_cross_customer_payment_rejected(self):
        """H8/IDOR: Payment from Customer A cannot be linked to Customer B's proforma."""
        from apps.billing.payment_models import Payment  # noqa: PLC0415
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        other_customer = Customer.objects.create(
            name="Other SRL", customer_type="company",
            status="active", primary_email="other@test.ro",
        )
        proforma = self._create_sent_proforma(customer=self.customer)

        # Create payment belonging to a DIFFERENT customer
        payment = Payment.objects.create(
            customer=other_customer, currency=self.currency,
            amount_cents=12100, payment_method="stripe",
            gateway_txn_id="pi_idor_test",
        )

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="stripe",
            existing_payment=payment,
        )
        self.assertTrue(result.is_err())
        self.assertIn("customer", result.unwrap_err().lower())

    def test_overpayment_rejected(self):
        """H8: Payment amount exceeding proforma total is rejected."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma(total_cents=12100)

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=99999,  # Overpayment
            payment_method="bank",
        )
        self.assertTrue(result.is_err())
        self.assertIn("must equal", result.unwrap_err())

    def test_idempotent_already_converted_returns_ok(self):
        """H8: Sequential calls to record_payment_and_convert are idempotent."""
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()

        # First call succeeds
        result1 = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result1.is_ok())

        # Second call — idempotent, returns Ok
        result2 = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result2.is_ok())

    def test_idempotent_converted_proforma_with_deleted_invoice_returns_ok(self):
        """B-2 regression test (confidence 85): When proforma.status == "converted" but
        the referenced invoice was hard-deleted, record_payment_and_convert must return
        Ok(None) with a critical log — NOT Err(...).

        Returning Err causes Stripe to retry indefinitely (retry storm).
        The invoice is gone — there is nothing to fix. Ok(None) + critical log
        is the correct response: data-loss must be surfaced via alerting, not retries.
        """
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = self._create_sent_proforma()
        # Simulate a converted proforma whose invoice was hard-deleted:
        # set status to "converted" and put a nonexistent invoice_id in meta.
        # Invoice uses integer PK, so use a large integer that cannot exist.
        nonexistent_invoice_id = "999999999"
        force_status(proforma, "converted")
        proforma.meta = {"invoice_id": nonexistent_invoice_id}
        proforma.save(update_fields=["meta"])

        with self.assertLogs("apps.billing.proforma_service", level="CRITICAL") as log_ctx:
            result = ProformaPaymentService.record_payment_and_convert(
                proforma_id=str(proforma.id),
                amount_cents=12100,
                payment_method="bank",
            )

        # B-2 BUG: Without fix, returns Err(...) → causes Stripe retry storm.
        # With fix: returns Ok(None) so Stripe acknowledges the event.
        self.assertTrue(result.is_ok(), f"Expected Ok(None), got Err: {result}")
        self.assertIsNone(result.unwrap())
        # Must emit a CRITICAL log so PagerDuty / alerting can surface data-loss
        critical_logs = [m for m in log_ctx.output if "CRITICAL" in m]
        self.assertTrue(len(critical_logs) >= 1, "Expected at least one CRITICAL log")

    def test_nonexistent_proforma_id_returns_err_not_found(self):
        """Task 5.3: record_payment_and_convert with a nonexistent integer ID returns Err 'not found'.

        ProformaInvoice uses an integer PK (auto-increment). Passing an ID that
        does not exist causes DoesNotExist which the service maps to Err('not found').
        Guard: must not raise — should return a structured Err.
        """
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        # Use a very large integer that cannot exist in a test DB
        nonexistent_id = "999999999"
        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=nonexistent_id,
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result.is_err(), "Expected Err for nonexistent proforma_id")
        self.assertIn("not found", result.unwrap_err().lower())

    def test_expired_proforma_payment_rejected_with_cannot_accept_payment(self):
        """Task 5.4: Proforma in a terminal status ('expired' or 'converted') rejects
        payment with an error containing 'cannot accept payment'.

        Valid ProformaInvoice statuses are: draft, sent, accepted, expired, converted.
        Only draft/sent/accepted can accept payment. This test uses 'expired' (a real
        terminal state reachable via force_status) to verify the guard.

        After force_status(proforma, 'expired'), record_payment_and_convert must return
        Err containing 'cannot accept payment' (not raise, not return Ok).
        """
        from apps.billing.proforma_service import ProformaPaymentService  # noqa: PLC0415

        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number=f"PRO-EXPD-{ProformaInvoice.objects.count() + 1:03d}",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            valid_until=timezone.now() + timedelta(days=7),
        )
        force_status(proforma, "expired")

        result = ProformaPaymentService.record_payment_and_convert(
            proforma_id=str(proforma.id),
            amount_cents=12100,
            payment_method="bank",
        )
        self.assertTrue(result.is_err(), "Expected Err for expired proforma payment")
        self.assertIn(
            "cannot accept payment",
            result.unwrap_err().lower(),
            f"Error message must contain 'cannot accept payment', got: {result.unwrap_err()!r}",
        )


class TestConfirmOrderGuards(ProformaLifecycleTestBase):
    """Task 5.5: confirm_order rejects non-awaiting_payment orders with Err."""

    def test_confirm_order_on_draft_order_returns_err(self):
        """Task 5.5: confirm_order on a 'draft' order returns Err (not Ok, not exception).

        Only 'awaiting_payment' orders can be confirmed. A draft order has not yet
        submitted payment intent so confirmation is semantically invalid.
        """
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        # order starts as 'draft' after creation
        self.assertEqual(order.status, "draft")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_err(), f"Expected Err for draft order confirm, got Ok: {result}")

    def test_confirm_order_on_cancelled_order_returns_err(self):
        """Task 5.5 boundary: confirm_order on a 'cancelled' order also returns Err."""
        from apps.orders.services import OrderPaymentConfirmationService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "cancelled")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_err(), f"Expected Err for cancelled order confirm, got Ok: {result}")
