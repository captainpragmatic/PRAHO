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

    def test_sets_valid_until_7_days(self):
        """Proforma valid_until defaults to 7 days from now."""
        from apps.billing.proforma_service import ProformaService  # noqa: PLC0415

        order = self._create_order_with_items()
        force_status(order, "awaiting_payment")

        result = ProformaService.create_from_order(order)
        proforma = result.unwrap()

        expected_min = timezone.now() + timedelta(days=6)
        expected_max = timezone.now() + timedelta(days=8)
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
