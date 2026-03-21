"""
Tests for Phase D: Review Gate implementation.

Validates:
- OrderPaymentConfirmationService respects review threshold
- Orders below threshold auto-advance to provisioning
- Orders at/above threshold go to in_review
- Admin approve/reject transitions work
"""

from decimal import Decimal
from unittest.mock import patch

from django.test import TestCase

from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.orders.models import Order, OrderItem
from apps.orders.services import OrderPaymentConfirmationService
from apps.products.models import Product
from tests.helpers.fsm_helpers import force_status

# Default review threshold from the service (500000 cents = 5000 RON)
DEFAULT_THRESHOLD = 500000


class ReviewGateTestBase(TestCase):
    def setUp(self):
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )
        self.customer = Customer.objects.create(
            name="Review Test SRL",
            customer_type="company",
            status="active",
            primary_email="review@test.ro",
        )
        self.product = Product.objects.create(
            name="VPS Premium",
            slug="vps-premium",
            product_type="vps",
            is_active=True,
        )

    def _create_order(self, total_cents=12100):
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total_cents - 2100,
            tax_cents=2100,
            total_cents=total_cents,
            billing_address={},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=total_cents - 2100,
            tax_rate=Decimal("0.2100"),
            tax_cents=2100,
            line_total_cents=total_cents,
        )
        return order

    def _create_order_exact(self, total_cents: int):
        """Create an order with exactly total_cents after item post_save recalculation.

        Uses tax_rate=Decimal("0") so OrderItem.calculate_totals() sets tax_cents=0
        and line_total_cents=total_cents. This ensures order.total_cents stays exactly
        at total_cents after the post_save signal recalculates totals from items.
        Required for boundary tests where off-by-one matters.
        """
        order = Order.objects.create(
            customer=self.customer,
            currency=self.currency,
            customer_email=self.customer.primary_email,
            customer_name=self.customer.name,
            subtotal_cents=total_cents,
            tax_cents=0,
            total_cents=total_cents,
            billing_address={},
        )
        OrderItem.objects.create(
            order=order,
            product=self.product,
            product_name=self.product.name,
            product_type=self.product.product_type,
            quantity=1,
            unit_price_cents=total_cents,
            tax_rate=Decimal("0"),
            tax_cents=0,
            line_total_cents=total_cents,
        )
        return order


class TestReviewGateBelowThreshold(ReviewGateTestBase):
    """Orders below threshold auto-advance to provisioning."""

    def test_small_order_goes_to_provisioning(self):
        """Order below 5000 RON auto-advances to provisioning."""
        order = self._create_order(total_cents=12100)  # 121 RON
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "provisioning")


class TestReviewGateAboveThreshold(ReviewGateTestBase):
    """Orders at/above threshold go to in_review."""

    def test_large_order_goes_to_in_review(self):
        """Order at/above 5000 RON goes to in_review for admin approval."""
        order = self._create_order(total_cents=DEFAULT_THRESHOLD)
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "in_review")

    def test_very_large_order_goes_to_in_review(self):
        """Order well above threshold goes to in_review."""
        order = self._create_order(total_cents=1000000)  # 10000 RON
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "in_review")

    def test_one_above_threshold_goes_to_in_review(self):
        """Order at threshold + 1 cent goes to in_review (boundary: above).

        Uses tax_rate=0 so OrderItem.calculate_totals() preserves the exact total_cents.
        With a non-zero tax_rate, VAT is recalculated from unit_price_cents and may differ
        from the intended total_cents by rounding.
        """
        order = self._create_order_exact(total_cents=DEFAULT_THRESHOLD + 1)
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "in_review")

    def test_one_below_threshold_goes_to_provisioning(self):
        """Order at threshold - 1 cent goes to provisioning (boundary: below).

        Uses tax_rate=0 so OrderItem.calculate_totals() preserves the exact total_cents.
        With a non-zero tax_rate, VAT is recalculated from unit_price_cents and may differ
        from the intended total_cents by rounding.
        """
        order = self._create_order_exact(total_cents=DEFAULT_THRESHOLD - 1)
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "provisioning")


class TestReviewGateAdminActions(ReviewGateTestBase):
    """Admin can approve or reject orders in review."""

    def test_approve_moves_to_provisioning(self):
        """approve_review() transitions in_review → provisioning."""
        order = self._create_order(total_cents=DEFAULT_THRESHOLD)
        force_status(order, "in_review")

        order.approve_review()
        order.save()
        self.assertEqual(order.status, "provisioning")

    def test_reject_moves_to_cancelled(self):
        """reject_review() transitions in_review → cancelled."""
        order = self._create_order(total_cents=DEFAULT_THRESHOLD)
        force_status(order, "in_review")

        order.reject_review()
        order.save()
        self.assertEqual(order.status, "cancelled")


class TestReviewGateBackgroundTask(ReviewGateTestBase):
    """C2 regression: Background task _process_paid_order must respect review gate."""

    def test_background_task_respects_review_gate_for_high_value_orders(self):
        """C2: _process_paid_order must route through confirm_order, not bypass it.

        ROOT CAUSE: _process_paid_order called mark_paid()+start_provisioning() directly,
        skipping OrderPaymentConfirmationService.confirm_order() which has the review threshold.
        """
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.tasks import _process_paid_order  # noqa: PLC0415

        order = self._create_order(total_cents=DEFAULT_THRESHOLD)  # At threshold → should go to in_review
        force_status(order, "awaiting_payment")

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=DEFAULT_THRESHOLD - 2100,
            tax_cents=2100,
            total_cents=DEFAULT_THRESHOLD,
        )
        order_result: dict = {"action": None, "status": None}
        results: dict = {"confirmed_orders": 0, "provisioning_triggered": 0, "errors": []}

        _process_paid_order(order, invoice, order_result, results)

        order.refresh_from_db()
        # Without C2 fix: order ends up in "provisioning" (review gate bypassed)
        # With C2 fix: order ends up in "in_review" (review gate respected)
        self.assertEqual(
            order.status,
            "in_review",
            f"High-value order should go to in_review, not {order.status}. "
            f"Background task must route through OrderPaymentConfirmationService.confirm_order().",
        )


class TestSyncTaskRespectsReviewGate(ReviewGateTestBase):
    """7-day payment sync task must route through confirm_order (review gate)."""

    def test_sync_task_respects_review_gate(self):
        """_process_payment_confirmation must route through confirm_order, not bypass it.

        ROOT CAUSE: _process_payment_confirmation called mark_paid()+save() directly,
        skipping OrderPaymentConfirmationService.confirm_order() which contains the
        review gate threshold check. High-value orders would be stuck in 'paid'.
        """
        from apps.billing.models import Invoice  # noqa: PLC0415
        from apps.orders.tasks import _process_payment_confirmation  # noqa: PLC0415

        # M9-test fix: Use _create_order_exact so total_cents stays exactly at DEFAULT_THRESHOLD
        # after the post_save signal recalculates item totals. _create_order adds tax that
        # would push total_cents above DEFAULT_THRESHOLD, making this a threshold-boundary test
        # that always routes to in_review regardless of the threshold value.
        order = self._create_order_exact(total_cents=DEFAULT_THRESHOLD)  # At threshold → should go to in_review
        force_status(order, "awaiting_payment")

        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            subtotal_cents=DEFAULT_THRESHOLD - 2100,
            tax_cents=2100,
            total_cents=DEFAULT_THRESHOLD,
        )
        results: dict = {"payment_confirmations": 0, "errors": []}

        confirmed = _process_payment_confirmation(order, invoice, DEFAULT_THRESHOLD, results)

        self.assertTrue(confirmed)
        order.refresh_from_db()
        # Without fix: order ends up in "paid" (review gate bypassed, stuck)
        # With fix: order ends up in "in_review" (review gate respected)
        self.assertEqual(
            order.status,
            "in_review",
            f"High-value order should go to in_review, not {order.status}. "
            f"7-day sync task must route through OrderPaymentConfirmationService.confirm_order().",
        )


class TestC1ProvisioningGuard(ReviewGateTestBase):
    """C1: confirm_order API must NOT provision in_review orders."""

    @patch("apps.api.orders.views._provision_confirmed_order_item")
    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    @patch("apps.api.secure_auth.get_authenticated_customer")
    @patch("apps.billing.gateways.base.PaymentGatewayFactory.create_gateway")
    def test_high_value_order_does_not_provision_after_confirm(
        self, mock_gateway_factory, mock_auth, mock_threshold, mock_provision
    ):
        """C1 RED: confirm_order API calls _provision_confirmed_order_item even for in_review orders.

        HIGH-VALUE order → confirm_order() → status becomes in_review (review gate).
        Bug: provisionable_items is collected and dispatched regardless of resulting status.
        Fix: guard provisioning with `if order.status == "provisioning":`.
        """
        from unittest.mock import MagicMock  # noqa: PLC0415

        from rest_framework.test import APIRequestFactory  # noqa: PLC0415

        from apps.api.orders.views import confirm_order  # noqa: PLC0415
        from apps.billing.gateways.base import PaymentConfirmResult  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        # Order at exactly the threshold → goes to in_review
        mock_threshold.return_value = DEFAULT_THRESHOLD

        # Bypass HMAC auth
        mock_auth.return_value = (self.customer, None)

        # Mock Stripe gateway to return success
        mock_gateway = MagicMock()
        mock_gateway.confirm_payment.return_value = PaymentConfirmResult(
            success=True, status="succeeded", error=None
        )
        mock_gateway_factory.return_value = mock_gateway

        # Need a staff user for the request
        user = User.objects.create_user(
            email="c1-test@pragmatichost.com", password="test123", is_staff=True, staff_role="admin"
        )

        # Create high-value order with a VPS item (provisionable product type)
        order = self._create_order(total_cents=DEFAULT_THRESHOLD)
        # Set payment_method=card and payment_intent_id so the view proceeds
        order.payment_method = "card"
        order.payment_intent_id = "pi_c1test1234567890"
        order.save(update_fields=["payment_method", "payment_intent_id"])
        force_status(order, "awaiting_payment")

        factory = APIRequestFactory()
        request = factory.post(
            "/api/orders/confirm/",
            data={"payment_intent_id": "pi_c1test1234567890", "payment_status": "succeeded"},
            content_type="application/json",
        )
        request.user = user

        confirm_order(request, str(order.id))

        order.refresh_from_db()
        self.assertEqual(
            order.status, "in_review",
            f"High-value order should be in_review after confirm, got: {order.status}"
        )
        # C1 BUG: without fix, _provision_confirmed_order_item IS called for in_review orders
        mock_provision.assert_not_called()


class TestReviewGateConfigurable(ReviewGateTestBase):
    """Review threshold is configurable via SettingsService."""

    @patch("apps.orders.services.OrderPaymentConfirmationService._get_review_threshold")
    def test_custom_threshold_respected(self, mock_threshold):
        """Custom threshold value is used when configured."""
        mock_threshold.return_value = 10000  # 100 RON threshold
        order = self._create_order(total_cents=12100)  # 121 RON — above custom threshold
        force_status(order, "awaiting_payment")

        result = OrderPaymentConfirmationService.confirm_order(order)
        self.assertTrue(result.is_ok())
        order.refresh_from_db()
        self.assertEqual(order.status, "in_review")

    @patch("apps.settings.services.SettingsService.get_integer_setting", side_effect=Exception("DB connection refused"))
    def test_threshold_db_failure_falls_back_to_default_with_warning(self, mock_get_setting):
        """H3 review fix: When SettingsService raises, use default threshold and log warning."""
        threshold = OrderPaymentConfirmationService._get_review_threshold()

        self.assertEqual(threshold, DEFAULT_THRESHOLD)

    @patch("apps.settings.services.SettingsService.get_integer_setting", side_effect=RuntimeError("DB timeout"))
    def test_threshold_db_failure_logs_warning(self, mock_get_setting):
        """H3 review fix: DB failure during threshold read produces a warning log."""
        with self.assertLogs("apps.orders.services", level="WARNING") as log_ctx:
            threshold = OrderPaymentConfirmationService._get_review_threshold()

        self.assertEqual(threshold, DEFAULT_THRESHOLD)
        self.assertTrue(
            any("Could not read review threshold" in msg for msg in log_ctx.output),
            f"Expected warning about threshold fallback, got: {log_ctx.output}",
        )


class TestReviewThresholdClamping(ReviewGateTestBase):
    """Task 5.6: _get_review_threshold clamps values to [0, 100_000_000].

    H8 fix: Misconfigured or negative thresholds must be clamped so the review
    gate behaves predictably. A negative threshold would make EVERY order bypass
    review (max(0, -1) = 0 means threshold=0 → all orders are >= 0 → in_review).
    A ludicrously large value disables the review gate effectively.
    """

    _MAX_THRESHOLD = 100_000_000  # must match the constant in services.py

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=-1)
    def test_negative_threshold_is_clamped_to_zero(self, mock_setting):
        """Task 5.6a: SettingsService returning -1 must clamp to 0.

        max(0, min(-1, 100_000_000)) == 0
        A threshold of 0 means ALL orders go to in_review (every total >= 0).
        """
        threshold = OrderPaymentConfirmationService._get_review_threshold()
        self.assertEqual(
            threshold,
            0,
            f"Expected clamped threshold=0 for configured value -1, got: {threshold}",
        )

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=999_000_000)
    def test_excessive_threshold_is_clamped_to_max(self, mock_setting):
        """Task 5.6b: SettingsService returning 999_000_000 must clamp to 100_000_000.

        max(0, min(999_000_000, 100_000_000)) == 100_000_000
        An excessive threshold prevents any order from going to in_review
        (only limited by the configured maximum).
        """
        threshold = OrderPaymentConfirmationService._get_review_threshold()
        self.assertEqual(
            threshold,
            self._MAX_THRESHOLD,
            f"Expected clamped threshold={self._MAX_THRESHOLD} for value 999_000_000, got: {threshold}",
        )

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=500_000)
    def test_valid_threshold_is_returned_unchanged(self, mock_setting):
        """Task 5.6 boundary: A value within [0, 100_000_000] is returned as-is."""
        threshold = OrderPaymentConfirmationService._get_review_threshold()
        self.assertEqual(threshold, 500_000)
