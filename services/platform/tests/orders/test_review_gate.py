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
