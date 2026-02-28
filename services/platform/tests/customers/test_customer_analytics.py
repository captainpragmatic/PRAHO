# ===============================================================================
# CUSTOMER ANALYTICS TESTS
# ===============================================================================
"""Tests for customer analytics calculation in tasks.py."""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.models import Currency, Invoice
from apps.customers.models import Customer
from apps.customers.tasks import _calculate_engagement_score, update_customer_analytics
from apps.orders.models import Order


class CustomerAnalyticsTestCase(TestCase):
    """Test update_customer_analytics with real database queries."""

    def setUp(self):
        self.currency = Currency.objects.create(code="RON", symbol="L", decimals=2)
        self.customer = Customer.objects.create(
            name="Analytics Test Co",
            customer_type="company",
            company_name="Analytics Test Co",
            status="active",
        )

    def test_analytics_counts_orders(self):
        """Verify total_orders reflects actual Order count."""
        for _i in range(3):
            Order.objects.create(
                customer=self.customer,
                currency=self.currency,
                customer_email="test@example.com",
                customer_name="Test",
                status="completed",
            )

        result = update_customer_analytics(str(self.customer.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["analytics"]["total_orders"], 3)

    def test_analytics_sums_paid_invoice_revenue(self):
        """Only paid invoices should contribute to total_revenue."""
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-PAID-001",
            total_cents=1000,
            subtotal_cents=1000,
            status="paid",
        )
        Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-UNPAID-001",
            total_cents=2000,
            subtotal_cents=2000,
            status="issued",
        )

        result = update_customer_analytics(str(self.customer.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["analytics"]["total_revenue"], 1000)

    def test_engagement_score_zero_for_inactive(self):
        """No login, no orders should yield engagement score 0."""
        score = _calculate_engagement_score(self.customer, total_orders=0, account_age_days=365)
        self.assertEqual(score, 0)

    def test_engagement_score_high_for_active_customer(self):
        """Customer with recent login and multiple orders should score > 50."""
        from django.contrib.auth import get_user_model  # noqa: PLC0415

        from apps.users.models import CustomerMembership  # noqa: PLC0415

        user_model = get_user_model()
        user = user_model.objects.create_user(
            email="active@test.com",
            password="testpass123",
            last_login=timezone.now() - timedelta(days=2),
        )
        CustomerMembership.objects.create(
            customer=self.customer,
            user=user,
            role="owner",
        )

        score = _calculate_engagement_score(self.customer, total_orders=10, account_age_days=90)
        self.assertGreater(score, 50)

    @patch("apps.settings.services.SettingsService.get_integer_setting")
    def test_engagement_score_respects_settings_weights(self, mock_get_int):
        """Custom weights from SettingsService should affect the score."""

        # Set all weight on orders (100%), zero on recency and activity
        def fake_get_integer(key, default):
            return {
                "customers.engagement_order_weight": 100,
                "customers.engagement_recency_weight": 0,
                "customers.engagement_activity_weight": 0,
            }.get(key, default)

        mock_get_int.side_effect = fake_get_integer

        # 5 orders -> order_score = 50, weight 100 -> total = 50*100/100 = 50
        score = _calculate_engagement_score(self.customer, total_orders=5, account_age_days=365)
        self.assertEqual(score, 50)

        # 10 orders -> order_score = 100, weight 100 -> total = 100
        score = _calculate_engagement_score(self.customer, total_orders=10, account_age_days=365)
        self.assertEqual(score, 100)
