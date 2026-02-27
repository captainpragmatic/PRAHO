"""Tests for Subscription.resume() paused duration calculation.

Validates that resuming a paused subscription correctly extends
current_period_end and next_billing_date by the paused duration.
"""

import uuid
from datetime import timedelta

from django.core.exceptions import ValidationError
from django.test import TransactionTestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.subscription_models import Subscription
from apps.customers.models import Customer
from apps.products.models import Product


class SubscriptionResumeTestCase(TransactionTestCase):
    """Test Subscription.resume() paused duration handling."""

    def setUp(self):
        self.currency = Currency.objects.create(code="RON", symbol="lei", decimals=2)
        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="company",
            company_name="Test SRL",
            primary_email="resume-test@example.com",
            status="active",
        )
        self.product = Product.objects.create(
            slug="hosting-resume-test",
            name="Hosting Plan",
            product_type="shared_hosting",
        )

    def _make_subscription(self, **kwargs):
        """Helper to create a subscription with canonical fields."""
        now = timezone.now()
        defaults = {
            "customer": self.customer,
            "product": self.product,
            "currency": self.currency,
            "subscription_number": f"SUB-{uuid.uuid4().hex[:8].upper()}",
            "status": "active",
            "billing_cycle": "monthly",
            "unit_price_cents": 2999,
            "current_period_start": now,
            "current_period_end": now + timedelta(days=30),
            "next_billing_date": now + timedelta(days=30),
        }
        defaults.update(kwargs)
        return Subscription.objects.create(**defaults)

    def test_resume_extends_period_by_paused_duration(self):
        """Pausing for ~5 days then resuming should shift end dates forward."""
        sub = self._make_subscription(status="paused")
        original_end = sub.current_period_end
        original_billing = sub.next_billing_date

        # Simulate paused 5 days ago
        sub.paused_at = timezone.now() - timedelta(days=5)
        sub.save()

        sub.resume()
        sub.refresh_from_db()

        self.assertEqual(sub.status, "active")
        self.assertIsNone(sub.paused_at)
        self.assertIsNone(sub.resume_at)

        # Period end and billing date should be extended by ~5 days
        extension = sub.current_period_end - original_end
        self.assertGreaterEqual(extension.total_seconds(), timedelta(days=4, hours=23).total_seconds())
        self.assertLessEqual(extension.total_seconds(), timedelta(days=5, minutes=5).total_seconds())

        billing_extension = sub.next_billing_date - original_billing
        self.assertGreaterEqual(billing_extension.total_seconds(), timedelta(days=4, hours=23).total_seconds())

    def test_resume_non_paused_raises_validation_error(self):
        """Resuming an active subscription should raise ValidationError."""
        sub = self._make_subscription(status="active")

        with self.assertRaises(ValidationError):
            sub.resume()

    def test_resume_with_none_paused_at_no_extension(self):
        """Edge case: paused status but paused_at=None should not crash and not extend dates."""
        sub = self._make_subscription(status="paused", paused_at=None)
        original_end = sub.current_period_end
        original_billing = sub.next_billing_date

        sub.resume()
        sub.refresh_from_db()

        self.assertEqual(sub.status, "active")
        # Dates should be unchanged since there's no paused_at to calculate from
        self.assertEqual(sub.current_period_end, original_end)
        self.assertEqual(sub.next_billing_date, original_billing)
