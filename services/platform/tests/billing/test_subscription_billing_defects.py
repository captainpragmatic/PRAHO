"""
Tests for the recurring-billing engine defects in #209.

The existing suite never created a ProductPrice and only asserted a subscription's price on the
custom_price_cents path — which bypasses the list-price resolution entirely. That is how a
subscription being billed 0 went unnoticed.
"""

from __future__ import annotations

import uuid
from datetime import timedelta

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import RecurringBillingService, SubscriptionService
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice


def _make_currency() -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code="RON", defaults={"name": "Romanian Leu", "symbol": "lei", "is_active": True}
    )
    return currency


def _make_customer() -> Customer:
    return Customer.objects.create(
        name="Test Company SRL",
        customer_type="company",
        company_name="Test Company SRL",
        primary_email=f"sub-{uuid.uuid4().hex[:8]}@example.ro",
        status="active",
    )


class SubscriptionListPriceResolutionTestCase(TestCase):
    """#209: a subscription without custom_price_cents must bill the product's list price.

    The price was read as `getattr(product, "price_cents", 0) or getattr(product,
    "unit_price_cents", 0)`. Product has neither attribute, so this was 0 for every subscription
    — the customer was billed nothing and proration went negative.
    """

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = Product.objects.create(
            slug=f"hosting-{uuid.uuid4().hex[:8]}",
            name="Basic Hosting",
            product_type="hosting",
        )
        self.price = ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2999,
            is_active=True,
        )

    def test_monthly_subscription_bills_the_list_price(self) -> None:
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly", "quantity": 1},
        )

        self.assertTrue(result.is_ok(), f"creation failed: {result}")
        self.assertEqual(result.unwrap().unit_price_cents, 2999)

    def test_yearly_subscription_bills_the_annual_price(self) -> None:
        """`yearly` is the Subscription vocabulary; ProductPrice calls the same period `annual`."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "yearly", "quantity": 1},
        )

        self.assertTrue(result.is_ok(), f"creation failed: {result}")
        self.assertEqual(result.unwrap().unit_price_cents, self.price.get_price_cents_for_period("annual"))

    def test_custom_price_still_overrides_the_list_price(self) -> None:
        """Non-regression: an explicit price wins over the catalog."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"custom_price_cents": 9900},
        )

        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap().unit_price_cents, 9900)

    def test_unpriceable_billing_cycle_fails_loudly(self) -> None:
        """ProductPrice defines no quarterly price, so there is no list price to resolve.

        Failing is the point: the alternative is inventing a rule the pricing model never
        defined, or silently billing 0 as before.
        """
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "quarterly", "quantity": 1},
        )

        self.assertTrue(result.is_err())
        self.assertIn("custom_price_cents", result.unwrap_err())

    def test_product_without_a_price_in_the_currency_fails_loudly(self) -> None:
        priceless = Product.objects.create(
            slug=f"priceless-{uuid.uuid4().hex[:8]}",
            name="Unpriced Product",
            product_type="hosting",
        )

        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=priceless,
            data={"billing_cycle": "monthly", "quantity": 1},
        )

        self.assertTrue(result.is_err())
        self.assertIn("No active RON price", result.unwrap_err())


class PeriodEndCancellationTestCase(TestCase):
    """#209: a subscription cancelled for end-of-period must stop billing when the period ends.

    cancel(at_period_end=True) only raises a flag and leaves status "active" so service continues
    until the paid period runs out. Nothing else in the codebase completes that cancellation, so
    the subscription was billed again on every run, forever, past the cancellation date.
    """

    def setUp(self) -> None:
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = Product.objects.create(
            slug=f"hosting-{uuid.uuid4().hex[:8]}",
            name="Basic Hosting",
            product_type="hosting",
        )
        ProductPrice.objects.create(
            product=self.product,
            currency=self.currency,
            monthly_price_cents=2999,
            is_active=True,
        )

    def _subscription(self, *, cancel_at_period_end: bool, period_end_days: int) -> Subscription:
        now = timezone.now()
        return Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            quantity=1,
            current_period_start=now - timedelta(days=30),
            current_period_end=now + timedelta(days=period_end_days),
            next_billing_date=now - timedelta(days=1),
            cancel_at_period_end=cancel_at_period_end,
        )

    def test_subscription_cancelled_at_period_end_is_retired_not_billed(self) -> None:
        subscription = self._subscription(cancel_at_period_end=True, period_end_days=-1)

        RecurringBillingService.run_billing_cycle(dry_run=True)

        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "cancelled")
        self.assertIsNotNone(subscription.ended_at)

    def test_subscription_cancelled_but_still_inside_its_period_keeps_billing(self) -> None:
        """The customer paid through the period end — service continues until then."""
        subscription = self._subscription(cancel_at_period_end=True, period_end_days=10)

        RecurringBillingService.run_billing_cycle(dry_run=True)

        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "active")

    def test_ordinary_active_subscription_is_untouched(self) -> None:
        subscription = self._subscription(cancel_at_period_end=False, period_end_days=-1)

        RecurringBillingService.run_billing_cycle(dry_run=True)

        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "active")
