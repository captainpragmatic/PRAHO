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

    def test_active_free_promotion_is_a_valid_list_price_for_supported_cycles(self) -> None:
        """An explicit, unexpired zero-cent promotion is a real price, not an unset base price."""
        self.price.promo_price_cents = 0
        self.price.promo_valid_until = timezone.now() + timedelta(days=1)
        self.price.save(update_fields=["promo_price_cents", "promo_valid_until", "updated_at"])

        for billing_cycle in ("monthly", "semi_annual", "yearly"):
            with self.subTest(billing_cycle=billing_cycle):
                result = SubscriptionService.create_subscription(
                    customer=self.customer,
                    product=self.product,
                    data={"billing_cycle": billing_cycle, "quantity": 1},
                )

                self.assertTrue(result.is_ok(), f"creation failed for {billing_cycle}: {result}")
                self.assertEqual(result.unwrap().unit_price_cents, 0)

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

        result = RecurringBillingService.run_billing_cycle(dry_run=False)

        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "cancelled")
        self.assertIsNotNone(subscription.ended_at)
        # Retired, not billed: the retirement happens before selection, so no invoice exists.
        self.assertEqual(result["invoices_created"], 0)

    def test_dry_run_does_not_cancel_anything(self) -> None:
        """#302 review: a preview must not mutate. The finalizer performs a real FSM
        transition and a permanent ended_at write — running it under dry_run would let an
        operator previewing month-end billing cancel live subscriptions."""
        subscription = self._subscription(cancel_at_period_end=True, period_end_days=-1)

        RecurringBillingService.run_billing_cycle(dry_run=True)

        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "active")
        self.assertIsNone(subscription.ended_at)

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


class SubscriptionPricingGuardsTestCase(TestCase):
    """#302 review: pricing edges the first round of fixes left open."""

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

    def test_quantity_only_change_keeps_the_negotiated_price(self) -> None:
        """Re-resolving the catalog on a quantity change would silently reprice a
        custom-priced (grandfathered) subscription to today's list price."""
        created = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly", "quantity": 1, "custom_price_cents": 1999},
        ).unwrap()

        change = SubscriptionService.change_subscription(created, {"new_quantity": 2})

        self.assertTrue(change.is_ok(), f"change failed: {change}")
        created.refresh_from_db()
        self.assertEqual(created.effective_price_cents, 1999)
        self.assertEqual(created.quantity, 2)

    def test_explicit_zero_custom_price_creates_a_free_subscription(self) -> None:
        """custom_price_cents=0 is a deliberate free subscription; truthiness would silently
        fall through to list-price resolution."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly", "quantity": 1, "custom_price_cents": 0},
        )

        self.assertTrue(result.is_ok(), f"creation failed: {result}")
        self.assertEqual(result.unwrap().effective_price_cents, 0)

    def test_unset_period_price_fails_loudly(self) -> None:
        """A ProductPrice whose monthly base is 0 derives 0 for every period — that is
        "unset", and returning it as a real price recreates the billed-zero defect."""
        zero_product = Product.objects.create(
            slug=f"zero-{uuid.uuid4().hex[:8]}",
            name="Zero Priced",
            product_type="hosting",
        )
        ProductPrice.objects.create(
            product=zero_product,
            currency=self.currency,
            monthly_price_cents=0,
            is_active=True,
        )

        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=zero_product,
            data={"billing_cycle": "monthly", "quantity": 1},
        )

        self.assertTrue(result.is_err())
        self.assertIn("no usable", result.unwrap_err())

    def test_zero_priced_subscription_is_reported_not_silently_billed_zero(self) -> None:
        """Rows priced 0 by the pre-fix defect are broken state: the billing run must
        surface them instead of generating 0-cent invoices forever."""
        now = timezone.now()
        subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            status="active",
            billing_cycle="monthly",
            unit_price_cents=0,
            quantity=1,
            current_period_start=now - timedelta(days=30),
            current_period_end=now + timedelta(days=1),
            next_billing_date=now - timedelta(days=1),
        )

        result = RecurringBillingService.run_billing_cycle(dry_run=False)

        self.assertEqual(result["invoices_created"], 0)
        self.assertTrue(any(subscription.subscription_number in e for e in result["errors"]))
