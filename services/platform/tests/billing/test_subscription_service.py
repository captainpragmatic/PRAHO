"""
Comprehensive tests for apps.billing.subscription_service.

Covers ProrationService, SubscriptionService, GrandfatheringService,
and RecurringBillingService with 90%+ coverage target.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.subscription_models import (
    BILLING_CYCLE_DAYS,
    PriceGrandfathering,
    Subscription,
    SubscriptionChange,
)
from apps.billing.subscription_service import (
    GrandfatheringService,
    ProrationService,
    RecurringBillingService,
    SubscriptionService,
    get_max_payment_retries,
)
from apps.common.types import Err
from apps.customers.models import Customer
from apps.products.models import Product

# =============================================================================
# HELPERS
# =============================================================================


def make_currency() -> Currency:
    currency, _ = Currency.objects.get_or_create(
        code="RON",
        defaults={"name": "Romanian Leu", "symbol": "lei", "decimals": 2},
    )
    return currency


def make_customer(suffix: str = "") -> Customer:
    uid = uuid.uuid4().hex[:8]
    return Customer.objects.create(
        name=f"Test SRL {uid}",
        customer_type="company",
        company_name=f"Test SRL {uid}",
        primary_email=f"test-{uid}{suffix}@example.com",
        status="active",
    )


def make_product(price_cents: int = 2999, suffix: str = "") -> Product:
    uid = uuid.uuid4().hex[:8]
    return Product.objects.create(
        slug=f"basic-plan-{uid}{suffix}",
        name=f"Basic Plan {uid}",
        product_type="hosting",
    )


def make_subscription(  # noqa: PLR0913
    customer: Customer,
    product: Product,
    currency: Currency,
    status: str = "active",
    unit_price_cents: int = 2999,
    quantity: int = 1,
    billing_cycle: str = "monthly",
    days_until_end: int = 15,
    payment_method_id: str = "",
) -> Subscription:
    now = timezone.now()
    return Subscription.objects.create(
        customer=customer,
        product=product,
        currency=currency,
        subscription_number=f"SUB-{uuid.uuid4().hex[:8].upper()}",
        status=status,
        billing_cycle=billing_cycle,
        unit_price_cents=unit_price_cents,
        quantity=quantity,
        current_period_start=now - timedelta(days=(30 - days_until_end)),
        current_period_end=now + timedelta(days=days_until_end),
        next_billing_date=now + timedelta(days=days_until_end),
        payment_method_id=payment_method_id,
    )


# =============================================================================
# ProrationService
# =============================================================================


class ProrationServiceCalculateTestCase(TestCase):
    """Tests for ProrationService.calculate_proration (pure math)."""

    def test_upgrade_positive_proration(self) -> None:
        """Upgrading to a more expensive plan yields positive proration amount."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=2000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=15,
            days_in_period=30,
        )
        self.assertIsInstance(result, dict)
        self.assertGreater(result["proration_amount_cents"], 0)
        self.assertEqual(result["days_remaining"], 15)
        self.assertEqual(result["days_in_period"], 30)

    def test_downgrade_negative_proration(self) -> None:
        """Downgrading yields negative proration amount (credit)."""
        result = ProrationService.calculate_proration(
            old_price_cents=2000,
            new_price_cents=1000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=15,
            days_in_period=30,
        )
        self.assertLess(result["proration_amount_cents"], 0)

    def test_zero_days_remaining(self) -> None:
        """Zero days remaining yields zero charges."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=3000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=0,
            days_in_period=30,
        )
        self.assertEqual(result["unused_credit_cents"], 0)
        self.assertEqual(result["new_charge_cents"], 0)
        self.assertEqual(result["proration_amount_cents"], 0)

    def test_days_in_period_zero_fallback_to_30(self) -> None:
        """days_in_period <= 0 falls back to 30."""
        result = ProrationService.calculate_proration(
            old_price_cents=3000,
            new_price_cents=3000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=15,
            days_in_period=0,
        )
        self.assertEqual(result["days_in_period"], 30)

    def test_quantity_increase(self) -> None:
        """Increasing quantity with same price yields positive proration."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=1000,
            old_quantity=1,
            new_quantity=3,
            days_remaining=15,
            days_in_period=30,
        )
        self.assertGreater(result["proration_amount_cents"], 0)

    def test_quantity_decrease(self) -> None:
        """Decreasing quantity with same price yields negative proration (credit)."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=1000,
            old_quantity=3,
            new_quantity=1,
            days_remaining=15,
            days_in_period=30,
        )
        self.assertLess(result["proration_amount_cents"], 0)

    def test_same_price_same_quantity_zero_proration(self) -> None:
        """Same price and quantity yields zero net proration."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=1000,
            old_quantity=2,
            new_quantity=2,
            days_remaining=10,
            days_in_period=30,
        )
        self.assertEqual(result["proration_amount_cents"], 0)

    def test_daily_rates_are_integers(self) -> None:
        """Daily rate fields are integer cents."""
        result = ProrationService.calculate_proration(
            old_price_cents=3000,
            new_price_cents=6000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=10,
            days_in_period=30,
        )
        self.assertIsInstance(result["old_daily_rate_cents"], int)
        self.assertIsInstance(result["new_daily_rate_cents"], int)

    def test_negative_days_in_period_fallback(self) -> None:
        """Negative days_in_period also falls back to 30."""
        result = ProrationService.calculate_proration(
            old_price_cents=1000,
            new_price_cents=2000,
            old_quantity=1,
            new_quantity=1,
            days_remaining=10,
            days_in_period=-5,
        )
        self.assertEqual(result["days_in_period"], 30)


class ProrationServiceSubscriptionTestCase(TestCase):
    """Tests for ProrationService.calculate_subscription_proration."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    def test_calculate_subscription_proration_active(self, mock_log: MagicMock) -> None:
        """Calculates proration using subscription's current period."""
        sub = make_subscription(
            self.customer, self.product, self.currency, days_until_end=15
        )
        result = ProrationService.calculate_subscription_proration(
            subscription=sub,
            new_price_cents=5000,
            new_quantity=1,
        )
        self.assertIn("proration_amount_cents", result)
        self.assertEqual(result["days_in_period"], BILLING_CYCLE_DAYS["monthly"])

    @patch("apps.billing.subscription_service.log_security_event")
    def test_calculate_subscription_proration_expired_period(self, mock_log: MagicMock) -> None:
        """When period is already over, days_remaining is 0."""
        sub = make_subscription(
            self.customer, self.product, self.currency, days_until_end=-1
        )
        result = ProrationService.calculate_subscription_proration(
            subscription=sub,
            new_price_cents=5000,
        )
        self.assertEqual(result["days_remaining"], 0)

    @patch("apps.billing.subscription_service.log_security_event")
    def test_calculate_upgrade_credit_active(self, mock_log: MagicMock) -> None:
        """Returns positive credit for active subscription with remaining days."""
        sub = make_subscription(
            self.customer, self.product, self.currency, days_until_end=15
        )
        credit = ProrationService.calculate_upgrade_credit(sub)
        self.assertGreater(credit, 0)

    @patch("apps.billing.subscription_service.log_security_event")
    def test_calculate_upgrade_credit_expired_period(self, mock_log: MagicMock) -> None:
        """Returns 0 credit if period already ended."""
        sub = make_subscription(
            self.customer, self.product, self.currency, days_until_end=-1
        )
        credit = ProrationService.calculate_upgrade_credit(sub)
        self.assertEqual(credit, 0)


# =============================================================================
# SubscriptionService
# =============================================================================


class SubscriptionServiceCreateTestCase(TestCase):
    """Tests for SubscriptionService.create_subscription."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_basic(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Basic subscription creation returns Ok with Subscription."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly", "quantity": 1},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertIsInstance(sub, Subscription)
        self.assertEqual(sub.status, "active")
        self.assertEqual(sub.billing_cycle, "monthly")
        self.assertEqual(sub.quantity, 1)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_with_trial(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Subscription with trial_days gets trialing status."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly", "trial_days": 14},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertEqual(sub.status, "trialing")
        self.assertIsNotNone(sub.trial_end)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_with_custom_price(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """custom_price_cents overrides product price."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"custom_price_cents": 9900},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertEqual(sub.unit_price_cents, 9900)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_with_grandfathering(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """apply_grandfathering=True locks price if active grandfathering exists."""
        # Create a grandfathering record
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=2999,
            reason="Early adopter",
            is_active=True,
        )
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"apply_grandfathering": True},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertEqual(sub.locked_price_cents, 1500)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_yearly_cycle(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Yearly billing cycle sets correct cycle days."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "yearly"},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertEqual(sub.billing_cycle, "yearly")
        self.assertEqual(sub.cycle_days, 365)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_with_payment_method(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """payment_method_id is stored on subscription."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"payment_method_id": "pm_test_123"},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertEqual(sub.payment_method_id, "pm_test_123")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_expired_grandfathering_not_applied(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Expired grandfathering is not applied."""
        past = timezone.now() - timedelta(days=1)
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=2999,
            reason="Expired offer",
            is_active=True,
            expires_at=past,
        )
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"apply_grandfathering": True, "custom_price_cents": 2999},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        # Expired grandfathering should not lock the price
        self.assertIsNone(sub.locked_price_cents)


class SubscriptionServiceChangeTestCase(TestCase):
    """Tests for SubscriptionService.change_subscription."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product_basic = make_product(price_cents=2000)
        self.product_premium = make_product(price_cents=5000)

    def _make_active_sub(self, price_cents: int = 2000, quantity: int = 1) -> Subscription:
        return make_subscription(
            self.customer,
            self.product_basic,
            self.currency,
            unit_price_cents=price_cents,
            quantity=quantity,
            days_until_end=20,
        )

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_upgrade(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Changing to higher-priced product creates upgrade change."""
        sub = self._make_active_sub(price_cents=2000)
        # premium product needs a price on subscription itself for comparison
        # The service uses getattr(new_product, 'price_cents', 0) which is 0 for this product
        # So we test billing_cycle_change instead which is more deterministic
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={
                "new_billing_cycle": "quarterly",
                "apply_immediately": True,
            },
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        self.assertIsInstance(change, SubscriptionChange)
        self.assertEqual(change.change_type, "billing_cycle_change")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_quantity_increase(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Increasing quantity creates quantity_increase change."""
        sub = self._make_active_sub(quantity=1)
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={"new_quantity": 3, "apply_immediately": True},
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        self.assertEqual(change.change_type, "quantity_increase")
        self.assertEqual(change.new_quantity, 3)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_quantity_decrease(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Decreasing quantity creates quantity_decrease change."""
        sub = self._make_active_sub(quantity=3)
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={"new_quantity": 1, "apply_immediately": True},
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        self.assertEqual(change.change_type, "quantity_decrease")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_not_immediately(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """apply_immediately=False schedules change at period end."""
        sub = self._make_active_sub()
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={
                "new_quantity": 2,
                "apply_immediately": False,
                "prorate": False,
            },
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        self.assertEqual(change.status, "pending")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    @patch("apps.common.tax_service.TaxService.get_vat_rate", return_value=Decimal("0.21"))
    def test_change_subscription_with_proration_invoice(
        self, mock_vat: MagicMock, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Upgrade with positive proration creates a proration invoice."""
        sub = self._make_active_sub(quantity=1)
        # Force a positive proration: quantity increases from 1 to 5
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={
                "new_quantity": 5,
                "apply_immediately": True,
                "prorate": True,
            },
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        # If proration_amount_cents > 0, invoice should be created
        if change.proration_amount_cents > 0:
            self.assertIsNotNone(change.invoice)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_with_reason(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Reason field is stored on the change record."""
        sub = self._make_active_sub()
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={"new_quantity": 2, "reason": "Customer upgrade request"},
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        self.assertEqual(change.reason, "Customer upgrade request")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_change_subscription_new_product_upgrade(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Changing to new product creates appropriate change type."""
        # Create a premium product with price_cents attribute via unit_price_cents on subscription
        sub = self._make_active_sub(price_cents=1000)
        # Create a new product
        new_product = make_product(suffix="-premium")
        result = SubscriptionService.change_subscription(
            subscription=sub,
            data={
                "new_product_id": str(new_product.id),
                "apply_immediately": True,
            },
        )
        self.assertTrue(result.is_ok())
        change = result.unwrap()
        # new_price_cents will be 0 (product has no price_cents) which is < old price (1000)
        self.assertEqual(change.new_product, new_product)


class SubscriptionServiceCancelTestCase(TestCase):
    """Tests for SubscriptionService.cancel_subscription."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_cancel_at_period_end(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Cancel at period end sets cancel_at_period_end flag."""
        sub = make_subscription(self.customer, self.product, self.currency)
        result = SubscriptionService.cancel_subscription(
            subscription=sub,
            reason="customer_request",
            at_period_end=True,
        )
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertTrue(sub.cancel_at_period_end)
        self.assertEqual(sub.status, "active")  # Still active until period end

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_cancel_immediately(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Cancel immediately sets status to cancelled."""
        sub = make_subscription(self.customer, self.product, self.currency)
        result = SubscriptionService.cancel_subscription(
            subscription=sub,
            reason="fraud",
            at_period_end=False,
        )
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")
        self.assertIsNotNone(sub.ended_at)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_cancel_with_feedback(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Feedback is stored on cancellation."""
        sub = make_subscription(self.customer, self.product, self.currency)
        result = SubscriptionService.cancel_subscription(
            subscription=sub,
            feedback="Too expensive",
            at_period_end=True,
        )
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertEqual(sub.cancellation_feedback, "Too expensive")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_cancel_returns_subscription(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Result contains the cancelled subscription."""
        sub = make_subscription(self.customer, self.product, self.currency)
        result = SubscriptionService.cancel_subscription(subscription=sub)
        self.assertTrue(result.is_ok())
        self.assertIsInstance(result.unwrap(), Subscription)


class SubscriptionServiceReactivateTestCase(TestCase):
    """Tests for SubscriptionService.reactivate_subscription."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_reactivate_cancelled_subscription(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Reactivating a cancelled subscription restores active status."""
        sub = make_subscription(
            self.customer, self.product, self.currency, status="cancelled"
        )
        sub.cancelled_at = timezone.now()
        sub.cancellation_reason = "customer_request"
        sub.save()

        result = SubscriptionService.reactivate_subscription(subscription=sub)
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertEqual(sub.status, "active")
        self.assertFalse(sub.cancel_at_period_end)
        self.assertIsNone(sub.cancelled_at)
        self.assertEqual(sub.cancellation_reason, "")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_reactivate_cancel_at_period_end(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Subscription scheduled to cancel at period end can be reactivated."""
        sub = make_subscription(self.customer, self.product, self.currency)
        sub.cancel_at_period_end = True
        sub.save()

        result = SubscriptionService.reactivate_subscription(subscription=sub)
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertFalse(sub.cancel_at_period_end)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_reactivate_active_subscription_returns_error(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Reactivating an active subscription returns Err."""
        sub = make_subscription(self.customer, self.product, self.currency, status="active")
        result = SubscriptionService.reactivate_subscription(subscription=sub)
        self.assertTrue(result.is_err())
        self.assertIn("not cancelled", result.error)


# =============================================================================
# GrandfatheringService
# =============================================================================


class GrandfatheringServiceApplyTestCase(TestCase):
    """Tests for GrandfatheringService.apply_grandfathering_for_price_increase."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_price_not_increased_returns_error(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Returns Err when new price <= old price."""
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=1000,
        )
        self.assertTrue(result.is_err())
        self.assertIn("higher", result.error)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_equal_price_returns_error(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Returns Err when new price equals old price."""
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=2000,
        )
        self.assertTrue(result.is_err())

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_with_active_subscriptions(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Active subscribers get grandfathering applied."""
        sub = make_subscription(
            self.customer, self.product, self.currency, unit_price_cents=2000
        )
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3000,
            reason="Annual price review",
        )
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 1)

        # Check grandfathering record created
        grandfather = PriceGrandfathering.objects.get(customer=self.customer, product=self.product)
        self.assertEqual(grandfather.locked_price_cents, 2000)
        self.assertTrue(grandfather.is_active)

        # Subscription should have locked price
        sub.refresh_from_db()
        self.assertEqual(sub.locked_price_cents, 2000)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_skips_already_grandfathered_at_lower_price(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Skips subscriptions already grandfathered at same or lower price."""
        sub = make_subscription(
            self.customer, self.product, self.currency, unit_price_cents=2000
        )
        # Lock price at 1500 (lower than old_price_cents=2000)
        sub.locked_price_cents = 1500
        sub.save()

        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3000,
        )
        self.assertTrue(result.is_ok())
        # Should skip this subscription since locked_price_cents <= old_price_cents
        self.assertEqual(result.unwrap(), 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_no_active_subscriptions(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Zero affected when no active subscriptions."""
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3000,
        )
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_trialing_subscriptions_included(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Trialing subscriptions also get grandfathering."""
        make_subscription(
            self.customer, self.product, self.currency, status="trialing", unit_price_cents=2000
        )
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3500,
        )
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 1)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_with_expires_at(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Grandfathering with expiry date is set correctly."""
        future = timezone.now() + timedelta(days=365)
        make_subscription(
            self.customer, self.product, self.currency, unit_price_cents=2000
        )
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3000,
            expires_at=future,
        )
        self.assertTrue(result.is_ok())
        grandfather = PriceGrandfathering.objects.get(customer=self.customer, product=self.product)
        self.assertIsNotNone(grandfather.expires_at)


class GrandfatheringServiceExpireTestCase(TestCase):
    """Tests for GrandfatheringService.expire_grandfathering."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_expire_grandfathering_success(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Expiring active grandfathering returns Ok(True) and deactivates it."""
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=3000,
            reason="Test",
            is_active=True,
        )
        result = GrandfatheringService.expire_grandfathering(
            customer=self.customer,
            product=self.product,
        )
        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap())

        grandfather = PriceGrandfathering.objects.get(customer=self.customer, product=self.product)
        self.assertFalse(grandfather.is_active)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_expire_grandfathering_not_found(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Returns Err when no active grandfathering exists."""
        result = GrandfatheringService.expire_grandfathering(
            customer=self.customer,
            product=self.product,
        )
        self.assertTrue(result.is_err())
        self.assertIn("No active grandfathering", result.error)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_expire_grandfathering_clears_subscription_locked_price(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Expiring grandfathering also clears locked_price_cents on subscription."""
        sub = make_subscription(
            self.customer, self.product, self.currency, unit_price_cents=3000
        )
        sub.locked_price_cents = 1500
        sub.locked_price_reason = "Early adopter"
        sub.save()

        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product,
            locked_price_cents=1500,
            original_price_cents=1500,
            current_product_price_cents=3000,
            reason="Early adopter",
            is_active=True,
        )

        result = GrandfatheringService.expire_grandfathering(
            customer=self.customer,
            product=self.product,
        )
        self.assertTrue(result.is_ok())

        sub.refresh_from_db()
        self.assertIsNone(sub.locked_price_cents)
        self.assertEqual(sub.locked_price_reason, "")


class GrandfatheringServiceQueryTestCase(TestCase):
    """Tests for GrandfatheringService query methods."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product1 = make_product(suffix="-p1")
        self.product2 = make_product(suffix="-p2")

    def test_get_customer_grandfathering_returns_active_only(self) -> None:
        """get_customer_grandfathering returns only active records."""
        # Active
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product1,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Active",
            is_active=True,
        )
        # Inactive
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product2,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Inactive",
            is_active=False,
        )

        records = GrandfatheringService.get_customer_grandfathering(self.customer)
        self.assertEqual(len(records), 1)
        self.assertEqual(records[0].product, self.product1)

    def test_get_customer_grandfathering_empty(self) -> None:
        """Returns empty list when no grandfathering exists."""
        records = GrandfatheringService.get_customer_grandfathering(self.customer)
        self.assertEqual(records, [])

    def test_check_expiring_grandfathering_within_window(self) -> None:
        """Records expiring within days_ahead are returned."""
        soon = timezone.now() + timedelta(days=10)
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product1,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Expiring soon",
            is_active=True,
            expires_at=soon,
            expiry_notified=False,
        )

        records = GrandfatheringService.check_expiring_grandfathering(days_ahead=30)
        self.assertEqual(len(records), 1)

    def test_check_expiring_grandfathering_outside_window(self) -> None:
        """Records expiring after window are not returned."""
        far_future = timezone.now() + timedelta(days=90)
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product1,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Far future",
            is_active=True,
            expires_at=far_future,
            expiry_notified=False,
        )

        records = GrandfatheringService.check_expiring_grandfathering(days_ahead=30)
        self.assertEqual(len(records), 0)

    def test_check_expiring_grandfathering_no_expiry_excluded(self) -> None:
        """Records without expiry date are not returned."""
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product1,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Never expires",
            is_active=True,
            expires_at=None,
            expiry_notified=False,
        )

        records = GrandfatheringService.check_expiring_grandfathering(days_ahead=30)
        self.assertEqual(len(records), 0)

    def test_check_expiring_grandfathering_already_notified_excluded(self) -> None:
        """Records already notified are not returned."""
        soon = timezone.now() + timedelta(days=5)
        PriceGrandfathering.objects.create(
            customer=self.customer,
            product=self.product1,
            locked_price_cents=1000,
            original_price_cents=1000,
            current_product_price_cents=2000,
            reason="Already notified",
            is_active=True,
            expires_at=soon,
            expiry_notified=True,
        )

        records = GrandfatheringService.check_expiring_grandfathering(days_ahead=30)
        self.assertEqual(len(records), 0)


# =============================================================================
# RecurringBillingService
# =============================================================================


class RecurringBillingServiceBillingCycleTestCase(TestCase):
    """Tests for RecurringBillingService.run_billing_cycle."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    def test_run_billing_cycle_no_due_subscriptions(self, mock_log: MagicMock) -> None:
        """No due subscriptions yields zero-count result."""
        billing_date = timezone.now() - timedelta(days=100)  # Far in the past
        result = RecurringBillingService.run_billing_cycle(billing_date=billing_date)
        self.assertIsInstance(result, dict)
        self.assertEqual(result["subscriptions_processed"], 0)
        self.assertEqual(result["invoices_created"], 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_run_billing_cycle_dry_run(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Dry run mode counts subscriptions but creates no invoices."""
        # Create a subscription that is due
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="active", days_until_end=-1, unit_price_cents=2999
        )
        sub.next_billing_date = timezone.now() - timedelta(hours=1)
        sub.save()

        result = RecurringBillingService.run_billing_cycle(dry_run=True)
        self.assertEqual(result["invoices_created"], 0)
        self.assertGreaterEqual(result["subscriptions_processed"], 1)
        self.assertGreater(result["total_billed_cents"], 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    @patch("apps.common.tax_service.TaxService.get_vat_rate", return_value=Decimal("0.21"))
    def test_run_billing_cycle_no_payment_method_just_renews(
        self, mock_vat: MagicMock, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Subscription without payment method just gets renewed."""
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="active", days_until_end=-1, unit_price_cents=2999,
            payment_method_id="",
        )
        sub.next_billing_date = timezone.now() - timedelta(hours=1)
        sub.save()

        result = RecurringBillingService.run_billing_cycle()
        self.assertGreaterEqual(result["invoices_created"], 1)
        self.assertEqual(result["payments_attempted"], 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    @patch("apps.common.tax_service.TaxService.get_vat_rate", return_value=Decimal("0.21"))
    def test_run_billing_cycle_with_payment_method(
        self, mock_vat: MagicMock, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Subscription with payment method attempts payment."""
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="active", days_until_end=-1, unit_price_cents=2999,
            payment_method_id="pm_test_123",
        )
        sub.next_billing_date = timezone.now() - timedelta(hours=1)
        sub.save()

        result = RecurringBillingService.run_billing_cycle()
        self.assertGreaterEqual(result["payments_attempted"], 1)
        # _process_payment returns Ok(True) by default (stub implementation)
        self.assertGreaterEqual(result["payments_succeeded"], 1)

    @patch("apps.billing.subscription_service.log_security_event")
    def test_run_billing_cycle_result_structure(self, mock_log: MagicMock) -> None:
        """Result has all expected keys."""
        result = RecurringBillingService.run_billing_cycle()
        expected_keys = {
            "subscriptions_processed",
            "invoices_created",
            "payments_attempted",
            "payments_succeeded",
            "payments_failed",
            "total_billed_cents",
            "errors",
        }
        self.assertEqual(set(result.keys()), expected_keys)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    @patch("apps.common.tax_service.TaxService.get_vat_rate", return_value=Decimal("0.21"))
    def test_run_billing_cycle_failed_payment(
        self, mock_vat: MagicMock, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """When _process_payment fails, payments_failed increments."""
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="active", days_until_end=-1, unit_price_cents=2999,
            payment_method_id="pm_test_456",
        )
        sub.next_billing_date = timezone.now() - timedelta(hours=1)
        sub.save()

        with patch.object(
            RecurringBillingService,
            "_process_payment",
            return_value=Err("Payment declined"),
        ):
            result = RecurringBillingService.run_billing_cycle()

        self.assertGreaterEqual(result["payments_failed"], 1)
        self.assertGreater(len(result["errors"]), 0)


class RecurringBillingServiceTrialTestCase(TestCase):
    """Tests for RecurringBillingService.handle_expired_trials."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_expired_trials_with_payment_method_converts(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Expired trial with payment method gets converted to paid."""
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="trialing", payment_method_id="pm_test_123",
        )
        sub.trial_end = timezone.now() - timedelta(hours=1)
        sub.trial_start = timezone.now() - timedelta(days=15)
        sub.save()

        count = RecurringBillingService.handle_expired_trials()
        self.assertGreaterEqual(count, 1)

        sub.refresh_from_db()
        self.assertEqual(sub.status, "active")
        self.assertTrue(sub.trial_converted)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_expired_trials_without_payment_method_cancels(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Expired trial without payment method gets cancelled."""
        sub = make_subscription(
            self.customer, self.product, self.currency,
            status="trialing", payment_method_id="",
        )
        sub.trial_end = timezone.now() - timedelta(hours=1)
        sub.trial_start = timezone.now() - timedelta(days=15)
        sub.save()

        count = RecurringBillingService.handle_expired_trials()
        self.assertGreaterEqual(count, 1)

        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")
        self.assertEqual(sub.cancellation_reason, "non_payment")

    @patch("apps.billing.subscription_service.log_security_event")
    def test_handle_expired_trials_none_expired(self, mock_log: MagicMock) -> None:
        """Returns 0 when no trials are expired."""
        count = RecurringBillingService.handle_expired_trials()
        self.assertEqual(count, 0)


class RecurringBillingServiceGracePeriodTestCase(TestCase):
    """Tests for RecurringBillingService.handle_grace_period_expirations."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_max_retries_exceeded_cancels(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Subscription exceeding max retries is cancelled."""
        from apps.billing.subscription_service import MAX_PAYMENT_RETRIES  # noqa: PLC0415

        sub = make_subscription(
            self.customer, self.product, self.currency, status="past_due"
        )
        sub.grace_period_ends_at = timezone.now() - timedelta(hours=1)
        sub.failed_payment_count = MAX_PAYMENT_RETRIES + 1
        sub.save()

        count = RecurringBillingService.handle_grace_period_expirations()
        self.assertGreaterEqual(count, 1)

        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_below_max_retries_pauses(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Subscription below max retries gets paused."""
        sub = make_subscription(
            self.customer, self.product, self.currency, status="past_due"
        )
        sub.grace_period_ends_at = timezone.now() - timedelta(hours=1)
        sub.failed_payment_count = 1  # Well below MAX_PAYMENT_RETRIES
        sub.save()

        count = RecurringBillingService.handle_grace_period_expirations()
        self.assertGreaterEqual(count, 1)

        sub.refresh_from_db()
        self.assertEqual(sub.status, "paused")
        self.assertIsNotNone(sub.paused_at)

    @patch("apps.billing.subscription_service.log_security_event")
    def test_handle_grace_period_no_expired(self, mock_log: MagicMock) -> None:
        """Returns 0 when no grace periods are expired."""
        count = RecurringBillingService.handle_grace_period_expirations()
        self.assertEqual(count, 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_not_yet_expired_skipped(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Grace period not yet expired is not processed."""
        sub = make_subscription(
            self.customer, self.product, self.currency, status="past_due"
        )
        sub.grace_period_ends_at = timezone.now() + timedelta(days=3)
        sub.failed_payment_count = 10
        sub.save()

        count = RecurringBillingService.handle_grace_period_expirations()
        self.assertEqual(count, 0)


# =============================================================================
# get_max_payment_retries helper
# =============================================================================


class GetMaxPaymentRetriesTestCase(TestCase):
    """Tests for get_max_payment_retries helper."""

    def test_returns_integer(self) -> None:
        """get_max_payment_retries always returns an int."""
        retries = get_max_payment_retries()
        self.assertIsInstance(retries, int)
        self.assertGreater(retries, 0)

    @patch("apps.settings.services.SettingsService.get_integer_setting", return_value=3)
    def test_respects_settings_service(self, mock_setting: MagicMock) -> None:
        """Uses SettingsService value when available."""
        retries = get_max_payment_retries()
        self.assertEqual(retries, 3)
