"""
Comprehensive tests for apps.billing.subscription_service.

Covers SubscriptionService, GrandfatheringService, and non-renewal
SubscriptionLifecycleService behavior.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from apps.billing.currency_models import Currency
from apps.billing.metering_models import BillingCycle
from apps.billing.subscription_models import (
    PriceGrandfathering,
    Subscription,
)
from apps.billing.subscription_service import (
    GrandfatheringService,
    SubscriptionLifecycleService,
    SubscriptionService,
    get_max_payment_retries,
)
from apps.customers.models import Customer
from apps.products.models import Product, ProductPrice

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
    """Create a product with a real list price.

    `price_cents` used to be accepted and silently ignored — no ProductPrice was created. The
    subscription code read the (nonexistent) `product.price_cents` and resolved 0, so these
    fixtures agreed with the bug and it went unnoticed (#209). The list price lives on
    ProductPrice, so create one.
    """
    uid = uuid.uuid4().hex[:8]
    product = Product.objects.create(
        slug=f"basic-plan-{uid}{suffix}",
        name=f"Basic Plan {uid}",
        product_type="hosting",
    )
    ProductPrice.objects.create(
        product=product,
        currency=make_currency(),
        monthly_price_cents=price_cents,
        is_active=True,
    )
    return product


def make_subscription(  # noqa: PLR0913
    customer: Customer,
    product: Product,
    currency: Currency,
    status: str = "active",
    unit_price_cents: int = 2999,
    quantity: int = 1,
    billing_cycle: str = "monthly",
    days_until_end: int = 15,
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
    )


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
        cycle = BillingCycle.objects.get(subscription=sub)
        self.assertEqual(cycle.status, "active")
        self.assertEqual(cycle.period_start, sub.current_period_start)
        self.assertEqual(cycle.period_end, sub.current_period_end)
        self.assertEqual(cycle.base_charge_cents, 0)

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
    def test_create_subscription_starts_without_automatic_payment_authority(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """Creation cannot silently opt a customer into off-session collection."""
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"billing_cycle": "monthly"},
        )
        self.assertTrue(result.is_ok())
        sub = result.unwrap()
        self.assertFalse(sub.auto_payment_enabled)
        self.assertIsNone(sub.saved_payment_method_id)
        self.assertIsNone(sub.payment_authorization_id)
        self.assertEqual(sub.billing_anchor_day, sub.current_period_start.day)
        self.assertIsNotNone(sub.next_proforma_at)
        self.assertIsNotNone(sub.next_charge_at)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_create_subscription_rejects_legacy_raw_gateway_method(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        result = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={"payment_method_id": "pm_unverified"},  # type: ignore[typeddict-unknown-key]  # legacy payload test
        )

        self.assertTrue(result.is_err())
        self.assertIn("authorization", result.unwrap_err().lower())

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_idempotent_service_enrollment_rejects_changed_financial_terms(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        """A retry is idempotent only when it describes the subscription already persisted."""
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        plan = ServicePlan.objects.create(
            name="Idempotent enrollment plan",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
        )
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Idempotent enrollment service",
            username=f"idempotent{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="pending",
        )
        first = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={
                "service_id": str(service.id),
                "billing_cycle": "monthly",
                "quantity": 1,
                "custom_price_cents": 2999,
            },
        )
        self.assertTrue(first.is_ok(), first)

        exact_retry = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={
                "service_id": str(service.id),
                "billing_cycle": "monthly",
                "quantity": 1,
                "custom_price_cents": 2999,
            },
        )
        self.assertTrue(exact_retry.is_ok(), exact_retry)
        self.assertEqual(exact_retry.unwrap().id, first.unwrap().id)

        retry = SubscriptionService.create_subscription(
            customer=self.customer,
            product=self.product,
            data={
                "service_id": str(service.id),
                "billing_cycle": "yearly",
                "quantity": 1,
                "custom_price_cents": 29_999,
            },
        )

        self.assertTrue(retry.is_err())
        self.assertIn("does not match", retry.unwrap_err().lower())
        self.assertEqual(Subscription.objects.filter(service=service).count(), 1)

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
        """Immediate cancellation also terminates the linked service renewal."""
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        plan = ServicePlan.objects.create(name="Cancel plan", plan_type="shared_hosting", price_monthly=29.99)
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Cancelled service",
            username="cancelled_service",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="active",
            auto_renew=True,
        )
        sub = make_subscription(self.customer, self.product, self.currency)
        sub.service = service
        sub.save(update_fields=["service", "updated_at"])

        result = SubscriptionService.cancel_subscription(
            subscription=sub,
            reason="fraud",
            at_period_end=False,
        )
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")
        self.assertIsNotNone(sub.ended_at)
        service.refresh_from_db()
        self.assertEqual(service.status, "expired")
        self.assertFalse(service.auto_renew)

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

    def _make_service(self):
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        plan = ServicePlan.objects.create(name="Reactivate plan", plan_type="shared_hosting", price_monthly=29.99)
        return Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Reactivated service",
            username=f"reactivated_{uuid.uuid4().hex[:8]}",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="active",
            auto_renew=True,
        )

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_reactivate_cancelled_subscription(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Reactivation within the paid period restores subscription and service."""
        service = self._make_service()
        sub = make_subscription(self.customer, self.product, self.currency)
        sub.service = service
        sub.save(update_fields=["service", "updated_at"])
        cancellation = SubscriptionService.cancel_subscription(subscription=sub, at_period_end=False)
        self.assertTrue(cancellation.is_ok())

        result = SubscriptionService.reactivate_subscription(subscription=cancellation.unwrap())
        self.assertTrue(result.is_ok())
        sub.refresh_from_db()
        self.assertEqual(sub.status, "active")
        self.assertFalse(sub.cancel_at_period_end)
        self.assertIsNone(sub.cancelled_at)
        self.assertEqual(sub.cancellation_reason, "")
        service.refresh_from_db()
        self.assertEqual(service.status, "active")
        self.assertTrue(service.auto_renew)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_reactivate_cancelled_subscription_rejects_ended_paid_period(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        sub = make_subscription(self.customer, self.product, self.currency, status="cancelled", days_until_end=-1)

        result = SubscriptionService.reactivate_subscription(subscription=sub)

        self.assertTrue(result.is_err())
        self.assertIn("paid period has ended", result.unwrap_err().lower())
        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")

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
    def test_reactivate_active_subscription_returns_error(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
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
        sub = make_subscription(self.customer, self.product, self.currency, unit_price_cents=2000)
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
        sub = make_subscription(self.customer, self.product, self.currency, unit_price_cents=2000)
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
    def test_apply_grandfathering_no_active_subscriptions(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
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
        make_subscription(self.customer, self.product, self.currency, status="trialing", unit_price_cents=2000)
        result = GrandfatheringService.apply_grandfathering_for_price_increase(
            product=self.product,
            old_price_cents=2000,
            new_price_cents=3500,
        )
        self.assertTrue(result.is_ok())
        self.assertEqual(result.unwrap(), 1)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_apply_grandfathering_with_expires_at(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        """Grandfathering with expiry date is set correctly."""
        future = timezone.now() + timedelta(days=365)
        make_subscription(self.customer, self.product, self.currency, unit_price_cents=2000)
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
        """Expiring a customer/product grant clears every service subscription."""
        subscriptions = [
            make_subscription(self.customer, self.product, self.currency, unit_price_cents=3000),
            make_subscription(self.customer, self.product, self.currency, unit_price_cents=3000),
        ]
        for subscription in subscriptions:
            subscription.locked_price_cents = 1500
            subscription.locked_price_reason = "Early adopter"
            subscription.save()

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

        for subscription in subscriptions:
            subscription.refresh_from_db()
            self.assertIsNone(subscription.locked_price_cents)
            self.assertEqual(subscription.locked_price_reason, "")


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
# SubscriptionLifecycleService
# =============================================================================


class SubscriptionLifecycleServiceGracePeriodTestCase(TestCase):
    """Tests for explicit non-payment grace-period expiration."""

    def setUp(self) -> None:
        self.currency = make_currency()
        self.customer = make_customer()
        self.product = make_product()

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_max_retries_exceeded_cancels(
        self, mock_model_log: MagicMock, mock_log: MagicMock
    ) -> None:
        from apps.billing.subscription_service import MAX_PAYMENT_RETRIES  # noqa: PLC0415
        from apps.provisioning.models import Service, ServicePlan  # noqa: PLC0415

        plan = ServicePlan.objects.create(name="Grace plan", plan_type="shared_hosting", price_monthly=29.99)
        service = Service.objects.create(
            customer=self.customer,
            service_plan=plan,
            currency=self.currency,
            service_name="Grace service",
            username="grace_service",
            billing_cycle="monthly",
            price=Decimal("29.99"),
            status="active",
            auto_renew=True,
        )

        sub = make_subscription(self.customer, self.product, self.currency, status="past_due")
        sub.service = service
        sub.grace_period_ends_at = timezone.now() - timedelta(hours=1)
        sub.failed_payment_count = MAX_PAYMENT_RETRIES + 1
        sub.save()

        count, errors = SubscriptionLifecycleService.handle_grace_period_expirations()

        self.assertGreaterEqual(count, 1)
        self.assertEqual(errors, 0)
        sub.refresh_from_db()
        self.assertEqual(sub.status, "cancelled")
        service.refresh_from_db()
        self.assertFalse(service.auto_renew)
        self.assertEqual(service.status, "suspended")

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_below_max_retries_pauses(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        sub = make_subscription(self.customer, self.product, self.currency, status="past_due")
        sub.grace_period_ends_at = timezone.now() - timedelta(hours=1)
        sub.failed_payment_count = 1
        sub.save()

        count, errors = SubscriptionLifecycleService.handle_grace_period_expirations()

        self.assertGreaterEqual(count, 1)
        self.assertEqual(errors, 0)
        sub.refresh_from_db()
        self.assertEqual(sub.status, "paused")
        self.assertIsNotNone(sub.paused_at)

    @patch("apps.billing.subscription_service.log_security_event")
    def test_handle_grace_period_no_expired(self, mock_log: MagicMock) -> None:
        count, errors = SubscriptionLifecycleService.handle_grace_period_expirations()
        self.assertEqual(errors, 0)
        self.assertEqual(count, 0)

    @patch("apps.billing.subscription_service.log_security_event")
    @patch("apps.billing.subscription_models.log_security_event")
    def test_handle_grace_period_not_yet_expired_skipped(self, mock_model_log: MagicMock, mock_log: MagicMock) -> None:
        sub = make_subscription(self.customer, self.product, self.currency, status="past_due")
        sub.grace_period_ends_at = timezone.now() + timedelta(days=3)
        sub.failed_payment_count = 10
        sub.save()

        count, errors = SubscriptionLifecycleService.handle_grace_period_expirations()
        self.assertEqual(errors, 0)
        self.assertEqual(count, 0)

    @patch("apps.billing.subscription_models.Subscription._pause_now", side_effect=RuntimeError("transition broke"))
    def test_handle_grace_period_counts_isolated_item_failure(self, mock_pause: MagicMock) -> None:
        sub = make_subscription(self.customer, self.product, self.currency, status="past_due")
        sub.grace_period_ends_at = timezone.now() - timedelta(hours=1)
        sub.failed_payment_count = 1
        sub.save()

        count, errors = SubscriptionLifecycleService.handle_grace_period_expirations()

        self.assertEqual(count, 0)
        self.assertEqual(errors, 1)
        sub.refresh_from_db()
        self.assertEqual(sub.status, "past_due")


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
