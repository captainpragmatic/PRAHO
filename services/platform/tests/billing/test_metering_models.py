# ===============================================================================
# USAGE-BASED BILLING MODELS TEST SUITE
# ===============================================================================
"""
Comprehensive test suite for usage-based billing models.
Tests all metering models: UsageMeter, UsageEvent, UsageAggregation,
Subscription, BillingCycle, PricingTier, UsageThreshold, UsageAlert.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal

from django.db import IntegrityError, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import (
    BillingCycle,
    Currency,
    PricingTier,
    PricingTierBracket,
    Subscription,
    SubscriptionItem,
    UsageAggregation,
    UsageAlert,
    UsageEvent,
    UsageMeter,
    UsageThreshold,
)
from apps.customers.models import Customer
from apps.products.models import Product
from apps.provisioning.models import ServicePlan
from apps.users.models import User


class UsageMeterModelTestCase(TestCase):
    """Test UsageMeter model functionality."""

    def test_create_usage_meter(self):
        """Test creating a basic usage meter."""
        meter = UsageMeter.objects.create(
            name="disk_usage_gb",
            display_name="Disk Space Usage",
            description="Tracks disk space in gigabytes",
            aggregation_type="last",
            unit="gb",
            unit_display="GB",
            category="storage",
            is_active=True,
            is_billable=True,
        )

        self.assertEqual(meter.name, "disk_usage_gb")
        self.assertEqual(meter.aggregation_type, "last")
        self.assertEqual(meter.unit, "gb")
        self.assertTrue(meter.is_active)
        self.assertTrue(meter.is_billable)

    def test_meter_name_unique(self):
        """Test that meter names are unique."""
        UsageMeter.objects.create(
            name="bandwidth_gb",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

        with self.assertRaises(IntegrityError):
            UsageMeter.objects.create(
                name="bandwidth_gb",
                display_name="Bandwidth 2",
                aggregation_type="sum",
                unit="gb",
            )

    def test_aggregation_types(self):
        """Test all aggregation types are valid."""
        valid_types = ["sum", "count", "max", "last", "unique"]

        for agg_type in valid_types:
            meter = UsageMeter.objects.create(
                name=f"test_meter_{agg_type}",
                display_name=f"Test Meter {agg_type}",
                aggregation_type=agg_type,
                unit="count",
            )
            self.assertEqual(meter.aggregation_type, agg_type)

    def test_meter_categories(self):
        """Test all meter categories."""
        categories = [
            "storage", "bandwidth", "compute", "email",
            "database", "api", "domain", "ssl", "backup", "other"
        ]

        for category in categories:
            meter = UsageMeter.objects.create(
                name=f"test_{category}",
                display_name=f"Test {category}",
                aggregation_type="sum",
                unit="count",
                category=category,
            )
            self.assertEqual(meter.category, category)

    def test_rounding_modes(self):
        """Test rounding mode options."""
        modes = ["none", "up", "down", "nearest"]

        for mode in modes:
            meter = UsageMeter.objects.create(
                name=f"test_rounding_{mode}",
                display_name=f"Test {mode}",
                aggregation_type="sum",
                unit="gb",
                rounding_mode=mode,
            )
            self.assertEqual(meter.rounding_mode, mode)

    def test_get_unit_display_text(self):
        """Test unit display text method."""
        meter = UsageMeter.objects.create(
            name="test_unit",
            display_name="Test",
            aggregation_type="sum",
            unit="gb",
            unit_display="GB",
        )
        self.assertEqual(meter.get_unit_display_text(), "GB")

        meter2 = UsageMeter.objects.create(
            name="test_unit2",
            display_name="Test 2",
            aggregation_type="sum",
            unit="count",
        )
        # Should return Django's display value for choice
        self.assertIsNotNone(meter2.get_unit_display_text())

    def test_stripe_integration_fields(self):
        """Test Stripe meter integration fields."""
        meter = UsageMeter.objects.create(
            name="stripe_meter",
            display_name="Stripe Meter",
            aggregation_type="sum",
            unit="count",
            stripe_meter_id="meter_abc123",
            stripe_meter_event_name="api_calls",
        )
        self.assertEqual(meter.stripe_meter_id, "meter_abc123")
        self.assertEqual(meter.stripe_meter_event_name, "api_calls")


class UsageEventModelTestCase(TransactionTestCase):
    """Test UsageEvent model functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="individual",
            primary_email="test@example.com",
            status="active",
        )

        self.meter = UsageMeter.objects.create(
            name="api_requests",
            display_name="API Requests",
            aggregation_type="sum",
            unit="requests",
        )

    def test_create_usage_event(self):
        """Test creating a usage event."""
        event = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("100"),
            timestamp=timezone.now(),
            idempotency_key="unique-key-123",
            source="api_gateway",
        )

        self.assertEqual(event.meter, self.meter)
        self.assertEqual(event.customer, self.customer)
        self.assertEqual(event.value, Decimal("100"))
        self.assertEqual(event.source, "api_gateway")
        self.assertFalse(event.is_processed)

    def test_idempotency_key_uniqueness(self):
        """Test idempotency key prevents duplicates."""
        UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("100"),
            timestamp=timezone.now(),
            idempotency_key="duplicate-key",
        )

        with transaction.atomic(), self.assertRaises(IntegrityError):
            UsageEvent.objects.create(
                meter=self.meter,
                customer=self.customer,
                value=Decimal("200"),
                timestamp=timezone.now(),
                idempotency_key="duplicate-key",
            )

    def test_auto_generate_idempotency_key(self):
        """Test automatic idempotency key generation."""
        event = UsageEvent(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("100"),
            timestamp=timezone.now(),
        )
        # Generate key manually
        generated_key = event.generate_idempotency_key()
        self.assertIsNotNone(generated_key)
        self.assertEqual(len(generated_key), 64)  # SHA256 hex truncated

    def test_event_properties_json(self):
        """Test event properties JSON field."""
        event = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("1"),
            timestamp=timezone.now(),
            idempotency_key="props-test",
            properties={
                "endpoint": "/api/v1/users",
                "method": "GET",
                "response_time_ms": 45,
            },
        )

        event.refresh_from_db()
        self.assertEqual(event.properties["endpoint"], "/api/v1/users")
        self.assertEqual(event.properties["response_time_ms"], 45)

    def test_event_processing_status(self):
        """Test event processing status fields."""
        event = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("100"),
            timestamp=timezone.now(),
            idempotency_key="process-test",
        )

        self.assertFalse(event.is_processed)
        self.assertIsNone(event.processed_at)
        self.assertIsNone(event.aggregation)

        # Mark as processed
        event.is_processed = True
        event.processed_at = timezone.now()
        event.save()

        event.refresh_from_db()
        self.assertTrue(event.is_processed)
        self.assertIsNotNone(event.processed_at)


class SubscriptionModelTestCase(TransactionTestCase):
    """Test Subscription and related models."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="company",
            company_name="Test SRL",
            primary_email="test@example.com",
            status="active",
        )

        self.product = Product.objects.create(
            slug="basic-hosting",
            name="Basic Hosting",
            product_type="shared_hosting",
        )

        self.product2 = Product.objects.create(
            slug="bandwidth-addon",
            name="Bandwidth Add-on",
            product_type="addon",
        )

        self.meter = UsageMeter.objects.create(
            name="bandwidth_gb",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
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

    def test_create_subscription(self):
        """Test creating a subscription."""
        now = timezone.now()
        subscription = self._make_subscription(
            started_at=now,
        )

        self.assertEqual(subscription.customer, self.customer)
        self.assertEqual(subscription.status, "active")
        self.assertEqual(subscription.effective_price, Decimal("29.99"))
        self.assertTrue(subscription.is_active)

    def test_subscription_statuses(self):
        """Test all subscription statuses."""
        statuses = ["trialing", "active", "past_due", "paused", "cancelled", "expired"]

        for status in statuses:
            sub = self._make_subscription(status=status)
            self.assertEqual(sub.status, status)

    def test_subscription_is_active(self):
        """Test is_active property."""
        active_sub = self._make_subscription(status="active")
        self.assertTrue(active_sub.is_active)

        trial_sub = self._make_subscription(status="trialing")
        self.assertTrue(trial_sub.is_active)

        cancelled_sub = self._make_subscription(status="cancelled")
        self.assertFalse(cancelled_sub.is_active)

    def test_subscription_item(self):
        """Test subscription items with products."""
        subscription = self._make_subscription()

        item = SubscriptionItem.objects.create(
            subscription=subscription,
            product=self.product2,
            unit_price_cents=50,  # 0.50 per unit
        )

        self.assertEqual(item.effective_price_cents, 50)
        self.assertEqual(item.line_total_cents, 50)

    def test_subscription_item_unique_constraint(self):
        """Test subscription can only have one item per product."""
        subscription = self._make_subscription()

        SubscriptionItem.objects.create(
            subscription=subscription,
            product=self.product2,
            unit_price_cents=50,
        )

        with transaction.atomic(), self.assertRaises(IntegrityError):
            SubscriptionItem.objects.create(
                subscription=subscription,
                product=self.product2,
                unit_price_cents=100,
            )


class BillingCycleModelTestCase(TransactionTestCase):
    """Test BillingCycle model."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            customer_type="company",
            primary_email="test@example.com",
            status="active",
        )

        self.product = Product.objects.create(
            slug="basic-hosting-bc",
            name="Basic Hosting",
            product_type="shared_hosting",
        )

        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-BC-TEST001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    def test_create_billing_cycle(self):
        """Test creating a billing cycle."""
        now = timezone.now()
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
            base_charge_cents=2999,
        )

        self.assertEqual(cycle.subscription, self.subscription)
        self.assertEqual(cycle.status, "active")
        self.assertEqual(cycle.base_charge, Decimal("29.99"))

    def test_billing_cycle_statuses(self):
        """Test billing cycle statuses."""
        statuses = ["upcoming", "active", "closing", "closed", "invoiced", "finalized"]
        now = timezone.now()

        for i, status in enumerate(statuses):
            cycle = BillingCycle.objects.create(
                subscription=self.subscription,
                period_start=now + timedelta(days=i * 30),
                period_end=now + timedelta(days=(i + 1) * 30),
                status=status,
            )
            self.assertEqual(cycle.status, status)

    def test_is_current_property(self):
        """Test is_current property."""
        now = timezone.now()

        current_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=15),
            period_end=now + timedelta(days=15),
            status="active",
        )
        self.assertTrue(current_cycle.is_current)

        past_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=60),
            period_end=now - timedelta(days=30),
            status="finalized",
        )
        self.assertFalse(past_cycle.is_current)

    def test_close_billing_cycle(self):
        """Test closing a billing cycle."""
        now = timezone.now()
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=30),
            period_end=now,
            status="active",
        )

        cycle.close()

        self.assertEqual(cycle.status, "closed")
        self.assertIsNotNone(cycle.closed_at)

    def test_billing_cycle_amounts(self):
        """Test billing cycle amount calculations."""
        now = timezone.now()
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
            base_charge_cents=2999,
            usage_charge_cents=1500,
            discount_cents=500,
            credit_applied_cents=200,
            tax_cents=912,  # 19% VAT
            total_cents=4711,
        )

        self.assertEqual(cycle.base_charge, Decimal("29.99"))
        self.assertEqual(cycle.usage_charge, Decimal("15.00"))
        self.assertEqual(cycle.discount, Decimal("5.00"))
        self.assertEqual(cycle.credit_applied, Decimal("2.00"))
        self.assertEqual(cycle.tax, Decimal("9.12"))
        self.assertEqual(cycle.total, Decimal("47.11"))


class UsageAggregationModelTestCase(TransactionTestCase):
    """Test UsageAggregation model."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        self.product = Product.objects.create(
            slug="basic-agg",
            name="Basic",
            product_type="shared_hosting",
        )

        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-AGG-TEST001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

        self.meter = UsageMeter.objects.create(
            name="bandwidth",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

        now = timezone.now()
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
        )

    def test_create_aggregation(self):
        """Test creating an aggregation."""
        now = timezone.now()
        agg = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("150.5"),
            event_count=100,
        )

        self.assertEqual(agg.total_value, Decimal("150.5"))
        self.assertEqual(agg.event_count, 100)
        self.assertEqual(agg.status, "accumulating")

    def test_aggregation_overage_calculation(self):
        """Test overage calculation fields."""
        now = timezone.now()
        agg = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("150"),
            billable_value=Decimal("150"),
            included_allowance=Decimal("100"),
            overage_value=Decimal("50"),
            charge_cents=2500,  # 50 GB * 0.50
        )

        self.assertEqual(agg.overage_value, Decimal("50"))
        self.assertEqual(agg.charge, Decimal("25.00"))

    def test_unique_meter_customer_cycle_constraint(self):
        """Test unique constraint on meter/customer/cycle."""
        now = timezone.now()

        UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
        )

        with transaction.atomic(), self.assertRaises(IntegrityError):
            UsageAggregation.objects.create(
                meter=self.meter,
                customer=self.customer,
                billing_cycle=self.billing_cycle,
                period_start=now,
                period_end=now + timedelta(days=30),
            )


class PricingTierModelTestCase(TransactionTestCase):
    """Test PricingTier and PricingTierBracket models."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.meter = UsageMeter.objects.create(
            name="bandwidth",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

    def test_create_per_unit_pricing(self):
        """Test per-unit pricing tier."""
        tier = PricingTier.objects.create(
            name="Standard Bandwidth",
            meter=self.meter,
            pricing_model="per_unit",
            currency=self.currency,
            unit_price_cents=50,  # 0.50 per GB
        )

        self.assertEqual(tier.pricing_model, "per_unit")
        self.assertEqual(tier.unit_price, Decimal("0.50"))

    def test_create_graduated_pricing(self):
        """Test graduated/tiered pricing."""
        tier = PricingTier.objects.create(
            name="Tiered Bandwidth",
            meter=self.meter,
            pricing_model="graduated",
            currency=self.currency,
            minimum_charge_cents=100,  # 1.00 minimum
        )

        # Create brackets
        bracket1 = PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("0"),
            to_quantity=Decimal("100"),
            unit_price_cents=50,  # 0.50 per GB for first 100
            sort_order=1,
        )

        bracket2 = PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("100"),
            to_quantity=Decimal("500"),
            unit_price_cents=40,  # 0.40 per GB for 100-500
            sort_order=2,
        )

        bracket3 = PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("500"),
            to_quantity=None,  # Unlimited
            unit_price_cents=30,  # 0.30 per GB for 500+
            sort_order=3,
        )

        self.assertEqual(tier.brackets.count(), 3)
        self.assertEqual(bracket1.unit_price, Decimal("0.50"))
        self.assertEqual(bracket2.unit_price, Decimal("0.40"))
        self.assertEqual(bracket3.unit_price, Decimal("0.30"))

    def test_volume_pricing(self):
        """Test volume pricing model."""
        tier = PricingTier.objects.create(
            name="Volume Bandwidth",
            meter=self.meter,
            pricing_model="volume",
            currency=self.currency,
        )

        PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("0"),
            to_quantity=Decimal("100"),
            unit_price_cents=50,
        )

        PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("100"),
            to_quantity=None,
            unit_price_cents=40,  # All units at this rate if over 100
        )

        self.assertEqual(tier.pricing_model, "volume")

    def test_package_pricing(self):
        """Test package pricing model."""
        tier = PricingTier.objects.create(
            name="Package Bandwidth",
            meter=self.meter,
            pricing_model="package",
            currency=self.currency,
        )

        PricingTierBracket.objects.create(
            pricing_tier=tier,
            from_quantity=Decimal("0"),
            to_quantity=Decimal("100"),
            unit_price_cents=0,
            flat_fee_cents=1000,  # 10.00 for up to 100 GB
        )

        self.assertEqual(tier.pricing_model, "package")


class UsageThresholdAndAlertTestCase(TransactionTestCase):
    """Test UsageThreshold and UsageAlert models."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(
            code="RON", defaults={"symbol": "lei", "decimals": 2}
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        self.meter = UsageMeter.objects.create(
            name="bandwidth",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

        self.service_plan = ServicePlan.objects.create(
            name="Basic",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
        )

    def test_create_percentage_threshold(self):
        """Test percentage-based threshold."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),  # 75% of allowance
            notify_customer=True,
            notify_staff=False,
            action_on_breach="warn",
        )

        self.assertEqual(threshold.threshold_type, "percentage")
        self.assertEqual(threshold.threshold_value, Decimal("75"))
        self.assertTrue(threshold.notify_customer)

    def test_create_absolute_threshold(self):
        """Test absolute value threshold."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="absolute",
            threshold_value=Decimal("80"),  # 80 GB absolute
            notify_customer=True,
            action_on_breach="throttle",
        )

        self.assertEqual(threshold.threshold_type, "absolute")

    def test_threshold_actions(self):
        """Test threshold action options."""
        actions = ["", "warn", "throttle", "suspend", "block_new"]

        for action in actions:
            threshold = UsageThreshold.objects.create(
                meter=self.meter,
                threshold_type="percentage",
                threshold_value=Decimal("90"),
                action_on_breach=action,
            )
            self.assertEqual(threshold.action_on_breach, action)

    def test_create_usage_alert(self):
        """Test creating a usage alert."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
        )

        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            usage_value=Decimal("80"),
            usage_percentage=Decimal("80.00"),
            allowance_value=Decimal("100"),
        )

        self.assertEqual(alert.status, "pending")
        self.assertEqual(alert.usage_value, Decimal("80"))

    def test_alert_mark_sent(self):
        """Test marking alert as sent."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
        )

        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            usage_value=Decimal("80"),
        )

        alert.mark_sent("email")

        self.assertEqual(alert.status, "sent")
        self.assertEqual(alert.notification_channel, "email")
        self.assertIsNotNone(alert.notified_at)

    def test_alert_mark_failed(self):
        """Test marking alert as failed."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
        )

        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            usage_value=Decimal("80"),
        )

        alert.mark_failed("SMTP error")

        self.assertEqual(alert.status, "failed")
        self.assertEqual(alert.notification_error, "SMTP error")

    def test_alert_resolve(self):
        """Test resolving an alert."""
        user = User.objects.create_user(
            email="admin@example.com",
            password="testpass123",
            is_staff=True,
        )

        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
        )

        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            usage_value=Decimal("80"),
            status="sent",
        )

        alert.resolve(user=user, notes="Customer upgraded plan")

        self.assertEqual(alert.status, "resolved")
        self.assertEqual(alert.resolved_by, user)
        self.assertEqual(alert.resolution_notes, "Customer upgraded plan")
        self.assertIsNotNone(alert.resolved_at)
