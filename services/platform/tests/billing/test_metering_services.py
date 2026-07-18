# ===============================================================================
# USAGE-BASED BILLING SERVICES TEST SUITE
# ===============================================================================
"""
Comprehensive test suite for usage-based billing services.
Tests MeteringService, AggregationService, RatingEngine,
UsageAlertService and UsageInvoiceService.
"""

from __future__ import annotations

import hashlib
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.db.models import Sum
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.gateways.base import PaymentIntentResult
from apps.billing.models import (
    BillingCycle,
    CreditLedger,
    Currency,
    Invoice,
    InvoiceSequence,
    Payment,
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
from apps.billing.recurring_authorization_service import RecurringPaymentAuthorizationService
from apps.billing.recurring_models import RecurringPaymentAuthorization
from apps.billing.services import (
    MeteringService,
    RatingEngine,
    UsageAlertService,
    UsageEventData,
    UsageInvoiceService,
)
from apps.billing.usage_invoice_service import UsageBillingService
from apps.common.types import Err
from apps.customers.models import Customer, CustomerAddress, CustomerPaymentMethod
from apps.products.models import Product
from apps.settings.services import SettingsService


def _metering_service_setup(test_instance):
    """Shared setup for metering service test classes."""
    test_instance.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
    test_instance.customer = Customer.objects.create(
        name="Test Customer",
        customer_type="individual",
        primary_email="test@example.com",
        status="active",
    )
    test_instance.meter = UsageMeter.objects.create(
        name="api_requests",
        display_name="API Requests",
        aggregation_type="sum",
        unit="requests",
        is_active=True,
        is_billable=True,
        event_grace_period_hours=24,
    )
    test_instance.service = MeteringService()


class MeteringServiceTestCase(TestCase):
    """Test MeteringService functionality."""

    def setUp(self):
        """Set up test data."""
        _metering_service_setup(self)

    def test_record_event_success(self):
        """Test successful event recording."""
        result = self.service.record_event(
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                source="api_gateway",
                idempotency_key="test-key-001",
            )
        )

        self.assertTrue(result.is_ok())
        event = result.unwrap()
        self.assertEqual(event.value, Decimal("100"))
        self.assertEqual(event.source, "api_gateway")

    def test_record_event_meter_not_found(self):
        """Test event recording with invalid meter."""
        result = self.service.record_event(
            UsageEventData(
                meter_name="nonexistent_meter",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
            )
        )

        self.assertTrue(result.is_err())
        self.assertIn("Meter not found", result.error)

    def test_record_event_customer_not_found(self):
        """Test event recording with invalid customer."""
        result = self.service.record_event(
            UsageEventData(
                meter_name="api_requests",
                customer_id="99999999",  # Non-existent customer ID
                value=Decimal("100"),
            )
        )

        self.assertTrue(result.is_err())
        # Error could be about customer not found or field type mismatch
        self.assertTrue("Customer" in result.error or "Field" in result.error)

    def test_record_event_inactive_meter(self):
        """Test event recording with inactive meter."""
        self.meter.is_active = False
        self.meter.save()

        result = self.service.record_event(
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
            )
        )

        self.assertTrue(result.is_err())
        self.assertIn("inactive", result.error.lower())

    def test_record_event_idempotency(self):
        """Test idempotency prevents duplicates."""
        event_data = UsageEventData(
            meter_name="api_requests",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
            idempotency_key="duplicate-test-key",
        )

        # First call succeeds
        result1 = self.service.record_event(event_data)
        self.assertTrue(result1.is_ok())

        # Second call with same key returns existing event
        result2 = self.service.record_event(event_data)
        self.assertTrue(result2.is_ok())

        # Both should return the same event
        self.assertEqual(result1.unwrap().id, result2.unwrap().id)

        # Only one event should exist
        self.assertEqual(UsageEvent.objects.filter(idempotency_key="duplicate-test-key").count(), 1)

    def test_record_event_timestamp_too_old(self):
        """Test event with timestamp outside grace period."""
        old_timestamp = timezone.now() - timedelta(hours=48)  # 48 hours ago

        result = self.service.record_event(
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                timestamp=old_timestamp,
            )
        )

        self.assertTrue(result.is_err())
        self.assertIn("too old", result.error.lower())

    def test_record_event_timestamp_in_future(self):
        """Test event with future timestamp."""
        future_timestamp = timezone.now() + timedelta(hours=1)

        result = self.service.record_event(
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                timestamp=future_timestamp,
            )
        )

        self.assertTrue(result.is_err())
        self.assertIn("future", result.error.lower())

    def test_record_bulk_events(self):
        """Test bulk event recording."""
        events = [
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal(str(i)),
                idempotency_key=f"bulk-key-{i}",
            )
            for i in range(1, 6)
        ]

        results, success, errors = self.service.record_bulk_events(events)

        self.assertEqual(success, 5)
        self.assertEqual(errors, 0)
        self.assertEqual(len(results), 5)

    def test_record_bulk_events_with_errors(self):
        """Test bulk event recording with some failures."""
        events = [
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                idempotency_key="bulk-good-1",
            ),
            UsageEventData(
                meter_name="nonexistent",  # This will fail
                customer_id=str(self.customer.id),
                value=Decimal("100"),
            ),
            UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("200"),
                idempotency_key="bulk-good-2",
            ),
        ]

        _results, success, errors = self.service.record_bulk_events(events)

        self.assertEqual(success, 2)
        self.assertEqual(errors, 1)


class MeteringServiceTransactionTests(TransactionTestCase):
    """Tests requiring TransactionTestCase (concurrent thread access)."""

    def setUp(self):
        """Set up test data."""
        _metering_service_setup(self)

    def test_record_event_idempotency_race_condition(self):
        """
        Test that concurrent requests with same idempotency key
        don't create duplicate events (race condition protection).

        This tests the database constraint-based idempotency rather
        than the check-then-insert pattern that has race conditions.

        Note: SQLite doesn't support true concurrent writes, so this test
        verifies sequential behavior there, but exercises the full path.
        In PostgreSQL/MySQL, the database constraint handles true concurrency.
        """
        from django.conf import settings

        # Check if using SQLite (which doesn't support concurrent writes)
        db_engine = settings.DATABASES["default"]["ENGINE"]
        is_sqlite = "sqlite" in db_engine

        if is_sqlite:
            # For SQLite, just verify the basic idempotency works sequentially
            # Real concurrency test would need PostgreSQL
            idempotency_key = "concurrent-test-key-sqlite"

            result1 = self.service.record_event(
                UsageEventData(
                    meter_name="api_requests",
                    customer_id=str(self.customer.id),
                    value=Decimal("100"),
                    idempotency_key=idempotency_key,
                )
            )
            result2 = self.service.record_event(
                UsageEventData(
                    meter_name="api_requests",
                    customer_id=str(self.customer.id),
                    value=Decimal("100"),
                    idempotency_key=idempotency_key,
                )
            )

            self.assertTrue(result1.is_ok())
            self.assertTrue(result2.is_ok())
            self.assertEqual(result1.unwrap().id, result2.unwrap().id)

            # Only ONE event should exist
            event_count = UsageEvent.objects.filter(idempotency_key=idempotency_key).count()
            self.assertEqual(event_count, 1)
        else:
            # Full concurrent test for PostgreSQL/MySQL
            from concurrent.futures import ThreadPoolExecutor, as_completed

            idempotency_key = "concurrent-test-key"
            results = []
            errors = []

            def record_event():
                try:
                    svc = MeteringService()
                    result = svc.record_event(
                        UsageEventData(
                            meter_name="api_requests",
                            customer_id=str(self.customer.id),
                            value=Decimal("100"),
                            idempotency_key=idempotency_key,
                        )
                    )
                    return result
                except Exception as e:
                    return e

            with ThreadPoolExecutor(max_workers=5) as executor:
                futures = [executor.submit(record_event) for _ in range(5)]
                for future in as_completed(futures):
                    result = future.result()
                    if isinstance(result, Exception):
                        errors.append(result)
                    else:
                        results.append(result)

            self.assertEqual(len(errors), 0, f"Unexpected errors: {errors}")
            for result in results:
                self.assertTrue(result.is_ok(), f"Expected success, got: {result}")

            event_count = UsageEvent.objects.filter(idempotency_key=idempotency_key).count()
            self.assertEqual(event_count, 1, f"Expected 1 event, found {event_count}")


class RatingEngineTestCase(TestCase):
    """Test RatingEngine functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

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
            rounding_mode="up",
            rounding_increment=Decimal("1"),
        )

        self.product = Product.objects.create(
            slug="basic-rating",
            name="Basic",
            product_type="shared_hosting",
        )

        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-RATING-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
        )

        self.engine = RatingEngine()

    def test_rate_aggregation_per_unit(self):
        """Test per-unit pricing rating."""
        # Create subscription item with overage price
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.product,
            unit_price_cents=50,  # 0.50 per GB overage
            meta={"meter_name": self.meter.name},
        )

        # Create aggregation with overage
        now = timezone.now()
        aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("150"),  # 150 GB used
            status="pending_rating",
        )

        result = self.engine.rate_aggregation(str(aggregation.id))

        self.assertTrue(result.is_ok())
        aggregation.refresh_from_db()

        self.assertEqual(aggregation.billable_value, Decimal("150"))
        self.assertEqual(aggregation.included_allowance, Decimal("0"))
        self.assertEqual(aggregation.overage_value, Decimal("150"))
        self.assertEqual(aggregation.charge_cents, 7500)  # 150 * 50 cents
        self.assertEqual(aggregation.status, "rated")

    def test_rate_aggregation_all_billable(self):
        """Test rating where all usage is billable (no included allowance)."""
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.product,
            unit_price_cents=50,
            meta={"meter_name": self.meter.name},
        )

        now = timezone.now()
        aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("80"),
            status="pending_rating",
        )

        result = self.engine.rate_aggregation(str(aggregation.id))

        self.assertTrue(result.is_ok())
        aggregation.refresh_from_db()

        self.assertEqual(aggregation.overage_value, Decimal("80"))
        self.assertEqual(aggregation.charge_cents, 4000)  # 80 * 50 cents

    def test_rate_aggregation_with_default_tier(self):
        """Test rating using default pricing tier."""
        PricingTier.objects.create(
            name="Default Bandwidth",
            meter=self.meter,
            pricing_model="per_unit",
            currency=self.currency,
            unit_price_cents=100,
            is_default=True,
            is_active=True,
        )

        now = timezone.now()
        aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("50"),
            status="pending_rating",
        )

        result = self.engine.rate_aggregation(str(aggregation.id))

        self.assertTrue(result.is_ok())
        aggregation.refresh_from_db()

        self.assertEqual(aggregation.charge_cents, 5000)  # 50 * 100 cents

    def test_rate_billing_cycle(self):
        """Test rating all aggregations in a cycle."""
        meter2 = UsageMeter.objects.create(
            name="storage",
            display_name="Storage",
            aggregation_type="last",
            unit="gb",
        )

        PricingTier.objects.create(
            name="Bandwidth unit price",
            meter=self.meter,
            pricing_model="per_unit",
            currency=self.currency,
            unit_price_cents=50,
            is_default=True,
            is_active=True,
        )
        PricingTier.objects.create(
            name="Storage unit price",
            meter=meter2,
            pricing_model="per_unit",
            currency=self.currency,
            unit_price_cents=50,
            is_default=True,
            is_active=True,
        )

        now = timezone.now()

        UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("150"),
            status="pending_rating",
        )

        UsageAggregation.objects.create(
            meter=meter2,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("15"),
            status="pending_rating",
        )

        result = self.engine.rate_billing_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok())
        data = result.unwrap()

        self.assertEqual(data["rated_count"], 2)
        # 150 GB bandwidth * 50 cents + 15 GB storage * 50 cents
        self.assertEqual(data["total_usage_charge_cents"], 7500 + 750)

    def test_rate_billing_cycle_retry_keeps_previously_rated_charges(self):
        storage_meter = UsageMeter.objects.create(
            name="retry_storage",
            display_name="Retry storage",
            aggregation_type="last",
            unit="gb",
        )
        PricingTier.objects.create(
            name="Retry bandwidth unit price",
            meter=self.meter,
            pricing_model="per_unit",
            currency=self.currency,
            unit_price_cents=50,
            is_default=True,
            is_active=True,
        )
        now = timezone.now()
        UsageAggregation.objects.create(
            meter=storage_meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("50"),
            billable_value=Decimal("50"),
            overage_value=Decimal("50"),
            charge_cents=2500,
            status="rated",
        )
        UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("10"),
            status="pending_rating",
        )

        result = self.engine.rate_billing_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok())
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.usage_charge_cents, 3000)
        self.assertEqual(result.unwrap()["total_usage_charge_cents"], 3000)

    def test_rate_billing_cycle_rolls_back_every_aggregation_when_one_fails(self):
        storage_meter = UsageMeter.objects.create(
            name="atomic_storage",
            display_name="Atomic storage",
            aggregation_type="last",
            unit="gb",
        )
        for meter in (self.meter, storage_meter):
            PricingTier.objects.create(
                name=f"Atomic {meter.name}",
                meter=meter,
                pricing_model="per_unit",
                currency=self.currency,
                unit_price_cents=50,
                is_default=True,
                is_active=True,
            )
        now = timezone.now()
        first = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("10"),
            status="pending_rating",
        )
        second = UsageAggregation.objects.create(
            meter=storage_meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("5"),
            status="pending_rating",
        )
        real_rate = self.engine.rate_aggregation
        calls = 0

        def fail_second(aggregation_id: str):
            nonlocal calls
            calls += 1
            if calls == 2:
                return Err("second meter pricing unavailable")
            return real_rate(aggregation_id)

        with patch.object(self.engine, "rate_aggregation", side_effect=fail_second):
            result = self.engine.rate_billing_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_err())
        first.refresh_from_db()
        second.refresh_from_db()
        self.billing_cycle.refresh_from_db()
        self.assertEqual(first.status, "pending_rating")
        self.assertEqual(second.status, "pending_rating")
        self.assertEqual(first.charge_cents, 0)
        self.assertEqual(self.billing_cycle.usage_charge_cents, 0)

    def test_apply_rounding_up(self):
        """Test rounding up mode."""
        result = self.engine._apply_rounding(Decimal("5.3"), "up", Decimal("1"))
        self.assertEqual(result, Decimal("6"))

    def test_apply_rounding_down(self):
        """Test rounding down mode."""
        result = self.engine._apply_rounding(Decimal("5.9"), "down", Decimal("1"))
        self.assertEqual(result, Decimal("5"))

    def test_apply_rounding_nearest(self):
        """Test rounding to nearest mode."""
        result1 = self.engine._apply_rounding(Decimal("5.3"), "nearest", Decimal("1"))
        self.assertEqual(result1, Decimal("5"))

        result2 = self.engine._apply_rounding(Decimal("5.5"), "nearest", Decimal("1"))
        self.assertEqual(result2, Decimal("6"))


class GraduatedPricingTestCase(TestCase):
    """Test graduated/tiered pricing calculations."""

    def setUp(self):
        """Set up graduated pricing test data."""
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

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

        # Create graduated pricing tier
        self.tier = PricingTier.objects.create(
            name="Graduated Bandwidth",
            meter=self.meter,
            pricing_model="graduated",
            currency=self.currency,
            minimum_charge_cents=100,
            is_default=True,
            is_active=True,
        )

        # 0-100 GB: 0.50/GB
        PricingTierBracket.objects.create(
            pricing_tier=self.tier,
            from_quantity=Decimal("0"),
            to_quantity=Decimal("100"),
            unit_price_cents=50,
            sort_order=1,
        )

        # 100-500 GB: 0.40/GB
        PricingTierBracket.objects.create(
            pricing_tier=self.tier,
            from_quantity=Decimal("100"),
            to_quantity=Decimal("500"),
            unit_price_cents=40,
            sort_order=2,
        )

        # 500+ GB: 0.30/GB
        PricingTierBracket.objects.create(
            pricing_tier=self.tier,
            from_quantity=Decimal("500"),
            to_quantity=None,
            unit_price_cents=30,
            sort_order=3,
        )

        self.engine = RatingEngine()

    def test_graduated_pricing_single_bracket(self):
        """Test usage in single bracket."""
        charge = self.engine._calculate_tiered_charge(Decimal("50"), self.tier)
        # 50 GB * 50 cents = 2500 cents
        self.assertEqual(charge, 2500)

    def test_graduated_pricing_multiple_brackets(self):
        """Test usage spanning multiple brackets."""
        charge = self.engine._calculate_tiered_charge(Decimal("250"), self.tier)
        # First 100 GB: 100 * 50 = 5000
        # Next 150 GB: 150 * 40 = 6000
        # Total: 11000 cents
        self.assertEqual(charge, 11000)

    def test_graduated_pricing_all_brackets(self):
        """Test usage spanning all brackets."""
        charge = self.engine._calculate_tiered_charge(Decimal("700"), self.tier)
        # First 100 GB: 100 * 50 = 5000
        # Next 400 GB: 400 * 40 = 16000
        # Last 200 GB: 200 * 30 = 6000
        # Total: 27000 cents
        self.assertEqual(charge, 27000)

    def test_minimum_charge(self):
        """Test minimum charge is applied."""
        charge = self.engine._calculate_tiered_charge(
            Decimal("0.5"),  # Very small usage
            self.tier,
        )
        # 0.5 * 50 = 25 cents, but minimum is 100
        self.assertEqual(charge, 100)


class UsageInvoiceServiceTestCase(TestCase):
    """Test UsageInvoiceService functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

        self.customer = Customer.objects.create(
            name="Test Company SRL",
            customer_type="company",
            company_name="Test Company SRL",
            primary_email="test@example.com",
            status="active",
        )

        self.meter = UsageMeter.objects.create(
            name="bandwidth",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

        self.product = Product.objects.create(
            slug="basic-hosting-inv",
            name="Basic Hosting",
            product_type="shared_hosting",
        )

        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-INV-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
        )

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.product,
            unit_price_cents=50,
        )

        now = timezone.now()
        self.collection_invoice = Invoice.objects.create(
            customer=self.customer,
            number="INV-FIXED-COLLECTION",
            currency=self.currency,
            subtotal_cents=2999,
            tax_cents=0,
            total_cents=2999,
            due_at=now,
            bill_to_name=self.customer.company_name,
            bill_to_email=self.customer.primary_email,
        )
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=30),
            period_end=now,
            status="closed",
            base_charge_cents=2999,
            usage_charge_cents=2500,
            invoice=self.collection_invoice,
        )

        # Create aggregation with overage
        self.aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now - timedelta(days=30),
            period_end=now,
            total_value=Decimal("150"),
            billable_value=Decimal("150"),
            included_allowance=Decimal("100"),
            overage_value=Decimal("50"),
            charge_cents=2500,
            status="rated",
        )

        # Create invoice sequence
        InvoiceSequence.objects.get_or_create(scope="default")

        self.service = UsageInvoiceService()

    def _enable_usage_auto_payment(self) -> CustomerPaymentMethod:
        method = CustomerPaymentMethod.objects.create(
            customer=self.customer,
            method_type="stripe_card",
            stripe_customer_id="cus_usage_invoice",
            stripe_payment_method_id="pm_usage_invoice",
            display_name="Visa ending 4242",
            last_four="4242",
            is_active=True,
        )
        authorization = RecurringPaymentAuthorization.objects.create(
            customer=self.customer,
            payment_method=method,
            status="active",
            setup_intent_id="seti_usage_invoice",
            terms_version=RecurringPaymentAuthorizationService.TERMS_VERSION,
            terms_text=RecurringPaymentAuthorizationService.TERMS_TEXT,
            terms_text_hash=hashlib.sha256(RecurringPaymentAuthorizationService.TERMS_TEXT.encode("utf-8")).hexdigest(),
            granted_by_role="owner",
            granted_at=timezone.now(),
        )
        self.subscription.saved_payment_method = method
        self.subscription.payment_authorization = authorization
        self.subscription.auto_payment_enabled = True
        self.subscription.save(
            update_fields=["saved_payment_method", "payment_authorization", "auto_payment_enabled", "updated_at"]
        )
        return method

    def test_generate_invoice_from_cycle(self):
        """Test generating invoice from billing cycle."""
        zero_charge_aggregation = UsageAggregation.objects.create(
            meter=UsageMeter.objects.create(
                name="included_storage",
                display_name="Included storage",
                aggregation_type="sum",
                unit="gb",
            ),
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=self.billing_cycle.period_start,
            period_end=self.billing_cycle.period_end,
            total_value=Decimal("10"),
            included_allowance=Decimal("10"),
            charge_cents=0,
            status="rated",
        )

        with patch.object(
            BillingCycle.objects,
            "select_for_update",
            wraps=BillingCycle.objects.select_for_update,
        ) as lock_cycle:
            result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok())
        lock_cycle.assert_called()
        data = result.unwrap()

        self.assertIn("invoice_id", data)
        self.assertIn("invoice_number", data)

        # Verify invoice was created
        invoice = Invoice.objects.get(id=data["invoice_id"])
        self.assertEqual(invoice.customer, self.customer)
        self.assertEqual(invoice.status, "issued")
        self.assertEqual(invoice.subtotal_cents, 2500)

        # Verify line items
        lines = invoice.lines.all()
        self.assertEqual(lines.count(), 1)
        self.assertNotIn("Basic Hosting", lines.get().description)

        # Verify billing cycle updated
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.status, "invoiced")
        self.assertEqual(self.billing_cycle.invoice, self.collection_invoice)
        self.assertEqual(self.billing_cycle.usage_invoice, invoice)
        zero_charge_aggregation.refresh_from_db()
        self.assertEqual(zero_charge_aggregation.status, "invoiced")

    def test_usage_invoice_snapshots_individual_cnp(self):
        from apps.customers.models import CustomerTaxProfile  # noqa: PLC0415

        self.customer.customer_type = "individual"
        self.customer.company_name = ""
        self.customer.save(update_fields=["customer_type", "company_name"])
        CustomerTaxProfile.objects.create(customer=self.customer, cnp="1850101123451")

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result)
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.bill_to_cnp, "1850101123451")
        self.assertEqual(invoice.bill_to_tax_id, "")

    def test_usage_invoice_normalizes_romanian_address_country(self):
        CustomerAddress.objects.create(
            customer=self.customer,
            is_billing=True,
            address_line1="Strada Test 1",
            city="Bucharest",
            county="Bucharest",
            postal_code="010101",
            country="România",
        )

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result)
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.bill_to_country, "RO")

    def test_usage_invoice_uses_foreign_billing_country_for_snapshot_and_vat(self):
        CustomerAddress.objects.create(
            customer=self.customer,
            is_billing=True,
            address_line1="Unter den Linden 1",
            city="Berlin",
            county="Berlin",
            postal_code="10117",
            country="Germany",
        )

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result)
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.bill_to_country, "DE")
        self.assertEqual(invoice.tax_cents, 475)

    def test_generate_invoice_already_exists(self):
        """Test error when invoice already generated (cycle marked as invoiced)."""
        # First generation
        result1 = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))
        self.assertTrue(result1.is_ok())

        # Second generation should fail - cycle is now marked as invoiced
        result2 = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))
        self.assertTrue(result2.is_err())
        # Error message indicates billing cycle isn't ready (already invoiced)
        self.assertIn("invoiced", result2.error.lower())

    def test_account_credit_is_a_payment_and_does_not_reduce_invoice_tax_base(self):
        CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,
            reason="Customer account credit",
        )

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.subtotal_cents, 2500)
        self.assertEqual(invoice.tax_cents, 525)
        self.assertEqual(invoice.total_cents, 3025)
        self.assertEqual(invoice.get_remaining_amount(), 2025)
        credit_payment = Payment.objects.get(invoice=invoice, meta__source="customer_credit")
        self.assertEqual(credit_payment.amount_cents, 1000)
        self.assertEqual(credit_payment.status, "succeeded")
        self.assertFalse(invoice.lines.filter(kind="credit").exists())
        self.assertEqual(
            CreditLedger.objects.filter(customer=self.customer).aggregate(total=Sum("delta_cents"))["total"],
            0,
        )

    def test_usage_discount_uses_document_allowance_without_negative_line(self):
        self.billing_cycle.discount_cents = 500
        self.billing_cycle.save(update_fields=["discount_cents", "updated_at"])

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.discount_cents, 500)
        self.assertEqual(invoice.subtotal_cents, 2000)
        self.assertEqual(invoice.tax_cents, 420)
        self.assertEqual(invoice.total_cents, 2420)
        self.assertEqual(invoice.lines.count(), 1)
        self.assertEqual(invoice.lines.get().subtotal_cents, 2500)

    def test_usage_vat_uses_authoritative_financial_rounding(self):
        self.aggregation.overage_value = Decimal("1")
        self.aggregation.charge_cents = 3
        self.aggregation.save(update_fields=["overage_value", "charge_cents", "updated_at"])
        self.billing_cycle.usage_charge_cents = 3
        self.billing_cycle.save(update_fields=["usage_charge_cents", "updated_at"])

        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok(), result.unwrap_err() if result.is_err() else "")
        invoice = Invoice.objects.get(id=result.unwrap()["invoice_id"])
        self.assertEqual(invoice.subtotal_cents, 3)
        self.assertEqual(invoice.tax_cents, 1)
        self.assertEqual(invoice.total_cents, 4)

    @patch("apps.billing.tasks.process_auto_payment_async")
    def test_pending_usage_invoice_waits_for_scheduled_charge_time(self, mock_auto_payment):
        self._enable_usage_auto_payment()

        generated, errors = UsageBillingService.generate_pending_invoices()

        self.assertEqual((generated, errors), (1, 0))
        self.billing_cycle.refresh_from_db()
        assert self.billing_cycle.usage_invoice_id is not None
        usage_invoice = Invoice.objects.get(id=self.billing_cycle.usage_invoice_id)
        self.assertEqual(usage_invoice.due_at, self.billing_cycle.period_end + timedelta(days=7))
        mock_auto_payment.assert_not_called()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_usage_collection_charges_once_at_due_boundary(self, mock_create_gateway):
        self._enable_usage_auto_payment()
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=True,
            reason="Exercise usage collection schedule",
        )
        generated, errors = UsageBillingService.generate_pending_invoices()
        self.assertEqual((generated, errors), (1, 0))
        self.billing_cycle.refresh_from_db()
        assert self.billing_cycle.usage_invoice_id is not None
        usage_invoice = Invoice.objects.get(id=self.billing_cycle.usage_invoice_id)

        gateway = MagicMock()
        gateway.create_off_session_payment_intent.return_value = PaymentIntentResult(
            success=True,
            payment_intent_id="pi_usage_due_305",
            client_secret=None,
            error=None,
        )
        mock_create_gateway.return_value = gateway

        before_due = UsageBillingService.collect_due_usage_invoices(
            as_of=usage_invoice.due_at - timedelta(microseconds=1)
        )
        at_due = UsageBillingService.collect_due_usage_invoices(as_of=usage_invoice.due_at)
        after_due = UsageBillingService.collect_due_usage_invoices(as_of=usage_invoice.due_at + timedelta(hours=1))

        self.assertEqual(before_due, (0, 0))
        self.assertEqual(at_due, (1, 0))
        self.assertEqual(after_due, (0, 0))
        payment = Payment.objects.get(invoice=usage_invoice, payment_method="stripe")
        self.assertEqual(payment.gateway_txn_id, "pi_usage_due_305")
        self.assertEqual(payment.status, "pending")
        gateway.create_off_session_payment_intent.assert_called_once()

    @patch("apps.billing.payment_service.PaymentGatewayFactory.create_gateway")
    def test_usage_collection_resumes_an_uncertain_gateway_attempt(self, mock_create_gateway):
        self._enable_usage_auto_payment()
        SettingsService.update_setting(
            key="billing.recurring_auto_collection_enabled",
            value=True,
            reason="Exercise resumable usage collection",
        )
        generated, errors = UsageBillingService.generate_pending_invoices()
        self.assertEqual((generated, errors), (1, 0))
        self.billing_cycle.refresh_from_db()
        assert self.billing_cycle.usage_invoice_id is not None
        usage_invoice = Invoice.objects.get(id=self.billing_cycle.usage_invoice_id)

        gateway = MagicMock()
        gateway.create_off_session_payment_intent.side_effect = [
            PaymentIntentResult(
                success=False,
                payment_intent_id="",
                client_secret=None,
                error="connection interrupted",
                retryable=True,
            ),
            PaymentIntentResult(
                success=True,
                payment_intent_id="pi_usage_resumed_305",
                client_secret=None,
                error=None,
            ),
        ]
        mock_create_gateway.return_value = gateway

        uncertain = UsageBillingService.collect_due_usage_invoices(as_of=usage_invoice.due_at)
        resumed = UsageBillingService.collect_due_usage_invoices(as_of=usage_invoice.due_at + timedelta(hours=1))

        self.assertEqual(uncertain, (0, 1))
        self.assertEqual(resumed, (1, 0))
        payment = Payment.objects.get(invoice=usage_invoice, payment_method="stripe")
        self.assertEqual(payment.gateway_txn_id, "pi_usage_resumed_305")
        self.assertEqual(gateway.create_off_session_payment_intent.call_count, 2)
        first_key = gateway.create_off_session_payment_intent.call_args_list[0].kwargs["idempotency_key"]
        second_key = gateway.create_off_session_payment_intent.call_args_list[1].kwargs["idempotency_key"]
        self.assertEqual(first_key, second_key)

    def test_cycle_without_billable_usage_finalizes_without_zero_invoice(self):
        self.aggregation.charge_cents = 0
        self.aggregation.overage_value = Decimal("0")
        self.aggregation.save(update_fields=["charge_cents", "overage_value", "updated_at"])
        self.billing_cycle.usage_charge_cents = 0
        self.billing_cycle.save(update_fields=["usage_charge_cents", "updated_at"])

        generated, errors = UsageBillingService.generate_pending_invoices()

        self.assertEqual((generated, errors), (0, 0))
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.status, "finalized")
        self.assertIsNone(self.billing_cycle.usage_invoice_id)

    def test_unrated_usage_is_never_finalized_from_a_stale_zero_total(self):
        UsageAggregation.objects.filter(pk=self.aggregation.pk).update(
            status="pending_rating",
            charge_cents=0,
            charge_calculated_at=None,
        )
        self.billing_cycle.usage_charge_cents = 0
        self.billing_cycle.save(update_fields=["usage_charge_cents", "updated_at"])

        generated, errors = UsageBillingService.generate_pending_invoices()

        self.assertEqual((generated, errors), (0, 1))
        self.billing_cycle.refresh_from_db()
        self.aggregation.refresh_from_db()
        self.assertEqual(self.billing_cycle.status, "closed")
        self.assertEqual(self.aggregation.status, "pending_rating")
        self.assertIsNone(self.billing_cycle.usage_invoice_id)

    def test_expired_cycles_wait_for_active_meter_late_event_window(self):
        now = timezone.now()
        inside_subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-INV-GRACE-INSIDE",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
        )
        beyond_subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-INV-GRACE-BEYOND",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now - timedelta(days=30),
            current_period_end=now,
            next_billing_date=now,
        )
        inside_grace = BillingCycle.objects.create(
            subscription=inside_subscription,
            period_start=now - timedelta(days=61),
            period_end=now - timedelta(hours=23),
            status="active",
        )
        beyond_grace = BillingCycle.objects.create(
            subscription=beyond_subscription,
            period_start=now - timedelta(days=62),
            period_end=now - timedelta(hours=25),
            status="active",
        )

        closed, errors = UsageBillingService.close_expired_cycles()

        self.assertEqual((closed, errors), (1, 0))
        inside_grace.refresh_from_db()
        beyond_grace.refresh_from_db()
        self.assertEqual(inside_grace.status, "active")
        self.assertEqual(beyond_grace.status, "closed")

    def test_credit_ledger_can_be_created(self):
        """Test that credit ledger entries can be created for customers."""
        # Add credit to customer
        credit = CreditLedger.objects.create(
            customer=self.customer,
            delta_cents=1000,  # 10.00 credit
            reason="Promotional credit",
        )

        # Verify credit was recorded
        self.assertEqual(credit.delta_cents, 1000)
        self.assertEqual(credit.reason, "Promotional credit")

        # Verify credit can be queried for customer
        credits = CreditLedger.objects.filter(customer=self.customer)
        self.assertEqual(credits.count(), 1)
        self.assertEqual(credits.first().delta_cents, 1000)

    def test_issue_invoice_not_found(self):
        """Test issuing a non-existent invoice."""
        fake_invoice_id = "999999"  # Non-existent integer ID
        result = self.service.issue_invoice(fake_invoice_id)

        self.assertTrue(result.is_err())
        self.assertIn("not found", result.error.lower())


class UsageAlertServiceTestCase(TestCase):
    """Test UsageAlertService functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})

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

        self.product = Product.objects.create(
            slug="basic-alert-svc",
            name="Basic",
            product_type="shared_hosting",
        )

        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-ALERTSVC-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.product,
            unit_price_cents=2999,
        )

        now = timezone.now()
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
        )

        self.aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("80"),  # 80% of allowance
            status="accumulating",
        )

        self.service = UsageAlertService()

    def test_check_thresholds_no_breach(self):
        """Test threshold check with no breach (absolute threshold above usage)."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="absolute",
            threshold_value=Decimal("100"),  # 100 GB absolute, usage is 80
            is_active=True,
        )

        alerts = self.service.check_thresholds(str(self.customer.id), str(self.meter.id), str(self.subscription.id))

        self.assertEqual(len(alerts), 0)

    def test_check_thresholds_breach(self):
        """Test threshold check with breach (absolute threshold below usage)."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="absolute",
            threshold_value=Decimal("50"),  # 50 GB absolute, usage is 80
            is_active=True,
            notify_customer=True,
        )

        alerts = self.service.check_thresholds(str(self.customer.id), str(self.meter.id), str(self.subscription.id))

        self.assertEqual(len(alerts), 1)
        self.assertEqual(alerts[0].status, "pending")

    def test_check_thresholds_absolute(self):
        """Test absolute threshold check."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="absolute",
            threshold_value=Decimal("50"),  # 50 GB absolute
            is_active=True,
        )

        alerts = self.service.check_thresholds(str(self.customer.id), str(self.meter.id), str(self.subscription.id))

        self.assertEqual(len(alerts), 1)

    def test_check_thresholds_no_duplicate(self):
        """Test no duplicate alerts created."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="absolute",
            threshold_value=Decimal("50"),  # 50 GB, usage is 80
            is_active=True,
            repeat_notification=False,
        )

        # First check
        alerts1 = self.service.check_thresholds(str(self.customer.id), str(self.meter.id), str(self.subscription.id))
        self.assertEqual(len(alerts1), 1)

        # Second check should not create new alert
        alerts2 = self.service.check_thresholds(str(self.customer.id), str(self.meter.id), str(self.subscription.id))
        self.assertEqual(len(alerts2), 0)

    @patch("apps.notifications.services.EmailService.send_template_email")
    @patch("apps.billing.metering_service.logger")
    def test_send_alert_notification(self, mock_logger, mock_send_email):
        """Test sending alert notification."""
        mock_send_email.return_value = MagicMock(success=True, error=None)
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
            notify_customer=True,
        )

        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            usage_value=Decimal("80"),
            status="pending",
        )

        result = self.service.send_alert_notification(str(alert.id))

        self.assertTrue(result.is_ok())

        alert.refresh_from_db()
        self.assertEqual(alert.status, "sent")
