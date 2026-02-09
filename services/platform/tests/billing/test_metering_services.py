# ===============================================================================
# USAGE-BASED BILLING SERVICES TEST SUITE
# ===============================================================================
"""
Comprehensive test suite for usage-based billing services.
Tests MeteringService, AggregationService, RatingEngine,
UsageAlertService, UsageInvoiceService, and BillingCycleManager.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    Invoice,
    InvoiceLine,
    InvoiceSequence,
    CreditLedger,
    UsageMeter,
    UsageEvent,
    UsageAggregation,
    Subscription,
    SubscriptionItem,
    BillingCycle,
    PricingTier,
    PricingTierBracket,
    UsageThreshold,
    UsageAlert,
)
from apps.billing.services import (
    MeteringService,
    AggregationService,
    RatingEngine,
    UsageAlertService,
    UsageEventData,
    UsageInvoiceService,
    BillingCycleManager,
)
from apps.customers.models import Customer
from apps.provisioning.models import ServicePlan, Service
from apps.users.models import User


class MeteringServiceTestCase(TransactionTestCase):
    """Test MeteringService functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
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
            is_active=True,
            is_billable=True,
            event_grace_period_hours=24,
        )

        self.service = MeteringService()

    def test_record_event_success(self):
        """Test successful event recording."""
        result = self.service.record_event(UsageEventData(
            meter_name="api_requests",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
            source="api_gateway",
            idempotency_key="test-key-001",
        ))

        self.assertTrue(result.is_ok())
        event = result.unwrap()
        self.assertEqual(event.value, Decimal("100"))
        self.assertEqual(event.source, "api_gateway")

    def test_record_event_meter_not_found(self):
        """Test event recording with invalid meter."""
        result = self.service.record_event(UsageEventData(
            meter_name="nonexistent_meter",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
        ))

        self.assertTrue(result.is_err())
        self.assertIn("Meter not found", result.error)

    def test_record_event_customer_not_found(self):
        """Test event recording with invalid customer."""
        result = self.service.record_event(UsageEventData(
            meter_name="api_requests",
            customer_id="99999999",  # Non-existent customer ID
            value=Decimal("100"),
        ))

        self.assertTrue(result.is_err())
        # Error could be about customer not found or field type mismatch
        self.assertTrue("Customer" in result.error or "Field" in result.error)

    def test_record_event_inactive_meter(self):
        """Test event recording with inactive meter."""
        self.meter.is_active = False
        self.meter.save()

        result = self.service.record_event(UsageEventData(
            meter_name="api_requests",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
        ))

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
        self.assertEqual(
            UsageEvent.objects.filter(idempotency_key="duplicate-test-key").count(),
            1
        )

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
        db_engine = settings.DATABASES['default']['ENGINE']
        is_sqlite = 'sqlite' in db_engine

        if is_sqlite:
            # For SQLite, just verify the basic idempotency works sequentially
            # Real concurrency test would need PostgreSQL
            idempotency_key = "concurrent-test-key-sqlite"

            result1 = self.service.record_event(UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                idempotency_key=idempotency_key,
            ))
            result2 = self.service.record_event(UsageEventData(
                meter_name="api_requests",
                customer_id=str(self.customer.id),
                value=Decimal("100"),
                idempotency_key=idempotency_key,
            ))

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
                    result = svc.record_event(UsageEventData(
                        meter_name="api_requests",
                        customer_id=str(self.customer.id),
                        value=Decimal("100"),
                        idempotency_key=idempotency_key,
                    ))
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
                self.assertTrue(result.is_ok(), f"Expected success, got error: {result.error}")

            event_count = UsageEvent.objects.filter(idempotency_key=idempotency_key).count()
            self.assertEqual(event_count, 1, f"Expected 1 event, found {event_count}")

    def test_record_event_timestamp_too_old(self):
        """Test event with timestamp outside grace period."""
        old_timestamp = timezone.now() - timedelta(hours=48)  # 48 hours ago

        result = self.service.record_event(UsageEventData(
            meter_name="api_requests",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
            timestamp=old_timestamp,
        ))

        self.assertTrue(result.is_err())
        self.assertIn("too old", result.error.lower())

    def test_record_event_timestamp_in_future(self):
        """Test event with future timestamp."""
        future_timestamp = timezone.now() + timedelta(hours=1)

        result = self.service.record_event(UsageEventData(
            meter_name="api_requests",
            customer_id=str(self.customer.id),
            value=Decimal("100"),
            timestamp=future_timestamp,
        ))

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

        results, success, errors = self.service.record_bulk_events(events)

        self.assertEqual(success, 2)
        self.assertEqual(errors, 1)


class RatingEngineTestCase(TransactionTestCase):
    """Test RatingEngine functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
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
            rounding_mode="up",
            rounding_increment=Decimal("1"),
        )

        self.service_plan = ServicePlan.objects.create(
            name="Basic",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
        )

        self.subscription = Subscription.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            status="active",
            billing_interval="monthly",
        )

        now = timezone.now()
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
        )

        self.engine = RatingEngine()

    def test_rate_aggregation_per_unit(self):
        """Test per-unit pricing rating."""
        # Create subscription item with included quantity and overage price
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=self.meter,
            included_quantity=Decimal("100"),  # 100 GB included
            unit_price_cents=50,  # 0.50 per GB overage
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
        self.assertEqual(aggregation.included_allowance, Decimal("100"))
        self.assertEqual(aggregation.overage_value, Decimal("50"))
        self.assertEqual(aggregation.charge_cents, 2500)  # 50 * 50 cents
        self.assertEqual(aggregation.status, "rated")

    def test_rate_aggregation_no_overage(self):
        """Test rating with usage within allowance."""
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=self.meter,
            included_quantity=Decimal("100"),
            unit_price_cents=50,
        )

        now = timezone.now()
        aggregation = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=self.billing_cycle,
            period_start=now,
            period_end=now + timedelta(days=30),
            total_value=Decimal("80"),  # Under allowance
            status="pending_rating",
        )

        result = self.engine.rate_aggregation(str(aggregation.id))

        self.assertTrue(result.is_ok())
        aggregation.refresh_from_db()

        self.assertEqual(aggregation.overage_value, Decimal("0"))
        self.assertEqual(aggregation.charge_cents, 0)

    def test_rate_aggregation_with_default_tier(self):
        """Test rating using default pricing tier."""
        tier = PricingTier.objects.create(
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

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=self.meter,
            included_quantity=Decimal("100"),
            unit_price_cents=50,
        )

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=meter2,
            included_quantity=Decimal("10"),
            unit_price_cents=100,
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
        # 50 GB bandwidth overage * 50 cents + 5 GB storage overage * 100 cents
        self.assertEqual(data["total_usage_charge_cents"], 2500 + 500)

    def test_apply_rounding_up(self):
        """Test rounding up mode."""
        result = self.engine._apply_rounding(
            Decimal("5.3"),
            "up",
            Decimal("1")
        )
        self.assertEqual(result, Decimal("6"))

    def test_apply_rounding_down(self):
        """Test rounding down mode."""
        result = self.engine._apply_rounding(
            Decimal("5.9"),
            "down",
            Decimal("1")
        )
        self.assertEqual(result, Decimal("5"))

    def test_apply_rounding_nearest(self):
        """Test rounding to nearest mode."""
        result1 = self.engine._apply_rounding(
            Decimal("5.3"),
            "nearest",
            Decimal("1")
        )
        self.assertEqual(result1, Decimal("5"))

        result2 = self.engine._apply_rounding(
            Decimal("5.5"),
            "nearest",
            Decimal("1")
        )
        self.assertEqual(result2, Decimal("6"))


class GraduatedPricingTestCase(TransactionTestCase):
    """Test graduated/tiered pricing calculations."""

    def setUp(self):
        """Set up graduated pricing test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
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
        charge = self.engine._calculate_tiered_charge(
            Decimal("50"),
            self.tier
        )
        # 50 GB * 50 cents = 2500 cents
        self.assertEqual(charge, 2500)

    def test_graduated_pricing_multiple_brackets(self):
        """Test usage spanning multiple brackets."""
        charge = self.engine._calculate_tiered_charge(
            Decimal("250"),
            self.tier
        )
        # First 100 GB: 100 * 50 = 5000
        # Next 150 GB: 150 * 40 = 6000
        # Total: 11000 cents
        self.assertEqual(charge, 11000)

    def test_graduated_pricing_all_brackets(self):
        """Test usage spanning all brackets."""
        charge = self.engine._calculate_tiered_charge(
            Decimal("700"),
            self.tier
        )
        # First 100 GB: 100 * 50 = 5000
        # Next 400 GB: 400 * 40 = 16000
        # Last 200 GB: 200 * 30 = 6000
        # Total: 27000 cents
        self.assertEqual(charge, 27000)

    def test_minimum_charge(self):
        """Test minimum charge is applied."""
        charge = self.engine._calculate_tiered_charge(
            Decimal("0.5"),  # Very small usage
            self.tier
        )
        # 0.5 * 50 = 25 cents, but minimum is 100
        self.assertEqual(charge, 100)


class UsageInvoiceServiceTestCase(TransactionTestCase):
    """Test UsageInvoiceService functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
        )

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

        self.service_plan = ServicePlan.objects.create(
            name="Basic Hosting",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
        )

        self.subscription = Subscription.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            status="active",
            billing_interval="monthly",
            base_price_cents=2999,
        )

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=self.meter,
            included_quantity=Decimal("100"),
            unit_price_cents=50,
        )

        now = timezone.now()
        self.billing_cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=30),
            period_end=now,
            status="closed",
            base_charge_cents=2999,
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

    def test_generate_invoice_from_cycle(self):
        """Test generating invoice from billing cycle."""
        result = self.service.generate_invoice_from_cycle(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok())
        data = result.unwrap()

        self.assertIn("invoice_id", data)
        self.assertIn("invoice_number", data)

        # Verify invoice was created
        invoice = Invoice.objects.get(id=data["invoice_id"])
        self.assertEqual(invoice.customer, self.customer)
        self.assertEqual(invoice.status, "draft")

        # Verify line items
        lines = invoice.lines.all()
        self.assertGreaterEqual(lines.count(), 2)  # Base + usage

        # Verify billing cycle updated
        self.billing_cycle.refresh_from_db()
        self.assertEqual(self.billing_cycle.status, "invoiced")
        self.assertEqual(self.billing_cycle.invoice, invoice)

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


class BillingCycleManagerTestCase(TransactionTestCase):
    """Test BillingCycleManager functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
        )

        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        self.service_plan = ServicePlan.objects.create(
            name="Basic",
            plan_type="shared_hosting",
            price_monthly=Decimal("29.99"),
        )

        self.subscription = Subscription.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            status="active",
            billing_interval="monthly",
            base_price_cents=2999,
        )

        self.manager = BillingCycleManager()

    def test_create_billing_cycle(self):
        """Test creating a new billing cycle."""
        now = timezone.now()

        result = self.manager.create_billing_cycle(
            str(self.subscription.id),
            period_start=now
        )

        self.assertTrue(result.is_ok())
        cycle = result.unwrap()

        self.assertEqual(cycle.subscription, self.subscription)
        self.assertEqual(cycle.status, "active")
        self.assertEqual(cycle.base_charge_cents, 2999)

        # Verify period end is 1 month later
        expected_end = now + timedelta(days=30)
        self.assertAlmostEqual(
            cycle.period_end.timestamp(),
            expected_end.timestamp(),
            delta=86400  # Within 1 day
        )

    def test_create_billing_cycle_quarterly(self):
        """Test creating quarterly billing cycle."""
        self.subscription.billing_interval = "quarterly"
        self.subscription.save()

        now = timezone.now()
        result = self.manager.create_billing_cycle(
            str(self.subscription.id),
            period_start=now
        )

        self.assertTrue(result.is_ok())
        cycle = result.unwrap()

        # Verify period is ~3 months
        delta = cycle.period_end - cycle.period_start
        self.assertGreater(delta.days, 85)
        self.assertLess(delta.days, 95)

    def test_create_billing_cycle_inactive_subscription(self):
        """Test error for inactive subscription."""
        self.subscription.status = "canceled"
        self.subscription.save()

        result = self.manager.create_billing_cycle(str(self.subscription.id))

        self.assertTrue(result.is_err())
        self.assertIn("not active", result.error.lower())

    def test_advance_all_subscriptions(self):
        """Test advancing all subscriptions."""
        # Set up subscription with expired period
        past = timezone.now() - timedelta(days=35)
        self.subscription.current_period_start = past
        self.subscription.current_period_end = timezone.now() - timedelta(days=5)
        self.subscription.save()

        created, errors, _ = self.manager.advance_all_subscriptions()

        self.assertEqual(created, 1)
        self.assertEqual(errors, 0)

    def test_close_expired_cycles(self):
        """Test closing expired billing cycles."""
        now = timezone.now()

        # Create expired cycle
        BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=35),
            period_end=now - timedelta(days=5),
            status="active",
        )

        closed, errors = self.manager.close_expired_cycles()

        self.assertEqual(closed, 1)
        self.assertEqual(errors, 0)


class UsageAlertServiceTestCase(TransactionTestCase):
    """Test UsageAlertService functionality."""

    def setUp(self):
        """Set up test data."""
        self.currency = Currency.objects.create(
            code="RON", symbol="lei", decimals=2
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

        self.subscription = Subscription.objects.create(
            customer=self.customer,
            service_plan=self.service_plan,
            currency=self.currency,
            status="active",
            billing_interval="monthly",
        )

        SubscriptionItem.objects.create(
            subscription=self.subscription,
            meter=self.meter,
            included_quantity=Decimal("100"),
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
        """Test threshold check with no breach."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("90"),  # 90% threshold
            is_active=True,
        )

        alerts = self.service.check_thresholds(
            str(self.customer.id),
            str(self.meter.id),
            str(self.subscription.id)
        )

        self.assertEqual(len(alerts), 0)

    def test_check_thresholds_breach(self):
        """Test threshold check with breach."""
        UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),  # 75% threshold
            is_active=True,
            notify_customer=True,
        )

        alerts = self.service.check_thresholds(
            str(self.customer.id),
            str(self.meter.id),
            str(self.subscription.id)
        )

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

        alerts = self.service.check_thresholds(
            str(self.customer.id),
            str(self.meter.id),
            str(self.subscription.id)
        )

        self.assertEqual(len(alerts), 1)

    def test_check_thresholds_no_duplicate(self):
        """Test no duplicate alerts created."""
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_type="percentage",
            threshold_value=Decimal("75"),
            is_active=True,
            repeat_notification=False,
        )

        # First check
        alerts1 = self.service.check_thresholds(
            str(self.customer.id),
            str(self.meter.id),
            str(self.subscription.id)
        )
        self.assertEqual(len(alerts1), 1)

        # Second check should not create new alert
        alerts2 = self.service.check_thresholds(
            str(self.customer.id),
            str(self.meter.id),
            str(self.subscription.id)
        )
        self.assertEqual(len(alerts2), 0)

    @patch("apps.billing.metering_service.logger")
    def test_send_alert_notification(self, mock_logger):
        """Test sending alert notification."""
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
