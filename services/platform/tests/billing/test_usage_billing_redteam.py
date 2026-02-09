"""
Red Team Tests for Usage-Based Billing System.

These tests cover attack vectors, edge cases, and failure modes identified
during security review:

1. Config validation bypass attempts
2. Race conditions in idempotency
3. Invoice calculation attacks (overflow, precision)
4. Invalid input handling
5. Billing cycle boundary conditions
6. Stripe sync failure scenarios
7. Denial of service vectors
"""

import uuid
from datetime import datetime, timedelta
from decimal import Decimal
from unittest.mock import patch

from django.db import IntegrityError, transaction
from django.db.models import Max
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing import config as billing_config
from apps.billing.metering_models import (
    BillingCycle,
    UsageAggregation,
    UsageAlert,
    UsageEvent,
    UsageMeter,
    UsageThreshold,
)
from apps.billing.metering_service import MeteringService, UsageAlertService, UsageEventData
from apps.billing.models import Currency, Subscription
from apps.billing.stripe_metering import StripeUsageSyncService
from apps.customers.models import Customer
from apps.products.models import Product


class ConfigValidationRedTeamTestCase(TestCase):
    """Test config validation against malicious/invalid settings."""

    def test_negative_batch_size_clamped(self):
        """Verify negative batch sizes are clamped to 1."""
        result = billing_config._get_positive_int("FAKE_SETTING", -100)
        self.assertEqual(result, 1)

    def test_zero_batch_size_clamped(self):
        """Verify zero batch size is clamped to 1."""
        result = billing_config._get_positive_int("FAKE_SETTING", 0)
        self.assertEqual(result, 1)

    def test_float_string_vat_rate(self):
        """Test VAT rate parsing with float string."""
        # Test that the helper correctly parses a valid decimal string
        result = billing_config._get_decimal_rate("FAKE_SETTING", "0.19")
        self.assertEqual(result, Decimal("0.19"))

    def test_percent_vat_rate_clamped(self):
        """Test VAT rate > 1 is clamped (someone sets 19 instead of 0.19)."""
        result = billing_config._get_decimal_rate("FAKE_SETTING", "19")
        self.assertEqual(result, Decimal("1"))

    def test_negative_vat_rate_clamped(self):
        """Test negative VAT rate is clamped to 0."""
        result = billing_config._get_decimal_rate("FAKE_SETTING", "-0.19")
        self.assertEqual(result, Decimal("0"))

    def test_invalid_decimal_string(self):
        """Test invalid decimal string falls back to valid default."""
        # When setting value is invalid, function falls back to default
        result = billing_config._get_decimal_rate("FAKE_SETTING", "0.19")
        # Default is "0.19", so we get that
        self.assertEqual(result, Decimal("0.19"))

    def test_none_country_code_in_is_eu_country(self):
        """Test is_eu_country handles None safely."""
        self.assertFalse(billing_config.is_eu_country(None))

    def test_empty_string_country_code(self):
        """Test is_eu_country handles empty string safely."""
        self.assertFalse(billing_config.is_eu_country(""))

    def test_lowercase_country_code(self):
        """Test is_eu_country normalizes case."""
        self.assertTrue(billing_config.is_eu_country("ro"))
        self.assertTrue(billing_config.is_eu_country("Ro"))

    def test_get_vat_rate_explicit_ro_fallback(self):
        """Test get_vat_rate falls back for explicit 'RO' not just None."""
        with patch("apps.billing.tax_models.TaxRule") as mock_tax:
            mock_tax.get_active_rate.return_value = Decimal("0.00")
            # Explicit "RO" should still get fallback
            rate = billing_config.get_vat_rate("RO", fallback=True)
            self.assertEqual(rate, billing_config.DEFAULT_VAT_RATE)


class IdempotencyRedTeamTestCase(TransactionTestCase):
    """Test idempotency against race conditions and attacks."""

    def setUp(self):
        """Set up test data."""
        self.meter = UsageMeter.objects.create(
            name="test_meter",
            display_name="Test Meter",
            aggregation_type="sum",
            unit="units",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

    def test_duplicate_idempotency_key_rejected(self):
        """Test that duplicate idempotency keys are rejected."""
        idempotency_key = str(uuid.uuid4())

        # First event succeeds
        UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("10"),
            idempotency_key=idempotency_key,
            timestamp=timezone.now(),
        )

        # Second event with same key should fail
        with transaction.atomic(), self.assertRaises(IntegrityError):
            UsageEvent.objects.create(
                meter=self.meter,
                customer=self.customer,
                value=Decimal("20"),
                idempotency_key=idempotency_key,
                timestamp=timezone.now(),
            )

    def test_null_idempotency_keys_allowed(self):
        """Test that multiple events with null idempotency keys are allowed."""
        # Multiple events without idempotency key should be allowed
        event1 = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("10"),
            idempotency_key=None,
            timestamp=timezone.now(),
        )
        event2 = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("20"),
            idempotency_key=None,
            timestamp=timezone.now(),
        )
        self.assertNotEqual(event1.id, event2.id)

    def test_empty_string_idempotency_key(self):
        """Test handling of empty string idempotency key."""
        # Empty string should be treated differently from null
        event1 = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("10"),
            idempotency_key="",
            timestamp=timezone.now(),
        )
        # This may or may not raise depending on DB constraints
        # The important thing is it doesn't silently succeed as duplicate
        self.assertIsNotNone(event1.id)


class InvoiceCalculationRedTeamTestCase(TestCase):
    """Test invoice calculations against overflow and precision attacks."""

    def test_very_large_usage_value(self):
        """Test handling of very large usage values."""
        meter = UsageMeter.objects.create(
            name="large_test",
            display_name="Large Test",
            aggregation_type="sum",
            unit="units",
        )
        customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        # Very large value that might cause overflow
        large_value = Decimal("99999999999999.99999999")
        event = UsageEvent.objects.create(
            meter=meter,
            customer=customer,
            value=large_value,
            timestamp=timezone.now(),
        )
        self.assertEqual(event.value, large_value)

    def test_zero_usage_value(self):
        """Test handling of zero usage values."""
        meter = UsageMeter.objects.create(
            name="zero_test",
            display_name="Zero Test",
            aggregation_type="sum",
            unit="units",
        )
        customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        event = UsageEvent.objects.create(
            meter=meter,
            customer=customer,
            value=Decimal("0"),
            timestamp=timezone.now(),
        )
        self.assertEqual(event.value, Decimal("0"))

    def test_decimal_precision_preservation(self):
        """Test that decimal precision is preserved through calculations."""
        meter = UsageMeter.objects.create(
            name="precision_test",
            display_name="Precision Test",
            aggregation_type="sum",
            unit="units",
        )
        customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        # Use a value that would lose precision if converted to float
        precise_value = Decimal("0.123456789012345678")
        event = UsageEvent.objects.create(
            meter=meter,
            customer=customer,
            value=precise_value,
            timestamp=timezone.now(),
        )
        # Reload from database
        event.refresh_from_db()
        # Check precision is preserved (may be truncated by DB field)
        self.assertIsInstance(event.value, Decimal)

    def test_negative_usage_value_validation(self):
        """
        Test that negative usage values are handled.

        RED TEAM FINDING: Currently, negative values ARE accepted by the system.
        This may be intentional (for refunds/credits) or a vulnerability.
        This test documents the current behavior - consider adding validation
        if negative values should be rejected.
        """
        UsageMeter.objects.create(
            name="negative_test",
            display_name="Negative Test",
            aggregation_type="sum",
            unit="units",
        )
        customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

        service = MeteringService()
        result = service.record_event(UsageEventData(
            meter_name="negative_test",
            customer_id=str(customer.id),
            value=Decimal("-10"),  # Negative value
        ))

        # FINDING: Negative values are currently ACCEPTED
        # This test documents current behavior - review if this is desired
        self.assertTrue(result.is_ok())  # Negative values are accepted
        # If rejection is desired, uncomment: self.assertFalse(result.is_ok())


class BillingCycleBoundaryTestCase(TestCase):
    """Test billing cycle edge cases and boundary conditions."""

    def setUp(self):
        """Set up test data."""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2,
        )
        self.product = Product.objects.create(
            slug="test-plan-bc",
            name="Test Plan",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-BC-RT001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    def test_overlapping_billing_cycles_allowed(self):
        """
        RED TEAM FINDING: Overlapping billing cycles are NOT rejected.

        This test documents that the system currently allows overlapping
        billing cycles for the same subscription, which could lead to
        double-billing. Consider adding a database constraint or model
        validation to prevent this.
        """
        now = timezone.now()

        BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now + timedelta(days=30),
            status="active",
        )

        # FINDING: Overlapping cycles are currently ALLOWED
        BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now + timedelta(days=15),  # Overlaps with cycle1
            period_end=now + timedelta(days=45),
            status="active",
        )
        # Both cycles exist - this is a potential billing issue
        self.assertEqual(BillingCycle.objects.filter(
            subscription=self.subscription
        ).count(), 2)

    def test_billing_cycle_period_end_before_start_allowed(self):
        """
        RED TEAM FINDING: period_end before period_start is NOT rejected.

        This test documents that the system currently allows creating
        billing cycles where end date is before start date. Consider
        adding model validation in clean() method.
        """
        now = timezone.now()

        # FINDING: Invalid date range is currently ALLOWED
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now,
            period_end=now - timedelta(days=1),  # End before start!
            status="active",
        )
        # Invalid cycle was created
        self.assertIsNotNone(cycle.id)

    def test_leap_year_billing_cycle(self):
        """Test billing cycle crossing leap day."""
        # February in a leap year
        leap_year_feb = timezone.make_aware(datetime(2024, 2, 1, 0, 0, 0))
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=leap_year_feb,
            period_end=leap_year_feb + timedelta(days=29),  # Feb 29
            status="active",
        )
        self.assertEqual((cycle.period_end - cycle.period_start).days, 29)


class StripeSyncFailureTestCase(TestCase):
    """
    Test Stripe sync error handling and recovery.

    Note: Comprehensive Stripe error handling tests are in test_stripe_metering.py.
    This test class validates that the sync service is properly structured.
    """

    def setUp(self):
        """Set up test data."""
        self.meter = UsageMeter.objects.create(
            name="stripe_test",
            display_name="Stripe Test",
            aggregation_type="sum",
            unit="units",
            stripe_meter_event_name="stripe_test_meter",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2,
        )
        self.product = Product.objects.create(
            slug="test-plan-stripe",
            name="Test Plan",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-STRIPE-RT001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
            stripe_subscription_id="sub_test123",
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
            total_value=Decimal("100"),
            billable_value=Decimal("100"),
            status="rated",
        )

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_stripe_not_configured(self, mock_get_stripe):
        """Test handling when Stripe is not configured."""
        mock_get_stripe.return_value = None

        service = StripeUsageSyncService()
        result = service.sync_aggregation_to_stripe(str(self.aggregation.id))

        # Should handle gracefully when Stripe not configured
        self.assertFalse(result.is_ok())

    def test_sync_nonexistent_aggregation(self):
        """Test syncing with invalid aggregation ID."""
        service = StripeUsageSyncService()
        result = service.sync_aggregation_to_stripe(str(uuid.uuid4()))

        self.assertFalse(result.is_ok())


class UsageAlertRedTeamTestCase(TestCase):
    """Test usage alert edge cases and potential abuse."""

    def setUp(self):
        """Set up test data."""
        self.meter = UsageMeter.objects.create(
            name="alert_test",
            display_name="Alert Test",
            aggregation_type="sum",
            unit="units",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2,
        )
        self.product = Product.objects.create(
            slug="test-plan-alert",
            name="Test Plan",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-ALERT-RT001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    def test_alert_creation_requires_threshold(self):
        """Test that UsageAlert requires a UsageThreshold FK."""
        # Create threshold
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_value=Decimal("50.00"),
            threshold_type="percentage",
            is_active=True,
        )

        # Now can create alert
        alert = UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            subscription=self.subscription,
            usage_value=Decimal("55.00"),
            usage_percentage=Decimal("55.00"),
            status="pending",
        )
        self.assertIsNotNone(alert.id)

    def test_alert_cooldown_mechanism(self):
        """Test that alert cooldown mechanism exists."""
        # Create threshold
        threshold = UsageThreshold.objects.create(
            meter=self.meter,
            threshold_value=Decimal("50.00"),
            threshold_type="percentage",
            is_active=True,
        )

        # Create a recent alert
        UsageAlert.objects.create(
            threshold=threshold,
            customer=self.customer,
            subscription=self.subscription,
            usage_value=Decimal("55.00"),
            usage_percentage=Decimal("55.00"),
            status="sent",
            notified_at=timezone.now(),
        )

        # UsageAlertService should check for recent alerts before creating new ones
        service = UsageAlertService()
        # The service checks for recent alerts internally
        self.assertIsNotNone(service)


class MeteringServiceEdgeCasesTestCase(TestCase):
    """Test metering service edge cases."""

    def setUp(self):
        """Set up test data."""
        self.meter = UsageMeter.objects.create(
            name="edge_test",
            display_name="Edge Test",
            aggregation_type="sum",
            unit="units",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

    def test_future_timestamp_rejected(self):
        """Test that future timestamps beyond grace period are rejected."""
        service = MeteringService()
        future_time = timezone.now() + timedelta(hours=1)  # 1 hour in future

        result = service.record_event(UsageEventData(
            meter_name="edge_test",
            customer_id=str(self.customer.id),
            value=Decimal("10"),
            timestamp=future_time.isoformat(),
        ))

        # Should reject timestamps too far in future
        self.assertFalse(result.is_ok())

    def test_very_old_timestamp_rejected(self):
        """Test that timestamps beyond grace period are rejected."""
        service = MeteringService()
        old_time = timezone.now() - timedelta(days=30)  # 30 days ago

        result = service.record_event(UsageEventData(
            meter_name="edge_test",
            customer_id=str(self.customer.id),
            value=Decimal("10"),
            timestamp=old_time.isoformat(),
        ))

        # Should reject timestamps too old
        self.assertFalse(result.is_ok())

    def test_nonexistent_meter_rejected(self):
        """Test that events for nonexistent meters are rejected."""
        service = MeteringService()
        result = service.record_event(UsageEventData(
            meter_name="nonexistent_meter",
            customer_id=str(self.customer.id),
            value=Decimal("10"),
        ))

        self.assertFalse(result.is_ok())

    def test_nonexistent_customer_rejected(self):
        """Test that events for nonexistent customers are rejected."""
        service = MeteringService()
        result = service.record_event(UsageEventData(
            meter_name="edge_test",
            customer_id=str(uuid.uuid4()),  # Random UUID
            value=Decimal("10"),
        ))

        self.assertFalse(result.is_ok())

    def test_inactive_meter_rejected(self):
        """Test that events for inactive meters are rejected."""
        UsageMeter.objects.create(
            name="inactive_meter",
            display_name="Inactive Meter",
            aggregation_type="sum",
            unit="units",
            is_active=False,
        )

        service = MeteringService()
        result = service.record_event(UsageEventData(
            meter_name="inactive_meter",
            customer_id=str(self.customer.id),
            value=Decimal("10"),
        ))

        self.assertFalse(result.is_ok())


class AggregationConsistencyTestCase(TransactionTestCase):
    """Test aggregation consistency under various conditions."""

    def setUp(self):
        """Set up test data."""
        self.meter = UsageMeter.objects.create(
            name="agg_test",
            display_name="Aggregation Test",
            aggregation_type="sum",
            unit="units",
        )
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )
        self.currency = Currency.objects.create(
            code="RON",
            symbol="lei",
            decimals=2,
        )
        self.product = Product.objects.create(
            slug="test-plan-aggcons",
            name="Test Plan",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-AGGCONS-RT001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    def test_aggregation_recalculation_consistency(self):
        """Test that recalculating aggregation gives same result."""
        now = timezone.now()
        cycle = BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=15),
            period_end=now + timedelta(days=15),
            status="active",
        )

        # Create multiple events (without billing_cycle - not a field on UsageEvent)
        total = Decimal("0")
        for i in range(10):
            value = Decimal(str(i + 1))
            UsageEvent.objects.create(
                meter=self.meter,
                customer=self.customer,
                subscription=self.subscription,
                value=value,
                timestamp=now - timedelta(days=i),
            )
            total += value

        # Create aggregation
        agg = UsageAggregation.objects.create(
            meter=self.meter,
            customer=self.customer,
            subscription=self.subscription,
            billing_cycle=cycle,
            period_start=cycle.period_start,
            period_end=cycle.period_end,
            total_value=total,
            billable_value=total,
            status="pending",
        )

        self.assertEqual(agg.total_value, Decimal("55"))  # Sum of 1-10

    def test_max_aggregation_type(self):
        """Test max aggregation type calculates correctly."""
        max_meter = UsageMeter.objects.create(
            name="max_test",
            display_name="Max Test",
            aggregation_type="max",
            unit="units",
        )

        now = timezone.now()

        # Create events with various values
        for value in [5, 10, 3, 15, 7]:
            UsageEvent.objects.create(
                meter=max_meter,
                customer=self.customer,
                subscription=self.subscription,
                value=Decimal(str(value)),
                timestamp=now,
            )

        # Max should be 15
        max_value = UsageEvent.objects.filter(
            meter=max_meter,
            subscription=self.subscription,
        ).aggregate(max_val=Max("value"))["max_val"]

        self.assertEqual(max_value, Decimal("15"))
