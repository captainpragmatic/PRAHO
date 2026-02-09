# ===============================================================================
# STRIPE METERING INTEGRATION TEST SUITE
# ===============================================================================
"""
Comprehensive test suite for Stripe metering integration.
Tests StripeMeterService, StripeMeterEventService, StripeUsageSyncService,
and StripeMeterWebhookHandler with mocked Stripe API.
"""

from __future__ import annotations

import uuid
from decimal import Decimal
from datetime import timedelta
from unittest.mock import patch, MagicMock, PropertyMock

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.models import (
    Currency,
    UsageMeter,
    UsageEvent,
    UsageAggregation,
    Subscription,
    SubscriptionItem,
    BillingCycle,
)
from apps.billing.stripe_metering import (
    StripeMeterService,
    StripeMeterEventService,
    StripeSubscriptionMeterService,
    StripeUsageSyncService,
    StripeMeterWebhookHandler,
)
from apps.customers.models import Customer
from apps.provisioning.models import ServicePlan


class StripeMeterServiceTestCase(TestCase):
    """Test StripeMeterService functionality."""

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_create_meter_success(self, mock_get_stripe):
        """Test successful meter creation."""
        mock_stripe = MagicMock()
        mock_meter = MagicMock()
        mock_meter.id = "meter_abc123"
        mock_stripe.billing.Meter.create.return_value = mock_meter
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterService()
        result = service.create_meter(
            display_name="API Requests",
            event_name="api_requests",
            aggregation_formula="sum",
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["meter_id"], "meter_abc123")
        self.assertEqual(data["event_name"], "api_requests")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_create_meter_stripe_error(self, mock_get_stripe):
        """Test meter creation with Stripe error."""
        mock_stripe = MagicMock()
        mock_stripe.error = MagicMock()
        mock_stripe.error.StripeError = Exception
        mock_stripe.billing.Meter.create.side_effect = Exception("API Error")
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterService()
        result = service.create_meter(
            display_name="Test",
            event_name="test",
        )

        self.assertTrue(result.is_err())

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_create_meter_no_stripe(self, mock_get_stripe):
        """Test meter creation when Stripe not configured."""
        mock_get_stripe.return_value = None

        service = StripeMeterService()
        result = service.create_meter(
            display_name="Test",
            event_name="test",
        )

        self.assertTrue(result.is_err())
        self.assertIn("not configured", result.error.lower())

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_get_meter(self, mock_get_stripe):
        """Test retrieving a meter."""
        mock_stripe = MagicMock()
        mock_meter = MagicMock()
        mock_meter.id = "meter_abc123"
        mock_stripe.billing.Meter.retrieve.return_value = mock_meter
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterService()
        result = service.get_meter("meter_abc123")

        self.assertTrue(result.is_ok())
        mock_stripe.billing.Meter.retrieve.assert_called_once_with("meter_abc123")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_list_meters(self, mock_get_stripe):
        """Test listing meters."""
        mock_stripe = MagicMock()
        mock_meters = MagicMock()
        mock_meters.data = [MagicMock(), MagicMock()]
        mock_stripe.billing.Meter.list.return_value = mock_meters
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterService()
        result = service.list_meters(limit=50)

        self.assertTrue(result.is_ok())
        self.assertEqual(len(result.unwrap()), 2)

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_deactivate_meter(self, mock_get_stripe):
        """Test deactivating a meter."""
        mock_stripe = MagicMock()
        mock_meter = MagicMock()
        mock_stripe.billing.Meter.modify.return_value = mock_meter
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterService()
        result = service.deactivate_meter("meter_abc123")

        self.assertTrue(result.is_ok())
        mock_stripe.billing.Meter.modify.assert_called_once_with(
            "meter_abc123",
            status="inactive"
        )


class StripeMeterEventServiceTestCase(TestCase):
    """Test StripeMeterEventService functionality."""

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_report_usage_success(self, mock_get_stripe):
        """Test successful usage reporting."""
        mock_stripe = MagicMock()
        mock_event = MagicMock()
        mock_event.identifier = "evt_123"
        mock_stripe.billing.MeterEvent.create.return_value = mock_event
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterEventService()
        result = service.report_usage(
            event_name="api_requests",
            stripe_customer_id="cus_abc123",
            value=100,
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["event_id"], "evt_123")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_report_usage_with_timestamp(self, mock_get_stripe):
        """Test usage reporting with timestamp."""
        mock_stripe = MagicMock()
        mock_event = MagicMock()
        mock_event.identifier = "evt_123"
        mock_stripe.billing.MeterEvent.create.return_value = mock_event
        mock_get_stripe.return_value = mock_stripe

        timestamp = timezone.now() - timedelta(hours=1)

        service = StripeMeterEventService()
        result = service.report_usage(
            event_name="api_requests",
            stripe_customer_id="cus_abc123",
            value=Decimal("50.5"),
            timestamp=timestamp,
            identifier="unique-id",
        )

        self.assertTrue(result.is_ok())

        # Verify timestamp was passed
        call_kwargs = mock_stripe.billing.MeterEvent.create.call_args[1]
        self.assertIn("timestamp", call_kwargs)
        self.assertEqual(call_kwargs["identifier"], "unique-id")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_report_usage_missing_customer(self, mock_get_stripe):
        """Test usage reporting without customer ID."""
        mock_get_stripe.return_value = MagicMock()

        service = StripeMeterEventService()
        result = service.report_usage(
            event_name="api_requests",
            stripe_customer_id="",
            value=100,
        )

        self.assertTrue(result.is_err())
        self.assertIn("customer ID", result.error)

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_report_bulk_usage(self, mock_get_stripe):
        """Test bulk usage reporting."""
        mock_stripe = MagicMock()
        mock_event = MagicMock()
        mock_event.identifier = "evt_123"
        mock_stripe.billing.MeterEvent.create.return_value = mock_event
        mock_get_stripe.return_value = mock_stripe

        service = StripeMeterEventService()

        events = [
            {
                "event_name": "api_requests",
                "stripe_customer_id": "cus_1",
                "value": 100,
            },
            {
                "event_name": "api_requests",
                "stripe_customer_id": "cus_2",
                "value": 200,
            },
            {
                "event_name": "api_requests",
                "stripe_customer_id": "",  # This will fail
                "value": 300,
            },
        ]

        success, errors, error_messages = service.report_bulk_usage(events)

        self.assertEqual(success, 2)
        self.assertEqual(errors, 1)


class StripeUsageSyncServiceTestCase(TransactionTestCase):
    """Test StripeUsageSyncService functionality."""

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
            stripe_meter_id="meter_abc123",
            stripe_meter_event_name="bandwidth_usage",
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
            stripe_customer_id="cus_test123",
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
            total_value=Decimal("150"),
            billable_value=Decimal("150"),
            status="rated",
        )

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_sync_aggregation_success(self, mock_get_stripe):
        """Test successful aggregation sync."""
        mock_stripe = MagicMock()
        mock_event = MagicMock()
        mock_event.identifier = "evt_sync123"
        mock_stripe.billing.MeterEvent.create.return_value = mock_event
        mock_get_stripe.return_value = mock_stripe

        service = StripeUsageSyncService()
        result = service.sync_aggregation_to_stripe(str(self.aggregation.id))

        self.assertTrue(result.is_ok())

        self.aggregation.refresh_from_db()
        self.assertIsNotNone(self.aggregation.stripe_synced_at)

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_sync_aggregation_no_event_name(self, mock_get_stripe):
        """Test sync fails when meter has no Stripe event name."""
        self.meter.stripe_meter_event_name = ""
        self.meter.save()

        mock_get_stripe.return_value = MagicMock()

        service = StripeUsageSyncService()
        result = service.sync_aggregation_to_stripe(str(self.aggregation.id))

        self.assertTrue(result.is_err())
        self.assertIn("event name", result.error.lower())

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_sync_billing_cycle(self, mock_get_stripe):
        """Test syncing entire billing cycle."""
        mock_stripe = MagicMock()
        mock_event = MagicMock()
        mock_event.identifier = "evt_123"
        mock_stripe.billing.MeterEvent.create.return_value = mock_event
        mock_get_stripe.return_value = mock_stripe

        service = StripeUsageSyncService()
        result = service.sync_billing_cycle_to_stripe(str(self.billing_cycle.id))

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["success_count"], 1)


class StripeMeterWebhookHandlerTestCase(TestCase):
    """Test StripeMeterWebhookHandler functionality."""

    def setUp(self):
        """Set up handler."""
        self.handler = StripeMeterWebhookHandler()

    def test_handle_meter_created(self):
        """Test handling meter.created event."""
        event = MagicMock()
        event.type = "billing.meter.created"
        event.data.object.id = "meter_new123"

        result = self.handler.handle_event(event)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap()["handled"])

    def test_handle_meter_updated(self):
        """Test handling meter.updated event."""
        event = MagicMock()
        event.type = "billing.meter.updated"
        event.data.object.id = "meter_abc123"
        event.data.object.event_name = "updated_event_name"

        result = self.handler.handle_event(event)

        self.assertTrue(result.is_ok())

    def test_handle_unknown_event(self):
        """Test handling unknown event type."""
        event = MagicMock()
        event.type = "unknown.event.type"

        result = self.handler.handle_event(event)

        self.assertTrue(result.is_ok())
        self.assertFalse(result.unwrap()["handled"])

    def test_handle_invoice_created(self):
        """Test handling invoice.created with metered items."""
        event = MagicMock()
        event.type = "invoice.created"
        event.data.object.id = "inv_123"
        event.data.object.get.return_value = {
            "data": [
                {"price": {"recurring": {"usage_type": "metered"}}}
            ]
        }

        result = self.handler.handle_event(event)

        self.assertTrue(result.is_ok())
        self.assertTrue(result.unwrap()["handled"])


class StripeSubscriptionMeterServiceTestCase(TestCase):
    """Test StripeSubscriptionMeterService functionality."""

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_create_metered_subscription(self, mock_get_stripe):
        """Test creating metered subscription."""
        mock_stripe = MagicMock()
        mock_subscription = MagicMock()
        mock_subscription.id = "sub_123"
        mock_subscription.status = "active"
        mock_subscription.current_period_start = 1704067200
        mock_subscription.current_period_end = 1706745600
        mock_stripe.Subscription.create.return_value = mock_subscription
        mock_get_stripe.return_value = mock_stripe

        service = StripeSubscriptionMeterService()
        result = service.create_metered_subscription(
            customer_id="cus_123",
            price_id="price_abc",
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["subscription_id"], "sub_123")
        self.assertEqual(data["status"], "active")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_add_metered_item(self, mock_get_stripe):
        """Test adding metered item to subscription."""
        mock_stripe = MagicMock()
        mock_item = MagicMock()
        mock_item.id = "si_123"
        mock_stripe.SubscriptionItem.create.return_value = mock_item
        mock_get_stripe.return_value = mock_stripe

        service = StripeSubscriptionMeterService()
        result = service.add_metered_item(
            subscription_id="sub_123",
            price_id="price_metered",
        )

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(data["subscription_item_id"], "si_123")

    @patch("apps.billing.stripe_metering.get_stripe")
    def test_get_usage_summary(self, mock_get_stripe):
        """Test getting usage summary."""
        mock_stripe = MagicMock()
        mock_summaries = MagicMock()
        mock_summary = MagicMock()
        mock_summary.id = "sis_123"
        mock_summary.total_usage = 1500
        mock_summary.period.start = 1704067200
        mock_summary.period.end = 1706745600
        mock_summaries.data = [mock_summary]
        mock_stripe.SubscriptionItem.list_usage_record_summaries.return_value = mock_summaries
        mock_get_stripe.return_value = mock_stripe

        service = StripeSubscriptionMeterService()
        result = service.get_usage_summary("si_123")

        self.assertTrue(result.is_ok())
        data = result.unwrap()
        self.assertEqual(len(data["summaries"]), 1)
        self.assertEqual(data["summaries"][0]["total_usage"], 1500)
