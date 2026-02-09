# ===============================================================================
# METERING BACKGROUND TASKS TEST SUITE
# ===============================================================================
"""
Comprehensive test suite for metering background tasks.
Tests all scheduled and async tasks with mocked dependencies.
"""

from __future__ import annotations

import uuid
from datetime import timedelta
from decimal import Decimal
from unittest.mock import MagicMock, patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.metering_models import (
    BillingCycle,
    UsageAggregation,
    UsageEvent,
    UsageMeter,
)
from apps.billing.metering_tasks import (
    advance_billing_cycles,
    check_all_usage_thresholds,
    check_usage_thresholds,
    check_usage_thresholds_async,
    close_expired_billing_cycles,
    collect_service_usage,
    collect_virtualmin_usage,
    generate_pending_invoices,
    process_pending_usage_events,
    rate_pending_aggregations,
    register_scheduled_tasks,
    run_billing_cycle_workflow,
    send_usage_alert_notification,
    send_usage_alert_notification_async,
    sync_aggregation_to_stripe,
    sync_aggregation_to_stripe_async,
    sync_billing_cycle_to_stripe,
    sync_pending_to_stripe,
    update_aggregation_for_event,
    update_aggregation_for_event_async,
)
from apps.billing.models import Currency, Subscription, SubscriptionItem
from apps.customers.models import Customer
from apps.products.models import Product


class UpdateAggregationForEventTestCase(TransactionTestCase):
    """Test update_aggregation_for_event task."""

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
            name="api_requests",
            display_name="API Requests",
            aggregation_type="sum",
            unit="requests",
        )
        self.product = Product.objects.create(
            slug="basic-agg-evt",
            name="Basic",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-AGGEVT-001",
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

    def test_event_not_found(self):
        """Test handling of non-existent event."""
        fake_id = str(uuid.uuid4())
        result = update_aggregation_for_event(fake_id)

        self.assertFalse(result["success"])
        self.assertIn("not found", result["error"])

    def test_already_processed_event(self):
        """Test skipping already processed events."""
        event = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("10"),
            is_processed=True,  # Already processed
            timestamp=timezone.now(),  # Provide timestamp
        )

        result = update_aggregation_for_event(str(event.id))

        self.assertTrue(result["success"])
        self.assertIn("already processed", result["message"])

    @patch("apps.billing.metering_service.MeteringService")
    def test_successful_aggregation_update(self, mock_service_class):
        """Test successful aggregation update."""
        mock_service = MagicMock()
        mock_service_class.return_value = mock_service

        event = UsageEvent.objects.create(
            meter=self.meter,
            customer=self.customer,
            value=Decimal("10"),
            is_processed=False,
            timestamp=timezone.now(),  # Provide timestamp to avoid isoformat error
        )

        result = update_aggregation_for_event(str(event.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["event_id"], str(event.id))
        mock_service._update_aggregation_sync.assert_called_once()


class ProcessPendingUsageEventsTestCase(TestCase):
    """Test process_pending_usage_events task."""

    @patch("apps.audit.services.AuditService")
    @patch("apps.billing.metering_service.AggregationService")
    def test_successful_batch_processing(self, mock_service_class, mock_audit):
        """Test successful batch processing of pending events."""
        mock_service = MagicMock()
        mock_service.process_pending_events.return_value = (50, 2)
        mock_service_class.return_value = mock_service

        result = process_pending_usage_events(limit=100)

        self.assertTrue(result["success"])
        self.assertEqual(result["processed"], 50)
        self.assertEqual(result["errors"], 2)
        mock_service.process_pending_events.assert_called_once_with(
            meter_id=None, limit=100
        )

    @patch("apps.audit.services.AuditService")
    @patch("apps.billing.metering_service.AggregationService")
    def test_with_meter_filter(self, mock_service_class, mock_audit):
        """Test batch processing with meter filter."""
        mock_service = MagicMock()
        mock_service.process_pending_events.return_value = (10, 0)
        mock_service_class.return_value = mock_service

        process_pending_usage_events(limit=50, meter_id="meter123")

        mock_service.process_pending_events.assert_called_once_with(
            meter_id="meter123", limit=50
        )

    @patch("apps.billing.metering_service.AggregationService")
    def test_exception_handling(self, mock_service_class):
        """Test exception handling in batch processing."""
        mock_service_class.return_value.process_pending_events.side_effect = (
            Exception("Database error")
        )

        result = process_pending_usage_events()

        self.assertFalse(result["success"])
        self.assertIn("Database error", result["error"])


class BillingCycleTasksTestCase(TransactionTestCase):
    """Test billing cycle management tasks."""

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
        self.product = Product.objects.create(
            slug="basic-bctask",
            name="Basic",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-BCTASK-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    @patch("apps.audit.services.AuditService")
    @patch("apps.billing.usage_invoice_service.BillingCycleManager")
    def test_advance_billing_cycles(self, mock_manager_class, mock_audit):
        """Test advancing billing cycles."""
        mock_manager = MagicMock()
        mock_manager.advance_all_subscriptions.return_value = (5, 1, ["Error 1"])
        mock_manager_class.return_value = mock_manager

        result = advance_billing_cycles()

        self.assertTrue(result["success"])
        self.assertEqual(result["created"], 5)
        self.assertEqual(result["errors"], 1)
        mock_manager.advance_all_subscriptions.assert_called_once()

    @patch("apps.billing.usage_invoice_service.BillingCycleManager")
    def test_close_expired_billing_cycles(self, mock_manager_class):
        """Test closing expired billing cycles."""
        mock_manager = MagicMock()
        mock_manager.close_expired_cycles.return_value = (10, 0)
        mock_manager_class.return_value = mock_manager

        result = close_expired_billing_cycles()

        self.assertTrue(result["success"])
        self.assertEqual(result["closed"], 10)
        self.assertEqual(result["errors"], 0)

    @patch("apps.billing.usage_invoice_service.BillingCycleManager")
    def test_generate_pending_invoices(self, mock_manager_class):
        """Test generating pending invoices."""
        mock_manager = MagicMock()
        mock_manager.generate_pending_invoices.return_value = (3, 0)
        mock_manager_class.return_value = mock_manager

        result = generate_pending_invoices()

        self.assertTrue(result["success"])
        self.assertEqual(result["generated"], 3)


class RatePendingAggregationsTestCase(TransactionTestCase):
    """Test rate_pending_aggregations task."""

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
            name="api_requests",
            display_name="API Requests",
            aggregation_type="sum",
            unit="requests",
        )
        self.product = Product.objects.create(
            slug="basic-rate",
            name="Basic",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-RATE-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    @patch("apps.billing.metering_service.RatingEngine")
    def test_rate_specific_billing_cycle(self, mock_engine_class):
        """Test rating a specific billing cycle."""
        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"rated_count": 5}
        mock_engine.rate_billing_cycle.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        result = rate_pending_aggregations(billing_cycle_id="cycle123")

        self.assertEqual(result["rated_count"], 5)
        mock_engine.rate_billing_cycle.assert_called_once_with("cycle123")

    @patch("apps.billing.metering_service.RatingEngine")
    def test_rate_all_pending(self, mock_engine_class):
        """Test rating all pending aggregations."""
        # Create a closed billing cycle
        now = timezone.now()
        BillingCycle.objects.create(
            subscription=self.subscription,
            period_start=now - timedelta(days=30),
            period_end=now,
            status="closed",
        )

        mock_engine = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"rated_count": 3}
        mock_engine.rate_billing_cycle.return_value = mock_result
        mock_engine_class.return_value = mock_engine

        result = rate_pending_aggregations()

        self.assertTrue(result["success"])
        self.assertEqual(result["rated"], 3)


class BillingWorkflowTestCase(TestCase):
    """Test run_billing_cycle_workflow task."""

    @patch("apps.audit.services.AuditService")
    @patch("apps.billing.metering_tasks.advance_billing_cycles")
    @patch("apps.billing.metering_tasks.generate_pending_invoices")
    @patch("apps.billing.metering_tasks.rate_pending_aggregations")
    @patch("apps.billing.metering_tasks.close_expired_billing_cycles")
    def test_complete_workflow(
        self,
        mock_close,
        mock_rate,
        mock_generate,
        mock_advance,
        mock_audit
    ):
        """Test complete billing cycle workflow."""
        mock_close.return_value = {"success": True, "closed": 5}
        mock_rate.return_value = {"success": True, "rated": 10}
        mock_generate.return_value = {"success": True, "generated": 3}
        mock_advance.return_value = {"success": True, "created": 2}

        result = run_billing_cycle_workflow()

        self.assertTrue(result["success"])
        self.assertIn("results", result)
        mock_close.assert_called_once()
        mock_rate.assert_called_once()
        mock_generate.assert_called_once()
        mock_advance.assert_called_once()


class AlertTasksTestCase(TransactionTestCase):
    """Test alert-related tasks."""

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
            name="api_requests",
            display_name="API Requests",
            aggregation_type="sum",
            unit="requests",
        )
        self.product = Product.objects.create(
            slug="basic-alert",
            name="Basic",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-ALERT-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
        )

    @patch("apps.billing.metering_service.UsageAlertService")
    def test_check_usage_thresholds(self, mock_service_class):
        """Test checking usage thresholds."""
        mock_service = MagicMock()
        mock_alert = MagicMock()
        mock_alert.id = uuid.uuid4()
        mock_service.check_thresholds.return_value = [mock_alert]
        mock_service_class.return_value = mock_service

        result = check_usage_thresholds(
            customer_id=str(self.customer.id),
            meter_id=str(self.meter.id),
            subscription_id=str(self.subscription.id)
        )

        self.assertTrue(result["success"])
        self.assertEqual(result["alerts_created"], 1)
        mock_service.check_thresholds.assert_called_once()

    @patch("apps.billing.metering_service.UsageAlertService")
    def test_send_usage_alert_notification(self, mock_service_class):
        """Test sending usage alert notification."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_service.send_alert_notification.return_value = mock_result
        mock_service_class.return_value = mock_service

        alert_id = str(uuid.uuid4())
        result = send_usage_alert_notification(alert_id)

        self.assertTrue(result["success"])
        self.assertEqual(result["alert_id"], alert_id)

    @patch("apps.billing.metering_service.UsageAlertService")
    def test_check_all_usage_thresholds(self, mock_service_class):
        """Test checking all usage thresholds."""
        # Create subscription item
        SubscriptionItem.objects.create(
            subscription=self.subscription,
            product=self.product,
            unit_price_cents=2999,
        )

        mock_service = MagicMock()
        mock_service.check_thresholds.return_value = []
        mock_service_class.return_value = mock_service

        result = check_all_usage_thresholds()

        self.assertTrue(result["success"])
        self.assertEqual(result["subscriptions_checked"], 1)


class StripeSyncTasksTestCase(TransactionTestCase):
    """Test Stripe sync tasks."""

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
            name="api_requests",
            display_name="API Requests",
            aggregation_type="sum",
            unit="requests",
            stripe_meter_id="meter_abc",
            stripe_meter_event_name="api_requests",
        )
        self.product = Product.objects.create(
            slug="basic-stripe",
            name="Basic",
            product_type="shared_hosting",
        )
        now = timezone.now()
        self.subscription = Subscription.objects.create(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            subscription_number="SUB-STRIPE-001",
            status="active",
            billing_cycle="monthly",
            unit_price_cents=2999,
            current_period_start=now,
            current_period_end=now + timedelta(days=30),
            next_billing_date=now + timedelta(days=30),
            stripe_subscription_id="sub_abc123",
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

    @patch("apps.billing.stripe_metering.StripeUsageSyncService")
    def test_sync_aggregation_to_stripe_success(self, mock_service_class):
        """Test successful aggregation sync to Stripe."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"synced": True}
        mock_service.sync_aggregation_to_stripe.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = sync_aggregation_to_stripe(str(self.aggregation.id))

        self.assertTrue(result["success"])
        mock_service.sync_aggregation_to_stripe.assert_called_once_with(
            str(self.aggregation.id)
        )

    @patch("apps.billing.stripe_metering.StripeUsageSyncService")
    def test_sync_aggregation_to_stripe_error(self, mock_service_class):
        """Test aggregation sync error handling."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = False
        mock_result.error = "Stripe API error"
        mock_service.sync_aggregation_to_stripe.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = sync_aggregation_to_stripe(str(self.aggregation.id))

        self.assertFalse(result["success"])
        self.assertIn("Stripe API error", result["error"])

    @patch("apps.billing.stripe_metering.StripeUsageSyncService")
    def test_sync_billing_cycle_to_stripe(self, mock_service_class):
        """Test syncing entire billing cycle to Stripe."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {"success_count": 5}
        mock_service.sync_billing_cycle_to_stripe.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = sync_billing_cycle_to_stripe(str(self.billing_cycle.id))

        self.assertTrue(result["success"])
        self.assertEqual(result["success_count"], 5)

    @patch("apps.billing.stripe_metering.StripeUsageSyncService")
    def test_sync_pending_to_stripe(self, mock_service_class):
        """Test syncing all pending aggregations to Stripe."""
        mock_service = MagicMock()
        mock_result = MagicMock()
        mock_result.is_ok.return_value = True
        mock_result.unwrap.return_value = {}
        mock_service.sync_aggregation_to_stripe.return_value = mock_result
        mock_service_class.return_value = mock_service

        result = sync_pending_to_stripe()

        self.assertTrue(result["success"])
        self.assertIn("synced", result)


class VirtualminUsageCollectionTestCase(TransactionTestCase):
    """Test Virtualmin usage collection task."""

    def setUp(self):
        """Set up test data."""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

    def test_collect_virtualmin_usage_no_meters(self):
        """Test collection when meters aren't configured."""
        # No meters exist, so should fail
        result = collect_virtualmin_usage()

        self.assertFalse(result["success"])
        self.assertIn("Meters not configured", result["error"])

    @patch("apps.audit.services.AuditService")
    @patch("apps.provisioning.models.VirtualminAccount")
    def test_collect_virtualmin_usage_success(
        self, mock_account_model, mock_audit
    ):
        """Test successful Virtualmin usage collection."""
        # Create real meters
        UsageMeter.objects.create(
            name="disk_usage_gb",
            display_name="Disk Usage",
            aggregation_type="last",
            unit="gb",
        )
        UsageMeter.objects.create(
            name="bandwidth_gb",
            display_name="Bandwidth",
            aggregation_type="sum",
            unit="gb",
        )

        # Set up mock accounts - return empty queryset (no accounts to process)
        mock_queryset = MagicMock()
        mock_queryset.__iter__ = lambda s: iter([])
        mock_queryset.count.return_value = 0
        mock_account_model.objects.filter.return_value.select_related.return_value = mock_queryset

        result = collect_virtualmin_usage()

        self.assertTrue(result["success"])
        self.assertEqual(result["accounts_processed"], 0)


class ServiceUsageCollectionTestCase(TransactionTestCase):
    """Test service usage collection task."""

    def setUp(self):
        """Set up test data."""
        self.customer = Customer.objects.create(
            name="Test Customer",
            primary_email="test@example.com",
            status="active",
        )

    @patch("apps.provisioning.models.Service")
    def test_collect_service_usage_success(self, mock_service_model):
        """Test successful service usage collection."""
        # Set up mock services - return empty queryset
        mock_queryset = MagicMock()
        mock_queryset.__iter__ = lambda s: iter([])
        mock_queryset.count.return_value = 0
        mock_service_model.objects.filter.return_value.select_related.return_value = mock_queryset

        result = collect_service_usage()

        self.assertTrue(result["success"])
        self.assertEqual(result["services_processed"], 0)

    @patch("apps.provisioning.models.Service")
    def test_collect_service_usage_exception(self, mock_service_model):
        """Test exception handling in service collection."""
        mock_service_model.objects.filter.side_effect = Exception("DB error")

        result = collect_service_usage()

        self.assertFalse(result["success"])
        self.assertIn("DB error", result["error"])


class AsyncWrapperTestCase(TestCase):
    """Test async wrapper functions."""

    @patch("apps.billing.metering_tasks.async_task")
    def test_update_aggregation_for_event_async(self, mock_async_task):
        """Test async aggregation update wrapper."""
        mock_async_task.return_value = "task_id_123"

        result = update_aggregation_for_event_async("event123")

        self.assertEqual(result, "task_id_123")
        mock_async_task.assert_called_once_with(
            "apps.billing.metering_tasks.update_aggregation_for_event",
            "event123",
            timeout=300
        )

    @patch("apps.billing.metering_tasks.async_task")
    def test_check_usage_thresholds_async(self, mock_async_task):
        """Test async threshold check wrapper."""
        mock_async_task.return_value = "task_id_456"

        result = check_usage_thresholds_async("cust123", "meter456", "sub789")

        self.assertEqual(result, "task_id_456")
        mock_async_task.assert_called_once_with(
            "apps.billing.metering_tasks.check_usage_thresholds",
            "cust123",
            "meter456",
            "sub789",
            timeout=300
        )

    @patch("apps.billing.metering_tasks.async_task")
    def test_send_usage_alert_notification_async(self, mock_async_task):
        """Test async alert notification wrapper."""
        mock_async_task.return_value = "task_id_789"

        result = send_usage_alert_notification_async("alert123")

        self.assertEqual(result, "task_id_789")
        mock_async_task.assert_called_once()

    @patch("apps.billing.metering_tasks.async_task")
    def test_sync_aggregation_to_stripe_async(self, mock_async_task):
        """Test async Stripe sync wrapper."""
        mock_async_task.return_value = "task_id_stripe"

        result = sync_aggregation_to_stripe_async("agg123")

        self.assertEqual(result, "task_id_stripe")
        mock_async_task.assert_called_once()


class ScheduledTaskRegistrationTestCase(TestCase):
    """Test scheduled task registration."""

    @patch("django_q.models.Schedule")
    def test_register_scheduled_tasks(self, mock_schedule):
        """Test registering all scheduled tasks."""
        mock_schedule.MINUTES = "M"
        mock_schedule.HOURLY = "H"

        register_scheduled_tasks()

        # Verify 6 tasks are registered
        self.assertEqual(mock_schedule.objects.update_or_create.call_count, 6)

        # Check that specific tasks are registered
        calls = mock_schedule.objects.update_or_create.call_args_list
        task_names = [call[1]["name"] for call in calls]

        self.assertIn("Process Pending Usage Events", task_names)
        self.assertIn("Run Billing Cycle Workflow", task_names)
        self.assertIn("Check All Usage Thresholds", task_names)
        self.assertIn("Sync Pending to Stripe", task_names)
        self.assertIn("Collect Virtualmin Usage", task_names)
        self.assertIn("Collect Service Usage", task_names)


class TaskErrorHandlingTestCase(TestCase):
    """Test error handling across tasks."""

    @patch("apps.billing.usage_invoice_service.BillingCycleManager")
    def test_advance_billing_cycles_exception(self, mock_manager_class):
        """Test exception handling in advance_billing_cycles."""
        mock_manager_class.return_value.advance_all_subscriptions.side_effect = (
            Exception("Database connection error")
        )

        result = advance_billing_cycles()

        self.assertFalse(result["success"])
        self.assertIn("Database connection error", result["error"])

    @patch("apps.billing.usage_invoice_service.BillingCycleManager")
    def test_close_expired_cycles_exception(self, mock_manager_class):
        """Test exception handling in close_expired_billing_cycles."""
        mock_manager_class.return_value.close_expired_cycles.side_effect = (
            Exception("Lock timeout")
        )

        result = close_expired_billing_cycles()

        self.assertFalse(result["success"])
        self.assertIn("Lock timeout", result["error"])

    @patch("apps.billing.metering_service.UsageAlertService")
    def test_check_thresholds_exception(self, mock_service_class):
        """Test exception handling in check_usage_thresholds."""
        mock_service_class.return_value.check_thresholds.side_effect = (
            Exception("Service unavailable")
        )

        result = check_usage_thresholds("cust1", "meter1")

        self.assertFalse(result["success"])
        self.assertIn("Service unavailable", result["error"])

    @patch("apps.billing.stripe_metering.StripeUsageSyncService")
    def test_stripe_sync_exception(self, mock_service_class):
        """Test exception handling in sync_aggregation_to_stripe."""
        mock_service_class.return_value.sync_aggregation_to_stripe.side_effect = (
            Exception("Stripe rate limit exceeded")
        )

        result = sync_aggregation_to_stripe("agg123")

        self.assertFalse(result["success"])
        self.assertIn("Stripe rate limit exceeded", result["error"])
