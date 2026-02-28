"""
Comprehensive coverage tests for metering_service.py and stripe_gateway.py.

Targets uncovered lines in:
- apps.billing.metering_service (507 stmts, 71% covered, 147 missed)
- apps.billing.gateways.stripe_gateway (146 stmts, 14% covered, 125 missed)
"""

from __future__ import annotations

import logging
import uuid
from datetime import timedelta
from decimal import Decimal
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.billing.metering_models import (
    BillingCycle,
    PricingTier,
    PricingTierBracket,
    UsageAggregation,
    UsageAlert,
    UsageEvent,
    UsageMeter,
    UsageThreshold,
)
from apps.billing.metering_service import (
    AggregationService,
    MeteringService,
    RatingEngine,
    Result,
    UsageAlertService,
    UsageEventData,
    _get_allowance_from_service_plan,
    _get_allowance_from_subscription_item,
    _get_subscription_item_for_meter,
    _parse_decimal,
)
from apps.billing.models import Currency, Subscription, SubscriptionItem
from apps.customers.models import Customer
from apps.products.models import Product

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_currency():
    return Currency.objects.create(code=f"C{uuid.uuid4().hex[:3].upper()}", symbol="X", decimals=2)


def _make_customer(name="Test Co"):
    return Customer.objects.create(name=name, customer_type="company", company_name=name, status="active")


def _make_product(slug=None, name="Hosting Plan"):
    slug = slug or f"prod-{uuid.uuid4().hex[:8]}"
    return Product.objects.create(slug=slug, name=name, product_type="shared_hosting", is_active=True)


def _make_meter(**kwargs):
    defaults = {
        "name": f"meter_{uuid.uuid4().hex[:8]}",
        "display_name": "Test Meter",
        "aggregation_type": "sum",
        "unit": "count",
        "is_active": True,
        "is_billable": True,
        "event_grace_period_hours": 24,
        "rounding_mode": "none",
        "rounding_increment": Decimal("1"),
    }
    defaults.update(kwargs)
    return UsageMeter.objects.create(**defaults)


def _make_subscription(customer, product, currency, **kwargs):
    defaults = {
        "subscription_number": f"SUB-{uuid.uuid4().hex[:8]}",
        "status": "active",
        "billing_cycle": "monthly",
        "unit_price_cents": 1000,
        "current_period_start": timezone.now() - timedelta(days=15),
        "current_period_end": timezone.now() + timedelta(days=15),
        "next_billing_date": timezone.now() + timedelta(days=15),
    }
    defaults.update(kwargs)
    return Subscription.objects.create(customer=customer, product=product, currency=currency, **defaults)


def _make_billing_cycle(subscription, **kwargs):
    defaults = {
        "period_start": timezone.now() - timedelta(days=15),
        "period_end": timezone.now() + timedelta(days=15),
        "status": "active",
    }
    defaults.update(kwargs)
    return BillingCycle.objects.create(subscription=subscription, **defaults)


def _make_aggregation(meter, customer, billing_cycle, subscription=None, **kwargs):
    defaults = {
        "period_start": billing_cycle.period_start,
        "period_end": billing_cycle.period_end,
        "status": "accumulating",
        "total_value": Decimal("0"),
    }
    defaults.update(kwargs)
    return UsageAggregation.objects.create(
        meter=meter, customer=customer, billing_cycle=billing_cycle, subscription=subscription, **defaults
    )


# ============================================================================
# Result dataclass tests
# ============================================================================

class TestResult(TestCase):
    def test_ok(self):
        r = Result.ok(42)
        assert r.is_ok()
        assert not r.is_err()
        assert r.unwrap() == 42
        assert r.value == 42
        assert r.error is None

    def test_err(self):
        r = Result.err("boom")
        assert r.is_err()
        assert not r.is_ok()
        assert r.error == "boom"
        assert r.value is None

    def test_unwrap_on_error_raises(self):
        r = Result.err("nope")
        with self.assertRaises(ValueError):
            r.unwrap()

    def test_unwrap_or(self):
        assert Result.ok(5).unwrap_or(0) == 5
        assert Result.err("x").unwrap_or(99) == 99


# ============================================================================
# _parse_decimal
# ============================================================================

class TestParseDecimal(TestCase):
    def test_none(self):
        assert _parse_decimal(None) == Decimal("0")

    def test_empty_string(self):
        assert _parse_decimal("") == Decimal("0")

    def test_valid(self):
        assert _parse_decimal("3.14") == Decimal("3.14")

    def test_invalid(self):
        assert _parse_decimal("abc") == Decimal("0")

    def test_int(self):
        assert _parse_decimal(10) == Decimal("10")


# ============================================================================
# _get_allowance helpers
# ============================================================================

class TestGetAllowanceFromSubscriptionItem(TestCase):
    def test_none_item(self):
        assert _get_allowance_from_subscription_item(None) == Decimal("0")

    def test_item_meta_included_quantity(self):
        item = SimpleNamespace(meta={"included_quantity": "50"}, product=SimpleNamespace(meta={}))
        assert _get_allowance_from_subscription_item(item) == Decimal("50")

    def test_item_meta_allowance(self):
        item = SimpleNamespace(meta={"allowance": 100}, product=SimpleNamespace(meta={}))
        assert _get_allowance_from_subscription_item(item) == Decimal("100")

    def test_product_meta_fallback(self):
        item = SimpleNamespace(meta={}, product=SimpleNamespace(meta={"included_quantity": "25"}))
        assert _get_allowance_from_subscription_item(item) == Decimal("25")

    def test_product_meta_none(self):
        item = SimpleNamespace(meta={}, product=SimpleNamespace(meta=None))
        assert _get_allowance_from_subscription_item(item) == Decimal("0")

    def test_no_meta(self):
        item = SimpleNamespace(meta=None, product=SimpleNamespace(meta=None))
        assert _get_allowance_from_subscription_item(item) == Decimal("0")


class TestGetAllowanceFromServicePlan(TestCase):
    def test_none_inputs(self):
        assert _get_allowance_from_service_plan(None, None) == Decimal("0")
        meter = SimpleNamespace(category="storage")
        assert _get_allowance_from_service_plan(meter, None) == Decimal("0")

    def test_storage(self):
        meter = SimpleNamespace(category="storage")
        plan = SimpleNamespace(disk_space_gb=50, bandwidth_gb=None, email_accounts=None, databases=None, domains=None)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("50")

    def test_bandwidth(self):
        meter = SimpleNamespace(category="bandwidth")
        plan = SimpleNamespace(disk_space_gb=None, bandwidth_gb=100, email_accounts=None, databases=None, domains=None)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("100")

    def test_email(self):
        meter = SimpleNamespace(category="email")
        plan = SimpleNamespace(disk_space_gb=None, bandwidth_gb=None, email_accounts=10, databases=None, domains=None)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("10")

    def test_database(self):
        meter = SimpleNamespace(category="database")
        plan = SimpleNamespace(disk_space_gb=None, bandwidth_gb=None, email_accounts=None, databases=5, domains=None)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("5")

    def test_domain(self):
        meter = SimpleNamespace(category="domain")
        plan = SimpleNamespace(disk_space_gb=None, bandwidth_gb=None, email_accounts=None, databases=None, domains=3)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("3")

    def test_unknown_category(self):
        meter = SimpleNamespace(category="compute")
        plan = SimpleNamespace(disk_space_gb=None, bandwidth_gb=None, email_accounts=None, databases=None, domains=None)
        assert _get_allowance_from_service_plan(meter, plan) == Decimal("0")


# ============================================================================
# _get_subscription_item_for_meter
# ============================================================================

class TestGetSubscriptionItemForMeter(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter()
        self.subscription = _make_subscription(self.customer, self.product, self.currency)

    def test_none_subscription(self):
        assert _get_subscription_item_for_meter(None, self.meter) is None

    def test_none_meter(self):
        assert _get_subscription_item_for_meter(self.subscription, None) is None

    def test_no_items(self):
        assert _get_subscription_item_for_meter(self.subscription, self.meter) is None

    def test_returns_item_by_product_slug(self):
        # Create product with slug matching meter name
        prod = _make_product(slug=self.meter.name)
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=prod, unit_price_cents=500, meta={}
        )
        result = _get_subscription_item_for_meter(self.subscription, self.meter)
        assert result is not None

    def test_returns_fallback_item(self):
        # Item with no matching slug/meta — should still return items.first() as fallback
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=self.product, unit_price_cents=500, meta={}
        )
        result = _get_subscription_item_for_meter(self.subscription, self.meter)
        assert result is not None

    def test_active_items_filtered(self):
        # Create two items, one with is_active meta
        prod2 = _make_product()
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=self.product, unit_price_cents=500, meta={"is_active": True}
        )
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=prod2, unit_price_cents=600, meta={"is_active": False}
        )
        result = _get_subscription_item_for_meter(self.subscription, self.meter)
        assert result is not None


# ============================================================================
# MeteringService
# ============================================================================

class TestMeteringServiceRecordEvent(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.meter = _make_meter()
        self.svc = MeteringService()

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_success(self, mock_agg, mock_thresh):
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("10"),
        ))
        assert result.is_ok()
        assert UsageEvent.objects.count() == 1

    def test_meter_not_found(self):
        result = self.svc.record_event(UsageEventData(
            meter_name="nonexistent", customer_id=str(self.customer.id), value=Decimal("1")
        ))
        assert result.is_err()
        assert "Meter not found" in result.error

    def test_meter_inactive(self):
        self.meter.is_active = False
        self.meter.save()
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name, customer_id=str(self.customer.id), value=Decimal("1")
        ))
        assert result.is_err()
        assert "inactive" in result.error

    def test_customer_not_found(self):
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name, customer_id="999999", value=Decimal("1")
        ))
        assert result.is_err()
        assert "Customer not found" in result.error

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_timestamp_too_old(self, mock_agg, mock_thresh):
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("1"),
            timestamp=timezone.now() - timedelta(hours=48),
        ))
        assert result.is_err()
        assert "too old" in result.error

    @patch("apps.billing.metering_service.billing_config.get_future_event_drift_minutes", return_value=5)
    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_timestamp_in_future(self, mock_agg, mock_thresh, mock_drift):
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("1"),
            timestamp=timezone.now() + timedelta(hours=1),
        ))
        assert result.is_err()
        assert "future" in result.error

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_idempotency_duplicate(self, mock_agg, mock_thresh):
        data = UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("10"),
            idempotency_key="unique-key-1",
        )
        r1 = self.svc.record_event(data)
        assert r1.is_ok()
        r2 = self.svc.record_event(data)
        assert r2.is_ok()
        assert UsageEvent.objects.count() == 1

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_with_subscription_and_service(self, mock_agg, mock_thresh):
        product = _make_product()
        sub = _make_subscription(self.customer, product, self.currency)
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("5"),
            subscription_id=str(sub.id),
            service_id="999999",  # non-existent, should warn but not fail
        ))
        assert result.is_ok()

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_nonexistent_subscription_warns(self, mock_agg, mock_thresh):
        result = self.svc.record_event(UsageEventData(
            meter_name=self.meter.name,
            customer_id=str(self.customer.id),
            value=Decimal("5"),
            subscription_id=str(uuid.uuid4()),
        ))
        assert result.is_ok()


class TestMeteringServiceBulkEvents(TransactionTestCase):
    def setUp(self):
        self.customer = _make_customer()
        self.meter = _make_meter()
        self.svc = MeteringService()

    @patch("apps.billing.metering_service.MeteringService._check_thresholds_async")
    @patch("apps.billing.metering_service.MeteringService._schedule_aggregation_update")
    def test_bulk_success(self, mock_agg, mock_thresh):
        events = [
            UsageEventData(meter_name=self.meter.name, customer_id=str(self.customer.id), value=Decimal(str(i)))
            for i in range(3)
        ]
        _results, ok, err = self.svc.record_bulk_events(events)
        assert ok == 3
        assert err == 0

    def test_bulk_stop_on_error(self):
        events = [
            UsageEventData(meter_name="bad", customer_id=str(self.customer.id), value=Decimal("1")),
            UsageEventData(meter_name=self.meter.name, customer_id=str(self.customer.id), value=Decimal("1")),
        ]
        results, ok, err = self.svc.record_bulk_events(events, stop_on_error=True)
        assert err == 1
        assert ok == 0
        assert len(results) == 1


class TestScheduleAggregationUpdate(TransactionTestCase):
    def setUp(self):
        self.svc = MeteringService()

    @patch("apps.billing.metering_service.MeteringService._update_aggregation_sync")
    def test_fallback_to_sync_on_import_error(self, mock_sync):
        """When django_q is unavailable, falls back to sync."""
        event = MagicMock(id=uuid.uuid4())
        with (
            patch(
                "apps.billing.metering_service.MeteringService._schedule_aggregation_update",
                wraps=self.svc._schedule_aggregation_update,
            ),
            patch.dict("sys.modules", {"django_q": None, "django_q.tasks": None}),
        ):
            self.svc._schedule_aggregation_update(event)
        mock_sync.assert_called_once_with(event)


class TestUpdateAggregationSync(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter(aggregation_type="sum")
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.svc = MeteringService()

    def test_sync_update_with_subscription(self):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, subscription=self.subscription,
            value=Decimal("10"), timestamp=timezone.now(), idempotency_key="k1",
        )
        with patch.object(Subscription, "get_current_billing_cycle", return_value=self.billing_cycle, create=True):
            self.svc._update_aggregation_sync(event)
        event.refresh_from_db()
        assert event.is_processed

    def test_sync_update_no_subscription_finds_active(self):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, subscription=None,
            value=Decimal("5"), timestamp=timezone.now(), idempotency_key="k2",
        )
        with patch.object(Subscription, "get_current_billing_cycle", return_value=self.billing_cycle, create=True):
            self.svc._update_aggregation_sync(event)
        event.refresh_from_db()
        assert event.is_processed

    def test_sync_update_no_subscription_at_all(self):
        """No subscription for customer — should log warning and return."""
        # Make subscription inactive
        self.subscription.status = "cancelled"
        self.subscription.save()
        event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, subscription=None,
            value=Decimal("5"), timestamp=timezone.now(), idempotency_key="k3",
        )
        self.svc._update_aggregation_sync(event)
        event.refresh_from_db()
        assert not event.is_processed

    def test_sync_no_billing_cycle(self):
        event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, subscription=self.subscription,
            value=Decimal("5"), timestamp=timezone.now(), idempotency_key="k4",
        )
        with patch.object(Subscription, "get_current_billing_cycle", return_value=None, create=True):
            self.svc._update_aggregation_sync(event)
        event.refresh_from_db()
        assert not event.is_processed


class TestApplyEventToAggregation(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.svc = MeteringService()

    def _make_event_and_agg(self, agg_type, value=Decimal("10")):
        meter = _make_meter(aggregation_type=agg_type)
        agg = _make_aggregation(meter, self.customer, self.billing_cycle, self.subscription)
        event = UsageEvent.objects.create(
            meter=meter, customer=self.customer, value=value,
            timestamp=timezone.now(), idempotency_key=f"evt-{uuid.uuid4().hex[:8]}",
        )
        return event, agg

    def test_sum(self):
        event, agg = self._make_event_and_agg("sum", Decimal("10"))
        self.svc._apply_event_to_aggregation(event, agg)
        assert agg.total_value == Decimal("10")
        assert agg.event_count == 1

    def test_count(self):
        event, agg = self._make_event_and_agg("count", Decimal("99"))
        self.svc._apply_event_to_aggregation(event, agg)
        # count adds 1 regardless of value
        assert agg.total_value == Decimal("1")

    def test_max_new_max(self):
        event, agg = self._make_event_and_agg("max", Decimal("50"))
        self.svc._apply_event_to_aggregation(event, agg)
        assert agg.max_value == Decimal("50")
        assert agg.total_value == Decimal("50")

    def test_max_not_exceeded(self):
        event, agg = self._make_event_and_agg("max", Decimal("50"))
        agg.max_value = Decimal("100")
        agg.save()
        self.svc._apply_event_to_aggregation(event, agg)
        # max_value should stay 100, total_value stays at whatever F expression gives
        agg.refresh_from_db()
        assert agg.max_value == Decimal("100")

    def test_last(self):
        event, agg = self._make_event_and_agg("last", Decimal("42"))
        self.svc._apply_event_to_aggregation(event, agg)
        assert agg.last_value == Decimal("42")
        assert agg.total_value == Decimal("42")

    def test_last_older_event(self):
        meter = _make_meter(aggregation_type="last")
        agg = _make_aggregation(meter, self.customer, self.billing_cycle, self.subscription)
        agg.last_value_at = timezone.now() + timedelta(hours=1)
        agg.save()
        event = UsageEvent.objects.create(
            meter=meter, customer=self.customer, value=Decimal("5"),
            timestamp=timezone.now() - timedelta(hours=1),
            idempotency_key=f"evt-{uuid.uuid4().hex[:8]}",
        )
        self.svc._apply_event_to_aggregation(event, agg)
        agg.refresh_from_db()
        # Older event should not update last_value
        assert agg.last_value is None or agg.last_value != Decimal("5")

    def test_unique(self):
        event, agg = self._make_event_and_agg("unique", Decimal("7"))
        self.svc._apply_event_to_aggregation(event, agg)
        assert "7" in agg.unique_values
        assert agg.total_value == Decimal("1")


class TestCheckThresholdsAsync(TransactionTestCase):
    def test_handles_django_q_unavailable(self):
        svc = MeteringService()
        customer = MagicMock(id=1)
        meter = MagicMock(id=2)
        # Should not raise
        with patch.dict("sys.modules", {"django_q": None, "django_q.tasks": None}):
            svc._check_thresholds_async(customer, meter, None)


# ============================================================================
# AggregationService
# ============================================================================

class TestAggregationService(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter()
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.svc = AggregationService()

    def test_process_pending_events(self):
        _event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, subscription=self.subscription,
            value=Decimal("5"), timestamp=timezone.now(), idempotency_key="p1", is_processed=False,
        )
        with patch.object(MeteringService, "_update_aggregation_sync"):
            processed, errors = self.svc.process_pending_events()
        assert processed == 1
        assert errors == 0

    def test_process_pending_with_filters(self):
        _event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, value=Decimal("5"),
            timestamp=timezone.now(), idempotency_key="p2", is_processed=False,
        )
        with patch.object(MeteringService, "_update_aggregation_sync"):
            processed, _errors = self.svc.process_pending_events(
                meter_id=str(self.meter.id), customer_id=str(self.customer.id)
            )
        assert processed == 1

    def test_process_pending_error(self):
        _event = UsageEvent.objects.create(
            meter=self.meter, customer=self.customer, value=Decimal("5"),
            timestamp=timezone.now(), idempotency_key="p3", is_processed=False,
        )
        with patch.object(MeteringService, "_update_aggregation_sync", side_effect=Exception("boom")):
            _processed, errors = self.svc.process_pending_events()
        assert errors == 1

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_close_billing_cycle(self, mock_audit):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        with patch.object(AggregationService, "process_pending_events", return_value=(0, 0)):
            result = self.svc.close_billing_cycle(str(self.billing_cycle.id))
        assert result.is_ok()
        self.billing_cycle.refresh_from_db()
        assert self.billing_cycle.status == "closed"

    def test_close_billing_cycle_not_found(self):
        result = self.svc.close_billing_cycle(str(uuid.uuid4()))
        assert result.is_err()
        assert "not found" in result.error

    def test_close_billing_cycle_bad_status(self):
        self.billing_cycle.status = "closed"
        self.billing_cycle.save()
        result = self.svc.close_billing_cycle(str(self.billing_cycle.id))
        assert result.is_err()
        assert "cannot be closed" in result.error

    def test_get_customer_usage_summary(self):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("100"), billable_value=Decimal("100"),
                                 charge_cents=500)
        summary = self.svc.get_customer_usage_summary(str(self.customer.id))
        assert self.meter.name in summary["meters"]
        assert summary["total_charge_cents"] == 500

    def test_get_customer_usage_summary_with_dates(self):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("50"), charge_cents=200)
        start = timezone.now() - timedelta(days=30)
        end = timezone.now() + timedelta(days=30)
        summary = self.svc.get_customer_usage_summary(str(self.customer.id), start, end)
        assert self.meter.name in summary["meters"]


# ============================================================================
# RatingEngine
# ============================================================================

class TestRatingEngine(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter(is_billable=True, rounding_mode="none")
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.engine = RatingEngine()

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_not_found(self, mock_audit):
        result = self.engine.rate_aggregation(str(uuid.uuid4()))
        assert result.is_err()

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_already_rated(self, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription, status="rated")
        result = self.engine.rate_aggregation(str(agg.id))
        assert result.is_err()
        assert "already rated" in result.error

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_no_overage(self, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                total_value=Decimal("5"))
        result = self.engine.rate_aggregation(str(agg.id))
        assert result.is_ok()
        agg.refresh_from_db()
        assert agg.status == "rated"
        assert agg.charge_cents == 0

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_with_pricing_tier(self, mock_audit):
        PricingTier.objects.create(
            name="Default", meter=self.meter, pricing_model="per_unit",
            currency=self.currency, unit_price_cents=100, is_active=True, is_default=True,
        )
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                total_value=Decimal("10"))
        # Create sub item to set included_quantity=0 so full value is overage
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=self.product, unit_price_cents=100, meta={}
        )
        result = self.engine.rate_aggregation(str(agg.id))
        assert result.is_ok()
        agg.refresh_from_db()
        assert agg.charge_cents > 0

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_with_unit_price_from_sub_item(self, mock_audit):
        """When sub_item has effective_price_cents but no pricing tier."""
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                total_value=Decimal("10"))
        SubscriptionItem.objects.create(
            subscription=self.subscription, product=self.product, unit_price_cents=50, meta={}
        )
        result = self.engine.rate_aggregation(str(agg.id))
        assert result.is_ok()

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_aggregation_default_tier_fallback(self, mock_audit):
        """When there's no sub_item pricing_tier, but a default PricingTier exists."""
        PricingTier.objects.create(
            name="Default Fallback", meter=self.meter, pricing_model="per_unit",
            currency=self.currency, unit_price_cents=200, minimum_charge_cents=0,
            is_active=True, is_default=True,
        )
        # No subscription items
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, None,
                                total_value=Decimal("5"))
        result = self.engine.rate_aggregation(str(agg.id))
        assert result.is_ok()

    def test_apply_rounding_none(self):
        assert self.engine._apply_rounding(Decimal("3.7"), "none", Decimal("1")) == Decimal("3.7")

    def test_apply_rounding_up(self):
        assert self.engine._apply_rounding(Decimal("3.2"), "up", Decimal("1")) == Decimal("4")

    def test_apply_rounding_up_exact(self):
        assert self.engine._apply_rounding(Decimal("3.0"), "up", Decimal("1")) == Decimal("3")

    def test_apply_rounding_down(self):
        assert self.engine._apply_rounding(Decimal("3.9"), "down", Decimal("1")) == Decimal("3")

    def test_apply_rounding_nearest_up(self):
        assert self.engine._apply_rounding(Decimal("3.6"), "nearest", Decimal("1")) == Decimal("4")

    def test_apply_rounding_nearest_down(self):
        assert self.engine._apply_rounding(Decimal("3.4"), "nearest", Decimal("1")) == Decimal("3")

    def test_apply_rounding_zero_increment(self):
        # increment <= 0 should default to 1
        assert self.engine._apply_rounding(Decimal("3.2"), "up", Decimal("0")) == Decimal("4")

    def test_apply_rounding_unknown_mode(self):
        assert self.engine._apply_rounding(Decimal("3.7"), "banana", Decimal("1")) == Decimal("3.7")


class TestRatingEngineTieredCharge(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.meter = _make_meter()
        self.engine = RatingEngine()

    def _make_tier(self, pricing_model, unit_price_cents=100, minimum_charge_cents=0):
        return PricingTier.objects.create(
            name=f"Tier-{uuid.uuid4().hex[:6]}", meter=self.meter, pricing_model=pricing_model,
            currency=self.currency, unit_price_cents=unit_price_cents,
            minimum_charge_cents=minimum_charge_cents, is_active=True, is_default=True,
        )

    def test_per_unit(self):
        tier = self._make_tier("per_unit", unit_price_cents=100)
        charge = self.engine._calculate_tiered_charge(Decimal("5"), tier)
        assert charge == 500

    def test_per_unit_no_price(self):
        tier = self._make_tier("per_unit", unit_price_cents=None, minimum_charge_cents=50)
        tier.unit_price_cents = None
        tier.save()
        charge = self.engine._calculate_per_unit_charge(Decimal("5"), tier)
        assert charge == 50  # falls back to minimum

    def test_per_unit_minimum(self):
        tier = self._make_tier("per_unit", unit_price_cents=1, minimum_charge_cents=500)
        charge = self.engine._calculate_per_unit_charge(Decimal("3"), tier)
        assert charge == 500

    def test_volume_with_bracket(self):
        tier = self._make_tier("volume")
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("0"), to_quantity=Decimal("100"),
            unit_price_cents=50, flat_fee_cents=0,
        )
        charge = self.engine._calculate_volume_charge(Decimal("10"), tier)
        assert charge == 500

    def test_volume_no_bracket(self):
        tier = self._make_tier("volume", minimum_charge_cents=100)
        charge = self.engine._calculate_volume_charge(Decimal("10"), tier)
        assert charge == 100

    def test_volume_unlimited_bracket(self):
        tier = self._make_tier("volume")
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("0"), to_quantity=None,
            unit_price_cents=30, flat_fee_cents=10,
        )
        charge = self.engine._calculate_volume_charge(Decimal("5"), tier)
        assert charge == 160  # 5*30 + 10

    def test_graduated(self):
        tier = self._make_tier("graduated")
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("0"), to_quantity=Decimal("5"),
            unit_price_cents=100, flat_fee_cents=0, sort_order=0,
        )
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("5"), to_quantity=None,
            unit_price_cents=50, flat_fee_cents=0, sort_order=1,
        )
        charge = self.engine._calculate_graduated_charge(Decimal("8"), tier)
        # First bracket: min(8, 5-0=5) * 100 = 500; remaining=3
        # Second bracket: min(3, 3) * 50 = 150; total=650
        assert charge == 650

    def test_package(self):
        tier = self._make_tier("package")
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("0"), to_quantity=Decimal("100"),
            unit_price_cents=0, flat_fee_cents=999, sort_order=0,
        )
        charge = self.engine._calculate_package_charge(Decimal("50"), tier)
        assert charge == 999

    def test_package_no_matching_bracket(self):
        tier = self._make_tier("package", minimum_charge_cents=200)
        PricingTierBracket.objects.create(
            pricing_tier=tier, from_quantity=Decimal("0"), to_quantity=Decimal("10"),
            unit_price_cents=0, flat_fee_cents=100, sort_order=0,
        )
        charge = self.engine._calculate_package_charge(Decimal("50"), tier)
        assert charge == 200  # minimum

    def test_unknown_pricing_model(self):
        tier = self._make_tier("per_unit")
        tier.pricing_model = "mystery"
        tier.minimum_charge_cents = 42
        tier.save()
        charge = self.engine._calculate_tiered_charge(Decimal("10"), tier)
        assert charge == 42


class TestRateBillingCycle(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter(is_billable=True)
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.engine = RatingEngine()

    def test_not_found(self):
        result = self.engine.rate_billing_cycle(str(uuid.uuid4()))
        assert result.is_err()

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_cycle_success(self, mock_audit):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("10"), status="pending_rating")
        _tier = PricingTier.objects.create(
            name="Default", meter=self.meter, pricing_model="per_unit",
            currency=self.currency, unit_price_cents=100, is_active=True, is_default=True,
        )
        result = self.engine.rate_billing_cycle(str(self.billing_cycle.id))
        assert result.is_ok()
        data = result.unwrap()
        assert data["rated_count"] == 1

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_rate_cycle_with_error(self, mock_audit):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("10"), status="pending_rating")
        with patch.object(RatingEngine, "rate_aggregation", return_value=Result.err("fail")):
            result = self.engine.rate_billing_cycle(str(self.billing_cycle.id))
        assert result.is_ok()
        assert result.unwrap()["error_count"] == 1


# ============================================================================
# UsageAlertService
# ============================================================================

class TestUsageAlertService(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter()
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.svc = UsageAlertService()

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_check_thresholds_percentage(self, mock_audit):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("90"), included_allowance=Decimal("100"))
        UsageThreshold.objects.create(
            meter=self.meter, threshold_type="percentage", threshold_value=Decimal("80"),
            is_active=True, notify_customer=True,
        )
        with patch.object(UsageAlertService, "_schedule_alert_notification"):
            alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert len(alerts) == 1

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_check_thresholds_absolute(self, mock_audit):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("50"))
        UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("40"),
            is_active=True, notify_customer=True,
        )
        with patch.object(UsageAlertService, "_schedule_alert_notification"):
            alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert len(alerts) == 1

    def test_check_thresholds_customer_not_found(self):
        alerts = self.svc.check_thresholds("999999", str(self.meter.id))
        assert alerts == []

    def test_check_thresholds_no_aggregation(self):
        alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert alerts == []

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_check_thresholds_duplicate_alert_skipped(self, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                total_value=Decimal("90"), included_allowance=Decimal("100"))
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="percentage", threshold_value=Decimal("80"),
            is_active=True, repeat_notification=False,
        )
        # Create existing alert
        UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("85"), status="pending",
        )
        with patch.object(UsageAlertService, "_schedule_alert_notification"):
            alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert len(alerts) == 0

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_check_thresholds_repeat_notification(self, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                total_value=Decimal("90"), included_allowance=Decimal("100"))
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="percentage", threshold_value=Decimal("80"),
            is_active=True, repeat_notification=True,
        )
        UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("85"), status="pending",
        )
        with patch.object(UsageAlertService, "_schedule_alert_notification"):
            alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert len(alerts) == 1

    def test_threshold_not_breached(self):
        _agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription,
                                 total_value=Decimal("10"), included_allowance=Decimal("100"))
        UsageThreshold.objects.create(
            meter=self.meter, threshold_type="percentage", threshold_value=Decimal("80"), is_active=True,
        )
        alerts = self.svc.check_thresholds(str(self.customer.id), str(self.meter.id))
        assert len(alerts) == 0

    def test_threshold_breach_status_percentage_no_allowance(self):
        """percentage threshold with 0 allowance => not breached"""
        threshold = SimpleNamespace(threshold_type="percentage", threshold_value=Decimal("80"))
        agg = SimpleNamespace(total_value=Decimal("50"))
        is_breached, _pct = self.svc._threshold_breach_status(threshold, agg, Decimal("0"))
        assert not is_breached


class TestUsageAlertServiceNotification(TransactionTestCase):
    def setUp(self):
        self.currency = _make_currency()
        self.customer = _make_customer()
        self.product = _make_product()
        self.meter = _make_meter()
        self.subscription = _make_subscription(self.customer, self.product, self.currency)
        self.billing_cycle = _make_billing_cycle(self.subscription)
        self.svc = UsageAlertService()

    def test_send_alert_not_found(self):
        result = self.svc.send_alert_notification(str(uuid.uuid4()))
        assert result.is_err()

    def test_send_alert_already_sent(self):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=True,
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="sent",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()

    def test_send_alert_success(self):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=True,
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="pending",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()
        alert.refresh_from_db()
        assert alert.status == "sent"

    def test_send_alert_with_action_warn(self):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=False, action_on_breach="warn",
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="pending",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()
        alert.refresh_from_db()
        assert alert.action_taken == "warn"

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_take_action_throttle(self, mock_suspend, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=False, action_on_breach="throttle",
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="pending",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()
        mock_suspend.assert_called_once()
        alert.refresh_from_db()
        assert alert.action_taken == "throttle"

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    @patch("apps.provisioning.provisioning_service.ProvisioningService.suspend_services_for_customer")
    def test_take_action_suspend(self, mock_suspend, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=False, action_on_breach="suspend",
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="pending",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()
        mock_suspend.assert_called_once()
        alert.refresh_from_db()
        assert alert.action_taken == "suspend"

    @patch("apps.billing.metering_service.AuditService.log_simple_event")
    def test_take_action_block_new(self, mock_audit):
        agg = _make_aggregation(self.meter, self.customer, self.billing_cycle, self.subscription)
        threshold = UsageThreshold.objects.create(
            meter=self.meter, threshold_type="absolute", threshold_value=Decimal("10"),
            is_active=True, notify_customer=False, action_on_breach="block_new",
        )
        alert = UsageAlert.objects.create(
            threshold=threshold, customer=self.customer, aggregation=agg,
            usage_value=Decimal("15"), status="pending",
        )
        result = self.svc.send_alert_notification(str(alert.id))
        assert result.is_ok()
        alert.refresh_from_db()
        assert alert.action_taken == "block_new"

    def test_schedule_alert_notification_django_q_unavailable(self):
        alert = MagicMock(id=uuid.uuid4())
        with patch.dict("sys.modules", {"django_q": None, "django_q.tasks": None}):
            self.svc._schedule_alert_notification(alert)  # should not raise


# ============================================================================
# StripeGateway tests (fully mocked — no real Stripe calls)
# ============================================================================

class TestStripeGateway(TestCase):
    """Test StripeGateway with all Stripe SDK calls mocked."""

    def _make_gateway(self, mock_stripe):
        """Create a StripeGateway with mocked Stripe SDK and settings."""
        with patch("apps.billing.gateways.stripe_gateway.StripeGateway._initialize_stripe"):
            from apps.billing.gateways.stripe_gateway import StripeGateway  # noqa: PLC0415
            gw = StripeGateway.__new__(StripeGateway)
            gw.logger = logging.getLogger("test")
            gw._stripe = mock_stripe
            return gw

    def test_gateway_name(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        assert gw.gateway_name == "stripe"

    def test_create_payment_intent_success(self):
        mock_stripe = MagicMock()
        mock_stripe.PaymentIntent.create.return_value = MagicMock(
            id="pi_123", client_secret="secret_456"
        )
        gw = self._make_gateway(mock_stripe)
        result = gw.create_payment_intent("order-1", 2999, "RON", "cus_abc", {"key": "val"})
        assert result["success"] is True
        assert result["payment_intent_id"] == "pi_123"
        assert result["client_secret"] == "secret_456"

    def test_create_payment_intent_no_customer(self):
        mock_stripe = MagicMock()
        mock_stripe.PaymentIntent.create.return_value = MagicMock(id="pi_x", client_secret="sec")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_payment_intent("order-2", 1000)
        assert result["success"] is True

    def test_create_payment_intent_stripe_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.PaymentIntent.create.side_effect = mock_stripe.error.StripeError("card declined")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_payment_intent("order-3", 500)
        assert result["success"] is False
        assert "card declined" in result["error"]

    def test_create_payment_intent_unexpected_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.PaymentIntent.create.side_effect = RuntimeError("network")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_payment_intent("order-4", 500)
        assert result["success"] is False
        assert "Unexpected" in result["error"]

    def test_confirm_payment_success(self):
        mock_stripe = MagicMock()
        mock_stripe.PaymentIntent.retrieve.return_value = MagicMock(status="succeeded")
        gw = self._make_gateway(mock_stripe)
        result = gw.confirm_payment("pi_123")
        assert result["success"] is True
        assert result["status"] == "succeeded"

    def test_confirm_payment_stripe_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.PaymentIntent.retrieve.side_effect = mock_stripe.error.StripeError("not found")
        gw = self._make_gateway(mock_stripe)
        result = gw.confirm_payment("pi_bad")
        assert result["success"] is False

    def test_confirm_payment_unexpected_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.PaymentIntent.retrieve.side_effect = RuntimeError("timeout")
        gw = self._make_gateway(mock_stripe)
        result = gw.confirm_payment("pi_bad2")
        assert result["success"] is False

    def test_create_subscription_success(self):
        mock_stripe = MagicMock()
        mock_stripe.Subscription.create.return_value = MagicMock(id="sub_123", status="active")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_subscription("cus_1", "price_1", {"plan": "pro"})
        assert result["success"] is True
        assert result["subscription_id"] == "sub_123"

    def test_create_subscription_stripe_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.Subscription.create.side_effect = mock_stripe.error.StripeError("invalid")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_subscription("cus_1", "price_1")
        assert result["success"] is False

    def test_create_subscription_unexpected_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.Subscription.create.side_effect = RuntimeError("boom")
        gw = self._make_gateway(mock_stripe)
        result = gw.create_subscription("cus_1", "price_1")
        assert result["success"] is False

    def test_cancel_subscription_success(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        assert gw.cancel_subscription("sub_123") is True

    def test_cancel_subscription_stripe_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.Subscription.cancel.side_effect = mock_stripe.error.StripeError("nope")
        gw = self._make_gateway(mock_stripe)
        assert gw.cancel_subscription("sub_bad") is False

    def test_cancel_subscription_unexpected_error(self):
        mock_stripe = MagicMock()
        mock_stripe.error.StripeError = type("StripeError", (Exception,), {})
        mock_stripe.Subscription.cancel.side_effect = RuntimeError("fail")
        gw = self._make_gateway(mock_stripe)
        assert gw.cancel_subscription("sub_bad2") is False

    def test_validate_configuration_success(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting") as mock_get:
            mock_get.side_effect = lambda key, **kw: {
                "integrations.stripe_enabled": True,
                "integrations.stripe_secret_key": "sk_test",
                "integrations.stripe_publishable_key": "pk_test",
                "integrations.stripe_webhook_secret": "whsec_test",
            }.get(key, kw.get("default"))
            assert gw.validate_configuration() is True

    def test_validate_configuration_disabled(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting") as mock_get:
            mock_get.side_effect = lambda key, **kw: {
                "integrations.stripe_enabled": False,
            }.get(key, kw.get("default"))
            assert gw.validate_configuration() is False

    def test_validate_configuration_no_secret_key(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting") as mock_get:
            mock_get.side_effect = lambda key, **kw: {
                "integrations.stripe_enabled": True,
                "integrations.stripe_secret_key": None,
                "integrations.stripe_publishable_key": "pk",
                "integrations.stripe_webhook_secret": "wh",
            }.get(key, kw.get("default"))
            assert gw.validate_configuration() is False

    def test_validate_configuration_no_publishable_key(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting") as mock_get:
            mock_get.side_effect = lambda key, **kw: {
                "integrations.stripe_enabled": True,
                "integrations.stripe_secret_key": "sk",
                "integrations.stripe_publishable_key": None,
                "integrations.stripe_webhook_secret": "wh",
            }.get(key, kw.get("default"))
            assert gw.validate_configuration() is False

    def test_validate_configuration_no_webhook_secret(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting") as mock_get:
            mock_get.side_effect = lambda key, **kw: {
                "integrations.stripe_enabled": True,
                "integrations.stripe_secret_key": "sk",
                "integrations.stripe_publishable_key": "pk",
                "integrations.stripe_webhook_secret": None,
            }.get(key, kw.get("default"))
            # Should still return True (webhook secret is just a warning)
            assert gw.validate_configuration() is True

    def test_validate_configuration_exception(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        with patch("apps.settings.services.SettingsService.get_setting", side_effect=Exception("db error")):
            assert gw.validate_configuration() is False

    # Webhook tests
    def test_webhook_payment_intent_succeeded(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, msg = gw.handle_webhook_event("payment_intent.succeeded", {"object": {"id": "pi_1"}})
        assert ok is True
        assert "succeeded" in msg

    def test_webhook_payment_intent_failed(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, msg = gw.handle_webhook_event("payment_intent.payment_failed", {"object": {"id": "pi_2"}})
        assert ok is True
        assert "failed" in msg

    def test_webhook_payment_intent_other(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("payment_intent.created", {"object": {"id": "pi_3"}})
        assert ok is True

    def test_webhook_invoice_succeeded(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("invoice.payment_succeeded", {"object": {"id": "in_1"}})
        assert ok is True

    def test_webhook_invoice_failed(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("invoice.payment_failed", {"object": {"id": "in_2"}})
        assert ok is True

    def test_webhook_invoice_other(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("invoice.created", {"object": {"id": "in_3"}})
        assert ok is True

    def test_webhook_subscription_created(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("customer.subscription.created", {"object": {"id": "sub_1"}})
        assert ok is True

    def test_webhook_subscription_deleted(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("customer.subscription.deleted", {"object": {"id": "sub_2"}})
        assert ok is True

    def test_webhook_subscription_other(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, _msg = gw.handle_webhook_event("customer.subscription.updated", {"object": {"id": "sub_3"}})
        assert ok is True

    def test_webhook_unhandled_type(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        ok, msg = gw.handle_webhook_event("charge.refunded", {})
        assert ok is True
        assert "Unhandled" in msg

    def test_webhook_exception(self):
        mock_stripe = MagicMock()
        gw = self._make_gateway(mock_stripe)
        # Force an exception in _handle_payment_intent_webhook
        with patch.object(gw, "_handle_payment_intent_webhook", side_effect=RuntimeError("oops")):
            ok, msg = gw.handle_webhook_event("payment_intent.succeeded", {})
        assert ok is False
        assert "oops" in msg


class TestStripeGatewayInitialization(TestCase):
    """Test _initialize_stripe method."""

    def test_initialize_success(self):
        from apps.billing.gateways.stripe_gateway import StripeGateway  # noqa: PLC0415
        gw = StripeGateway.__new__(StripeGateway)
        gw.logger = logging.getLogger("test")
        gw._stripe = None

        mock_stripe_mod = MagicMock()
        with (
            patch.dict("sys.modules", {"stripe": mock_stripe_mod}),
            patch("apps.settings.services.SettingsService.get_setting", return_value="sk_test"),
        ):
            StripeGateway._initialize_stripe(gw)
        assert gw._stripe is mock_stripe_mod

    def test_initialize_no_api_key(self):
        from apps.billing.gateways.stripe_gateway import StripeGateway  # noqa: PLC0415
        gw = StripeGateway.__new__(StripeGateway)
        gw.logger = logging.getLogger("test")
        mock_stripe_mod = MagicMock()
        with (
            patch.dict("sys.modules", {"stripe": mock_stripe_mod}),
            patch("apps.settings.services.SettingsService.get_setting", return_value=None),
            self.assertRaises(ValueError),
        ):
            StripeGateway._initialize_stripe(gw)

    def test_initialize_import_error(self):
        from apps.billing.gateways.stripe_gateway import StripeGateway  # noqa: PLC0415
        gw = StripeGateway.__new__(StripeGateway)
        gw.logger = logging.getLogger("test")
        with (
            patch.dict("sys.modules", {"stripe": None}),
            self.assertRaises(ImportError),
        ):
            StripeGateway._initialize_stripe(gw)
