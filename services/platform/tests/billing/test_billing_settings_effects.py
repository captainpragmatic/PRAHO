"""Observable effects for the WP18 billing settings batch."""

from __future__ import annotations

from datetime import datetime, timedelta
from decimal import Decimal
from io import StringIO
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.core.management import call_command
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext
from django.utils import timezone
from django_q.brokers.orm import ORM
from django_q.conf import Conf
from django_q.models import OrmQ
from django_q.signing import SignedPackage

from apps.audit.models import AuditAlert
from apps.billing.metering_models import BillingCycle, UsageAggregation, UsageEvent, UsageMeter, UsageThreshold
from apps.billing.metering_service import MeteringService, UsageAlertService, UsageEventData
from apps.billing.metering_tasks import (
    check_usage_thresholds_async,
    send_usage_alert_notification_async,
    update_aggregation_for_event_async,
)
from apps.billing.models import Currency
from apps.billing.subscription_models import Subscription
from apps.billing.subscription_service import SubscriptionLifecycleService
from apps.customers.models import Customer
from apps.products.models import Product
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService

EVENT_GRACE_KEY = "billing.event_grace_period_hours"
TASK_TIMEOUT_KEY = "billing.metering_task_timeout"
SUBSCRIPTION_GRACE_KEY = "billing.subscription_grace_period_days"
LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


@override_settings(CACHES=LOCMEM_CACHE)
class BillingSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(
            name="Billing settings customer",
            customer_type="individual",
            primary_email="billing-settings@example.com",
            status="active",
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.product = Product.objects.create(
            name="Billing settings plan", slug="billing-settings-plan", product_type="shared_hosting"
        )

    def set_value(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def subscription(self, grace_days: int | None = None) -> Subscription:
        now = timezone.now()
        subscription = Subscription(
            customer=self.customer,
            product=self.product,
            currency=self.currency,
            unit_price_cents=1000,
            status="active",
            current_period_start=now - timedelta(days=30),
            current_period_end=now + timedelta(hours=1),
            next_billing_date=now + timedelta(hours=1),
        )
        if grace_days is not None:
            subscription.grace_period_days = grace_days
        subscription.save()
        return subscription

    def test_new_meter_grace_controls_late_event_acceptance_and_preserves_stored_values(self) -> None:
        existing = UsageMeter.objects.create(name="existing", display_name="Existing")
        self.set_value(EVENT_GRACE_KEY, 1)
        explicit = UsageMeter.objects.create(name="explicit", display_name="Explicit", event_grace_period_hours=3)
        meter = UsageMeter.objects.create(name="configured", display_name="Configured")
        timestamp = timezone.now() - timedelta(hours=2)

        result = MeteringService().record_event(
            UsageEventData(
                meter_name=meter.name,
                customer_id=str(self.customer.pk),
                value=Decimal("1"),
                timestamp=timestamp,
                idempotency_key="configured-late",
            )
        )

        self.assertTrue(result.is_err(), result)
        self.assertIn("Event timestamp too old", result.unwrap_err())
        self.assertFalse(UsageEvent.objects.filter(meter=meter).exists())
        for preserved, expected in ((existing, 24), (explicit, 3)):
            preserved.refresh_from_db()
            self.assertEqual(preserved.event_grace_period_hours, expected)
            accepted = MeteringService().record_event(
                UsageEventData(
                    meter_name=preserved.name,
                    customer_id=str(self.customer.pk),
                    value=Decimal("1"),
                    timestamp=timestamp,
                    idempotency_key=f"{preserved.name}-late",
                )
            )
            self.assertTrue(accepted.is_ok(), accepted)
            self.assertTrue(UsageEvent.objects.filter(pk=accepted.unwrap().pk, meter=preserved).exists())

        self.set_value(EVENT_GRACE_KEY, 4)
        later = UsageMeter.objects.create(name="later", display_name="Later")
        self.assertEqual(later.event_grace_period_hours, 4)
        meter.refresh_from_db()
        self.assertEqual(meter.event_grace_period_hours, 1)

    def test_new_subscription_grace_controls_failed_payment_deadline_and_preserves_stored_values(self) -> None:
        existing = self.subscription()
        self.set_value(SUBSCRIPTION_GRACE_KEY, 2)
        explicit = self.subscription(grace_days=5)
        subscription = self.subscription()
        failed_at = subscription.current_period_end + timedelta(seconds=1)

        with patch("django.utils.timezone.now", return_value=failed_at):
            subscription.mark_payment_failed()
        subscription.refresh_from_db()

        self.assertEqual(subscription.grace_period_ends_at, failed_at + timedelta(days=2))
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(subscription.failed_payment_count, 1)
        for preserved, expected in ((existing, 7), (explicit, 5)):
            preserved.refresh_from_db()
            self.assertEqual(preserved.grace_period_days, expected)
            with patch("django.utils.timezone.now", return_value=failed_at):
                preserved.mark_payment_failed()
            preserved.refresh_from_db()
            self.assertEqual(preserved.grace_period_ends_at, failed_at + timedelta(days=expected))

        self.set_value(SUBSCRIPTION_GRACE_KEY, 3)
        later = self.subscription()
        self.assertEqual(later.grace_period_days, 3)
        subscription.refresh_from_db()
        self.assertEqual(subscription.grace_period_days, 2)

    def test_zero_meter_grace_rejects_late_events_but_accepts_the_boundary(self) -> None:
        self.set_value(EVENT_GRACE_KEY, 0)
        meter = UsageMeter.objects.create(name="zero-grace", display_name="Zero grace")
        now = timezone.now()
        broker = ORM(list_key="wp18-zero-grace")
        with (
            patch("django.utils.timezone.now", return_value=now),
            patch("django_q.tasks.get_broker", return_value=broker),
            patch.object(Conf, "SYNC", False),
        ):
            for offset in (-1, 0, 1):
                with self.subTest(offset=offset):
                    result = MeteringService().record_event(
                        UsageEventData(
                            meter_name=meter.name,
                            customer_id=str(self.customer.pk),
                            value=Decimal("1"),
                            timestamp=now + timedelta(microseconds=offset),
                            idempotency_key=f"zero-grace-{offset}",
                        )
                    )
                    if offset < 0:
                        self.assertTrue(result.is_err(), result)
                        self.assertIn("Event timestamp too old", result.unwrap_err())
                        self.assertFalse(UsageEvent.objects.filter(idempotency_key=f"zero-grace-{offset}").exists())
                    else:
                        self.assertTrue(result.is_ok(), result)
                        self.assertEqual(result.unwrap().timestamp, now + timedelta(microseconds=offset))
        meter.refresh_from_db()
        self.assertEqual(meter.event_grace_period_hours, 0)

    def test_zero_grace_accepts_an_implicit_timestamp_with_an_advancing_clock(self) -> None:
        meter = UsageMeter.objects.create(
            name="zero-implicit", display_name="Zero implicit", event_grace_period_hours=0
        )
        now = timezone.now()
        clock_reads = 0

        def advancing_now() -> datetime:
            nonlocal clock_reads
            instant = now + timedelta(microseconds=clock_reads)
            clock_reads += 1
            return instant

        broker = ORM(list_key="wp18-zero-implicit")
        with (
            patch("django.utils.timezone.now", side_effect=advancing_now),
            patch("django_q.tasks.get_broker", return_value=broker),
            patch.object(Conf, "SYNC", False),
        ):
            result = MeteringService().record_event(
                UsageEventData(
                    meter_name=meter.name,
                    customer_id=str(self.customer.pk),
                    value=Decimal("1"),
                    idempotency_key="zero-implicit",
                )
            )
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().timestamp, now)
        self.assertTrue(UsageEvent.objects.filter(pk=result.unwrap().pk, timestamp=now).exists())

    def test_zero_subscription_grace_expires_at_payment_failure(self) -> None:
        self.set_value(SUBSCRIPTION_GRACE_KEY, 0)
        subscription = self.subscription()
        failed_at = subscription.current_period_end + timedelta(seconds=1)
        with patch("django.utils.timezone.now", return_value=failed_at):
            subscription.mark_payment_failed()
        subscription.refresh_from_db()
        self.assertEqual(subscription.grace_period_ends_at, failed_at)
        self.assertEqual(subscription.grace_period_days, 0)
        self.assertEqual(subscription.status, "past_due")
        self.assertEqual(
            SubscriptionLifecycleService.handle_grace_period_expirations(as_of=failed_at - timedelta(microseconds=1)),
            (0, 0),
        )
        self.assertEqual(SubscriptionLifecycleService.handle_grace_period_expirations(as_of=failed_at), (1, 0))
        subscription.refresh_from_db()
        self.assertEqual(subscription.status, "paused")
        self.assertEqual(subscription.paused_at, failed_at)

    def test_record_event_queues_the_configured_budget_on_both_paths(self) -> None:
        meter = UsageMeter.objects.create(name="queued-event", display_name="Queued event")
        subscription = self.subscription()
        broker = ORM(list_key="wp18-production-events")
        with patch("django_q.tasks.get_broker", return_value=broker), patch.object(Conf, "SYNC", False):
            for configured, budgets in ((17, (17, 17)), (19, (19, 19)), (None, (60, 60)), (300, (300, 300))):
                if configured is None:
                    SystemSetting.objects.filter(key=TASK_TIMEOUT_KEY).delete()
                    cache.clear()
                else:
                    self.set_value(TASK_TIMEOUT_KEY, configured)
                OrmQ.objects.filter(key=broker.list_key).delete()
                result = MeteringService().record_event(
                    UsageEventData(
                        meter_name=meter.name,
                        customer_id=str(self.customer.pk),
                        subscription_id=str(subscription.pk),
                        value=Decimal("1"),
                        idempotency_key=f"queued-event-{configured}",
                    )
                )
                self.assertTrue(result.is_ok(), result)
                event = result.unwrap()
                tasks = {
                    task["func"]: task
                    for row in OrmQ.objects.filter(key=broker.list_key)
                    for task in (cast("dict[str, object]", SignedPackage.loads(row.payload)),)
                }
                expected = (
                    ("apps.billing.metering_tasks.update_aggregation_for_event", (str(event.pk),), budgets[0]),
                    (
                        "apps.billing.metering_tasks.check_usage_thresholds",
                        (str(self.customer.pk), str(meter.pk), str(subscription.pk)),
                        budgets[1],
                    ),
                )
                self.assertEqual(set(tasks), {function for function, _, _ in expected})
                for function, arguments, budget in expected:
                    with self.subTest(configured=configured, function=function):
                        self.assertEqual(tasks[function]["args"], arguments)
                        self.assertEqual(tasks[function]["kwargs"], {})
                        self.assertEqual(tasks[function]["timeout"], budget)

    def test_threshold_processing_queues_the_configured_alert_budget(self) -> None:
        meter = UsageMeter.objects.create(name="queued-alert", display_name="Queued alert")
        subscription = self.subscription()
        cycle = BillingCycle.objects.create(
            subscription=subscription,
            period_start=subscription.current_period_start,
            period_end=subscription.current_period_end,
        )
        aggregation = UsageAggregation.objects.create(
            meter=meter,
            customer=self.customer,
            subscription=subscription,
            billing_cycle=cycle,
            period_start=cycle.period_start,
            period_end=cycle.period_end,
            total_value=Decimal("2"),
        )
        UsageThreshold.objects.create(
            meter=meter,
            threshold_type="absolute",
            threshold_value=Decimal("1"),
            repeat_notification=True,
        )
        broker = ORM(list_key="wp18-production-alerts")
        with patch("django_q.tasks.get_broker", return_value=broker), patch.object(Conf, "SYNC", False):
            for configured, budget in ((17, 17), (19, 19), (None, 60), (300, 300)):
                if configured is None:
                    SystemSetting.objects.filter(key=TASK_TIMEOUT_KEY).delete()
                    cache.clear()
                else:
                    self.set_value(TASK_TIMEOUT_KEY, configured)
                OrmQ.objects.filter(key=broker.list_key).delete()
                alerts = UsageAlertService().check_thresholds(
                    str(self.customer.pk), str(meter.pk), str(subscription.pk)
                )
                self.assertEqual(len(alerts), 1)
                self.assertEqual(alerts[0].aggregation_id, aggregation.pk)
                row = OrmQ.objects.get(key=broker.list_key)
                task = cast("dict[str, object]", SignedPackage.loads(row.payload))
                with self.subTest(configured=configured):
                    self.assertEqual(task["func"], "apps.billing.metering_tasks.send_usage_alert_notification")
                    self.assertEqual(task["args"], (str(alerts[0].pk),))
                    self.assertEqual(task["kwargs"], {})
                    self.assertEqual(task["timeout"], budget)

    def test_metering_timeout_rejects_zero(self) -> None:
        self.assertTrue(SettingsService.update_setting(TASK_TIMEOUT_KEY, 0).is_err())

    def test_each_metering_helper_persists_the_timeout_resolved_at_enqueue(self) -> None:
        broker = ORM(list_key="wp18-billing")
        with patch("django_q.tasks.get_broker", return_value=broker), patch.object(Conf, "SYNC", False):
            for timeout in (17, 19):
                self.set_value(TASK_TIMEOUT_KEY, timeout)
                jobs = (
                    (
                        update_aggregation_for_event_async("event-id"),
                        "apps.billing.metering_tasks.update_aggregation_for_event",
                        ("event-id",),
                    ),
                    (
                        check_usage_thresholds_async("customer-id", "meter-id", "subscription-id"),
                        "apps.billing.metering_tasks.check_usage_thresholds",
                        ("customer-id", "meter-id", "subscription-id"),
                    ),
                    (
                        send_usage_alert_notification_async("alert-id"),
                        "apps.billing.metering_tasks.send_usage_alert_notification",
                        ("alert-id",),
                    ),
                )
                tasks = {
                    task["id"]: task
                    for row in OrmQ.objects.filter(key=broker.list_key)
                    for task in (cast("dict[str, object]", SignedPackage.loads(row.payload)),)
                }
                for task_id, function, arguments in jobs:
                    with self.subTest(timeout=timeout, function=function):
                        self.assertEqual(tasks[task_id]["timeout"], timeout)
                        self.assertEqual(tasks[task_id]["func"], function)
                        self.assertEqual(tasks[task_id]["args"], arguments)

    def test_callable_defaults_read_once_each_inside_atomic_and_never_on_hydration(self) -> None:
        self.set_value(EVENT_GRACE_KEY, 1)
        self.set_value(SUBSCRIPTION_GRACE_KEY, 2)
        with transaction.atomic():
            with self.assertNumQueries(2):
                meter = UsageMeter(name="atomic", display_name="Atomic")
                subscription = Subscription()
            self.assertEqual(meter.event_grace_period_hours, 1)
            self.assertEqual(subscription.grace_period_days, 2)
            with self.assertNumQueries(0):
                explicit_meter = UsageMeter(event_grace_period_hours=9)
                explicit_subscription = Subscription(grace_period_days=9)
            self.assertEqual(explicit_meter.event_grace_period_hours, 9)
            self.assertEqual(explicit_subscription.grace_period_days, 9)

        meter.save()
        stored_subscription = self.subscription()
        self.set_value(EVENT_GRACE_KEY, 4)
        self.set_value(SUBSCRIPTION_GRACE_KEY, 5)
        with self.assertNumQueries(2):
            hydrated_meter = UsageMeter.objects.get(pk=meter.pk)
            hydrated_subscription = Subscription.objects.get(pk=stored_subscription.pk)
        self.assertEqual(hydrated_meter.event_grace_period_hours, 1)
        self.assertEqual(hydrated_subscription.grace_period_days, 2)

    def test_activation_preserves_defaults_and_reports_retained_values_once(self) -> None:
        defaults = {EVENT_GRACE_KEY: 24, TASK_TIMEOUT_KEY: 60, SUBSCRIPTION_GRACE_KEY: 7}
        old_catalog_defaults = {**defaults, TASK_TIMEOUT_KEY: 300}
        keys = set(defaults)

        # Missing rows retain the previously enforced behavior and receive durable receipts.
        SystemSetting.objects.filter(key__in=keys).delete()
        SettingActivation.objects.filter(key__in=keys).delete()
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), defaults)
        self.assertEqual(
            set(
                SettingActivation.objects.filter(key__in=keys, completed_at__isnull=False).values_list("key", flat=True)
            ),
            keys,
        )

        # Explicit old catalog defaults and metadata-only reconciliation have the same classification:
        # they never took effect, so they become the enforced value.
        SettingActivation.objects.filter(key__in=keys).delete()
        for key, value in old_catalog_defaults.items():
            self.set_value(key, value)
        SystemSetting.objects.filter(key__in=keys).update(name="Stale metadata")
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), defaults)
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())

        SettingActivation.objects.filter(key__in=keys).delete()
        retained = {EVENT_GRACE_KEY: 1, TASK_TIMEOUT_KEY: 17, SUBSCRIPTION_GRACE_KEY: 2}
        for key, value in retained.items():
            self.set_value(key, value)
        output = StringIO()
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=output)
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), retained)
        alert = AuditAlert.objects.get(metadata__activation_version="wp18-v1")
        self.assertEqual((alert.alert_type, alert.severity, alert.status), ("data_integrity", "warning", "active"))
        self.assertEqual(alert.evidence["previous_enforced_values"], defaults)
        self.assertEqual(alert.evidence["retained_values"], retained)
        for key in keys:
            self.assertIn(key, output.getvalue())
            self.assertIn(key, alert.description)
        self.assertEqual(UsageMeter().event_grace_period_hours, 1)
        self.assertEqual(Subscription().grace_period_days, 2)

        # After activation, returning to a historical default must not create another alert.
        for key, value in defaults.items():
            self.set_value(key, value)
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), defaults)
        self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), 1)


@override_settings(CACHES=LOCMEM_CACHE)
class BillingSettingsWarmCacheEffectTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def restore_setting(self, key: str, original: SystemSetting | None) -> None:
        if original is None:
            SystemSetting.objects.filter(key=key).delete()
        else:
            original.save()

    def test_callable_defaults_use_warm_cache_without_queries_in_autocommit(self) -> None:
        self.assertTrue(connection.get_autocommit())
        cache.clear()
        self.addCleanup(cache.clear)
        for key, value in ((EVENT_GRACE_KEY, 1), (SUBSCRIPTION_GRACE_KEY, 2)):
            original = SystemSetting.objects.filter(key=key).first()
            self.addCleanup(self.restore_setting, key, original)
            result = SettingsService.update_setting(key, value)
            self.assertTrue(result.is_ok(), result)
            self.assertEqual(SettingsService.get_integer_setting(key), value)

        with CaptureQueriesContext(connection) as queries:
            meters = [UsageMeter() for _ in range(3)]
            subscriptions = [Subscription() for _ in range(3)]
        self.assertEqual(len(queries), 0)
        self.assertEqual([meter.event_grace_period_hours for meter in meters], [1, 1, 1])
        self.assertEqual([subscription.grace_period_days for subscription in subscriptions], [2, 2, 2])
