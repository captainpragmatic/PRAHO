"""Provisioning operations settings govern their enforcement paths at call or dispatch time."""

from __future__ import annotations

from collections.abc import Generator
from contextlib import contextmanager
from dataclasses import replace
from decimal import Decimal
from io import StringIO
from threading import Event, Lock
from typing import ClassVar
from unittest.mock import patch
from uuid import UUID

from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.contrib.sessions.backends.signed_cookies import SessionStore
from django.core.cache import cache
from django.core.management import call_command
from django.db import connection, transaction
from django.http import HttpRequest
from django.test import RequestFactory, SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

import apps.provisioning.virtualmin_views as views
from apps.audit.models import AuditAlert
from apps.billing.models import Currency
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminProvisioningService
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.management.commands import setup_default_settings as sync
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService

TRANSITIONS = {
    "provisioning.max_concurrent_health_checks": (5, 10),
    "provisioning.max_error_display": (10, 3),
    "provisioning.max_username_uniqueness_attempts": (10, 1000),
    "provisioning.overall_health_check_timeout": (30, 300),
}
CONFIGURED = {
    "provisioning.max_concurrent_health_checks": 1,
    "provisioning.max_error_display": 1,
    "provisioning.max_username_uniqueness_attempts": 2,
    "provisioning.overall_health_check_timeout": 1,
}
LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "provops-effects"}}


def backup_request() -> HttpRequest:
    request = RequestFactory().get("/")
    request.session = SessionStore()
    request._messages = FallbackStorage(request)
    return request


def rollback_message() -> str:
    request = backup_request()
    views._handle_backup_action_result(
        request,
        views.BulkOperationResult(3, 0, 3, ["first error", "second error", "third error"], rollback_performed=True),
    )
    return str(next(iter(get_messages(request))))


def healthy_check(account: VirtualminAccount) -> tuple[VirtualminAccount, bool, str | None]:
    return account, True, None


class ConcurrencyProbe:
    def __init__(self) -> None:
        self.lock = Lock()
        self.overlap = Event()
        self.active = 0
        self.peak = 0
        self.visited: list[str] = []

    def check(self, account: VirtualminAccount) -> tuple[VirtualminAccount, bool, str | None]:
        with self.lock:
            self.active += 1
            self.peak = max(self.peak, self.active)
            first = not self.visited
            self.visited.append(account.domain)
            if self.active > 1:
                self.overlap.set()
        if first:
            self.overlap.wait(0.2)
        with self.lock:
            self.active -= 1
        return healthy_check(account)


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class ProvisioningSettingsEffectTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.customer = Customer.objects.create(name="Provisioning settings", primary_email="provops@example.test")
        self.plan = ServicePlan.objects.create(
            name="Provisioning settings", plan_type="shared_hosting", price_monthly=Decimal("10.00")
        )
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.server = VirtualminServer.objects.create(
            name="provops", hostname="provops.example.test", api_username="provops"
        )

    def set_setting(self, key: str, value: int) -> None:
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def account(self, username: str, status: str = "active") -> VirtualminAccount:
        domain = f"{username}.example.test"
        # fsm-bypass: establish existing services and accounts for operation fixtures.
        service = Service.objects.create(
            customer=self.customer,
            service_plan=self.plan,
            currency=self.currency,
            service_name=domain,
            domain=domain,
            username=username,
            price=Decimal("10.00"),
            status="active",
        )
        return VirtualminAccount.objects.create(
            service=service,
            server=self.server,
            domain=domain,
            virtualmin_username=username,
            encrypted_password=b"",
            status=status,
        )

    def test_max_concurrent_health_checks_limits_active_workers_and_handles_empty_batches(self) -> None:
        accounts = [VirtualminAccount(domain=f"worker{number}.example.test") for number in range(3)]
        self.set_setting("provisioning.max_concurrent_health_checks", 1)
        probe = ConcurrencyProbe()
        with patch.object(views, "_perform_single_health_check", side_effect=probe.check):
            result = views._execute_bulk_health_check(accounts)
        self.assertEqual(probe.peak, 1)
        self.assertCountEqual(probe.visited, [account.domain for account in accounts])
        self.assertEqual((result.successful_count, result.failed_count, result.errors), (3, 0, []))
        self.set_setting("provisioning.max_concurrent_health_checks", 2)
        probe = ConcurrencyProbe()
        with patch.object(views, "_perform_single_health_check", side_effect=probe.check):
            result = views._execute_bulk_health_check(accounts)
        self.assertEqual(probe.peak, 2)
        self.assertEqual((result.successful_count, result.failed_count), (3, 0))
        empty = views._execute_bulk_health_check([])
        self.assertEqual(
            (empty.total_processed, empty.successful_count, empty.failed_count, empty.errors), (0, 0, 0, [])
        )
        self.assertTrue(SettingsService.update_setting("provisioning.max_concurrent_health_checks", 0).is_err())
        # Legacy rows written outside the validated service must not construct a zero-worker pool.
        SystemSetting.objects.filter(key="provisioning.max_concurrent_health_checks").update(value=0)
        probe = ConcurrencyProbe()
        with patch.object(views, "_perform_single_health_check", side_effect=probe.check):
            legacy = views._execute_bulk_health_check(accounts)
        self.assertEqual(probe.peak, 2)
        self.assertEqual((legacy.successful_count, legacy.failed_count, legacy.errors), (3, 0, []))

    def test_max_error_display_truncates_rollback_errors_at_call_time(self) -> None:
        self.set_setting("provisioning.max_error_display", 1)
        message = rollback_message()
        self.assertNotIn("second error", message)
        self.assertNotIn("third error", message)
        self.assertIn("first error...", message)
        self.set_setting("provisioning.max_error_display", 3)
        message = rollback_message()
        self.assertIn("third error", message)
        self.assertNotIn("...", message)
        self.set_setting("provisioning.max_error_display", 0)
        message = rollback_message()
        self.assertNotIn("first error", message)
        self.assertIn("...", message)

    def test_max_username_uniqueness_attempts_controls_uuid_fallback_at_call_time(self) -> None:
        self.account("collision")
        self.account("collision1")
        service = VirtualminProvisioningService()
        self.set_setting("provisioning.max_username_uniqueness_attempts", 2)
        with (
            patch("apps.provisioning.virtualmin_service.uuid.uuid4", return_value=UUID(int=0)),
            CaptureQueriesContext(connection) as queries,
        ):
            username = service._generate_username_from_domain("collision.example.test")
        self.assertEqual(username, "user_00000000")
        self.assertEqual(
            sum(row["sql"].startswith("SELECT") and SystemSetting._meta.db_table in row["sql"] for row in queries),
            1,
        )
        self.set_setting("provisioning.max_username_uniqueness_attempts", 3)
        self.assertEqual(service._generate_username_from_domain("collision.example.test"), "collision2")
        self.set_setting("provisioning.max_username_uniqueness_attempts", 1)
        with patch("apps.provisioning.virtualmin_service.uuid.uuid4", return_value=UUID(int=0)):
            self.assertEqual(service._generate_username_from_domain("collision.example.test"), "user_00000000")
        self.assertEqual(service._generate_username_from_domain("unused.example.test"), "unused")

    def test_overall_health_check_timeout_records_an_unfinished_collection(self) -> None:
        self.set_setting("provisioning.overall_health_check_timeout", 1)
        account = VirtualminAccount(domain="slow.example.test")

        def slow_check(account: VirtualminAccount) -> tuple[VirtualminAccount, bool, str | None]:
            Event().wait(1.2)
            return healthy_check(account)

        with patch.object(views, "_perform_single_health_check", side_effect=slow_check):
            result = views._execute_bulk_health_check([account])
        self.assertEqual(result.successful_count, 0)
        self.assertEqual((result.total_processed, result.failed_count), (1, 1))
        self.assertTrue(any(account.domain in error and "timed out" in error for error in result.errors), result.errors)
        self.assertFalse(result.rollback_performed)
        self.set_setting("provisioning.overall_health_check_timeout", 3)
        with patch.object(views, "_perform_single_health_check", side_effect=slow_check):
            result = views._execute_bulk_health_check([account])
        self.assertEqual((result.successful_count, result.failed_count, result.errors), (1, 0, []))


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class ProvisioningSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    @contextmanager
    def setting_mode(self, atomic: bool) -> Generator[None]:
        if atomic:
            with transaction.atomic():
                try:
                    for key, value in CONFIGURED.items():
                        self.assertTrue(SettingsService.update_setting(key, value).is_ok())
                    yield
                finally:
                    transaction.set_rollback(True)
        else:
            self.assertTrue(connection.get_autocommit())
            for key, value in CONFIGURED.items():
                cache.set(SettingsService._get_cache_key(key), value, version=SettingsService.CACHE_VERSION)
            yield

    def setting_reads(self, queries: CaptureQueriesContext) -> int:
        return sum(row["sql"].startswith("SELECT") and SystemSetting._meta.db_table in row["sql"] for row in queries)

    def check_paths(self, atomic: bool) -> None:
        with self.setting_mode(atomic):
            with CaptureQueriesContext(connection) as queries:
                message = rollback_message()
            self.assertNotIn("second error", message)
            self.assertIn("first error...", message)
            self.assertEqual(len(queries), int(atomic))
            for size in (1, 25):
                accounts = [
                    VirtualminAccount(domain=f"query{number}.example.test", status="provisioning")
                    for number in range(size)
                ]
                with self.subTest(operation="health", size=size):
                    with (
                        patch.object(views, "_perform_single_health_check", side_effect=healthy_check),
                        CaptureQueriesContext(connection) as queries,
                    ):
                        result = views._execute_bulk_health_check(accounts)
                    # Each of the two health settings is read once: from the database inside a
                    # transaction (the cache is bypassed there), and not at all from a warm cache.
                    self.assertEqual(self.setting_reads(queries), 2 if atomic else 0)
                    self.assertEqual((result.successful_count, result.failed_count, result.errors), (size, 0, []))
            with CaptureQueriesContext(connection) as queries:
                username = VirtualminProvisioningService()._generate_username_from_domain("queryunused.example.test")
            self.assertEqual(username, "queryunused")
            self.assertEqual(self.setting_reads(queries), int(atomic))
            self.assertEqual(len(queries), 1 + int(atomic))

    def test_hot_paths_with_warm_cache(self) -> None:
        self.check_paths(atomic=False)

    def test_hot_paths_inside_atomic_read_once_per_operation(self) -> None:
        self.check_paths(atomic=True)


@override_settings(CACHES=LOCMEM, DISABLE_AUDIT_SIGNALS=True)
class ProvisioningSettingsActivationTests(TestCase):
    def test_batch_preserves_enforced_defaults_and_activates_retained_values_once(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.assertEqual({key: sync.DEFAULT_VALUE_MIGRATIONS.get(key) for key in TRANSITIONS}, TRANSITIONS)
        definitions = tuple(CATALOG_BY_KEY[key] for key in TRANSITIONS)
        self.assertEqual({d.key: d.default for d in definitions}, {key: pair[1] for key, pair in TRANSITIONS.items()})
        for scenario in ("missing", "old-default", "retained"):
            with self.subTest(scenario=scenario), transaction.atomic():
                try:
                    SystemSetting.objects.filter(key__in=TRANSITIONS).delete()
                    SettingActivation.objects.filter(key__in=TRANSITIONS).delete()
                    if scenario != "missing":
                        for definition in definitions:
                            old = TRANSITIONS[definition.key][0]
                            value = old if scenario == "old-default" else CONFIGURED[definition.key]
                            old_definition = replace(definition, default=old)
                            SystemSetting.objects.create(
                                key=definition.key, value=value, **sync._row_defaults(old_definition)
                            )
                        # Metadata-only reconciliation must not obscure first activation.
                        old_definitions = tuple(replace(d, default=TRANSITIONS[d.key][0]) for d in definitions)
                        SystemSetting.objects.filter(key__in=TRANSITIONS).update(name="Stale metadata")
                        with (
                            patch.object(sync, "CATALOG", old_definitions),
                            patch.object(sync, "DEFAULT_VALUE_MIGRATIONS", {}),
                        ):
                            call_command("setup_default_settings", stdout=StringIO())
                    output = StringIO()
                    with patch.object(sync, "CATALOG", definitions), self.captureOnCommitCallbacks(execute=True):
                        call_command("setup_default_settings", stdout=output)
                    defaults = {key: pair[1] for key, pair in TRANSITIONS.items()}
                    expected = CONFIGURED if scenario == "retained" else defaults
                    self.assertEqual(
                        dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")), expected
                    )
                    self.assertEqual(
                        SettingActivation.objects.filter(key__in=TRANSITIONS, completed_at__isnull=False).count(),
                        len(TRANSITIONS),
                    )
                    for definition in definitions:
                        self.assertEqual(
                            SystemSetting.objects.get(key=definition.key).default_value, definition.default
                        )
                        self.assertEqual(SettingsService.get_integer_setting(definition.key), expected[definition.key])
                        old, new = TRANSITIONS[definition.key]
                        if scenario == "old-default" and old != new:
                            self.assertIn(f"{definition.key}: {old} → {new}", output.getvalue())
                    alerts = AuditAlert.objects.filter(metadata__activation_version=sync.ACTIVATION_VERSION)
                    self.assertEqual(alerts.count(), int(scenario == "retained"))
                    if scenario == "retained":
                        alert = alerts.get()
                        self.assertEqual(
                            (alert.alert_type, alert.severity, alert.status), ("data_integrity", "warning", "active")
                        )
                        self.assertEqual(set(alert.metadata["keys"]), set(TRANSITIONS))
                        self.assertEqual(alert.evidence["retained_values"], CONFIGURED)
                        self.assertEqual(
                            alert.evidence["previous_enforced_values"], {d.key: d.default for d in definitions}
                        )
                        for key in TRANSITIONS:
                            self.assertIn(key, alert.description)
                            self.assertIn(key, output.getvalue())
                    for key, pair in TRANSITIONS.items():
                        self.assertTrue(SettingsService.update_setting(key, pair[0]).is_ok())
                    with patch.object(sync, "CATALOG", definitions):
                        call_command("setup_default_settings", stdout=StringIO())
                    self.assertEqual(
                        dict(SystemSetting.objects.filter(key__in=TRANSITIONS).values_list("key", "value")),
                        {key: pair[0] for key, pair in TRANSITIONS.items()},
                    )
                    self.assertEqual(alerts.count(), int(scenario == "retained"))
                finally:
                    transaction.set_rollback(True)


class RetiredBulkThresholdTests(TestCase):
    """Bulk suspend and activate now confirm every account with Virtualmin, so the threshold that chose a
    database-only bulk update has nothing left to control."""

    def test_setup_removes_a_stored_bulk_threshold_and_the_catalog_no_longer_offers_it(self) -> None:
        key = "provisioning.bulk_operation_threshold"
        self.assertNotIn(key, CATALOG_BY_KEY)
        self.assertIn(key, sync.RETIRED_SETTING_KEYS)
        SystemSetting.objects.create(key=key, name="Bulk threshold", data_type="integer", value=2, default_value=10)
        output = StringIO()
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=output)
        self.assertFalse(SystemSetting.objects.filter(key=key).exists())
        self.assertIn(key, output.getvalue())
