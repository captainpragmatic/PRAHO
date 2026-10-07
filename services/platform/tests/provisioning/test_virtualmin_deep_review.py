"""Behaviour regressions for the provisioning deep review."""

from __future__ import annotations

import json
import time
from collections.abc import Callable, Iterator
from contextlib import contextmanager
from datetime import timedelta
from decimal import Decimal
from threading import Event
from typing import ClassVar, cast
from unittest.mock import patch

from django.core.cache import cache
from django.db import DatabaseError, connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from django.utils.module_loading import import_string
from django_q.models import OrmQ
from django_q.signing import SignedPackage
from requests import Response
from requests.exceptions import ConnectTimeout

from apps.billing.models import Currency
from apps.common.outbound_http import OutboundPolicy
from apps.common.types import Result
from apps.customers.models import Customer
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.security_utils import SecureTaskParameters
from apps.provisioning.virtualmin_gateway import (
    VirtualminAPIError,
    VirtualminConfig,
    VirtualminGateway,
    VirtualminRateLimitedError,
    VirtualminResponse,
)
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminAccountCreationData, VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import (
    VirtualminProvisioningParams,
    _recover_expired_claims,
    delete_virtualmin_account_async,
    provision_virtualmin_account_async,
    reconcile_virtualmin_service_state_async,
    suspend_virtualmin_account_async,
    unsuspend_virtualmin_account_async,
)
from apps.provisioning.virtualmin_views import (
    _execute_bulk_activate,
    _execute_bulk_health_check,
    _execute_bulk_suspend,
)
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService

LOCMEM = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


def response(program: str, **payload: object) -> Response:
    result = Response()
    result.status_code = 200
    result._content = json.dumps({"command": program, "status": "success", **payload}).encode()
    result._content_consumed = True
    return result


@override_settings(CACHES=LOCMEM, VIRTUALMIN_TIMEOUTS={})
class ProvisioningDeepReviewTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        customer = Customer.objects.create(
            name="Review customer", customer_type="individual", primary_email="review@example.test"
        )
        currency, _created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        plan = ServicePlan.objects.create(name="Review plan", price_monthly=Decimal("10"))
        self.service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name="review.example.com",
            domain="review.example.com",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(
            name="review", hostname="review-node.example.test", api_username="review-api", status="active"
        )
        self.server.set_api_password("ReviewServerPassword123!")
        self.server.save()
        self.account = VirtualminAccount.objects.create(
            service=self.service,
            server=self.server,
            domain=self.service.domain,
            virtualmin_username="reviewuser",
            template_name="Default",
            status="active",
            protected_from_deletion=False,
        )
        self.account.set_password("ReviewAccountPassword123!")
        self.account.save()
        self.sent: list[str] = []
        self.info_output = "disk_free: 104857600000\ndisk_total: 209715200000\n"
        self.observed_budget: object = None
        self.observed_recovery_status = ""
        self.observe_recovery = False

    def set_value(self, key: str, value: int) -> None:
        self.assertTrue(SettingsService.update_setting(key, value).is_ok())

    def http(self, method: str, url: str, **kwargs: object) -> Response:
        self.assertEqual(method, "GET")
        self.assertEqual(url, self.server.api_url)
        params = cast("dict[str, str]", kwargs["params"])
        program = params["program"]
        self.sent.append(program)
        if program == "info":
            return response(program, output=self.info_output)
        if program == "list-domains":
            return response(program, data=[])
        if program == "list-templates":
            return response(program, data=["Default"])
        if self.observe_recovery:
            job = VirtualminProvisioningJob.objects.get(account__domain=self.service.domain, status="running")
            self.observed_budget = job.parameters.get("task_budget_seconds")
            now = timezone.now()
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(started_at=now - timedelta(minutes=31))
            _recover_expired_claims(now)
            job.refresh_from_db()
            self.observed_recovery_status = job.status
        return response(program, output="Operation complete\n")

    def test_upstream_disk_bytes_allow_seeded_quota_at_and_above_capacity(self) -> None:
        self.set_value("virtualmin.domain_quota_default_mb", 1000)
        for free_bytes in (1000 * 1024**2, 1000 * 1024**2 + 1):
            with self.subTest(free_bytes=free_bytes):
                self.account.disk_quota_mb = None
                self.account.save(update_fields=["disk_quota_mb"])
                self.info_output = f"disk_free: {free_bytes}\ndisk_total: 2097152000\n"
                self.sent.clear()
                with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
                    result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account)
                self.assertTrue(result.is_ok(), result)
                self.account.refresh_from_db()
                self.assertEqual(self.account.status, "active")
                self.assertEqual(self.account.disk_quota_mb, 1000)
                self.assertIn("create-domain", self.sent)

    def test_disk_bytes_below_capacity_are_not_mistaken_for_megabytes(self) -> None:
        self.set_value("virtualmin.domain_quota_default_mb", 1000)
        self.info_output = f"disk_free: {1000 * 1024**2 - 1}\n"
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account)
        self.assertTrue(result.is_err(), result)
        self.assertIn("999MB available, 1000MB requested", result.unwrap_err())
        self.assertEqual(self.sent, ["info"])

    def test_unknown_free_space_warns_and_does_not_block_creation(self) -> None:
        self.set_value("virtualmin.domain_quota_default_mb", 1000)
        for output in ("host:\n    hostname: review-node.example.test\n", "disk_free: unknown\n"):
            with self.subTest(output=output):
                self.info_output = output
                with (
                    patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
                    self.assertLogs("apps.provisioning.virtualmin_service", level="WARNING") as logs,
                ):
                    result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account)
                self.assertTrue(result.is_ok(), result)
                self.assertTrue(any("free disk space is unknown" in line for line in logs.output))
                self.account.refresh_from_db()
                self.assertEqual(self.account.status, "active")

    def run_queued(self, enqueue: Callable[[], str], *, provision: bool = False) -> None:
        self.set_value("provisioning.task_time_limit", 7200)
        self.set_value("provisioning.task_soft_time_limit", 7200)
        task_id = enqueue()
        packets = [cast("dict[str, object]", SignedPackage.loads(row.payload)) for row in OrmQ.objects.all()]
        packet = next(item for item in packets if item["id"] == task_id)
        self.assertEqual(packet["timeout"], 7200)
        self.set_value("provisioning.task_time_limit", 3600)
        self.set_value("provisioning.task_soft_time_limit", 3600)
        worker = cast("Callable[..., dict[str, object]]", import_string(str(packet["func"])))
        self.observe_recovery = True
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            if provision:
                # The worker's UUID validator currently rejects Service's integer PK.
                # Exercise the real job producer with the actual queued budget.
                budget = cast("dict[str, object]", packet["kwargs"]).get("task_budget_seconds")
                self.assertEqual(budget, 7200)
                provisioner = VirtualminProvisioningService(self.server, task_budget_seconds=cast("int", budget))
                result = provisioner.create_virtualmin_account(
                    VirtualminAccountCreationData(service=self.service, domain=self.service.domain, server=self.server)
                )
                outcome: dict[str, object] = {"success": result.is_ok(), "result": str(result)}
            else:
                outcome = worker(
                    *cast("tuple[object, ...]", packet["args"]), **cast("dict[str, object]", packet["kwargs"])
                )
        self.assertEqual(self.observed_budget, 7200, outcome)
        self.assertEqual(self.observed_recovery_status, "running")
        self.assertTrue(outcome["success"], outcome)
        job = VirtualminProvisioningJob.objects.get(account__domain=self.service.domain)
        self.assertEqual(job.parameters["task_budget_seconds"], 7200)
        self.assertEqual(job.status, "completed")

    def test_provision_enqueue_budget_reaches_real_producer_before_recovery(self) -> None:
        self.account.delete()
        params: VirtualminProvisioningParams = {
            "service_id": str(self.service.pk),
            "domain": self.service.domain,
            "server_id": str(self.server.pk),
        }
        self.run_queued(lambda: provision_virtualmin_account_async(params), provision=True)

    def test_secure_provision_enqueue_budget_reaches_real_producer(self) -> None:
        self.account.delete()
        params = SecureTaskParameters.create(
            {"service_id": str(self.service.pk), "domain": self.service.domain, "server_id": str(self.server.pk)}
        )
        self.run_queued(lambda: provision_virtualmin_account_async(params), provision=True)

    def test_queued_suspend_persists_enqueue_budget_before_recovery(self) -> None:
        self.run_queued(lambda: suspend_virtualmin_account_async(str(self.account.pk), "Review"))

    def test_queued_unsuspend_persists_enqueue_budget_before_recovery(self) -> None:
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        self.run_queued(lambda: unsuspend_virtualmin_account_async(str(self.account.pk)))

    def test_queued_delete_persists_enqueue_budget_before_recovery(self) -> None:
        self.account.status = "error"
        self.account.save(update_fields=["status"])
        self.run_queued(lambda: delete_virtualmin_account_async(str(self.account.pk)))

    def test_queued_reconciliation_persists_enqueue_budget(self) -> None:
        self.account.status = "suspended"
        self.account.save(update_fields=["status"])
        self.run_queued(lambda: reconcile_virtualmin_service_state_async(str(self.service.pk)))

    def test_reprovision_producer_persists_budget_before_recovery(self) -> None:
        self.set_value("provisioning.task_time_limit", 7200)
        self.observe_recovery = True
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            result = VirtualminProvisioningService(self.server).reprovision_virtualmin_account(self.account)
        self.assertEqual(self.observed_budget, 7200)
        self.assertEqual(self.observed_recovery_status, "running")
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=self.account).status, "completed")

    @contextmanager
    def reject_job_completion(self) -> Iterator[None]:
        """A real database trigger rejects completion after the account write."""
        table = connection.ops.quote_name(VirtualminProvisioningJob._meta.db_table)
        with connection.cursor() as cursor:
            if connection.vendor == "postgresql":
                cursor.execute(
                    "CREATE FUNCTION review_reject_completion() RETURNS trigger LANGUAGE plpgsql AS $$ "
                    "BEGIN IF NEW.status = 'completed' THEN RAISE EXCEPTION 'review completion rejected' "
                    "USING ERRCODE = '23514'; END IF; RETURN NEW; END $$"
                )
                cursor.execute(
                    f"CREATE TRIGGER review_reject_completion BEFORE UPDATE ON {table} "
                    "FOR EACH ROW EXECUTE FUNCTION review_reject_completion()"
                )
            else:
                cursor.execute(
                    f"CREATE TEMP TRIGGER review_reject_completion BEFORE UPDATE ON {table} "
                    "WHEN NEW.status = 'completed' BEGIN SELECT RAISE(FAIL, 'review completion rejected'); END"
                )
        try:
            yield
        finally:
            with connection.cursor() as cursor:
                cursor.execute(
                    f"DROP TRIGGER review_reject_completion ON {table}"
                    if connection.vendor == "postgresql"
                    else "DROP TRIGGER review_reject_completion"
                )
                if connection.vendor == "postgresql":
                    cursor.execute("DROP FUNCTION review_reject_completion()")

    def compensated_retry(self, *, activate: bool) -> None:  # noqa: PLR0915  # Complete retry and failure trajectories
        previous_status = "suspended" if activate else "active"
        target_status = "active" if activate else "suspended"
        self.account.status = previous_status
        self.account.status_message = "Previous lifecycle message"
        self.account.save(update_fields=["status", "status_message"])
        operation = _execute_bulk_activate if activate else _execute_bulk_suspend
        compensation = "disable-domain" if activate else "enable-domain"

        def successful_compensation(method: str, url: str, **kwargs: object) -> Response:
            params = cast("dict[str, str]", kwargs["params"])
            if params["program"] == compensation:
                stored_status = VirtualminAccount.objects.values_list("status", flat=True).get(pk=self.account.pk)
                self.assertEqual(stored_status, previous_status)
            return self.http(method, url, **kwargs)

        with self.reject_job_completion():
            # Contain the unfixed producer's broken transaction so the red assertion can run.
            with (
                transaction.atomic(),
                patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=successful_compensation),
            ):
                first = operation([self.account])
            self.assertEqual(self.account.status, previous_status)
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, previous_status)
        self.assertEqual(self.account.status_message, "Previous lifecycle message")
        self.assertEqual(first.failed_count, 1)
        failed_job = VirtualminProvisioningJob.objects.get(account=self.account)
        self.assertEqual(failed_job.status, "failed")
        self.assertEqual(failed_job.rollback_status, "success")
        self.sent.clear()
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            retried = operation([self.account])
        self.assertEqual(retried.successful_count, 1)
        self.assertEqual(self.sent, ["enable-domain" if activate else "disable-domain"])
        self.account.refresh_from_db()
        self.assertEqual(self.account.status, target_status)
        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=self.account, status="completed").count(), 1)

        # An unresolved compensation still blocks bulk retry.
        self.account.status = previous_status
        self.account.save(update_fields=["status"])
        cache.clear()

        def failed_compensation(method: str, url: str, **kwargs: object) -> Response:
            params = cast("dict[str, str]", kwargs["params"])
            result = self.http(method, url, **kwargs)
            if params["program"] == compensation:
                result._content = b'{"status": "failure", "error": "remote compensation refused"}'
            return result

        with (
            self.reject_job_completion(),
            transaction.atomic(),
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=failed_compensation),
        ):
            unresolved = operation([self.account])
        self.account.refresh_from_db()
        self.assertEqual(unresolved.failed_count, 1)
        self.assertEqual(self.account.status, "error")
        latest = VirtualminProvisioningJob.objects.filter(account=self.account).first()
        assert latest is not None
        self.assertEqual((latest.status, latest.rollback_status), ("failed", "failed"))
        self.sent.clear()
        with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http):
            blocked = operation([self.account])
        self.assertEqual(blocked.failed_count, 1)
        self.assertEqual(self.sent, [])

    def test_compensated_suspend_can_be_retried_in_bulk(self) -> None:
        self.compensated_retry(activate=False)

    def test_compensated_activate_can_be_retried_in_bulk(self) -> None:
        self.compensated_retry(activate=True)


@override_settings(CACHES=LOCMEM, VIRTUALMIN_TIMEOUTS={})
class HealthSweepDeadlineTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def test_deadline_bounds_elapsed_time_and_cancels_queued_probes(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        values = {
            "provisioning.max_concurrent_health_checks": 1,
            "provisioning.overall_health_check_timeout": 1,
            "virtualmin.rate_limit_max_calls_per_hour": 100,
            "virtualmin.rate_limit_qps": 10,
            "virtualmin.max_retries": 3,
            "virtualmin.request_timeout_seconds": 30,
        }
        for key in ("provisioning.max_concurrent_health_checks", "provisioning.overall_health_check_timeout"):
            previous = SystemSetting.objects.filter(key=key).first()
            if previous is None:
                self.addCleanup(SystemSetting.objects.filter(key=key).delete)
            else:
                self.addCleanup(SystemSetting.objects.filter(pk=previous.pk).update, value=previous.value)
            self.assertTrue(SettingsService.update_setting(key, values[key]).is_ok())
        for key, value in values.items():
            cache.set(SettingsService._get_cache_key(key), value, 60, version=SettingsService.CACHE_VERSION)
        server = VirtualminServer(
            name="deadline", hostname="deadline.example.test", api_username="deadline", status="active"
        )
        server.set_api_password("DeadlineServerPassword123!")
        accounts = [
            VirtualminAccount(server=server, domain=f"deadline-{index}.example.test", status="active")
            for index in range(3)
        ]
        release = Event()
        finished = Event()
        timeouts: list[float] = []

        def slow_http(method: str, url: str, *, policy: OutboundPolicy, **kwargs: object) -> Response:
            timeouts.append(policy.timeout_seconds)
            try:
                release.wait(2.0)
                return response("info", output="host: deadline.example.test\n")
            finally:
                finished.set()

        try:
            with patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=slow_http):
                started = time.perf_counter()
                result = _execute_bulk_health_check(accounts)
                elapsed = time.perf_counter() - started
                self.assertLess(elapsed, 1.8)
                self.assertEqual(result.successful_count, 0)
                self.assertEqual(result.failed_count, 3)
                self.assertEqual(len(result.errors), 3)
                for account in accounts:
                    self.assertTrue(any(account.domain in error and "timed out" in error for error in result.errors))
                self.assertEqual(len(timeouts), 1)
                self.assertLessEqual(timeouts[0], 1.0)
                release.set()
                self.assertTrue(finished.wait(1.0))
        finally:
            release.set()
            finished.wait(1.0)


@override_settings(CACHES=LOCMEM, VIRTUALMIN_TIMEOUTS={})
class GatewaySettingsOutageTests(TestCase):
    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        self.server = VirtualminServer(
            name="outage", hostname="outage.example.test", api_username="outage", status="active"
        )
        self.server.set_api_password("OutagePassword123!")
        self.gateway = VirtualminGateway(VirtualminConfig(server=self.server, use_credential_vault=False))
        self.sent: list[float] = []
        self.failures_remaining = 0
        for key, value in (
            ("virtualmin.rate_limit_max_calls_per_hour", 100),
            ("virtualmin.rate_limit_qps", 10),
            ("virtualmin.max_retries", 1),
            ("virtualmin.request_timeout_seconds", 7),
        ):
            self.assertTrue(SettingsService.update_setting(key, value).is_ok())

    @contextmanager
    def unavailable_setting(self, key: str) -> Iterator[None]:
        """A database view makes the selected settings read fail inside the real SQL engine."""
        table = connection.ops.quote_name(SystemSetting._meta.db_table)
        saved = connection.ops.quote_name("review_available_settings")
        with connection.cursor() as cursor:
            cursor.execute(f"ALTER TABLE {table} RENAME TO {saved}")
            if connection.vendor == "postgresql":
                cursor.execute(
                    "CREATE FUNCTION review_settings_available(setting_key text) RETURNS boolean "
                    "LANGUAGE plpgsql AS $$ BEGIN IF setting_key = '" + key.replace("'", "''") + "' "
                    "THEN RAISE EXCEPTION 'settings table unavailable' USING ERRCODE = '42P01'; "
                    "END IF; RETURN true; END $$"
                )
            else:
                connection.ensure_connection()

                def available(setting_key: str) -> int:
                    if setting_key == key:
                        raise RuntimeError("settings table unavailable")
                    return 1

                connection.connection.create_function("review_settings_available", 1, available)
            cursor.execute(
                f"CREATE VIEW {table} AS SELECT * FROM {saved} WHERE review_settings_available(key)"  # noqa: S608
            )
        try:
            yield
        finally:
            # The current implementation may leave the surrounding savepoint aborted.
            with connection.cursor() as cursor:
                cursor.execute(f"DROP VIEW {table}")
                cursor.execute(f"ALTER TABLE {saved} RENAME TO {table}")
                if connection.vendor == "postgresql":
                    cursor.execute("DROP FUNCTION review_settings_available(text)")
                else:
                    connection.connection.create_function("review_settings_available", 1, None)

    def http(self, method: str, url: str, *, policy: OutboundPolicy, **kwargs: object) -> Response:
        self.sent.append(policy.timeout_seconds)
        if self.failures_remaining:
            self.failures_remaining -= 1
            raise ConnectTimeout("settings outage retry fixture")
        return response("info", output="host: outage.example.test\n")

    def call_during_outage(self, key: str) -> Result[VirtualminResponse, VirtualminAPIError] | None:
        with (
            self.unavailable_setting(key),
            patch("apps.provisioning.virtualmin_gateway.safe_request", side_effect=self.http),
        ):
            try:
                with transaction.atomic():
                    return self.gateway.call("info")
            except DatabaseError:
                return None

    def test_hourly_settings_outage_is_a_contained_backend_error(self) -> None:
        outcome = self.call_during_outage("virtualmin.rate_limit_max_calls_per_hour")
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertTrue(outcome.is_err(), outcome)
        self.assertIn("backend unavailable", str(outcome.unwrap_err()))
        self.assertNotIsInstance(outcome.unwrap_err(), VirtualminRateLimitedError)
        self.assertEqual(self.sent, [])

    def test_qps_settings_outage_is_a_contained_backend_error(self) -> None:
        outcome = self.call_during_outage("virtualmin.rate_limit_qps")
        self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertTrue(outcome.is_err(), outcome)
        self.assertIn("backend unavailable", str(outcome.unwrap_err()))
        self.assertNotIsInstance(outcome.unwrap_err(), VirtualminRateLimitedError)
        self.assertEqual(self.sent, [])

    def test_retry_settings_outage_falls_back_and_reaches_http(self) -> None:
        self.failures_remaining = 2
        with self.assertLogs("apps.provisioning.virtualmin_gateway", level="WARNING") as logs:
            outcome = self.call_during_outage("virtualmin.max_retries")
            self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(outcome.unwrap().data["output"], "host: outage.example.test\n")
        self.assertEqual(self.sent, [7.0, 7.0, 7.0])
        self.assertTrue(any("virtualmin.max_retries" in line for line in logs.output))

    def test_timeout_settings_outage_falls_back_to_thirty_seconds(self) -> None:
        with self.assertLogs("apps.provisioning.virtualmin_gateway", level="WARNING") as logs:
            outcome = self.call_during_outage("virtualmin.request_timeout_seconds")
            self.assertIsNotNone(outcome)
        assert outcome is not None
        self.assertTrue(outcome.is_ok(), outcome)
        self.assertEqual(self.sent, [30.0])
        self.assertTrue(any("virtualmin.request_timeout_seconds" in line for line in logs.output))
