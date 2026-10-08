"""Observable effects for the WP18 provisioning transport and task budgets."""

from __future__ import annotations

import time
from datetime import timedelta
from decimal import Decimal
from io import StringIO
from typing import ClassVar, cast
from unittest.mock import MagicMock, patch
from uuid import uuid4

import paramiko
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
from apps.billing.models import Currency
from apps.common.types import Ok
from apps.customers.models import Customer
from apps.provisioning import virtualmin_tasks
from apps.provisioning.models import Service, ServicePlan
from apps.provisioning.virtualmin_auth_manager import (
    CACHE_AUTH_METHOD_PREFIX,
    AuthMethod,
    VirtualminAuthenticationManager,
)
from apps.provisioning.virtualmin_migration_service import migration_task_timeout
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.settings.models import SettingActivation, SystemSetting
from apps.settings.services import SettingsService

CACHE_KEY = "provisioning.cache_timeout"
SSH_KEY = "provisioning.ssh_timeout"
SUDO_KEY = "provisioning.sudo_command_timeout"
SOFT_KEY = "provisioning.task_soft_time_limit"
HARD_KEY = "provisioning.task_time_limit"
DEFAULTS = {CACHE_KEY: 3600, SSH_KEY: 30, SUDO_KEY: 60, SOFT_KEY: 600, HARD_KEY: 900}
LOCMEM_CACHE = {"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}}


class ProvisioningSettingsFixture(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        super().setUp()
        cache.clear()
        self.addCleanup(cache.clear)
        for key in DEFAULTS:
            original = SystemSetting.objects.filter(key=key).first()
            self.addCleanup(self.restore_setting, key, original)
        customer = Customer.objects.create(
            name="Transport settings customer", customer_type="individual", primary_email="transport@example.test"
        )
        currency, created = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        if created:
            self.addCleanup(currency.delete)
        plan = ServicePlan.objects.create(name="Transport settings plan", price_monthly=Decimal("10"))
        self.addCleanup(plan.delete)
        self.addCleanup(customer.delete)
        service = Service.objects.create(
            customer=customer,
            service_plan=plan,
            currency=currency,
            service_name="transport.example.test",
            domain="transport.example.test",
            billing_cycle="monthly",
            price=Decimal("10"),
            status="active",
        )
        self.server = VirtualminServer.objects.create(name="transport-settings", hostname="transport-node.example.test")
        self.addCleanup(self.server.delete)
        self.account = VirtualminAccount.objects.create(
            service=service, server=self.server, domain=service.domain, virtualmin_username="transport_settings"
        )
        self.broker = ORM(list_key=f"wp18-provtrans-{uuid4().hex}")
        self.addCleanup(OrmQ.objects.filter(key=self.broker.list_key).delete)

    def restore_setting(self, key: str, original: SystemSetting | None) -> None:
        if original is None:
            SystemSetting.objects.filter(key=key).delete()
        else:
            original.save()

    def set_value(self, key: str, value: int) -> None:
        result = SettingsService.update_setting(key, value)
        self.assertTrue(result.is_ok(), result)

    def queued_tasks(self) -> dict[str, dict[str, object]]:
        return {
            cast("str", task["id"]): task
            for row in OrmQ.objects.filter(key=self.broker.list_key)
            for task in (cast("dict[str, object]", SignedPackage.loads(row.payload)),)
        }

    def failed_job(self, operation: str = "create_domain", budget: int | None = None) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation=operation,
            status="failed",
            next_retry_at=timezone.now() - timedelta(minutes=1),
            parameters={} if budget is None else {"task_budget_seconds": budget},
        )

    def assert_sweep_queries(self, expected: int) -> None:
        jobs = [self.failed_job() for _ in range(3)]
        explicit = self.failed_job(budget=41)
        migration = self.failed_job("migrate_domain", budget=43)
        migration_budget = migration_task_timeout()
        with (
            patch("django_q.tasks.get_broker", return_value=self.broker),
            patch.object(Conf, "SYNC", False),
            CaptureQueriesContext(connection) as queries,
        ):
            result = virtualmin_tasks.process_failed_virtualmin_jobs()
        self.assertTrue(result["success"], result)
        setting_reads = [
            query
            for query in queries
            if query["sql"].lstrip().upper().startswith("SELECT")
            and '"setting_entries"' in query["sql"]
            and HARD_KEY in query["sql"]
        ]
        self.assertEqual(len(setting_reads), expected)
        tasks = self.queued_tasks()
        for job, budget in [(job, 17) for job in jobs] + [(explicit, 41)]:
            job.refresh_from_db()
            self.assertEqual(tasks[job.task_id]["timeout"], budget)
            self.assertEqual(job.parameters["task_budget_seconds"], budget)
            self.assertEqual(job.status, "pending")
        migration.refresh_from_db()
        self.assertEqual(tasks[migration.task_id]["timeout"], migration_budget)
        self.assertEqual(migration.parameters["task_budget_seconds"], 43)


@override_settings(CACHES=LOCMEM_CACHE)
class ProvisioningSettingsEffectTests(ProvisioningSettingsFixture, TestCase):
    def test_cache_timeout_expires_the_working_method_at_call_time(self) -> None:
        manager = VirtualminAuthenticationManager(self.server)
        self.set_value(CACHE_KEY, 2)
        key = f"{CACHE_AUTH_METHOD_PREFIX}{self.server.pk}"
        now = time.time()
        with patch("django.core.cache.backends.locmem.time.time", return_value=now) as clock:
            manager._cache_working_auth_method(AuthMethod.SSH_SUDO)
            self.assertEqual(cache.get(key), AuthMethod.SSH_SUDO.value)
            clock.return_value = now + 3
            self.assertIsNone(cache.get(key))
            self.set_value(CACHE_KEY, 4)
            manager._cache_working_auth_method(AuthMethod.ACL)
            clock.return_value = now + 6
            self.assertEqual(cache.get(key), AuthMethod.ACL.value)
            clock.return_value = now + 7
            self.assertIsNone(cache.get(key))

    def test_ssh_timeout_controls_both_credential_branches_at_dispatch(self) -> None:
        manager = VirtualminAuthenticationManager(self.server)
        for private_key in ("fixture-key", None):
            with self.subTest(private_key=private_key):
                client = MagicMock(spec=paramiko.SSHClient)
                stdout, stderr = MagicMock(), MagicMock()
                stdout.read.return_value = b"completed"
                stdout.channel.recv_exit_status.return_value = 0
                stderr.read.return_value = b""
                client.exec_command.return_value = (MagicMock(), stdout, stderr)
                connected = False

                def connect(*, timeout: float, **credentials: object) -> None:
                    nonlocal connected
                    if timeout < 2:
                        raise TimeoutError("controlled connection timeout")
                    connected = True

                client.connect.side_effect = connect
                with (
                    override_settings(
                        VIRTUALMIN_SSH_PRIVATE_KEY_PATH=private_key, VIRTUALMIN_SSH_PASSWORD="fixture-password"
                    ),
                    patch("apps.provisioning.virtualmin_auth_manager.paramiko.SSHClient", return_value=client),
                ):
                    self.set_value(SSH_KEY, 1)
                    result = manager._execute_ssh_command("sudo true")
                    self.assertTrue(result.is_err(), result)
                    self.assertIn("controlled connection timeout", result.unwrap_err())
                    self.assertFalse(connected)
                    self.assertIsNone(manager._ssh_client)
                    self.set_value(SSH_KEY, 3)
                    manager._connect_ssh()
                    self.assertTrue(connected)
                    self.assertIs(manager._ssh_client, client)
                    manager._disconnect_ssh()

    def test_sudo_command_timeout_changes_each_channel_dispatch(self) -> None:
        manager = VirtualminAuthenticationManager(self.server)
        client = MagicMock(spec=paramiko.SSHClient)
        stdout, stderr = MagicMock(), MagicMock()
        stdout.read.return_value = b"completed"
        stdout.channel.recv_exit_status.return_value = 0
        stderr.read.return_value = b""

        def execute(command: str, *, timeout: float) -> tuple[MagicMock, MagicMock, MagicMock]:
            if timeout < 2:
                raise TimeoutError("controlled channel timeout")
            return MagicMock(), stdout, stderr

        client.exec_command.side_effect = execute
        manager._ssh_client = client
        self.set_value(SUDO_KEY, 1)
        result = manager._execute_ssh_command("sudo true")
        self.assertTrue(result.is_err(), result)
        self.assertIn("controlled channel timeout", result.unwrap_err())
        self.assertIsNone(manager._ssh_client)
        manager._ssh_client = client
        self.set_value(SUDO_KEY, 3)
        self.assertEqual(manager._execute_ssh_command("sudo true").unwrap(), "completed")

    def test_task_soft_time_limit_is_persisted_for_all_three_enqueuers(self) -> None:
        with patch("django_q.tasks.get_broker", return_value=self.broker), patch.object(Conf, "SYNC", False):
            self.set_value(SOFT_KEY, 17)
            task_ids = (
                virtualmin_tasks.reconcile_virtualmin_service_state_async(str(self.account.service_id)),
                virtualmin_tasks.suspend_virtualmin_account_async(str(self.account.pk), "maintenance"),
                virtualmin_tasks.unsuspend_virtualmin_account_async(str(self.account.pk)),
            )
            self.set_value(SOFT_KEY, 19)
            later = virtualmin_tasks.unsuspend_virtualmin_account_async(str(self.account.pk))
        tasks = self.queued_tasks()
        for task_id in task_ids:
            with self.subTest(task_id=task_id):
                self.assertEqual(tasks[task_id]["timeout"], 17)
        self.assertEqual(tasks[later]["timeout"], 19)

    def test_task_time_limit_is_persisted_for_provision_and_delete(self) -> None:
        with patch("django_q.tasks.get_broker", return_value=self.broker), patch.object(Conf, "SYNC", False):
            self.set_value(HARD_KEY, 17)
            task_ids = (
                virtualmin_tasks.provision_virtualmin_account_async(
                    {"service_id": str(self.account.service_id), "domain": self.account.domain}
                ),
                virtualmin_tasks.delete_virtualmin_account_async(str(self.account.pk)),
            )
            self.set_value(HARD_KEY, 19)
            later = virtualmin_tasks.delete_virtualmin_account_async(str(self.account.pk))
        tasks = self.queued_tasks()
        for task_id in task_ids:
            with self.subTest(task_id=task_id):
                self.assertEqual(tasks[task_id]["timeout"], 17)
        self.assertEqual(tasks[later]["timeout"], 19)

    def test_legacy_backup_and_restore_use_live_budget_but_stored_budgets_win(self) -> None:
        for operation in ("backup_domain", "restore_domain"):
            with self.subTest(operation=operation):
                self.set_value(HARD_KEY, 17)
                legacy = VirtualminProvisioningJob.objects.create(
                    server=self.server, account=self.account, operation=operation
                )
                explicit = VirtualminProvisioningJob.objects.create(
                    server=self.server,
                    account=self.account,
                    operation=operation,
                    parameters={"task_budget_seconds": 41},
                )
                now = timezone.now()
                with (
                    patch("apps.provisioning.virtualmin_tasks.timezone.now", return_value=now),
                    patch("apps.provisioning.virtualmin_backup_service.VirtualminBackupService") as transport,
                ):
                    transport.return_value.backup_domain.return_value = Ok({"backup_id": "fixture"})
                    transport.return_value.restore_domain.return_value = Ok({"restored": True})
                    for job, budget in ((legacy, 17), (explicit, 41)):
                        result = virtualmin_tasks._run_backup_restore_job(str(job.pk), operation)
                        self.assertEqual(result["status"], "completed")
                        job.refresh_from_db()
                        self.assertEqual(job.execution_deadline, now + timedelta(seconds=budget))

    def test_retry_sweep_reads_default_once_inside_atomic_and_preserves_budgets(self) -> None:
        self.set_value(HARD_KEY, 17)
        with transaction.atomic():
            self.assert_sweep_queries(1)
        self.set_value(HARD_KEY, 19)
        for task in self.queued_tasks().values():
            if task["timeout"] == 17:
                job = VirtualminProvisioningJob.objects.get(pk=cast("tuple[str, ...]", task["args"])[0])
                self.assertEqual(job.parameters["task_budget_seconds"], 17)

    def test_activation_reconciles_all_five_keys_and_reports_overrides_once(self) -> None:
        keys = set(DEFAULTS)
        SystemSetting.objects.filter(key__in=keys).delete()
        SettingActivation.objects.filter(key__in=keys).delete()
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), DEFAULTS)
        self.assertEqual(
            set(
                SettingActivation.objects.filter(key__in=keys, completed_at__isnull=False).values_list("key", flat=True)
            ),
            keys,
        )
        SettingActivation.objects.filter(key__in=keys).delete()
        old_defaults = {**DEFAULTS, HARD_KEY: 1200}
        for key, value in old_defaults.items():
            self.set_value(key, value)
        SystemSetting.objects.filter(key__in=keys).update(name="Stale metadata")
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), DEFAULTS)
        self.assertFalse(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").exists())
        SettingActivation.objects.filter(key__in=keys).delete()
        retained = dict.fromkeys(DEFAULTS, 17)
        for key, value in retained.items():
            self.set_value(key, value)
        output = StringIO()
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=output)
        alert = AuditAlert.objects.get(metadata__activation_version="wp18-v1")
        self.assertEqual(alert.evidence["previous_enforced_values"], DEFAULTS)
        self.assertEqual(alert.evidence["retained_values"], retained)
        self.assertEqual(dict(SystemSetting.objects.filter(key__in=keys).values_list("key", "value")), retained)
        for key in keys:
            self.assertIn(key, output.getvalue())
        self.set_value(HARD_KEY, 1200)
        with self.captureOnCommitCallbacks(execute=True):
            call_command("setup_default_settings", stdout=StringIO())
        self.assertEqual(SystemSetting.objects.get(key=HARD_KEY).value, 1200)
        self.assertEqual(AuditAlert.objects.filter(metadata__activation_version="wp18-v1").count(), 1)


@override_settings(CACHES=LOCMEM_CACHE)
class ProvisioningSettingsWarmCacheEffectTests(ProvisioningSettingsFixture):
    def test_retry_sweep_uses_warm_cache_in_autocommit_and_preserves_budgets(self) -> None:
        self.assertTrue(connection.get_autocommit())
        self.set_value(HARD_KEY, 17)
        self.assertEqual(SettingsService.get_integer_setting(HARD_KEY), 17)
        self.assert_sweep_queries(0)
