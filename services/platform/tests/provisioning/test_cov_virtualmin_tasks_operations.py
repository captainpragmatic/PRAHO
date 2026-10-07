"""WP17 coverage additions for lifecycle tasks, periodic sweeps, and recovery."""

from __future__ import annotations

from datetime import timedelta
from typing import cast
from unittest.mock import patch
from uuid import uuid4

from django.core.cache import cache
from django.utils import timezone
from django_q.models import Schedule
from requests.exceptions import ConnectTimeout, ReadTimeout

from apps.common.types import Retriability
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_gateway import VirtualminGateway
from apps.provisioning.virtualmin_migration_models import NodeDrain, VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from tests.helpers.fsm_helpers import force_status
from tests.provisioning.test_cov_virtualmin_tasks_signals import VirtualminCoverageCase


class LifecycleTaskEffectsTests(VirtualminCoverageCase):
    def test_suspend_persists_reason_job_and_returned_identity(self) -> None:
        account = self._account()
        result = virtualmin_tasks.suspend_virtualmin_account(str(account.pk), "Unpaid invoice")
        account.refresh_from_db()
        self.assertEqual(account.status, "suspended")
        self.assertEqual(account.status_message, "Unpaid invoice")
        self.assertEqual(
            result,
            {"success": True, "account_id": str(account.pk), "domain": account.domain, "reason": "Unpaid invoice"},
        )
        job = VirtualminProvisioningJob.objects.get(account=account)
        self.assertEqual(job.status, "completed")
        self.assertEqual(
            job.parameters, {"domain": account.domain, "reason": "Unpaid invoice", "task_budget_seconds": 600}
        )
        self.assertEqual(self.requests, [{"program": "disable-domain", "domain": account.domain, "json": "1"}])

    def test_unsuspend_clears_reason_and_persists_completed_job(self) -> None:
        account = self._account("suspended")
        account.status_message = "Unpaid invoice"
        account.save(update_fields=["status_message"])
        result = virtualmin_tasks.unsuspend_virtualmin_account(str(account.pk))
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(account.status_message, "")
        self.assertEqual(result, {"success": True, "account_id": str(account.pk), "domain": account.domain})
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "completed")
        self.assertEqual(self.requests, [{"program": "enable-domain", "domain": account.domain, "json": "1"}])

    def test_delete_retains_audit_row_and_decrements_server_usage(self) -> None:
        account = self._account("error")
        result = virtualmin_tasks.delete_virtualmin_account(str(account.pk))
        account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(result, {"success": True, "account_id": str(account.pk), "domain": account.domain})
        self.assertEqual(account.status, "terminated")
        self.assertEqual(self.server.current_domains, 2)
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "completed")
        self.assertEqual(self.requests, [{"program": "delete-domain", "domain": account.domain, "json": "1"}])

    def test_missing_accounts_return_the_requested_identity(self) -> None:
        account_id = str(uuid4())
        for task in (
            virtualmin_tasks.suspend_virtualmin_account,
            virtualmin_tasks.unsuspend_virtualmin_account,
            virtualmin_tasks.delete_virtualmin_account,
        ):
            with self.subTest(task=task.__name__):
                self.assertEqual(task(account_id), {"success": False, "error": f"Account {account_id} not found"})
        self.assertEqual(self.requests, [])

    def test_invalid_account_ids_return_unknown_failure_without_remote_work(self) -> None:
        for task in (
            virtualmin_tasks.suspend_virtualmin_account,
            virtualmin_tasks.unsuspend_virtualmin_account,
            virtualmin_tasks.delete_virtualmin_account,
        ):
            with self.subTest(task=task.__name__):
                result = task("invalid-uuid")
                self.assertFalse(result["success"])
                self.assertIn("valid UUID", result["error"])
                self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)
        self.assertEqual(self.requests, [])

    def test_application_failures_keep_account_state_and_failed_job(self) -> None:
        account = self._account()
        cases = (
            (virtualmin_tasks.suspend_virtualmin_account, "active", "disable-domain"),
            (virtualmin_tasks.unsuspend_virtualmin_account, "suspended", "enable-domain"),
            (virtualmin_tasks.delete_virtualmin_account, "error", "delete-domain"),
        )
        for task, status, program in cases:
            with self.subTest(task=task.__name__):
                account.status = status
                account.save(update_fields=["status"])
                self.rejections[program] = "Permission denied"
                result = task(str(account.pk))
                account.refresh_from_db()
                self.assertEqual(account.status, status)
                self.assertEqual(result["error"], "Permission denied")
                self.assertFalse(result["success"])
                self.assertEqual(result["retriability"], Retriability.NOT_RETRIABLE.value)
                job = VirtualminProvisioningJob.objects.filter(account=account).latest("created_at")
                self.assertEqual(job.status, "failed")
                self.assertEqual(job.status_message, "Permission denied")
                self.assertIsNone(job.next_retry_at)

    def test_connect_timeouts_raise_safe_retry_and_leave_failed_jobs(self) -> None:
        account = self._account()
        cases = (
            (virtualmin_tasks.suspend_virtualmin_account, "active"),
            (virtualmin_tasks.unsuspend_virtualmin_account, "suspended"),
            (virtualmin_tasks.delete_virtualmin_account, "error"),
        )
        for task, status in cases:
            with self.subTest(task=task.__name__):
                account.status = status
                account.save(update_fields=["status"])
                with (
                    patch.object(
                        VirtualminGateway, "_execute_http_request", side_effect=ConnectTimeout("not connected")
                    ),
                    patch("apps.provisioning.virtualmin_gateway.time.sleep"),
                    self.assertRaises(virtualmin_tasks.RetryableProvisioningError),
                ):
                    task(str(account.pk))
                account.refresh_from_db()
                self.assertEqual(account.status, status)
                job = VirtualminProvisioningJob.objects.filter(account=account).latest("created_at")
                self.assertEqual(job.status, "failed")
                self.assertIsNotNone(job.next_retry_at)

    def test_read_timeouts_return_unknown_failure_without_retrying_mutations(self) -> None:
        account = self._account()
        cases = (
            (virtualmin_tasks.suspend_virtualmin_account, "active"),
            (virtualmin_tasks.unsuspend_virtualmin_account, "suspended"),
            (virtualmin_tasks.delete_virtualmin_account, "error"),
        )
        for task, status in cases:
            with self.subTest(task=task.__name__):
                account.status = status
                account.save(update_fields=["status"])
                with patch.object(VirtualminGateway, "_execute_http_request", side_effect=ReadTimeout("response lost")):
                    result = task(str(account.pk))
                account.refresh_from_db()
                self.assertEqual(account.status, status)
                self.assertFalse(result["success"])
                self.assertEqual(result["retriability"], Retriability.UNKNOWN.value)
                job = VirtualminProvisioningJob.objects.filter(account=account).latest("created_at")
                self.assertEqual(job.status, "failed")
                self.assertIsNone(job.next_retry_at)

    def test_reconciliation_returns_suspend_failure_without_changing_account(self) -> None:
        account = self._account()
        force_status(self.service, "suspended")
        self.rejections["disable-domain"] = "Permission denied"
        result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        account.refresh_from_db()
        self.assertEqual(result, {"success": False, "action": "suspend", "error": "Permission denied"})
        self.assertEqual(account.status, "active")

    def test_reconciliation_returns_unsuspend_failure_without_changing_account(self) -> None:
        account = self._account("suspended")
        self.rejections["enable-domain"] = "Permission denied"
        result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        account.refresh_from_db()
        self.assertEqual(result, {"success": False, "action": "unsuspend", "error": "Permission denied"})
        self.assertEqual(account.status, "suspended")

    def test_migration_ownership_blocks_all_lifecycle_tasks_and_reconciliation(self) -> None:
        account = self._account()
        target = VirtualminServer.objects.create(name="Target", hostname="target.example.com", api_username="target")
        migration = VirtualminMigration.objects.create(
            account=account, source_server=self.server, target_server=target, status="needs_review"
        )
        for task in (
            virtualmin_tasks.suspend_virtualmin_account,
            virtualmin_tasks.unsuspend_virtualmin_account,
            virtualmin_tasks.delete_virtualmin_account,
        ):
            with self.subTest(task=task.__name__):
                self.assertEqual(task(str(account.pk)), {"success": True, "action": "migration_locked"})
        self.assertEqual(
            virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk)),
            {"success": True, "action": "migration_locked"},
        )
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(VirtualminMigration.objects.get(pk=migration.pk).status, "needs_review")
        self.assertEqual(self.requests, [])

    def test_pending_service_reconciliation_is_a_noop(self) -> None:
        force_status(self.service, "pending")
        self.assertEqual(
            virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk)),
            {"success": True, "action": "noop"},
        )
        self.assertEqual(self.broker.queued(), [])
        self.assertEqual(self.requests, [])

    def test_kill_switch_prevents_automatic_dispatch(self) -> None:
        with self.settings(VIRTUALMIN_AUTO_PROVISIONING_ENABLED=False):
            result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(result, {"success": True, "action": "kill_switch_disabled"})
        self.assertEqual(self.broker.queued(), [])

    def test_async_wrappers_preserve_task_names_arguments_and_budgets(self) -> None:
        account_id = str(uuid4())
        virtualmin_tasks.suspend_virtualmin_account_async(account_id, "Unpaid")
        virtualmin_tasks.unsuspend_virtualmin_account_async(account_id)
        virtualmin_tasks.delete_virtualmin_account_async(account_id)
        self.assertEqual(
            self.broker.queued(),
            [
                ("apps.provisioning.virtualmin_tasks.suspend_virtualmin_account", account_id, "Unpaid"),
                ("apps.provisioning.virtualmin_tasks.unsuspend_virtualmin_account", account_id),
                ("apps.provisioning.virtualmin_tasks.delete_virtualmin_account", account_id),
            ],
        )
        packages = self._packages()
        # The queued budget travels with each job so recovery can wait for it.
        self.assertEqual(
            [cast("dict[str, object]", package["kwargs"]) for package in packages],
            [{"task_budget_seconds": 600}, {"task_budget_seconds": 600}, {"task_budget_seconds": 900}],
        )
        self.assertEqual([package["timeout"] for package in packages], [600, 600, 900])


class PeriodicTaskEffectsTests(VirtualminCoverageCase):
    def test_statistics_update_persists_remote_domain_count(self) -> None:
        result = virtualmin_tasks.update_virtualmin_server_statistics()
        self.server.refresh_from_db()
        self.assertTrue(result["success"], result)
        self.assertEqual(self.server.current_domains, 1)
        self.assertEqual(result["results"]["updated_servers"], 1, result)
        self.assertEqual(result["results"]["failed_servers"], 0)
        row = result["results"]["servers"][0]
        self.assertEqual(row["hostname"], self.server.hostname)
        self.assertEqual(row["statistics"]["domain_count"], 1)
        self.assertIsNone(cache.get("virtualmin_stats_update_lock"))

    def test_statistics_transport_failure_preserves_usage_and_releases_lock(self) -> None:
        with (
            patch.object(VirtualminGateway, "_execute_http_request", side_effect=ReadTimeout("response lost")),
            patch("apps.provisioning.virtualmin_gateway.time.sleep"),
        ):
            result = virtualmin_tasks.update_virtualmin_server_statistics()
        self.server.refresh_from_db()
        self.assertTrue(result["success"], result)
        self.assertEqual(self.server.current_domains, 3)
        self.assertEqual(result["results"]["failed_servers"], 1)
        self.assertEqual(result["results"]["updated_servers"], 0)
        self.assertIn("Read timeout", result["results"]["servers"][0]["error"])
        self.assertIsNone(cache.get("virtualmin_stats_update_lock"))

    def test_statistics_lock_returns_already_running_without_remote_work(self) -> None:
        cache.set("virtualmin_stats_update_lock", True)
        self.assertEqual(
            virtualmin_tasks.update_virtualmin_server_statistics(), {"success": True, "message": "Already running"}
        )
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 3)
        self.assertEqual(self.requests, [])

    def test_health_lock_returns_already_running_without_remote_work(self) -> None:
        cache.set("virtualmin_health_check_lock", True)
        self.assertEqual(
            virtualmin_tasks.health_check_virtualmin_servers(), {"success": True, "message": "Already running"}
        )
        self.assertEqual(self.requests, [])

    def test_health_sweep_persists_success_and_releases_lock(self) -> None:
        self.server.consecutive_health_failures = 2
        self.server.health_check_error = "old failure"
        self.server.save(update_fields=["consecutive_health_failures", "health_check_error"])
        result = virtualmin_tasks.health_check_virtualmin_servers()
        self.server.refresh_from_db()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["results"]["healthy_servers"], 1)
        self.assertEqual(self.server.consecutive_health_failures, 0)
        self.assertEqual(self.server.health_check_error, "")
        self.assertIsNotNone(self.server.last_health_check)
        self.assertIsNone(cache.get("virtualmin_health_check_lock"))

    def test_schedule_setup_persists_real_periodic_tasks_and_is_idempotent(self) -> None:
        first = virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        second = virtualmin_tasks.setup_virtualmin_scheduled_tasks()
        self.assertEqual(first["statistics"], "created")
        self.assertEqual(second["statistics"], "already_exists")
        stats = Schedule.objects.get(name="virtualmin-statistics")
        self.assertEqual(stats.func, "apps.provisioning.virtualmin_tasks.update_virtualmin_server_statistics")
        self.assertEqual(stats.cron, "0 */6 * * *")
        self.assertEqual(Schedule.objects.get(name="virtualmin-health-check").minutes, 10)
        self.assertEqual(Schedule.objects.get(name="virtualmin-reconcile-divergence").minutes, 15)


class RecoveryTaskEffectsTests(VirtualminCoverageCase):
    def test_missing_backup_and_restore_jobs_return_missing_identity(self) -> None:
        job_id = str(uuid4())
        for task in (virtualmin_tasks.run_virtualmin_backup, virtualmin_tasks.run_virtualmin_restore):
            with self.subTest(task=task.__name__):
                self.assertEqual(task(job_id), {"status": "missing", "job_id": job_id})
        self.assertFalse(VirtualminProvisioningJob.objects.exists())

    def test_backup_without_account_is_failed_and_audited(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, operation="backup_domain", correlation_id="orphan-backup"
        )
        result = virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        job.refresh_from_db()
        self.assertEqual(result, {"status": "failed", "job_id": str(job.pk), "error": "no account"})
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.status_message, "Job has no account")
        self.assertIsNone(job.next_retry_at)
        self.assertEqual(self._event("virtualmin_provisioning_job_failed", job.pk).new_values["status"], "failed")

    def test_completed_backup_delivery_is_stale_and_keeps_terminal_state(self) -> None:
        account = self._account()
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=account,
            operation="backup_domain",
            status="completed",
            correlation_id="done-backup",
        )
        self.assertEqual(
            virtualmin_tasks.run_virtualmin_backup(str(job.pk)), {"status": "stale", "job_id": str(job.pk)}
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.assertIsNone(job.execution_token)
        self.assertEqual(self.requests, [])

    def test_retry_enqueue_failure_consumes_attempt_and_rearms_future_retry(self) -> None:
        account = self._account()
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=account,
            operation="suspend_domain",
            status="failed",
            next_retry_at=timezone.now() - timedelta(minutes=1),
            correlation_id="retry-suspend",
        )
        before = timezone.now()
        with patch.object(self.broker, "enqueue", side_effect=ConnectionError("broker unavailable")):
            result = virtualmin_tasks.process_failed_virtualmin_jobs()
        job.refresh_from_db()
        self.assertTrue(result["success"], result)
        self.assertEqual(result["results"]["retried_jobs"], 0)
        self.assertEqual(result["results"]["skipped_jobs"], 1)
        self.assertEqual(result["results"]["jobs"][0]["status"], "enqueue_failed")
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.retry_count, 1)
        self.assertIsNotNone(job.next_retry_at)
        assert job.next_retry_at is not None
        self.assertGreater(job.next_retry_at, before)
        self.assertEqual(job.parameters["task_budget_seconds"], 900)

    def test_unsupported_failed_job_is_terminalized_without_dispatch(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            operation="unsupported",
            status="failed",
            next_retry_at=timezone.now() - timedelta(minutes=1),
            correlation_id="unsupported-retry",
        )
        result = virtualmin_tasks.process_failed_virtualmin_jobs()
        job.refresh_from_db()
        self.assertEqual(result["results"]["jobs"][0]["status"], "terminal")
        self.assertIsNone(job.next_retry_at)
        self.assertEqual(self.broker.queued(), [])

    def test_stalled_backup_dispatch_is_failed_and_audited(self) -> None:
        job = VirtualminProvisioningJob.objects.create(
            server=self.server, operation="backup_domain", correlation_id="lost-backup"
        )
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(created_at=timezone.now() - timedelta(hours=3))
        counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        job.refresh_from_db()
        self.assertEqual(counts["jobs_dispatch_lost"], 1)
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.status_message, "Dispatch lost: queued task never arrived")
        self.assertEqual(self._event("virtualmin_provisioning_job_failed", job.pk).new_values["status"], "failed")

    def test_interrupted_running_drain_is_parked_for_review(self) -> None:
        old = timezone.now() - timedelta(days=1)
        drain = NodeDrain.objects.create(server=self.server, status="running", worker_started_at=old)
        NodeDrain.objects.filter(pk=drain.pk).update(updated_at=old)
        counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        drain.refresh_from_db()
        self.assertEqual(counts["drains_reviewed"], 1)
        self.assertEqual(drain.status, "paused_needs_review")
        self.assertIn("Worker interrupted", drain.error_detail)
        self.assertEqual(self._event("node_drain_paused", drain.pk).metadata["requires_review"], True)
        self.assertEqual(self.broker.queued(), [])

    def test_invalid_migration_and_drain_ids_return_errors(self) -> None:
        for task in (virtualmin_tasks.run_virtualmin_migration, virtualmin_tasks.run_node_drain):
            with self.subTest(task=task.__name__):
                result = task("invalid-uuid")
                self.assertFalse(result["success"])
                self.assertIn("UUID", result["error"])
        self.assertEqual(self.requests, [])

    def test_missing_migration_returns_error_from_the_real_service(self) -> None:
        self.assertEqual(
            virtualmin_tasks.run_virtualmin_migration(str(uuid4())), {"success": False, "error": "migration not found"}
        )
        self.assertEqual(self.requests, [])

    def test_missing_drain_returns_lookup_error(self) -> None:
        result = virtualmin_tasks.run_node_drain(str(uuid4()))
        self.assertFalse(result["success"])
        self.assertIn("does not exist", result["error"])
        self.assertEqual(self.requests, [])

    def test_cancelled_drain_delivery_keeps_terminal_state(self) -> None:
        drain = NodeDrain.objects.create(server=self.server, status="cancelled")
        result = virtualmin_tasks.run_node_drain(str(drain.pk), str(drain.task_token))
        self.assertEqual(result, {"success": True, "drain_id": str(drain.pk), "status": "cancelled"})
        self.assertEqual(NodeDrain.objects.get(pk=drain.pk).status, "cancelled")
        self.assertEqual(self.requests, [])

    def test_overdue_backup_and_restore_workers_get_distinct_terminal_outcomes(self) -> None:
        old = timezone.now() - timedelta(hours=1)
        backup = VirtualminProvisioningJob.objects.create(
            server=self.server,
            operation="backup_domain",
            status="running",
            execution_token=uuid4(),
            execution_deadline=old,
            correlation_id="overdue-backup",
        )
        restore = VirtualminProvisioningJob.objects.create(
            server=self.server,
            operation="restore_domain",
            status="running",
            execution_token=uuid4(),
            execution_deadline=old,
            correlation_id="overdue-restore",
        )
        backup_token = backup.execution_token
        restore_token = restore.execution_token
        counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        backup.refresh_from_db()
        restore.refresh_from_db()
        self.assertEqual(counts["jobs_taken_over"], 2)
        self.assertEqual(backup.status, "failed")
        self.assertEqual(restore.status, "attention")
        self.assertNotEqual(backup.execution_token, backup_token)
        self.assertNotEqual(restore.execution_token, restore_token)
        self.assertEqual(self._event("virtualmin_provisioning_job_failed", backup.pk).new_values["status"], "failed")
        self.assertEqual(
            self._event("virtualmin_provisioning_job_attention", restore.pk).new_values["status"], "attention"
        )

    def test_stalled_migration_enqueue_failure_preserves_phase_and_backs_off(self) -> None:
        account = self._account()
        target = VirtualminServer.objects.create(name="Target", hostname="target.example.com", api_username="target")
        migration = VirtualminMigration.objects.create(account=account, source_server=self.server, target_server=target)
        old = timezone.now() - timedelta(hours=1)
        VirtualminMigration.objects.filter(pk=migration.pk).update(updated_at=old)
        with patch.object(self.broker, "enqueue", side_effect=ConnectionError("broker unavailable")):
            counts = virtualmin_tasks.reclaim_stalled_virtualmin_operations()
        migration.refresh_from_db()
        self.assertEqual(counts["migrations_requeued"], 0)
        self.assertEqual(migration.status, "pending")
        self.assertGreater(migration.updated_at, old)
        self.assertEqual(self.broker.queued(), [])
