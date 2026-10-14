"""Account-level operation exclusion: backup source identity, deletion and lifecycle retries.

One rule across every writer of an account: admission takes the account row
lock, refuses while another operation is active, and records the durable job
row inside that same transaction. Backups and restores, deletes (first attempt
and retry) and the reconciler all go through it.
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Retriability, retriability_of
from apps.provisioning import virtualmin_tasks
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob, VirtualminServer
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase
from tests.provisioning.test_cov_virtualmin_tasks_operations import force_status


class ExclusionCase(VirtualminServiceCoverageCase):
    def _job(self, account: VirtualminAccount, operation: str, status: str, **extra: Any) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            operation=operation,
            account=account,
            server=account.server,
            status=status,
            parameters={"task_budget_seconds": 600},
            **extra,
        )

    def _other_server(self) -> VirtualminServer:
        return VirtualminServer.objects.create(
            name="Other VM",
            hostname="vm-other.example.com",
            api_username="other-api",
            status="active",
            max_domains=100,
            current_domains=0,
            last_health_check=timezone.now(),
        )


class BackupSourceIdentityTests(ExclusionCase):
    def test_backup_is_refused_when_the_account_moved_after_the_service_was_built(self) -> None:
        account = self._account()
        management = VirtualminBackupManagementService(self.server)
        moved_to = self._other_server()
        # The migration commits between constructing the service and admitting the job.
        VirtualminAccount.objects.filter(pk=account.pk).update(server=moved_to)
        with patch("django_q.tasks.async_task") as enqueue:
            result = management.create_backup_job(account)
        self.assertTrue(result.is_err(), result)
        self.assertIn("moved", result.unwrap_err())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        enqueue.assert_not_called()

    def test_backup_job_records_the_locked_accounts_server(self) -> None:
        account = self._account()
        management = VirtualminBackupManagementService(self.server)
        with patch("django_q.tasks.async_task"):
            result = management.create_backup_job(account)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().server_id, account.server_id)

    def test_restore_target_stays_an_explicit_choice(self) -> None:
        account = self._account()
        target = self._other_server()
        management = VirtualminBackupManagementService(self.server)
        with patch("django_q.tasks.async_task"):
            result = management.create_restore_job(account, RestoreConfig(backup_id="b-1"), target_server=target)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(result.unwrap().server_id, target.pk)


class DeleteJoinsTheExclusionTests(ExclusionCase):
    def test_delete_is_refused_while_a_backup_runs(self) -> None:
        account = self._account("error")
        self._job(account, "backup_domain", "running")
        result = self.provisioning.delete_account(account)
        self.assertTrue(result.is_err(), result)
        self.assertIn("active", result.unwrap_err())
        self.assertEqual(self.requests, [])
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="delete_domain").exists())
        account.refresh_from_db()
        self.assertEqual(account.status, "error")

    def test_a_refused_delete_releases_its_idempotency_key(self) -> None:
        account = self._account("error")
        backup = self._job(account, "backup_domain", "running")
        self.assertTrue(self.provisioning.delete_account(account).is_err())
        VirtualminProvisioningJob.objects.filter(pk=backup.pk).update(status="completed")
        recovered = self.provisioning.delete_account(account)
        self.assertIs(recovered.unwrap(), True)
        self.assertEqual(self._programs(), ["delete-domain"])

    def test_delete_job_is_created_inside_the_admission(self) -> None:
        account = self._account("error")
        self.assertIs(self.provisioning.delete_account(account).unwrap(), True)
        job = VirtualminProvisioningJob.objects.get(operation="delete_domain")
        self.assertEqual(job.status, "completed")

    def test_backup_and_restore_admission_are_refused_during_a_delete(self) -> None:
        account = self._account("error")
        management = VirtualminBackupManagementService(self.server)
        for status in ("pending", "running", "attention"):
            with self.subTest(delete_status=status):
                delete = self._job(account, "delete_domain", status)
                self.assertTrue(account_has_active_operation(account))
                with patch("django_q.tasks.async_task") as enqueue:
                    backup = management.create_backup_job(account)
                    restore = management.create_restore_job(account, RestoreConfig(backup_id="b-1"))
                self.assertTrue(backup.is_err(), backup)
                self.assertTrue(restore.is_err(), restore)
                enqueue.assert_not_called()
                self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account).count(), 1)
                VirtualminProvisioningJob.objects.filter(pk=delete.pk).delete()

    def test_finished_deletes_do_not_hold_the_exclusion(self) -> None:
        account = self._account("error")
        for status in ("failed", "completed", "cancelled"):
            job = self._job(account, "delete_domain", status)
            self.assertFalse(account_has_active_operation(account), status)
            job.delete()

    def test_the_retried_job_counts_as_the_accounts_operation_but_not_against_itself(self) -> None:
        account = self._account("error")
        retried = self._job(account, "delete_domain", "running")
        self.assertTrue(account_has_active_operation(account))
        self.assertFalse(account_has_active_operation(account, ignore_job_id=retried.pk))
        self._job(account, "backup_domain", "running")
        self.assertTrue(account_has_active_operation(account, ignore_job_id=retried.pk))


class LifecycleRetryJoinsTheExclusionTests(ExclusionCase):
    def test_delete_retry_is_refused_while_another_operation_runs(self) -> None:
        account = self._account("error")
        self._job(account, "restore_domain", "running")
        retried = self._job(account, "delete_domain", "running")
        result = self.provisioning.retry_job(retried)
        self.assertTrue(result.is_err(), result)
        self.assertEqual(self.requests, [])
        retried.refresh_from_db()
        # Not stranded running: the retry sweep picks it up once the operation ends.
        self.assertEqual(retried.status, "failed")
        self.assertEqual(retriability_of(result), Retriability.RETRIABLE)
        account.refresh_from_db()
        self.assertEqual(account.status, "error")

    def test_every_lifecycle_retry_is_refused_during_a_backup(self) -> None:
        account = self._account("error")
        self._job(account, "backup_domain", "attention")
        for operation in ("delete_domain", "suspend_domain", "unsuspend_domain"):
            with self.subTest(operation=operation):
                retried = self._job(account, operation, "running")
                result = self.provisioning.retry_job(retried)
                self.assertTrue(result.is_err(), result)
                self.assertEqual(self.requests, [])
                retried.refresh_from_db()
                self.assertEqual(retried.status, "failed")

    def test_delete_retry_proceeds_when_only_itself_is_active(self) -> None:
        account = self._account("error")
        force_status(self.service, "terminated")
        retried = self._job(account, "delete_domain", "running")
        result = self.provisioning.retry_job(retried)
        self.assertIs(result.unwrap(), True)
        self.assertEqual(self._programs(), ["delete-domain"])
        account.refresh_from_db()
        self.assertEqual(account.status, "terminated")


class ReconcileSkipsBusyAccountsTests(ExclusionCase):
    def test_reconcile_skips_an_account_with_any_active_operation(self) -> None:
        account = self._account()
        force_status(self.service, "suspended")
        cases = (
            ("backup_domain", "running"),
            ("restore_domain", "attention"),
            ("delete_domain", "pending"),
        )
        for operation, status in cases:
            with self.subTest(operation=operation, status=status):
                job = self._job(account, operation, status)
                result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
                self.assertEqual(result, {"success": True, "action": "operation_active"})
                self.assertEqual(self.requests, [])
                account.refresh_from_db()
                self.assertEqual(account.status, "active")
                VirtualminProvisioningJob.objects.filter(pk=job.pk).delete()

    def test_reconcile_converges_once_the_operation_has_ended(self) -> None:
        account = self._account()
        force_status(self.service, "suspended")
        job = self._job(account, "backup_domain", "running")
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            status="failed", completed_at=timezone.now() - timedelta(minutes=1)
        )
        result = virtualmin_tasks.reconcile_virtualmin_service_state(str(self.service.pk))
        self.assertEqual(result["action"], "suspended")
        self.assertEqual(self._programs(), ["disable-domain"])
