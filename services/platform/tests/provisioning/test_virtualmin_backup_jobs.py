"""Durable backup/restore job contracts: admission, claiming, fencing, recovery."""

from __future__ import annotations

from datetime import timedelta
from pathlib import Path
from typing import Any
from unittest.mock import patch
from uuid import uuid4

from django.db import connection, transaction
from django.test import TransactionTestCase
from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.common.types import Ok
from apps.provisioning import virtualmin_tasks
from apps.provisioning.spool import acquire_spool_reservation, release_spool_reservation
from apps.provisioning.virtualmin_migration_models import (
    SpoolReservation,
    VirtualminMigration,
    account_has_active_operation,
)
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from apps.users.models import User
from tests.provisioning import test_virtualmin_tasks as task_tests


class BackupJobAdmissionTests(task_tests.VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.management = VirtualminBackupManagementService(self.server)

    def _pending_job(self, operation: str = "backup_domain", **params: Any) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            operation=operation,
            account=self.account,
            server=self.server,
            parameters={"task_budget_seconds": 600, **params},
            status="pending",
        )

    def test_admission_enqueues_instead_of_executing_inline(self) -> None:
        """The request path must create a pending job and return immediately."""
        with (
            patch("django_q.tasks.async_task", return_value="task-1") as enqueue,
            patch("apps.provisioning.virtualmin_backup_service.VirtualminBackupService") as service,
        ):
            result = self.management.create_backup_job(self.account, initiated_by="test")
        self.assertTrue(result.is_ok(), result)
        job = result.unwrap()
        self.assertEqual(job.status, "pending")
        self.assertIn("run_virtualmin_backup", enqueue.call_args.args[0])
        self.assertFalse(enqueue.call_args.kwargs["sync"])
        self.assertEqual(enqueue.call_args.kwargs["timeout"], job.parameters["task_budget_seconds"])
        service.return_value.backup_domain.assert_not_called()

    def test_admission_is_two_sided(self) -> None:
        """Migrations and backup jobs must mutually exclude, in both orders."""
        migration = VirtualminMigration.objects.create(
            account=self.account, source_server=self.server, target_server=self.server, reason="manual"
        )
        refused = self.management.create_backup_job(self.account)
        self.assertTrue(refused.is_err())
        self.assertIn("active migration or backup/restore", refused.unwrap_err())
        # fsm-bypass: clear the migration so the job side can be tested.
        VirtualminMigration.objects.filter(pk=migration.pk).update(status="failed")

        self._pending_job()
        self.assertTrue(account_has_active_operation(self.account))
        from apps.provisioning.virtualmin_migration_service import VirtualminMigrationService  # noqa: PLC0415

        self.settings_patch = patch(
            "apps.settings.services.SettingsService.get_boolean_setting", return_value=True
        )
        self.settings_patch.start()
        self.addCleanup(self.settings_patch.stop)
        migration_refused = VirtualminMigrationService().start_migration(
            self.account, self.server, initiated_by=None
        )
        self.assertTrue(migration_refused.is_err())
        self.assertIn("active migration or backup/restore", migration_refused.unwrap_err())

    def test_attention_status_retains_exclusion(self) -> None:
        """An uncertain restore keeps the account locked until resolved."""
        job = self._pending_job(operation="restore_domain")
        # fsm-bypass: park the job in the uncertain-mutation state.
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="attention")
        self.assertTrue(account_has_active_operation(self.account))
        refused = self.management.create_backup_job(self.account)
        self.assertTrue(refused.is_err())

    def test_attention_job_resolves_only_via_the_staff_endpoint(self) -> None:
        """Resolution releases the exclusion; non-attention jobs refuse."""
        staff = User.objects.create_user(
            email="resolver@example.com", password="resolver-test-password", staff_role="admin"
        )
        self.client.force_login(staff)
        job = self._pending_job(operation="restore_domain")
        url = reverse("provisioning:virtualmin_job_resolve", args=[job.pk])

        refused = self.client.post(url, {"note": "not yet"})
        self.assertEqual(refused.status_code, 302)
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")

        # fsm-bypass: park the job as an uncertain mutation.
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status="attention")
        self.assertTrue(account_has_active_operation(self.account))
        resolved = self.client.post(url, {"note": "domain verified on the node"})
        self.assertEqual(resolved.status_code, 302)
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIn("resolver@example.com", job.status_message)
        self.assertIn("domain verified", job.status_message)
        self.assertFalse(account_has_active_operation(self.account))

    def test_budget_rejects_only_oversized_jobs(self) -> None:
        """Default-config admission succeeds; an oversized estimate fails actionably."""
        with (
            patch("django_q.tasks.async_task", return_value="task-1"),
        ):
            ok = self.management.create_backup_job(self.account)
        self.assertTrue(ok.is_ok(), ok)
        # fsm-bypass: free the account for the second admission.
        VirtualminProvisioningJob.objects.all().delete()

        self.account.current_disk_usage_mb = 500_000_000
        refused = self.management.create_backup_job(self.account)
        self.assertTrue(refused.is_err())
        self.assertIn("visibility timeout", refused.unwrap_err())

    def test_terminal_transitions_emit_audit_events(self) -> None:
        """C2: CAS transitions bypass post_save, so they must audit explicitly."""
        job = self._pending_job()
        with patch("apps.provisioning.virtualmin_backup_service.VirtualminBackupService") as service:
            service.return_value.backup_domain.return_value = Ok({"backup_id": "b1"})
            virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        self.assertTrue(
            AuditEvent.objects.filter(
                action="virtualmin_provisioning_job_completed", object_id=str(job.pk)
            ).exists(),
            "a CAS completion must still land on the audit trail",
        )

    def test_claim_is_single_owner(self) -> None:
        """Duplicate task deliveries resolve to exactly one claim."""
        job = self._pending_job()
        with patch(
            "apps.provisioning.virtualmin_backup_service.VirtualminBackupService"
        ) as service:
            service.return_value.backup_domain.return_value = Ok({"backup_id": "b1"})
            first = virtualmin_tasks.run_virtualmin_backup(str(job.pk))
            second = virtualmin_tasks.run_virtualmin_backup(str(job.pk))
        self.assertEqual(first["status"], "completed")
        self.assertEqual(second["status"], "stale")
        job.refresh_from_db()
        self.assertEqual(job.status, "completed")
        self.assertEqual(job.result["backup_id"], "b1")
        self.assertIsNone(job.next_retry_at)

    def test_token_fences_late_terminal_write(self) -> None:
        """After a takeover rotated the token, the old runner's write is a no-op."""
        job = self._pending_job()
        token = uuid4()
        self.assertEqual(
            VirtualminProvisioningJob.claim_execution(job.pk, token, timezone.now() + timedelta(seconds=600)), 1
        )
        self.assertEqual(VirtualminProvisioningJob.take_over_execution(job.pk, "failed", "interrupted"), 1)
        rows = VirtualminProvisioningJob.finish_execution(job.pk, token, "completed", "", {"backup_id": "x"})
        self.assertEqual(rows, 0)
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertEqual(job.status_message, "interrupted")

    def test_janitor_two_clock_recovery(self) -> None:
        """Pending stale → dispatch-lost; overdue restore → attention; live jobs survive."""
        counts = {"jobs_dispatch_lost": 0, "jobs_taken_over": 0}
        stale_pending = self._pending_job()
        VirtualminProvisioningJob.objects.filter(pk=stale_pending.pk).update(
            created_at=timezone.now() - timedelta(hours=3)
        )
        virtualmin_tasks._reclaim_backup_restore_jobs(counts)
        stale_pending.refresh_from_db()
        self.assertEqual(stale_pending.status, "failed")
        self.assertIn("Dispatch lost", stale_pending.status_message)
        self.assertEqual(counts["jobs_dispatch_lost"], 1)

        overdue = self._pending_job(operation="restore_domain")
        token = uuid4()
        VirtualminProvisioningJob.claim_execution(job_id=overdue.pk, token=token, deadline=timezone.now())
        VirtualminProvisioningJob.objects.filter(pk=overdue.pk).update(
            execution_deadline=timezone.now() - timedelta(seconds=600)
        )
        SpoolReservation.objects.create(
            archive_name="virtualmin_backup_test.tar.gz",
            expected_bytes=1,
            owner=f"job:{overdue.pk}",
            expires_at=timezone.now() + timedelta(hours=1),
        )
        virtualmin_tasks._reclaim_backup_restore_jobs(counts)
        overdue.refresh_from_db()
        self.assertEqual(overdue.status, "attention")
        self.assertFalse(SpoolReservation.objects.filter(owner=f"job:{overdue.pk}").exists())
        self.assertTrue(account_has_active_operation(self.account))

        # fsm-bypass: release exclusion, then prove a live running job survives.
        VirtualminProvisioningJob.objects.filter(pk=overdue.pk).update(status="failed")
        live = self._pending_job()
        VirtualminProvisioningJob.claim_execution(
            live.pk, uuid4(), timezone.now() + timedelta(seconds=3600)
        )
        before = dict(counts)
        virtualmin_tasks._reclaim_backup_restore_jobs(counts)
        live.refresh_from_db()
        self.assertEqual(live.status, "running")
        self.assertEqual(counts, before)

    def test_generic_sweep_excludes_backup_restore_jobs(self) -> None:
        """The 30-minute claim reaper must not touch backup/restore jobs."""
        job = self._pending_job()
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            updated_at=timezone.now() - timedelta(hours=2)
        )
        reaped = VirtualminProvisioningJob.recover_expired_claims(
            timezone.now() - timedelta(minutes=30), timezone.now() + timedelta(minutes=5)
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertEqual(reaped, 0)

    def test_spool_reservation_serializes_capacity(self) -> None:
        """Reservations admit within free space, refuse beyond it, and expire."""
        spool = Path(self.tmp_spool.name) if hasattr(self, "tmp_spool") else Path("/tmp")  # noqa: S108  # Remote node path, not a local tempfile
        with patch("apps.provisioning.spool.shutil.disk_usage") as usage:
            usage.return_value = type("du", (), {"free": 1000})()
            first = acquire_spool_reservation(spool, "virtualmin_backup_a.tar.gz", 800, "job:a", 60)
            self.assertTrue(first.is_ok(), first)
            second = acquire_spool_reservation(spool, "virtualmin_backup_b.tar.gz", 800, "job:b", 60)
            self.assertTrue(second.is_err())
            self.assertIn("capacity", second.unwrap_err())
            release_spool_reservation("virtualmin_backup_a.tar.gz")
            third = acquire_spool_reservation(spool, "virtualmin_backup_c.tar.gz", 800, "job:c", 60)
            self.assertTrue(third.is_ok(), third)
            SpoolReservation.objects.filter(archive_name="virtualmin_backup_c.tar.gz").update(
                expires_at=timezone.now() - timedelta(seconds=1)
            )
            fourth = acquire_spool_reservation(spool, "virtualmin_backup_d.tar.gz", 800, "job:d", 60)
            self.assertTrue(fourth.is_ok(), fourth)


class BackupJobDurabilityTests(TransactionTestCase):
    """Real-broker properties: these need genuine commits, so no TestCase atomic."""

    def _account(self) -> Any:
        from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase  # noqa: PLC0415  # Circular

        helper = VirtualminTaskTestBase()
        helper.setUp()
        self.addCleanup(getattr(helper, "doCleanups", lambda: None))
        return helper

    def test_job_and_queue_message_commit_or_roll_back_together(self) -> None:
        from django_q.models import OrmQ  # noqa: PLC0415  # Circular

        helper = self._account()
        management = VirtualminBackupManagementService(helper.server)

        class BoomError(Exception):
            pass

        jobs_before = VirtualminProvisioningJob.objects.count()
        queue_before = OrmQ.objects.count()
        try:
            with transaction.atomic():
                result = management.create_backup_job(helper.account)
                self.assertTrue(result.is_ok(), result)
                raise BoomError
        except BoomError:
            pass
        self.assertEqual(VirtualminProvisioningJob.objects.count(), jobs_before)
        self.assertEqual(OrmQ.objects.count(), queue_before)

        result = management.create_backup_job(helper.account)
        self.assertTrue(result.is_ok(), result)
        self.assertEqual(VirtualminProvisioningJob.objects.filter(status="pending").count(), 1)
        self.assertEqual(OrmQ.objects.count(), queue_before + 1)

    def test_sync_mode_cannot_execute_inside_the_transaction(self) -> None:
        """sync=False must defeat a global sync configuration."""
        from django_q.conf import Conf  # noqa: PLC0415  # Circular
        from django_q.models import OrmQ  # noqa: PLC0415  # Circular

        helper = self._account()
        management = VirtualminBackupManagementService(helper.server)
        queue_before = OrmQ.objects.count()
        with (
            patch.object(Conf, "SYNC", True),
            patch("apps.provisioning.virtualmin_backup_service.VirtualminBackupService") as service,
        ):
            result = management.create_backup_job(helper.account)
        self.assertTrue(result.is_ok(), result)
        service.return_value.backup_domain.assert_not_called()
        self.assertEqual(OrmQ.objects.count(), queue_before + 1)

    def test_inline_execution_requires_autocommit_and_runs_in_process(self) -> None:
        helper = self._account()
        management = VirtualminBackupManagementService(helper.server)

        with transaction.atomic():
            refused = management.create_backup_job(helper.account, execute_inline=True)
        self.assertTrue(refused.is_err())
        self.assertIn("autocommit", refused.unwrap_err())

        seen: dict[str, bool] = {}

        def probe(**kwargs: Any) -> Ok[dict[str, Any]]:
            seen["in_atomic"] = connection.in_atomic_block
            return Ok({"backup_id": "inline-1"})

        with patch(
            "apps.provisioning.virtualmin_backup_service.VirtualminBackupService"
        ) as service:
            service.return_value.backup_domain.side_effect = probe
            result = management.create_backup_job(helper.account, execute_inline=True)
        self.assertTrue(result.is_ok(), result)
        job = result.unwrap()
        self.assertEqual(job.status, "completed")
        # The transport/S3 body must never run inside a transaction.
        self.assertFalse(seen["in_atomic"])
