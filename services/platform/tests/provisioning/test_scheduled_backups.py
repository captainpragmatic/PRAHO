"""The existing periodic worker admits bounded customer backups without a queue flood."""

from datetime import UTC, datetime
from unittest.mock import patch
from uuid import UUID

from django.db import transaction

from apps.common.status_models import SystemCheckState
from apps.common.system_status import StatusLevel
from apps.common.types import Ok
from apps.provisioning.models import Service
from apps.provisioning.scheduled_backups import (
    continue_after_completed_backup,
    customer_backup_health,
    schedule_customer_backup,
)
from apps.provisioning.virtualmin_backup_service import backup_storage_configuration
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.settings.services import SettingsService
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class ScheduledBackupTests(VirtualminTaskTestBase):
    @patch("django_q.tasks.async_task", return_value="queued")
    def test_null_or_malformed_marker_cannot_certify_or_cover_a_backup(self, queue) -> None:
        job = VirtualminProvisioningJob.objects.create(account=self.account, server=self.server, operation="backup_domain", status="completed", parameters={"initiated_by": "scheduled_platform_backup"})
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 0 * * *")), patch("apps.provisioning.scheduled_backups.server_transport_ready", return_value=Ok(None)):
            for marker in (None, "", False, 17, "unrelated.json"):
                with self.subTest(marker=marker):
                    job.result = {"status": "completed", "checksum_sha256": "a" * 64,
                                  "s3_info": {"metadata_key": marker, "storage_identity": backup_storage_configuration().identity}}
                    job.save(update_fields=["result"])
                    self.assertNotEqual(customer_backup_health().level, StatusLevel.GREEN)
                    self.assertEqual(schedule_customer_backup(), 1)
                    VirtualminProvisioningJob.objects.filter(status="pending").delete()
        self.assertEqual(queue.call_count, 5)

    @patch("django_q.tasks.async_task", return_value="queued")
    def test_destination_change_reopens_health_and_admission_for_a_completed_cycle(self, queue) -> None:
        VirtualminProvisioningJob.objects.create(account=self.account, server=self.server, operation="backup_domain", status="completed",
                                               parameters={"initiated_by": "scheduled_platform_backup"},
                                               result={"status": "completed", "checksum_sha256": "a" * 64,
                                                       "s3_info": {"metadata_key": "virtualmin-backups/current/metadata.json", "storage_identity": backup_storage_configuration().identity}})
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 0 * * *")), patch("apps.provisioning.scheduled_backups.server_transport_ready", return_value=Ok(None)):
            self.assertEqual(customer_backup_health().level, StatusLevel.GREEN)
            self.assertEqual(schedule_customer_backup(), 0)
            self.assertTrue(SettingsService.update_setting("backup.s3_bucket_name", "changed-backup-destination").is_ok())
            self.assertNotEqual(customer_backup_health().level, StatusLevel.GREEN)
            self.assertEqual(schedule_customer_backup(), 1)
        queue.assert_called_once()

    def test_legacy_completion_cannot_certify_the_current_destination(self) -> None:
        VirtualminProvisioningJob.objects.create(account=self.account, server=self.server, operation="backup_domain", status="completed",
                                               parameters={"initiated_by": "scheduled_platform_backup"},
                                               result={"status": "completed", "checksum_sha256": "a" * 64, "s3_info": {"metadata_key": "proof.json"}})
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 0 * * *")):
            self.assertNotEqual(customer_backup_health().level, StatusLevel.GREEN)

    def setUp(self) -> None:
        super().setUp()
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active", created_at=datetime(2026, 10, 1, tzinfo=UTC))

    @patch("django_q.tasks.async_task", return_value="queued")
    def test_repeated_tick_admits_only_one_job_for_the_due_cycle(self, queue) -> None:
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 2 * * *")), patch("apps.provisioning.scheduled_backups.timezone.now", return_value=datetime(2026, 10, 2, 3, tzinfo=UTC)), patch("apps.provisioning.scheduled_backups.server_transport_ready", return_value=Ok(None)):
            first = schedule_customer_backup()
            second = schedule_customer_backup()
        self.assertEqual(first, 1)
        self.assertEqual(second, 0)
        job = VirtualminProvisioningJob.objects.get(operation="backup_domain")
        self.assertEqual(job.parameters["initiated_by"], "scheduled_platform_backup")
        self.assertEqual(job.account_id, self.account.pk)
        self.assertEqual(job.status, "pending")
        queue.assert_called_once()

    def test_new_account_is_not_due_for_a_schedule_before_it_existed(self) -> None:
        VirtualminAccount.objects.filter(pk=self.account.pk).update(created_at=datetime(2026, 10, 2, 4, tzinfo=UTC))
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 2 * * *")), patch("apps.provisioning.scheduled_backups.timezone.now", return_value=datetime(2026, 10, 2, 5, tzinfo=UTC)):
            self.assertEqual(schedule_customer_backup(), 0)
        self.assertFalse(VirtualminProvisioningJob.objects.filter(operation="backup_domain").exists())

    def test_due_customer_without_completed_offsite_job_is_unhealthy_after_grace(self) -> None:
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 2 * * *")), patch("apps.provisioning.scheduled_backups.timezone.now", return_value=datetime(2026, 10, 2, 5, tzinfo=UTC)):
            result = customer_backup_health()
        self.assertEqual(result.level, StatusLevel.RED)
        self.assertIn("0/1", str(result.detail))

    @patch("django_q.tasks.async_task", return_value="queued")
    def test_fifty_blocked_accounts_cannot_starve_the_next_eligible_account(self, queue) -> None:
        services = [Service(customer=self.customer, service_plan=self.plan, currency=self.currency,
                            service_name=f"blocked{index}.example.test", domain=f"blocked{index}.example.test",
                            username=f"blocked{index}", billing_cycle="monthly", price=0, status="active") for index in range(1, 51)]
        Service.objects.bulk_create(services)
        accounts = [VirtualminAccount(id=UUID(int=index), service=service, server=self.server, domain=service.domain,
                                      virtualmin_username=service.username, encrypted_password=b"", status="active",
                                      praho_customer_id=self.customer.pk, praho_service_id=service.pk) for index, service in enumerate(services, start=1)]
        VirtualminAccount.objects.bulk_create(accounts)
        VirtualminAccount.objects.filter(pk__in=[account.pk for account in accounts]).update(created_at=datetime(2026, 10, 1, tzinfo=UTC))
        VirtualminProvisioningJob.objects.bulk_create([VirtualminProvisioningJob(account=account, server=self.server,
                                                                                operation="restore_domain", status="pending") for account in accounts])
        with patch("apps.provisioning.scheduled_backups.backup_configuration", return_value=(True, "0 2 * * *")), patch("apps.provisioning.scheduled_backups.timezone.now", return_value=datetime(2026, 10, 2, 3, tzinfo=UTC)), patch("apps.provisioning.scheduled_backups.server_transport_ready", return_value=Ok(None)):
            self.assertEqual(schedule_customer_backup(), 0)
            self.assertEqual(schedule_customer_backup(), 1)
        job = VirtualminProvisioningJob.objects.get(operation="backup_domain")
        self.assertEqual(job.account_id, self.account.pk)
        queue.assert_called_once()
        self.assertEqual(SystemCheckState.objects.get(check_key="hosting_backup_scheduler").details["scan_after"], str(self.account.pk))

    def test_completion_continuation_waits_for_commit_and_failure_keeps_completed_job(self) -> None:
        job = VirtualminProvisioningJob.objects.create(account=self.account, server=self.server, operation="backup_domain", status="completed", parameters={"initiated_by": "scheduled_platform_backup", "chain_role": "standalone"})
        with patch("apps.provisioning.scheduled_backups.schedule_customer_backup", side_effect=RuntimeError("queue unavailable")) as admit:
            with self.captureOnCommitCallbacks(execute=True):
                continue_after_completed_backup(job)
                admit.assert_not_called()
            admit.assert_called_once()
        job.refresh_from_db()
        self.assertEqual(job.status, "completed")

    def test_rolled_back_completion_does_not_admit_a_successor(self) -> None:
        job = VirtualminProvisioningJob(account=self.account, server=self.server, operation="backup_domain", parameters={"initiated_by": "scheduled_platform_backup"})
        with patch("apps.provisioning.scheduled_backups.schedule_customer_backup") as admit, self.captureOnCommitCallbacks(execute=True), self.assertRaises(RuntimeError), transaction.atomic():
            continue_after_completed_backup(job)
            raise RuntimeError("rollback")
        admit.assert_not_called()
