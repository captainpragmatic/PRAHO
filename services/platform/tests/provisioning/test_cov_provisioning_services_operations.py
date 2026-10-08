"""Coverage additions for Virtualmin health, statistics and durable backup admission."""

from __future__ import annotations

from apps.provisioning.virtualmin_backup_service import BackupConfig, RestoreConfig
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService, VirtualminServerManagementService
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase
from tests.provisioning.test_virtualmin_credentials import create_test_virtualmin_server


class VirtualminOperationsCoverageTests(VirtualminServiceCoverageCase):
    def test_health_failure_preserves_verified_timestamp_and_records_streak(self) -> None:
        verified_at = self.server.last_health_check
        self.rejections["info"] = "permission denied"
        result = VirtualminServerManagementService().health_check_server(self.server)
        self.assertIn("Server reported unhealthy:", result.unwrap_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertEqual(self.server.last_health_check, verified_at)
        self.assertEqual(self.server.consecutive_health_failures, 1)
        self.assertIn("Server reported unhealthy:", self.server.health_check_error)

    def test_successful_probe_recovers_only_health_failed_server(self) -> None:
        self.server.status = "failed"
        self.server.failed_by_health_check = True
        self.server.consecutive_health_failures = 3
        self.server.health_check_error = "previous failure"
        self.server.save(
            update_fields=["status", "failed_by_health_check", "consecutive_health_failures", "health_check_error"]
        )
        result = VirtualminServerManagementService().health_check_server(self.server)
        self.assertTrue(result.unwrap()["healthy"])
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "active")
        self.assertFalse(self.server.failed_by_health_check)
        self.assertEqual(self.server.consecutive_health_failures, 0)
        self.assertEqual(self.server.health_check_error, "")
        self.assertIsNotNone(self.server.last_health_check)

    def test_operator_failed_server_stays_failed_after_refused_probe(self) -> None:
        self.server.status = "failed"
        self.server.failed_by_health_check = False
        self.server.save(update_fields=["status", "failed_by_health_check"])
        result = VirtualminServerManagementService().health_check_server(self.server)
        self.assertIn("not active", result.unwrap_err())
        self.server.refresh_from_db()
        self.assertEqual(self.server.status, "failed")
        self.assertFalse(self.server.failed_by_health_check)
        self.assertEqual(self.requests, [])

    def test_statistics_persist_remote_domain_count_and_return_server_info(self) -> None:
        self.payloads["list-domains"] = {
            "status": "success",
            "data": [{"name": "one.example.com one First hosting"}, {"name": "two.example.com two Second hosting"}],
        }
        result = VirtualminServerManagementService().update_server_statistics(self.server)
        self.assertEqual(result.unwrap()["domain_count"], 2)
        self.assertEqual(result.unwrap()["server_info"]["data"]["hostname"], self.server.hostname)
        self.server.refresh_from_db()
        self.assertEqual(self.server.current_domains, 2)
        self.assertEqual(self._programs(), ["info", "list-domains"])
        self.assertEqual(self.requests[-1], {"program": "list-domains", "json": "1"})

    def test_statistics_failures_preserve_existing_counter(self) -> None:
        for program, expected in (("info", "Failed to get server info:"), ("list-domains", "Failed to list domains:")):
            with self.subTest(program=program):
                self.rejections[program] = "permission denied"
                result = VirtualminServerManagementService().update_server_statistics(self.server)
                self.assertIn(expected, result.unwrap_err())
                self.server.refresh_from_db()
                self.assertEqual(self.server.current_domains, 3)
                del self.rejections[program]

    def test_backup_admission_snapshots_config_and_signed_task_without_remote_work(self) -> None:
        account = self._account()
        config = BackupConfig(backup_type="config_only", include_email=False, include_databases=False)
        result = VirtualminBackupManagementService(self.server).create_backup_job(
            account, config=config, initiated_by="staff@example.com"
        )
        job = result.unwrap()
        job.refresh_from_db()
        self.assertEqual(job.status, "pending")
        self.assertEqual(job.operation, "backup_domain")
        self.assertEqual(job.account_id, account.pk)
        self.assertEqual(job.server_id, self.server.pk)
        self.assertEqual(job.parameters["backup_type"], "config_only")
        self.assertFalse(job.parameters["include_email"])
        self.assertFalse(job.parameters["include_databases"])
        self.assertEqual(job.parameters["initiated_by"], "staff@example.com")
        self.assertGreater(job.parameters["task_budget_seconds"], 0)
        self.assertEqual(
            self.broker.queued(), [("apps.provisioning.virtualmin_tasks.run_virtualmin_backup", str(job.pk))]
        )
        self.assertEqual(self._packages()[0]["timeout"], job.parameters["task_budget_seconds"])
        self.assertEqual(self.requests, [])

    def test_restore_admission_snapshots_target_and_restores_management_server(self) -> None:
        account = self._account()
        target = create_test_virtualmin_server(name="Restore target", hostname="restore-target.example.com")
        management = VirtualminBackupManagementService(self.server)
        config = RestoreConfig(backup_id="backup-coverage", restore_email=False, force_restore=True)
        job = management.create_restore_job(account, config, target_server=target, initiated_by="operator").unwrap()
        self.assertEqual(job.operation, "restore_domain")
        self.assertEqual(job.server_id, target.pk)
        self.assertEqual(job.parameters["target_server_id"], str(target.pk))
        self.assertEqual(job.parameters["backup_id"], "backup-coverage")
        self.assertFalse(job.parameters["restore_email"])
        self.assertTrue(job.parameters["force_restore"])
        self.assertEqual(job.parameters["initiated_by"], "operator")
        self.assertEqual(management.server.pk, self.server.pk)
        self.assertEqual(
            self.broker.queued(), [("apps.provisioning.virtualmin_tasks.run_virtualmin_restore", str(job.pk))]
        )
        self.assertEqual(self.requests, [])

    def test_inline_admission_refuses_testcase_transaction_without_job_or_payload(self) -> None:
        account = self._account()
        result = VirtualminBackupManagementService(self.server).create_backup_job(account, execute_inline=True)
        self.assertEqual(result.unwrap_err(), "Inline execution requires autocommit; run outside any transaction")
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.broker.queued(), [])
        self.assertEqual(self.requests, [])

    def test_insufficient_visibility_budget_refuses_job_and_enqueue(self) -> None:
        account = self._account()
        with self.settings(Q_CLUSTER={"retry": 0}):
            result = VirtualminBackupManagementService(self.server).create_backup_job(account)
        self.assertIn("does not fit under the broker visibility timeout 0s", result.unwrap_err())
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.broker.queued(), [])
        self.assertEqual(self.requests, [])

    def test_attention_job_blocks_new_backup_and_restore_admissions(self) -> None:
        account = self._account()
        existing = VirtualminProvisioningJob.objects.create(
            account=account, server=self.server, operation="restore_domain", status="attention"
        )
        management = VirtualminBackupManagementService(self.server)
        backup = management.create_backup_job(account)
        restore = management.create_restore_job(account, RestoreConfig(backup_id="previous-backup"))
        expected = "Account already has an active migration or backup/restore operation"
        self.assertEqual(backup.unwrap_err(), expected)
        self.assertEqual(restore.unwrap_err(), expected)
        self.assertEqual(list(VirtualminProvisioningJob.objects.values_list("pk", flat=True)), [existing.pk])
        self.assertEqual(self.broker.queued(), [])
        self.assertEqual(self.requests, [])
