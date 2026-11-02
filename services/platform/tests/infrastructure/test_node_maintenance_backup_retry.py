"""Failed archive jobs have no public retry writer that can cross maintenance."""

from collections.abc import Callable
from typing import Any

from django.contrib.messages import get_messages
from django.test import TestCase, override_settings
from django.urls import reverse

from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_node_capability import destination_refusal
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService, VirtualminProvisioningService
from apps.provisioning.virtualmin_tasks import run_virtualmin_backup, run_virtualmin_restore
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@override_settings(
    Q_CLUSTER={"name": "maintenance-backup-retry", "orm": "default", "retry": 100000},
    VIRTUALMIN_IMPORTED_SSH_PRIVATE_KEY_PATH="",
)
class NodeMaintenanceBackupRetryTests(MaintenanceAdmissionFixture, TestCase):
    def test_failed_backup_redelivery_and_staff_retry_cannot_revive_it_during_maintenance(self) -> None:
        admitted = VirtualminBackupManagementService(self.node).create_backup_job(self.account)
        self.assertTrue(admitted.is_ok(), admitted)
        job = admitted.unwrap()

        failed = run_virtualmin_backup(str(job.pk))

        self.assertEqual(failed["status"], "failed", failed)
        self.assertIn("private root SSH key", failed["error"])
        self._assert_failed_job_stays_terminal(job, run_virtualmin_backup)

    def test_failed_restore_redelivery_and_staff_retry_cannot_revive_it_during_maintenance(self) -> None:
        # This existing unmanaged node uses the explicit legacy admission policy;
        # no generated-node verification is asserted by the retry fixture.
        self.assertIsNone(getattr(self.node, "node_deployment", None))
        self.node.legacy_security_admission = True
        self.node.save(update_fields=["legacy_security_admission"])
        self.assertIsNone(destination_refusal(self.node))
        admitted = VirtualminBackupManagementService(self.node).create_restore_job(
            self.account, RestoreConfig(backup_id="missing-fixture-backup", restore_email=False)
        )
        self.assertTrue(admitted.is_ok(), admitted)
        job = admitted.unwrap()

        failed = run_virtualmin_restore(str(job.pk))

        self.assertEqual(failed["status"], "failed", failed)
        self.assertIn("Component-selective restore", failed["error"])
        self._assert_failed_job_stays_terminal(job, run_virtualmin_restore)

    def _assert_failed_job_stays_terminal(
        self, job: VirtualminProvisioningJob, worker: Callable[[str], dict[str, Any]]
    ) -> None:
        job.refresh_from_db()
        before = (job.status, job.execution_token, job.next_retry_at, job.retry_count, job.parameters)
        self.assertEqual(job.status, "failed")
        self.start(self.window())
        self.client.force_login(self.actor)

        with self.captureOnCommitCallbacks(execute=True) as callbacks:
            response = self.client.post(reverse("provisioning:virtualmin_job_retry", args=[job.pk]))

        self.assertEqual(response.status_code, 302)
        self.assertEqual(
            [str(message) for message in get_messages(response.wsgi_request)], ["This job cannot be retried."]
        )
        self.assertEqual(callbacks, [])
        retry = VirtualminProvisioningService(self.node).retry_job(job)
        self.assertTrue(retry.is_err(), retry)
        self.assertIn("Unsupported retry operation", retry.unwrap_err())
        self.assertEqual(worker(str(job.pk)), {"status": "stale", "job_id": str(job.pk)})
        job.refresh_from_db()
        self.assertEqual((job.status, job.execution_token, job.next_retry_at, job.retry_count, job.parameters), before)
