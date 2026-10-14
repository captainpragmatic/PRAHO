"""A delete whose outcome is unknown keeps the account excluded until an operator resolves it.

A timed-out or unclassifiable delete-domain may already have run on the node. Marking it
failed would release the exclusion (and arm a replay), so a backup or restore could start on
a domain that is half-deleted. Like a restore, such a delete parks in attention.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.common.types import Err, Ok, Retriability
from apps.provisioning.virtualmin_backup_service import RestoreConfig
from apps.provisioning.virtualmin_gateway import VirtualminGateway, VirtualminResponse
from apps.provisioning.virtualmin_migration_models import account_has_active_operation
from apps.provisioning.virtualmin_models import VirtualminAccount, VirtualminProvisioningJob
from apps.provisioning.virtualmin_service import VirtualminBackupManagementService
from tests.provisioning.test_cov_virtualmin_tasks_operations import force_status
from tests.provisioning.test_virtualmin_account_exclusion import ExclusionCase


def rejection(text: str) -> Ok[VirtualminResponse]:
    return Ok(
        VirtualminResponse(
            success=False,
            data={"error": text},
            raw_response="{}",
            http_status=200,
            execution_time=0.1,
            program="delete-domain",
            server_hostname="vm1.example.com",
        )
    )


class UncertainDeleteTests(ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account("error")

    def delete_with(self, gateway_result: object) -> VirtualminProvisioningJob:
        with patch.object(VirtualminGateway, "call", return_value=gateway_result):
            result = self.provisioning.delete_account(self.account)
        self.assertTrue(result.is_err(), result)
        return VirtualminProvisioningJob.objects.get(operation="delete_domain")

    def assert_account_held(self) -> None:
        self.assertTrue(account_has_active_operation(self.account))
        with patch("django_q.tasks.async_task") as enqueue:
            backup = VirtualminBackupManagementService(self.server).create_backup_job(self.account)
            restore = VirtualminBackupManagementService(self.server).create_restore_job(
                self.account, RestoreConfig(backup_id="b-1")
            )
        self.assertTrue(backup.is_err() and restore.is_err())
        enqueue.assert_not_called()

    def test_a_delete_whose_response_was_lost_parks_in_attention_and_holds_the_account(self) -> None:
        job = self.delete_with(Err("read timed out", retriability=Retriability.UNKNOWN))
        self.assertEqual(job.status, "attention")
        self.assertIsNone(job.next_retry_at)
        self.assertEqual(job.result["retriability"], "unknown")
        self.assert_account_held()

    def test_an_unclassifiable_rejection_parks_in_attention_too(self) -> None:
        job = self.delete_with(rejection("odd failure nobody documented"))
        self.assertEqual(job.status, "attention")
        self.assert_account_held()

    def test_a_definite_delete_failure_still_fails_and_releases_the_account(self) -> None:
        for gateway_result, retriability in (
            (Err("connection refused", retriability=Retriability.RETRIABLE), "retriable"),
            (Err("host rejected", retriability=Retriability.NOT_RETRIABLE), "not_retriable"),
            (rejection("domain does not exist"), "not_retriable"),
        ):
            with self.subTest(retriability=retriability):
                VirtualminProvisioningJob.objects.all().delete()
                job = self.delete_with(gateway_result)
                self.assertEqual(job.status, "failed")
                self.assertEqual(job.result["retriability"], retriability)
                self.assertFalse(account_has_active_operation(self.account))

    def test_a_lifecycle_retry_of_a_delete_parks_when_its_outcome_is_unknown(self) -> None:
        force_status(self.service, "terminated")
        retried = self._job(self.account, "delete_domain", "running")
        with patch.object(VirtualminGateway, "call", return_value=Err("timed out", retriability=Retriability.UNKNOWN)):
            result = self.provisioning.retry_job(retried)
        self.assertTrue(result.is_err())
        retried.refresh_from_db()
        self.assertEqual(retried.status, "attention")
        self.assert_account_held()

    def test_other_lifecycle_retries_keep_failing_on_unknown(self) -> None:
        # Only a delete is excluded from backups and restores; a suspend retry replays as before.
        VirtualminAccount.objects.filter(pk=self.account.pk).update(status="active")
        self.account.refresh_from_db()
        retried = self._job(self.account, "suspend_domain", "running")
        force_status(self.service, "suspended")
        with patch.object(VirtualminGateway, "call", return_value=Err("timed out", retriability=Retriability.UNKNOWN)):
            self.provisioning.retry_job(retried)
        retried.refresh_from_db()
        self.assertEqual(retried.status, "failed")


class ReclaimedDeleteTests(ExclusionCase):
    def setUp(self) -> None:
        super().setUp()
        self.account = self._account("error")

    def reclaim(self, job: VirtualminProvisioningJob) -> VirtualminProvisioningJob:
        recovered = VirtualminProvisioningJob.recover_expired_claims(
            timezone.now() - timedelta(minutes=30), timezone.now() + timedelta(minutes=5)
        )
        self.assertEqual(recovered, 1)
        job.refresh_from_db()
        return job

    def expired(self, operation: str, status: str) -> VirtualminProvisioningJob:
        job = self._job(self.account, operation, status)
        started = timezone.now() - timedelta(hours=3)
        VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
            started_at=started, claimed_at=started, updated_at=started
        )
        job.refresh_from_db()
        return job

    def test_a_dead_delete_worker_is_parked_not_failed_and_replayed(self) -> None:
        job = self.reclaim(self.expired("delete_domain", "running"))
        self.assertEqual(job.status, "attention")
        self.assertIsNone(job.next_retry_at)
        self.assertTrue(account_has_active_operation(self.account))

    def test_a_delete_that_never_started_is_still_returned_to_the_retry_pool(self) -> None:
        job = self.reclaim(self.expired("delete_domain", "pending"))
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)

    def test_other_dead_lifecycle_workers_still_fail_into_the_retry_pool(self) -> None:
        job = self.reclaim(self.expired("suspend_domain", "running"))
        self.assertEqual(job.status, "failed")
        self.assertIsNotNone(job.next_retry_at)
