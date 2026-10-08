"""Coverage additions for Virtualmin lifecycle failures, idempotency and deletion."""

from __future__ import annotations

from apps.common.types import Retriability, retriability_of
from apps.provisioning.security_utils import IdempotencyManager
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.provisioning.test_cov_provisioning_services_creation import VirtualminServiceCoverageCase


class VirtualminLifecycleCoverageTests(VirtualminServiceCoverageCase):
    def test_suspend_then_unsuspend_persists_state_messages_and_job_budgets(self) -> None:
        account = self._account()
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        account.refresh_from_db()
        self.assertEqual(account.status, "suspended")
        self.assertEqual(account.status_message, "billing hold")
        suspend = VirtualminProvisioningJob.objects.get(operation="suspend_domain", account=account)
        self.assertEqual(suspend.status, "completed")
        self.assertEqual(
            suspend.parameters, {"domain": account.domain, "reason": "billing hold", "task_budget_seconds": 777}
        )
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(account.status_message, "")
        unsuspend = VirtualminProvisioningJob.objects.get(operation="unsuspend_domain", account=account)
        self.assertEqual(unsuspend.status, "completed")
        self.assertEqual(unsuspend.parameters["task_budget_seconds"], 777)
        self.assertEqual(self._programs(), ["disable-domain", "enable-domain"])

    def test_application_rejections_preserve_state_and_release_idempotency(self) -> None:
        for status, operation, program in (
            ("active", "suspend_account", "disable-domain"),
            ("suspended", "unsuspend_account", "enable-domain"),
            ("error", "delete_account", "delete-domain"),
        ):
            with self.subTest(operation=operation):
                account = self._account(status)
                self.rejections[program] = "permission denied"
                result = getattr(self.provisioning, operation)(account)
                self.assertEqual(result.unwrap_err(), "permission denied")
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
                account.refresh_from_db()
                self.assertEqual(account.status, status)
                job = VirtualminProvisioningJob.objects.get(account=account)
                self.assertEqual(job.status, "failed")
                self.assertEqual(job.status_message, "permission denied")
                self.assertIsNone(job.next_retry_at)
                del self.rejections[program]
                recovered = getattr(self.provisioning, operation)(account)
                self.assertIs(recovered.unwrap(), True)
                account.refresh_from_db()
                self.assertEqual(
                    account.status, {"active": "suspended", "suspended": "active", "error": "terminated"}[status]
                )
                self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account).count(), 2)
                account.delete()

    def test_delete_retains_terminated_account_and_decrements_counter_exactly_once(self) -> None:
        account = self._account("error")
        self.assertIs(self.provisioning.delete_account(account).unwrap(), True)
        self.assertIs(self.provisioning.delete_account(account).unwrap(), True)
        account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(account.status, "terminated")
        self.assertEqual(self.server.current_domains, 2)
        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account).count(), 1)
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "completed")
        self.assertEqual(self.requests, [{"program": "delete-domain", "domain": account.domain, "json": "1"}])

    def test_delete_at_zero_capacity_does_not_underflow_counter(self) -> None:
        self.server.current_domains = 0
        self.server.save(update_fields=["current_domains"])
        account = self._account("error")
        self.assertIs(self.provisioning.delete_account(account).unwrap(), True)
        account.refresh_from_db()
        self.server.refresh_from_db()
        self.assertEqual(account.status, "terminated")
        self.assertEqual(self.server.current_domains, 0)
        self.assertEqual(VirtualminProvisioningJob.objects.get(account=account).status, "completed")

    def test_delete_refuses_protected_and_active_accounts_without_jobs(self) -> None:
        account = self._account("error")
        account.protected_from_deletion = True
        account.save(update_fields=["protected_from_deletion"])
        result = self.provisioning.delete_account(account)
        self.assertIn("protected from deletion", result.unwrap_err())
        account.protected_from_deletion = False
        account.status = "active"
        account.save(update_fields=["protected_from_deletion", "status"])
        result = self.provisioning.delete_account(account)
        self.assertIn("must be terminated or in error state", result.unwrap_err())
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_delete_in_progress_refuses_duplicate_remote_mutation(self) -> None:
        account = self._account("error")
        key = IdempotencyManager.generate_key(str(account.pk), "delete_account", {"domain": account.domain})
        self.assertTrue(IdempotencyManager.check_and_set(key)[0])
        self.assertEqual(self.provisioning.delete_account(account).unwrap_err(), "Operation already in progress")
        account.refresh_from_db()
        self.assertEqual(account.status, "error")
        self.assertFalse(VirtualminProvisioningJob.objects.exists())
        self.assertEqual(self.requests, [])

    def test_suspend_flip_flop_clears_stale_success_and_reapplies_current_intent(self) -> None:
        account = self._account()
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        account.refresh_from_db()
        self.assertEqual(account.status, "suspended")
        self.assertEqual(account.status_message, "billing hold")
        self.assertEqual(self._programs(), ["disable-domain", "enable-domain", "disable-domain"])
        self.assertEqual(
            list(VirtualminProvisioningJob.objects.filter(account=account).values_list("status", flat=True)),
            ["completed", "completed", "completed"],
        )

    def test_unsuspend_flip_flop_clears_stale_success_and_reapplies_current_intent(self) -> None:
        account = self._account("suspended")
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)
        account.refresh_from_db()
        self.assertEqual(account.status, "active")
        self.assertEqual(account.status_message, "")
        self.assertEqual(self._programs(), ["enable-domain", "disable-domain", "enable-domain"])
        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account, status="completed").count(), 3)

    def test_gateway_refusals_persist_failed_jobs_without_remote_mutations(self) -> None:
        self.server.status = "maintenance"
        self.server.save(update_fields=["status"])
        for status, operation in (
            ("active", "suspend_account"),
            ("suspended", "unsuspend_account"),
            ("error", "delete_account"),
        ):
            with self.subTest(operation=operation):
                account = self._account(status)
                result = getattr(self.provisioning, operation)(account)
                self.assertIn("not active", result.unwrap_err())
                self.assertEqual(retriability_of(result), Retriability.NOT_RETRIABLE)
                account.refresh_from_db()
                self.assertEqual(account.status, status)
                job = VirtualminProvisioningJob.objects.get(account=account)
                self.assertEqual(job.status, "failed")
                self.assertIn("not active", job.status_message)
                self.assertEqual(self.requests, [])
                account.delete()

    def test_cached_suspend_success_refreshes_stale_account_from_persisted_state(self) -> None:
        account = self._account()
        stale = account.__class__.objects.get(pk=account.pk)
        self.assertIs(self.provisioning.suspend_account(account, "billing hold").unwrap(), True)
        self.assertEqual(stale.status, "active")
        self.assertIs(self.provisioning.suspend_account(stale, "billing hold").unwrap(), True)
        self.assertEqual(stale.status, "suspended")
        self.assertEqual(self._programs(), ["disable-domain"])
        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account).count(), 1)

    def test_cached_unsuspend_success_refreshes_stale_account_from_persisted_state(self) -> None:
        account = self._account("suspended")
        stale = account.__class__.objects.get(pk=account.pk)
        self.assertIs(self.provisioning.unsuspend_account(account).unwrap(), True)
        self.assertEqual(stale.status, "suspended")
        self.assertIs(self.provisioning.unsuspend_account(stale).unwrap(), True)
        self.assertEqual(stale.status, "active")
        self.assertEqual(self._programs(), ["enable-domain"])
        self.assertEqual(VirtualminProvisioningJob.objects.filter(account=account).count(), 1)
