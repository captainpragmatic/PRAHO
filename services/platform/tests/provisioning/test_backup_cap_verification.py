"""Virtualmin lifts both kernel caps for a backup or restore and restores them only on a clean exit (ADR-0075).

After every finished PRAHO backup or restore job of a managed account, the dispatcher marks the account's cap proof
stale, so the existing managed-limits path probes the node and applies the caps again.
"""

from datetime import timedelta
from unittest.mock import patch

from django.utils import timezone

from apps.provisioning.hosting_limit_execution import apply_hosting_limits
from apps.provisioning.hosting_limit_models import ServiceHostingLimits
from apps.provisioning.hosting_limit_tasks import dispatch_hosting_limits
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.provisioning.test_hosting_limit_execution import HostingLimitWorkerFixture
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class BackupCapVerificationTests(HostingLimitWorkerFixture, VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.setup_native_fixture()
        self.native_calls = []
        self.assertEqual(self.apply(self.receipt()), "completed")
        self.account.refresh_from_db()
        self.assertTrue(self.account.quota_managed)
        self.account.status = "active"  # The dispatcher only schedules active or suspended accounts.
        self.account.save(update_fields=["status", "updated_at"])

    def apply(self, probe):
        def native(server, action, request):
            self.native_calls.append(action)
            return {**self.receipt(cap=request["disk_limit_kib"] // 1024, request=request), **self.receipt_extra}

        self.receipt_extra = getattr(self, "receipt_extra", {})
        with (
            patch("apps.provisioning.hosting_limit_transport.probe_account_quota", return_value=probe),
            patch("apps.provisioning.hosting_limit_transport.run_quota_operation", side_effect=native),
        ):
            return apply_hosting_limits(self.current_application_id())

    def current_application_id(self):
        from apps.provisioning.hosting_limit_tasks import current_application  # noqa: PLC0415

        return current_application(self.service.pk).pk

    def finished(self, operation="backup_domain", status="completed", *, after=True):
        job = VirtualminProvisioningJob.objects.create(
            operation=operation,
            account=self.account,
            server=self.server,
            status=status,
            correlation_id=f"{operation}-{status}-{timezone.now().timestamp()}",
        )
        if not after:
            verified = ServiceHostingLimits.objects.get(service=self.service).verified_at
            VirtualminProvisioningJob.objects.filter(pk=job.pk).update(updated_at=verified - timedelta(minutes=1))
        return job

    def dispatch(self):
        with patch("apps.provisioning.hosting_limit_tasks.async_task") as broker:
            queued = dispatch_hosting_limits()["queued"]
        return queued, broker

    def verified_at(self):
        return ServiceHostingLimits.objects.get(service=self.service).verified_at

    def test_a_finished_backup_or_restore_makes_the_caps_be_applied_again(self):
        for operation, status in (
            ("backup_domain", "completed"),
            ("backup_domain", "failed"),
            ("restore_domain", "completed"),
            ("restore_domain", "failed"),
        ):
            with self.subTest(operation=operation, status=status):
                self.finished(operation, status)
                queued, broker = self.dispatch()
                self.assertEqual(queued, 1)
                self.assertIsNone(self.verified_at())
                broker.assert_called_once()
                # Lifted caps on the node: the re-apply really reaches it and verifies its receipt again.
                lifted = {**self.receipt(), "uid_hard_kib": 0, "gid_hard_kib": 0, "uid_soft_kib": 0, "gid_soft_kib": 0}
                self.native_calls.clear()
                self.assertEqual(self.apply(lifted), "completed")
                self.assertEqual(self.native_calls, ["apply"])
                self.assertIsNotNone(self.verified_at())

    def test_once_verified_after_the_job_nothing_is_applied_again(self):
        self.finished()
        self.dispatch()
        self.assertEqual(self.apply(self.receipt()), "completed")
        queued, _broker = self.dispatch()
        self.assertEqual(queued, 0)

    def test_a_job_that_finished_before_the_last_verification_changes_nothing(self):
        self.finished(after=False)
        queued, _broker = self.dispatch()
        self.assertEqual(queued, 0)
        self.assertIsNotNone(self.verified_at())

    def test_running_or_held_jobs_are_left_to_their_own_resolution(self):
        for status in ("pending", "running", "attention"):
            job = self.finished(status=status)
            with self.subTest(status=status):
                self.dispatch()
                self.assertIsNotNone(self.verified_at())
            job.delete()

    def test_other_operations_do_not_count(self):
        self.finished(operation="suspend_domain")
        self.dispatch()
        self.assertIsNotNone(self.verified_at())

    def test_an_account_that_is_not_quota_managed_is_never_adopted_this_way(self):
        self.account.quota_managed = False
        self.account.save(update_fields=["quota_managed", "updated_at"])
        self.finished()
        self.dispatch()
        self.assertIsNotNone(self.verified_at())

    def test_a_leftover_backup_dump_is_reported_on_the_verification(self):
        self.finished()
        self.dispatch()
        self.receipt_extra = {"backup_staging_left": True}
        self.assertEqual(self.apply(self.receipt()), "completed")
        latest = VirtualminProvisioningJob.objects.filter(
            account=self.account, operation="apply_hosting_limits"
        ).latest("created_at")
        self.assertIn("~/.backup", latest.status_message)

    def test_a_receipt_from_an_older_helper_without_the_field_still_verifies(self):
        self.finished()
        self.dispatch()
        self.assertEqual(self.apply(self.receipt()), "completed")
        latest = VirtualminProvisioningJob.objects.filter(
            account=self.account, operation="apply_hosting_limits"
        ).latest("created_at")
        self.assertNotIn("~/.backup", latest.status_message)
