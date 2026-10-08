"""Recovery must respect each running job's persisted execution budget."""

from __future__ import annotations

from datetime import timedelta

from django.utils import timezone

from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from apps.provisioning.virtualmin_tasks import _recover_expired_claims
from tests.provisioning.test_virtualmin_tasks import VirtualminTaskTestBase


class VirtualminRecoveryBudgetTests(VirtualminTaskTestBase):
    def setUp(self) -> None:
        super().setUp()
        self.now = timezone.now()

    def running_job(
        self, age_seconds: int, budget: int | None, *, claimed_age_seconds: int | None = None
    ) -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="create_domain",
            status="running",
            started_at=self.now - timedelta(seconds=age_seconds),
            claimed_at=(None if claimed_age_seconds is None else self.now - timedelta(seconds=claimed_age_seconds)),
            parameters={} if budget is None else {"task_budget_seconds": budget},
        )

    def test_long_running_budget_preserves_execution_and_separate_pending_lease(self) -> None:
        initial = self.running_job(1860, 7200)
        retry = self.running_job(1860, 7200, claimed_age_seconds=8000)
        legacy_expired = self.running_job(1860, None)
        legacy_live = self.running_job(1799, None)
        pending_expired = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="create_domain",
            status="pending",
            claimed_at=self.now - timedelta(minutes=31),
            parameters={"task_budget_seconds": 7200},
        )
        pending_live = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="create_domain",
            status="pending",
            claimed_at=self.now - timedelta(minutes=29),
            parameters={"task_budget_seconds": 60},
        )
        for operation in ("backup_domain", "restore_domain"):
            VirtualminProvisioningJob.objects.create(
                server=self.server,
                account=self.account,
                operation=operation,
                status="running",
                started_at=self.now - timedelta(hours=3),
                parameters={"task_budget_seconds": 60},
            )

        recovered = _recover_expired_claims(self.now)

        for job in (initial, retry):
            job.refresh_from_db()
            self.assertEqual(job.status, "running")
            self.assertIsNone(job.next_retry_at)
        self.assertEqual(recovered, 2)
        for job in (legacy_expired, pending_expired):
            job.refresh_from_db()
            self.assertEqual(job.status, "failed")
            self.assertIsNone(job.claimed_at)
            self.assertEqual(job.next_retry_at, self.now + timedelta(minutes=5))
        legacy_live.refresh_from_db()
        pending_live.refresh_from_db()
        self.assertEqual(legacy_live.status, "running")
        self.assertEqual(pending_live.status, "pending")
        self.assertEqual(
            VirtualminProvisioningJob.objects.filter(
                operation__in=("backup_domain", "restore_domain"), status="running"
            ).count(),
            2,
        )

        _recover_expired_claims(self.now + timedelta(seconds=5401))
        for job in (initial, retry):
            job.refresh_from_db()
            self.assertEqual(job.status, "failed")
            self.assertIsNone(job.claimed_at)

    def test_short_running_budget_recovers_only_after_execution_margin(self) -> None:
        expired = self.running_job(181, 120)
        boundary = self.running_job(180, 120)
        live = self.running_job(179, 120)

        recovered = _recover_expired_claims(self.now)

        expired.refresh_from_db()
        self.assertEqual(expired.status, "failed")
        self.assertEqual(expired.next_retry_at, self.now + timedelta(minutes=5))
        self.assertEqual(recovered, 1)
        for job in (boundary, live):
            job.refresh_from_db()
            self.assertEqual(job.status, "running")
            self.assertIsNone(job.next_retry_at)

        self.assertEqual(_recover_expired_claims(self.now + timedelta(seconds=2)), 2)
        for job in (boundary, live):
            job.refresh_from_db()
            self.assertEqual(job.status, "failed")
