"""Coverage additions for Virtualmin properties consumed by production pages."""

from __future__ import annotations

from datetime import timedelta
from decimal import Decimal

from django.urls import reverse
from django.utils import timezone

from apps.common.encryption import DecryptionError
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class ProvisioningSupportModelTests(VirtualminViewsFixture):
    def test_server_health_requires_recent_success_without_a_live_error(self) -> None:
        self.server.last_health_check = timezone.now()
        self.assertTrue(self.server.is_healthy)
        self.server.health_check_error = "Remote authentication refused"
        self.assertFalse(self.server.is_healthy)
        self.server.health_check_error = ""
        self.server.last_health_check = timezone.now() - timedelta(hours=1)
        self.assertFalse(self.server.is_healthy)
        self.server.last_health_check = None
        self.assertFalse(self.server.is_healthy)
        self.server.last_health_check = timezone.now()
        self.assertTrue(self.server.is_healthy)
        self.server.status = "maintenance"
        self.assertFalse(self.server.is_healthy)

    def test_server_capacity_handles_zero_limit_and_reports_used_percentage(self) -> None:
        self.server.max_domains = 0
        self.assertEqual(self.server.capacity_percentage, 0.0)
        self.server.max_domains = 20
        self.server.current_domains = 5
        self.assertEqual(self.server.capacity_percentage, 25.0)

    def test_credentials_decrypt_memoryviews_and_server_corruption_is_not_silent(self) -> None:
        self.server.encrypted_api_password = memoryview(bytes(self.server.encrypted_api_password))
        self.account.encrypted_password = memoryview(bytes(self.account.encrypted_password))
        self.assertEqual(self.server.get_api_password(), "test_password")
        self.assertEqual(self.account.get_password(), "account_password")
        self.server.encrypted_api_password = b"invalid-ciphertext"
        with self.assertRaises(DecryptionError):
            self.server.get_api_password()

    def test_account_detail_renders_suspension_plan_and_unlimited_bandwidth(self) -> None:
        self.account.status = "suspended"
        self.account.current_disk_usage_mb = 5
        self.account.disk_quota_mb = 10
        self.account.current_bandwidth_usage_mb = 7
        self.account.bandwidth_quota_mb = -1
        self.account.save(
            update_fields=[
                "status",
                "current_disk_usage_mb",
                "disk_quota_mb",
                "current_bandwidth_usage_mb",
                "bandwidth_quota_mb",
            ]
        )
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertContains(response, "Suspended")
        self.assertContains(response, self.plan.name)
        self.assertContains(response, "Unlimited")
        self.assertContains(response, "5.0\u00a0MB")
        self.assertEqual(self.account.disk_usage, 5 * 1024 * 1024)
        self.assertEqual(self.account.disk_quota, 10 * 1024 * 1024)
        self.assertEqual(self.account.bandwidth_usage, 7 * 1024 * 1024)
        self.assertEqual(self.account.bandwidth_quota, -1)
        self.assertFalse(response.context["can_backup"])

    def test_account_detail_reports_finite_bandwidth_and_unknown_disk_quota(self) -> None:
        self.account.bandwidth_quota_mb = 20
        self.account.disk_quota_mb = None
        self.account.save(update_fields=["bandwidth_quota_mb", "disk_quota_mb"])
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertContains(response, self.account.domain)
        self.assertEqual(self.account.bandwidth_quota, 20 * 1024 * 1024)
        self.assertIsNone(self.account.disk_quota)
        self.assertEqual(self.account.disk_usage, 0)
        self.assertEqual(self.account.bandwidth_usage, 0)
        self.assertTrue(response.context["can_backup"])

    def test_job_completion_persists_result_duration_and_rollback_without_overwriting_it(self) -> None:
        rollback: list[dict[str, object]] = [{"program": "delete-domain", "domain": self.account.domain}]
        job = VirtualminProvisioningJob.objects.create(
            server=self.server,
            account=self.account,
            operation="create_domain",
            correlation_id="support-completion",
            started_at=timezone.now() - timedelta(seconds=2),
        )
        job.mark_completed({"domain": self.account.domain}, rollback)
        saved = VirtualminProvisioningJob.objects.get(pk=job.pk)
        self.assertEqual(saved.status, "completed")
        self.assertEqual(saved.result, {"domain": self.account.domain, "rollback_operations": rollback})
        self.assertIsNotNone(saved.completed_at)
        self.assertGreaterEqual(saved.execution_time_seconds, Decimal("2"))
        existing = [{"program": "disable-domain"}]
        job.mark_completed({"rollback_operations": existing}, rollback)
        self.assertEqual(VirtualminProvisioningJob.objects.get(pk=job.pk).result["rollback_operations"], existing)
