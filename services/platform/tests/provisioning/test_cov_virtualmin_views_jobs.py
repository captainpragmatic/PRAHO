"""Coverage additions for job status, JSON logs and operator resolutions."""

from __future__ import annotations

from datetime import timedelta
from uuid import uuid4

from django.urls import reverse
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.provisioning.virtualmin_migration_models import VirtualminMigration, account_has_active_migration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class VirtualminJobCoverageTests(VirtualminViewsFixture):
    def job(self, status: str = "pending") -> VirtualminProvisioningJob:
        return VirtualminProvisioningJob.objects.create(
            account=self.account,
            server=self.server,
            operation="backup_domain",
            status=status,
            correlation_id="coverage-job",
        )

    def migration(self, status: str = "needs_review") -> VirtualminMigration:
        target = VirtualminServer.objects.create(name="Migration target", hostname="target.example.com")
        return VirtualminMigration.objects.create(
            account=self.account,
            source_server=self.server,
            target_server=target,
            status=status,
            archive_name="coverage.tar.gz",
        )

    def test_job_status_offers_retry_only_for_failed_job_under_limit(self) -> None:
        job = self.job()
        for status, retries, expected in (
            ("pending", 0, False),
            ("completed", 0, False),
            ("failed", 2, True),
            ("failed", 3, False),
        ):
            with self.subTest(status=status, retries=retries):
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(status=status, retry_count=retries)
                response = self.client.get(reverse("provisioning:virtualmin_job_status", args=[job.pk]))
                self.assertContains(response, self.account.domain)
                self.assertEqual(response.context["can_retry"], expected)
                if expected:
                    self.assertContains(response, "Retry Job")
                else:
                    self.assertNotContains(response, "Retry Job")

    def test_pending_job_logs_contain_only_creation_event(self) -> None:
        job = self.job()
        response = self.client.get(reverse("provisioning:virtualmin_job_logs", args=[job.pk]), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(
            response.json()["logs"],
            [
                {
                    "timestamp": job.created_at.isoformat(),
                    "level": "INFO",
                    "message": f"Job created: backup_domain for {self.account.domain}",
                }
            ],
        )

    def test_terminal_job_logs_include_timestamps_outcome_and_result(self) -> None:
        job = self.job()
        started = timezone.now() - timedelta(minutes=1)
        completed = timezone.now()
        for status, level in (("completed", "SUCCESS"), ("failed", "ERROR")):
            with self.subTest(status=status):
                VirtualminProvisioningJob.objects.filter(pk=job.pk).update(
                    status=status,
                    started_at=started,
                    completed_at=completed,
                    status_message="Remote outcome",
                    result={"backup_id": "bk-42"},
                )
                response = self.client.get(
                    reverse("provisioning:virtualmin_job_logs", args=[job.pk]), HTTP_HX_REQUEST="true"
                )
                self.assertEqual(response.status_code, 200)
                logs = response.json()["logs"]
                self.assertEqual([entry["level"] for entry in logs], ["INFO", "INFO", level, "DEBUG"])
                self.assertEqual(logs[1]["message"], "Job started")
                self.assertEqual(logs[1]["timestamp"], started.isoformat())
                self.assertEqual(logs[2]["message"], f"Job {status}: Remote outcome")
                self.assertEqual(logs[2]["timestamp"], completed.isoformat())
                self.assertIn("bk-42", logs[3]["message"])

    def test_logs_support_job_without_account_and_in_progress_result(self) -> None:
        job = self.job("running")
        job.account = None
        job.result = {"phase": "uploading"}
        job.save()
        response = self.client.get(reverse("provisioning:virtualmin_job_logs", args=[job.pk]), HTTP_HX_REQUEST="true")
        self.assertEqual(response.status_code, 200)
        logs = response.json()["logs"]
        self.assertEqual(logs[0]["message"], "Job created: backup_domain for unknown")
        self.assertEqual(logs[1]["level"], "DEBUG")
        self.assertEqual(logs[1]["timestamp"], job.updated_at.isoformat())
        self.assertIn("uploading", logs[1]["message"])

    def test_resolve_attention_job_persists_actor_note_and_audit_event(self) -> None:
        job = self.job("attention")
        job.next_retry_at = timezone.now()
        job.save(update_fields=["next_retry_at"])
        response = self.client.post(
            reverse("provisioning:virtualmin_job_resolve", args=[job.pk]), {"note": "  Remote state repaired  "}
        )
        self.assertRedirects(
            response, reverse("provisioning:virtualmin_job_status", args=[job.pk]), fetch_redirect_response=False
        )
        job.refresh_from_db()
        self.assertEqual(job.status, "failed")
        self.assertIsNone(job.next_retry_at)
        self.assertEqual(job.status_message, f"Manually resolved by {self.admin.email}: Remote state repaired")
        event = AuditEvent.objects.get(
            object_id=str(job.pk), action="virtualmin_provisioning_job_failed", actor_type="user"
        )
        self.assertEqual(event.user_id, self.admin.pk)
        self.assertEqual(event.new_values["status"], "failed")
        self.assertEqual(event.new_values["status_message"], job.status_message)
        self.assertIn("account is unlocked", self.messages(response))

    def test_resolve_uses_default_note_and_refuses_a_second_resolution(self) -> None:
        job = self.job("attention")
        url = reverse("provisioning:virtualmin_job_resolve", args=[job.pk])
        response = self.client.post(url, {"note": " "})
        self.assertEqual(response.status_code, 302)
        job.refresh_from_db()
        self.assertIn("operator confirmed remote state", job.status_message)
        original = job.status_message
        response = self.client.post(url, {"note": "replacement"})
        self.assertEqual(response.status_code, 302)
        job.refresh_from_db()
        self.assertEqual(job.status_message, original)
        self.assertIn("Only a job awaiting attention", self.messages(response))

    def test_missing_jobs_return_404_without_log_payload(self) -> None:
        for name, method in (
            ("virtualmin_job_status", "get"),
            ("virtualmin_job_logs", "get"),
            ("virtualmin_job_resolve", "post"),
        ):
            with self.subTest(name=name):
                response = getattr(self.client, method)(
                    reverse(f"provisioning:{name}", args=[uuid4()]), HTTP_HX_REQUEST="true"
                )
                self.assertEqual(response.status_code, 404)
                self.assertNotIn(b'"logs"', response.content)

    def test_migration_form_rejects_source_as_target(self) -> None:
        url = reverse("provisioning:virtualmin_account_migrate", args=[self.account.pk])
        self.assertContains(self.client.get(url), 'name="target_server"')
        response = self.client.post(url, {"target_server": str(self.server.pk), "confirm": "on"})
        self.assertContains(response, "Select a valid choice")
        self.assertIn("target_server", response.context["form"].errors)
        self.assertFalse(VirtualminMigration.objects.filter(account=self.account).exists())

    def test_migration_resolution_rejects_stale_or_malformed_identity(self) -> None:
        migration = self.migration()
        url = reverse("provisioning:virtualmin_migration_resolve", args=[self.account.pk])
        for identity in ("bad-uuid", str(uuid4()), ""):
            with self.subTest(identity=identity):
                response = self.client.post(url, {"migration_id": identity})
                self.assertRedirects(
                    response,
                    reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
                    fetch_redirect_response=False,
                )
                migration.refresh_from_db()
                self.assertEqual(migration.status, "needs_review")
                self.assertIn("no longer awaiting review", self.messages(response))

    def test_migration_resolution_releases_lock_and_records_operator(self) -> None:
        migration = self.migration()
        response = self.client.post(
            reverse("provisioning:virtualmin_migration_resolve", args=[self.account.pk]),
            {"migration_id": str(migration.pk), "note": "Source restored"},
        )
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
            fetch_redirect_response=False,
        )
        migration.refresh_from_db()
        self.assertEqual(migration.status, "failed")
        self.assertFalse(account_has_active_migration(self.account))
        self.assertEqual(VirtualminMigration.active_reservations(migration.target_server), 0)
        self.assertIn(self.admin.email, migration.error_detail)
        self.assertIn("Source restored", migration.error_detail)
        self.assertIn("account is unlocked", self.messages(response))
