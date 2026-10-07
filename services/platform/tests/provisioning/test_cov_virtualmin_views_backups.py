"""Coverage additions for backup and restore forms with S3 mocked at boto3."""

from __future__ import annotations

import json
from datetime import timedelta
from io import BytesIO
from unittest.mock import MagicMock, patch

from django.urls import reverse
from django.utils import timezone

from apps.provisioning.virtualmin_migration_models import VirtualminMigration
from apps.provisioning.virtualmin_models import VirtualminProvisioningJob, VirtualminServer
from apps.settings.services import SettingsService
from tests.provisioning.test_cov_virtualmin_views_servers import VirtualminViewsFixture


class VirtualminBackupPageCoverageTests(VirtualminViewsFixture):
    def setUp(self) -> None:
        super().setUp()
        result = SettingsService.update_setting("backup.s3_bucket_name", "coverage-backups")
        self.assertTrue(result.is_ok(), result)
        self.metadata: list[dict[str, object]] = []
        self.s3 = MagicMock()
        self.s3.get_paginator.return_value.paginate.side_effect = self.pages
        self.s3.get_object.side_effect = self.metadata_object
        transport = patch("apps.provisioning.virtualmin_backup_service.boto3.client", return_value=self.s3)
        transport.start()
        self.addCleanup(transport.stop)

    def pages(self, **kwargs: object) -> list[dict[str, object]]:
        return [{"Contents": [{"Key": f"virtualmin-backups/{index}.json"} for index in range(len(self.metadata))]}]

    def metadata_object(self, **kwargs: object) -> dict[str, BytesIO]:
        key = str(kwargs["Key"])
        index = int(key.rsplit("/", 1)[1].removesuffix(".json"))
        return {"Body": BytesIO(json.dumps(self.metadata[index]).encode())}

    def add_backup(self, *, service_id: str | None = None) -> None:
        self.metadata.append(
            {
                "backup_id": f"bk-{len(self.metadata)}",
                "domain": self.account.domain,
                "praho_service_id": service_id or str(self.service.pk),
                "backup_type": "full",
                "created_at": (timezone.now() - timedelta(minutes=1)).isoformat(),
                "status": "completed",
                "size_mb": 12,
                "include_email": True,
                "include_databases": True,
                "include_files": True,
                "include_ssl": True,
            }
        )

    def test_account_detail_lists_own_backups_and_usage(self) -> None:
        self.add_backup()
        self.add_backup(service_id="another-service")
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertContains(response, self.account.domain)
        self.assertEqual([row["backup_id"] for row in response.context["recent_backups"]], ["bk-0"])
        self.assertTrue(response.context["can_backup"])
        self.assertTrue(response.context["can_restore"])
        self.assertEqual(response.context["account_stats"]["disk_quota_mb"], self.account.disk_quota_mb)

    def test_account_detail_survives_s3_failure(self) -> None:
        self.s3.get_paginator.side_effect = RuntimeError("S3 unavailable")
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertContains(response, self.account.domain)
        self.assertEqual(response.context["recent_backups"], [])
        self.assertFalse(response.context["can_restore"])

    def test_backup_get_renders_options_without_creating_job(self) -> None:
        response = self.client.get(reverse("provisioning:virtualmin_account_backup", args=[self.account.pk]))
        self.assertContains(response, 'name="include_email"')
        self.assertContains(response, 'name="include_ssl"')
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_invalid_backup_post_does_not_enqueue(self) -> None:
        response = self.client.post(
            reverse("provisioning:virtualmin_account_backup", args=[self.account.pk]),
            {"backup_type": "full"},
        )
        self.assertContains(response, "At least one feature must be included")
        self.assertTrue(response.context["form"].non_field_errors())
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_backup_admission_refusal_is_rendered_without_a_second_job(self) -> None:
        existing = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="backup_domain", status="running"
        )
        response = self.client.post(
            reverse("provisioning:virtualmin_account_backup", args=[self.account.pk]),
            {"backup_type": "full", "include_files": "on"},
        )
        self.assertContains(response, "Failed to create backup")
        self.assertIn("active migration or backup/restore", self.messages(response))
        self.assertEqual(list(VirtualminProvisioningJob.objects.values_list("pk", flat=True)), [existing.pk])

    def test_restore_without_own_backups_redirects_with_reason(self) -> None:
        self.add_backup(service_id="another-service")
        response = self.client.get(reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]))
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
            fetch_redirect_response=False,
        )
        self.assertIn("No backups available", self.messages(response))
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_restore_s3_failure_redirects_without_a_job(self) -> None:
        self.s3.get_paginator.side_effect = RuntimeError("S3 unavailable")
        response = self.client.get(reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]))
        self.assertRedirects(
            response,
            reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]),
            fetch_redirect_response=False,
        )
        self.assertIn("No backups available", self.messages(response))
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_restore_form_offers_only_own_backups_and_all_options(self) -> None:
        self.add_backup()
        self.add_backup(service_id="another-service")
        response = self.client.get(reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]))
        self.assertContains(response, 'value="bk-0"')
        self.assertNotContains(response, 'value="bk-1"')
        for field in ("restore_email", "restore_databases", "restore_files", "restore_ssl"):
            self.assertContains(response, f'name="{field}"')
        self.assertEqual([row["backup_id"] for row in response.context["available_backups"]], ["bk-0"])

    def test_restore_rejects_unknown_backup_and_missing_confirmation(self) -> None:
        self.add_backup()
        for data, error_field in (
            ({"backup_id": "bk-0", "restore_files": "on"}, "confirm_restore"),
            ({"backup_id": "foreign-backup", "restore_files": "on", "confirm_restore": "on"}, "backup_id"),
        ):
            with self.subTest(error_field=error_field):
                response = self.client.post(
                    reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]), data
                )
                self.assertContains(response, 'name="backup_id"')
                self.assertIn(error_field, response.context["form"].errors)
                self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_restore_rejects_empty_feature_selection(self) -> None:
        self.add_backup()
        response = self.client.post(
            reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]),
            {"backup_id": "bk-0", "confirm_restore": "on"},
        )
        self.assertContains(response, "At least one feature must be selected for restore")
        self.assertFalse(VirtualminProvisioningJob.objects.filter(account=self.account).exists())

    def test_restore_admission_refusal_renders_message_without_second_job(self) -> None:
        self.add_backup()
        existing = VirtualminProvisioningJob.objects.create(
            server=self.server, account=self.account, operation="restore_domain", status="attention"
        )
        response = self.client.post(
            reverse("provisioning:virtualmin_account_restore", args=[self.account.pk]),
            {"backup_id": "bk-0", "restore_files": "on", "confirm_restore": "on", "force_restore": "on"},
        )
        self.assertContains(response, "Failed to create restore")
        self.assertIn("active migration or backup/restore", self.messages(response))
        self.assertEqual(list(VirtualminProvisioningJob.objects.values_list("pk", flat=True)), [existing.pk])

    def test_backup_list_without_active_server_redirects(self) -> None:
        VirtualminServer.objects.update(status="disabled")
        response = self.client.get(reverse("provisioning:virtualmin_backups"))
        self.assertRedirects(response, reverse("provisioning:virtualmin_servers"), fetch_redirect_response=False)
        self.assertIn("No active Virtualmin servers found", self.messages(response))

    def test_completed_migration_detail_persists_routing_notice_acknowledgement(self) -> None:
        target = VirtualminServer.objects.create(name="Completed target", hostname="completed-target.example.com")
        migration = VirtualminMigration.objects.create(
            account=self.account,
            source_server=self.server,
            target_server=target,
            status="completed",
            archive_name="completed.tar.gz",
        )
        response = self.client.get(reverse("provisioning:virtualmin_account_detail", args=[self.account.pk]))
        self.assertContains(response, "Update routing/DNS manually")
        migration.refresh_from_db()
        self.assertTrue(migration.routing_note_shown)
        self.assertEqual(migration.status, "completed")
