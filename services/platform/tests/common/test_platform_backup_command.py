"""Backup configuration is reported by the applied runner, not inferred from a cron string."""

from io import StringIO
from pathlib import Path
from unittest.mock import Mock, patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.common.status_models import SystemCheckState


class BackupRunnerTests(TestCase):
    def test_destination_change_during_verification_prevents_marker_publication(self) -> None:
        values = {"backup.platform_offsite_enabled": True, "backup.s3_bucket_name": "original-backups"}
        markers = []
        publisher = Mock()

        def publish(_run, _artifacts, *, before_publish=None, **_kwargs):
            values["backup.s3_bucket_name"] = "changed-backups"
            if before_publish is not None:
                before_publish()
            markers.append("published")

        publisher.publish.side_effect = publish
        with patch("apps.common.management.commands.upload_platform_backup.SettingsService.get_setting", side_effect=lambda key, default=None: values.get(key, default)), patch("apps.common.management.commands.upload_platform_backup.storage_configured", return_value=True), patch("apps.common.management.commands.upload_platform_backup.backup_storage_client"), patch("apps.common.management.commands.upload_platform_backup.PlatformBackupPublisher", return_value=publisher), patch("apps.common.management.commands.upload_platform_backup._upload_local_pair", return_value=[]), self.assertRaises(CommandError):
            call_command("upload_platform_backup", database=Path("fixture.dump"), media=Path("fixture.media.tar.gz"))
        self.assertEqual(markers, [])
        self.assertNotEqual(SystemCheckState.objects.get(check_key="platform_backup").level, "green")

    def test_streaming_runner_can_check_disabled_without_claiming_or_reading_input(self) -> None:
        output = StringIO()
        with patch("apps.common.management.commands.upload_platform_backup.SettingsService.get_setting", return_value=False):
            call_command("upload_platform_backup", check_enabled=True, stdout=output)
        self.assertEqual(output.getvalue().strip(), "disabled")
        self.assertFalse(SystemCheckState.objects.filter(check_key="platform_backup").exists())

    def test_registration_records_applied_configuration_without_claiming_success(self) -> None:
        call_command("upload_platform_backup", register_runner="native", schedule="0 2 * * *")
        self.assertEqual(SystemCheckState.objects.filter(check_key="platform_backup").count(), 1)
        row = SystemCheckState.objects.get(check_key="platform_backup")
        self.assertTrue(row.details["runner_enabled"])
        self.assertTrue(row.details["configuration_applied"])
        self.assertEqual(row.details["source"], "native")
        self.assertIsNone(row.last_success_at)
        self.assertNotEqual(row.level, "green")
