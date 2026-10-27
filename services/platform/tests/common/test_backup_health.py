"""Backup health follows completed offsite pairs and its own schedule."""

from datetime import UTC, datetime
from unittest.mock import patch

from django.test import TestCase, override_settings

from apps.common.management.commands.upload_platform_backup import storage_identity
from apps.common.status_models import SystemCheckState
from apps.common.system_status import StatusLevel, _check_backup


@override_settings(TIME_ZONE="UTC")
class BackupHealthTests(TestCase):
    def test_configured_schedule_without_completed_backup_is_overdue_after_grace(self) -> None:
        row = SystemCheckState.objects.create(check_key="platform_backup", details={"runner_enabled": True, "configuration_applied": True, "schedule": "0 2 * * *"})
        SystemCheckState.objects.filter(pk=row.pk).update(created_at=datetime(2026, 10, 1, tzinfo=UTC))
        with patch("apps.common.system_status.timezone.now", return_value=datetime(2026, 10, 2, 5, tzinfo=UTC)):
            result = _check_backup()
        self.assertEqual(result.level, StatusLevel.RED)
        self.assertIn("overdue", str(result.message).lower())

    def test_yesterday_success_is_not_treated_as_stale_telemetry(self) -> None:
        SystemCheckState.objects.create(check_key="platform_backup", level="green", input_identity=storage_identity(), verified_generation=1, details={"runner_enabled": True, "configuration_applied": True, "schedule": "0 2 * * *"}, last_success_at=datetime(2026, 10, 1, 2, 30, tzinfo=UTC))
        with patch("apps.common.system_status.timezone.now", return_value=datetime(2026, 10, 1, 20, tzinfo=UTC)):
            self.assertEqual(_check_backup().level, StatusLevel.GREEN)

    def test_failed_attempt_is_visible_without_changing_configuration(self) -> None:
        row = SystemCheckState.objects.create(check_key="platform_backup", level="red", reason="backup_failed", details={"runner_enabled": True, "configuration_applied": True, "schedule": "0 2 * * *"})
        self.assertEqual(_check_backup().level, StatusLevel.RED)
        row.refresh_from_db()
        self.assertTrue(row.details["configuration_applied"])

    def test_changed_destination_cannot_reuse_previous_destination_success(self) -> None:
        SystemCheckState.objects.create(check_key="platform_backup", level="green", input_identity="a" * 64, verified_generation=1, details={"runner_enabled": True, "configuration_applied": True, "schedule": "0 2 * * *"}, last_success_at=datetime(2026, 10, 1, 2, 30, tzinfo=UTC))
        with patch("apps.common.system_status.timezone.now", return_value=datetime(2026, 10, 1, 20, tzinfo=UTC)):
            self.assertNotEqual(_check_backup().level, StatusLevel.GREEN)
