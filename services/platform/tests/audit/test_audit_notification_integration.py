"""
Tests for Audit → Notification integration.

Verifies that audit integrity alerts and file integrity alerts
correctly trigger email notifications via NotificationService.
"""

from __future__ import annotations

from unittest.mock import MagicMock, patch

from django.test import TestCase

from apps.audit.models import AuditAlert
from apps.audit.tasks import _create_file_integrity_alert, _send_integrity_escalation_alert


class IntegrityAlertNotificationTests(TestCase):
    """Tests for _send_integrity_escalation_alert notification wiring."""

    def _make_compromised_results(self) -> dict:
        return {
            "total_issues": 3,
            "status": "compromised",
            "checks": [
                {"type": "hash_verification", "status": "compromised", "issues_found": 2},
                {"type": "sequence_check", "status": "healthy", "issues_found": 0},
                {"type": "gdpr_compliance", "status": "compromised", "issues_found": 1},
            ],
        }

    @patch("apps.notifications.services.NotificationService")
    @patch("apps.settings.services.SettingsService")
    def test_integrity_alert_sends_notification(
        self, mock_settings_cls: MagicMock, mock_notif_cls: MagicMock
    ) -> None:
        """Critical integrity alert should send email notification to admins."""
        mock_settings_cls.get_boolean_setting.return_value = True

        results = self._make_compromised_results()
        _send_integrity_escalation_alert(results)

        mock_notif_cls.send_admin_alert.assert_called_once()
        call_kwargs = mock_notif_cls.send_admin_alert.call_args
        self.assertEqual(call_kwargs.kwargs["alert_type"], "critical")
        self.assertIn("Integrity Compromised", call_kwargs.kwargs["subject"])

        # AuditAlert should also be created
        self.assertTrue(AuditAlert.objects.filter(alert_type="data_integrity", severity="critical").exists())

    @patch("apps.notifications.services.NotificationService")
    @patch("apps.settings.services.SettingsService")
    def test_integrity_alert_respects_setting_toggle(
        self, mock_settings_cls: MagicMock, mock_notif_cls: MagicMock
    ) -> None:
        """When setting is disabled, notification should not be sent."""
        mock_settings_cls.get_boolean_setting.return_value = False

        results = self._make_compromised_results()
        _send_integrity_escalation_alert(results)

        mock_notif_cls.send_admin_alert.assert_not_called()
        # But the AuditAlert should still be created
        self.assertTrue(AuditAlert.objects.filter(alert_type="data_integrity", severity="critical").exists())

    @patch("apps.notifications.services.NotificationService")
    @patch("apps.settings.services.SettingsService")
    def test_notification_failure_does_not_break_alert(
        self, mock_settings_cls: MagicMock, mock_notif_cls: MagicMock
    ) -> None:
        """If notification sending fails, the AuditAlert should still exist."""
        mock_settings_cls.get_boolean_setting.return_value = True
        mock_notif_cls.send_admin_alert.side_effect = Exception("SMTP connection failed")

        results = self._make_compromised_results()
        _send_integrity_escalation_alert(results)

        # Alert must still be in the database despite notification failure
        self.assertTrue(AuditAlert.objects.filter(alert_type="data_integrity", severity="critical").exists())


class FileIntegrityAlertNotificationTests(TestCase):
    """Tests for _create_file_integrity_alert notification wiring."""

    def _make_file_change_results(self) -> dict:
        return {
            "changes_detected": [
                {
                    "path": "config/settings/base.py",
                    "previous_hash": "abc123...",
                    "current_hash": "def456...",
                    "detected_at": "2026-02-27T10:00:00",
                },
                {
                    "path": "apps/users/views.py",
                    "previous_hash": "111aaa...",
                    "current_hash": "222bbb...",
                    "detected_at": "2026-02-27T10:00:00",
                },
            ],
        }

    @patch("apps.notifications.services.NotificationService")
    @patch("apps.settings.services.SettingsService")
    def test_file_integrity_alert_sends_notification(
        self, mock_settings_cls: MagicMock, mock_notif_cls: MagicMock
    ) -> None:
        """File integrity changes should trigger a warning notification."""
        mock_settings_cls.get_boolean_setting.return_value = True

        results = self._make_file_change_results()
        _create_file_integrity_alert(results)

        mock_notif_cls.send_admin_alert.assert_called_once()
        call_kwargs = mock_notif_cls.send_admin_alert.call_args
        self.assertEqual(call_kwargs.kwargs["alert_type"], "warning")
        self.assertIn("File Integrity", call_kwargs.kwargs["subject"])
        self.assertIn("file_integrity_monitoring", call_kwargs.kwargs["metadata"]["source"])

    @patch("apps.notifications.services.NotificationService")
    @patch("apps.settings.services.SettingsService")
    def test_file_integrity_alert_respects_setting_toggle(
        self, mock_settings_cls: MagicMock, mock_notif_cls: MagicMock
    ) -> None:
        """When file integrity notifications are disabled, no email should be sent."""
        mock_settings_cls.get_boolean_setting.return_value = False

        results = self._make_file_change_results()
        _create_file_integrity_alert(results)

        mock_notif_cls.send_admin_alert.assert_not_called()
        # Alert record should still exist
        self.assertTrue(AuditAlert.objects.filter(alert_type="data_integrity", severity="high").exists())
