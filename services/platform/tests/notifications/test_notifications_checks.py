"""Tests for notifications system checks."""

from django.test import TestCase, override_settings

from apps.notifications.checks import check_deprecated_encryption_fallback_setting


class TestDeprecatedEncryptionFallbackCheck(TestCase):
    @override_settings(ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK=True)
    def test_deprecated_setting_present_warns(self) -> None:
        warnings = check_deprecated_encryption_fallback_setting(None)
        self.assertEqual(len(warnings), 1)
        self.assertEqual(warnings[0].id, "notifications.W001")

    def test_no_deprecated_setting_no_warning(self) -> None:
        warnings = check_deprecated_encryption_fallback_setting(None)
        self.assertEqual(len(warnings), 0)
