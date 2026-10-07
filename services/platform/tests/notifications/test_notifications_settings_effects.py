"""Commercial notification limits are evaluated at validation time."""

from contextlib import nullcontext
from typing import ClassVar

from django.core.cache import cache
from django.core.exceptions import ValidationError
from django.db import connection, transaction
from django.test import SimpleTestCase, TestCase, override_settings
from django.test.utils import CaptureQueriesContext

from apps.notifications.models import EmailCampaign, validate_email_subject, validate_template_content
from apps.settings.services import SettingsService


class NotificationSettingsEffectsTests(TestCase):
    def test_max_name_length_governs_campaign_validation(self) -> None:
        result = SettingsService.update_setting("notifications.max_name_length", 10)
        self.assertTrue(result.is_ok(), result)
        campaign = EmailCampaign(name="x" * 11, is_transactional=True)
        with self.assertRaisesMessage(ValidationError, "Campaign name too long"):
            campaign.clean()
        for size in (9, 10):
            campaign.name = "x" * size
            campaign.clean()
        result = SettingsService.update_setting("notifications.max_name_length", 12)
        self.assertTrue(result.is_ok(), result)
        campaign.name = "x" * 11
        campaign.clean()

    def test_max_subject_length_governs_subject_validation(self) -> None:
        result = SettingsService.update_setting("notifications.max_subject_length", 10)
        self.assertTrue(result.is_ok(), result)
        with self.assertRaisesMessage(ValidationError, "Subject too long"):
            validate_email_subject("x" * 11)
        for size in (9, 10):
            validate_email_subject("x" * size)
        result = SettingsService.update_setting("notifications.max_subject_length", 12)
        self.assertTrue(result.is_ok(), result)
        validate_email_subject("x" * 11)
        with self.assertRaisesMessage(ValidationError, "Subject contains invalid characters"):
            validate_email_subject("safe\n")

    def test_max_template_size_governs_content_validation(self) -> None:
        result = SettingsService.update_setting("notifications.max_template_size", 10)
        self.assertTrue(result.is_ok(), result)
        with self.assertRaisesMessage(ValidationError, "Template content too large"):
            validate_template_content("é" * 11)
        for size in (9, 10):
            validate_template_content("é" * size)
        result = SettingsService.update_setting("notifications.max_template_size", 100)
        self.assertTrue(result.is_ok(), result)
        validate_template_content("é" * 11)
        with self.assertRaisesMessage(ValidationError, "Template contains disallowed constructs"):
            validate_template_content("<script>alert(1)</script>")
        with self.assertRaisesMessage(ValidationError, "Template contains disallowed tags"):
            validate_template_content("{% autoescape off %}")


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache", "LOCATION": "notification-limits"}}
)
class NotificationSettingsQueryTests(SimpleTestCase):
    databases: ClassVar[set[str]] = {"default"}

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)

    def check_queries(self, *, atomic: bool) -> None:
        with transaction.atomic() if atomic else nullcontext():
            try:
                self.assertEqual(connection.get_autocommit(), not atomic)
                for key in (
                    "notifications.max_name_length",
                    "notifications.max_subject_length",
                    "notifications.max_template_size",
                ):
                    if atomic:
                        result = SettingsService.update_setting(key, 10)
                        self.assertTrue(result.is_ok(), result)
                    else:
                        cache.set(SettingsService._get_cache_key(key), 10, version=SettingsService.CACHE_VERSION)
                operations = (
                    (lambda: EmailCampaign(name="x" * 11, is_transactional=True).clean(), "Campaign name too long"),
                    (lambda: validate_email_subject("x" * 11), "Subject too long"),
                    (lambda: validate_template_content("x" * 11), "Template content too large"),
                )
                for operation, message in operations:
                    with self.subTest(message=message):
                        with (
                            CaptureQueriesContext(connection) as queries,
                            self.assertRaisesMessage(ValidationError, message),
                        ):
                            operation()
                        self.assertEqual(len(queries), int(atomic))
            finally:
                if atomic:
                    transaction.set_rollback(True)

    def test_warm_cache_enforces_limits_without_queries(self) -> None:
        self.check_queries(atomic=False)

    def test_atomic_validation_reads_each_limit_once(self) -> None:
        self.check_queries(atomic=True)
