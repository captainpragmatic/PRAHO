"""Password recovery uses the configured sender without changing its recipient."""

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.api.users.serializers import PasswordResetRequestSerializer
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from apps.users.models import User
from tests.helpers.task_queue import run_queued


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="deployment@example.test",
)
class PasswordResetSenderTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.user = User.objects.create_user(email="reset@example.test", password="Test-password-2099!")
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("portal.public_base_url", "https://portal.example.test")
        self.assertTrue(result.is_ok(), result)

    def test_password_reset_sender_uses_row_then_deployment_default(self) -> None:
        for stored, expected in (
            ("runtime@example.test", "runtime@example.test"),
            (None, "deployment@example.test"),
        ):
            with self.subTest(stored=stored):
                with self.captureOnCommitCallbacks(execute=True):
                    if stored is None:
                        SystemSetting.objects.filter(key="company.email_noreply").delete()
                    else:
                        result = SettingsService.update_setting("company.email_noreply", stored)
                        self.assertTrue(result.is_ok(), result)
                mail.outbox.clear()
                serializer = PasswordResetRequestSerializer(data={"email": self.user.email})
                self.assertTrue(serializer.is_valid(), serializer.errors)
                result = serializer.save()
                self.assertTrue(result["success"])
                self.assertEqual(run_queued("apps.users.tasks.send_password_reset_email"), [{"sent": True}])
                self.assertEqual(len(mail.outbox), 1)
                self.assertEqual(mail.outbox[0].from_email, expected)
                self.assertEqual(mail.outbox[0].to, [self.user.email])
                self.assertIn("https://portal.example.test/password-reset/confirm/", mail.outbox[0].body)
