"""Invoice delivery resolves its sender independently of its recipient override."""

from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.billing.invoice_service import send_invoice_email
from apps.settings.models import SystemSetting
from apps.settings.services import SettingsService
from tests.factories.core_factories import create_full_invoice


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="deployment@example.test",
)
class InvoiceSenderTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.invoice = create_full_invoice()

    def test_invoice_sender_uses_row_then_default_and_keeps_recipient_override(self) -> None:
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
                with patch("apps.billing.invoice_service.generate_invoice_pdf", return_value=b"%PDF-1.4 test"):
                    self.assertTrue(send_invoice_email(self.invoice, recipient_email="override@example.test"))
                self.assertEqual(len(mail.outbox), 1)
                self.assertEqual(mail.outbox[0].from_email, expected)
                self.assertEqual(mail.outbox[0].to, ["override@example.test"])
                self.assertEqual(len(mail.outbox[0].attachments), 1)
