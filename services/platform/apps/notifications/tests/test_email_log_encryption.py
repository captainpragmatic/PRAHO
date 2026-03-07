from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings

from apps.common.encryption import encrypt_value, is_encrypted
from apps.notifications.models import EmailLog


class TestEmailLogEncryptionFailureHandling(TestCase):
    @override_settings(ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK=False)
    def test_save_raises_when_encryption_fails_and_fallback_disabled(self) -> None:
        with (
            patch("apps.notifications.models.encrypt_value", side_effect=RuntimeError("encryption failed")),
            self.assertRaises(RuntimeError),
        ):
            EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Reset password",
                body_text="Sensitive plaintext",
                body_html="<p>Sensitive plaintext</p>",
            )

    @override_settings(ALLOW_UNENCRYPTED_EMAIL_LOG_FALLBACK=True)
    def test_save_allows_plaintext_when_encryption_fails_and_fallback_enabled(self) -> None:
        with patch("apps.notifications.models.encrypt_value", side_effect=RuntimeError("encryption failed")):
            email_log = EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Invoice update",
                body_text="Sensitive plaintext",
                body_html="<p>Sensitive plaintext</p>",
            )

        email_log.refresh_from_db()
        self.assertEqual(email_log.body_text, "Sensitive plaintext")
        self.assertEqual(email_log.body_html, "<p>Sensitive plaintext</p>")


class TestReencryptEmailLogsCommand(TestCase):
    def test_reencrypt_email_logs_dry_run_does_not_modify_data(self) -> None:
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Billing notice",
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )
        # Force plaintext state to simulate legacy rows stored before fail-closed behavior.
        EmailLog.objects.filter(pk=email_log.pk).update(
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )

        stdout = StringIO()
        call_command("reencrypt_email_logs", "--dry-run", stdout=stdout)

        email_log.refresh_from_db()
        self.assertEqual(email_log.body_text, "Sensitive plaintext")
        self.assertEqual(email_log.body_html, "<p>Sensitive plaintext</p>")

    def test_reencrypt_email_logs_updates_plaintext_rows(self) -> None:
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Billing notice",
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )
        # Force plaintext state to simulate legacy rows stored before fail-closed behavior.
        EmailLog.objects.filter(pk=email_log.pk).update(
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )

        already_encrypted_text = encrypt_value("Already encrypted")
        already_encrypted_html = encrypt_value("<p>Already encrypted</p>")
        already_encrypted = EmailLog.objects.create(
            to_addr="encrypted@example.com",
            subject="Encrypted row",
            body_text=already_encrypted_text or "",
            body_html=already_encrypted_html or "",
        )

        call_command("reencrypt_email_logs")

        email_log.refresh_from_db()
        already_encrypted.refresh_from_db()

        self.assertTrue(is_encrypted(email_log.body_text))
        self.assertTrue(is_encrypted(email_log.body_html))
        self.assertEqual(already_encrypted.body_text, already_encrypted_text)
        self.assertEqual(already_encrypted.body_html, already_encrypted_html)
