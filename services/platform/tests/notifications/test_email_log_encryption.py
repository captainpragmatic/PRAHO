from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.common.encryption import EncryptionError, encrypt_value, is_encrypted
from apps.common.model_secrets import encrypt_model_secret
from apps.notifications.models import EmailLog


class TestEmailLogEncryptionSave(TestCase):
    """Tests for EmailLog.save() encryption behavior."""

    def test_successful_encryption_sets_body_encrypted_true(self) -> None:
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Reset password",
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )
        email_log.refresh_from_db()
        self.assertTrue(email_log.body_encrypted)
        self.assertTrue(is_encrypted(email_log.body_text))
        self.assertTrue(is_encrypted(email_log.body_html))

    def test_encryption_failure_cannot_save_plaintext(self) -> None:
        with (
            patch("apps.notifications.models.seal_model_secret", side_effect=RuntimeError("encryption failed")),
            self.assertRaises(RuntimeError),
        ):
            EmailLog.objects.create(to_addr="customer@example.com", subject="Reset", body_text="secret")
        self.assertFalse(EmailLog.objects.exists())

    def test_no_partial_encryption_on_second_field_failure(self) -> None:
        row = EmailLog(to_addr="customer@example.com", subject="Invoice", body_text="text", body_html="html")
        with (
            patch(
                "apps.notifications.models.seal_model_secret", side_effect=["aes:v2:first", RuntimeError("failed")]
            ),
            self.assertRaises(RuntimeError),
        ):
            row.save()
        self.assertEqual((row.body_text, row.body_html), ("text", "html"))
        self.assertFalse(EmailLog.objects.exists())

    def test_encryption_failure_preserves_an_existing_encrypted_record(self) -> None:
        row = EmailLog.objects.create(to_addr="customer@example.com", subject="Invoice", body_text="original")
        original = row.body_text
        row.body_text = "replacement"
        with (
            patch("apps.notifications.models.seal_model_secret", side_effect=EncryptionError("key unavailable")),
            self.assertRaises(EncryptionError),
        ):
            row.save()
        row.refresh_from_db()
        self.assertEqual(row.body_text, original)
        self.assertEqual(row.get_decrypted_body_text(), "original")

    @patch("apps.notifications.models.ENCRYPTION_AVAILABLE", False)
    def test_unavailable_encryption_refuses_new_content(self) -> None:
        with self.assertRaises(EncryptionError):
            EmailLog.objects.create(to_addr="customer@example.com", subject="Test", body_text="secret")
        self.assertFalse(EmailLog.objects.exists())

    def test_default_settings_no_override(self) -> None:
        """Verify behavior under default settings without @override_settings."""
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Default settings test",
            body_text="Test body",
        )
        email_log.refresh_from_db()
        self.assertTrue(email_log.body_encrypted)
        self.assertTrue(is_encrypted(email_log.body_text))


class TestReencryptEmailLogsCommand(TestCase):
    def test_reencrypt_dry_run_no_changes(self) -> None:
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Billing notice",
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )
        # Force plaintext state to simulate a row saved with encryption failure
        EmailLog.objects.filter(pk=email_log.pk).update(
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
            body_encrypted=False,
        )

        stdout = StringIO()
        call_command("reencrypt_email_logs", "--dry-run", stdout=stdout)

        email_log.refresh_from_db()
        self.assertEqual(email_log.body_text, "Sensitive plaintext")
        self.assertEqual(email_log.body_html, "<p>Sensitive plaintext</p>")
        self.assertFalse(email_log.body_encrypted)

    def test_reencrypt_updates_plaintext_rows(self) -> None:
        email_log = EmailLog.objects.create(
            to_addr="customer@example.com",
            subject="Billing notice",
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
        )
        # Force plaintext state
        EmailLog.objects.filter(pk=email_log.pk).update(
            body_text="Sensitive plaintext",
            body_html="<p>Sensitive plaintext</p>",
            body_encrypted=False,
        )

        # Ciphertext the command must leave alone. Unbound (v1) values are refused by the save hook now, so
        # they are planted as stored data, the way an older row would hold them.
        already_encrypted_text = encrypt_value("Already encrypted") or ""
        already_encrypted_html = encrypt_value("<p>Already encrypted</p>") or ""
        already_encrypted = EmailLog.objects.create(to_addr="encrypted@example.com", subject="Encrypted row")
        EmailLog.objects.filter(pk=already_encrypted.pk).update(
            body_text=already_encrypted_text, body_html=already_encrypted_html
        )

        call_command("reencrypt_email_logs")

        email_log.refresh_from_db()
        already_encrypted.refresh_from_db()

        self.assertTrue(is_encrypted(email_log.body_text))
        self.assertTrue(is_encrypted(email_log.body_html))
        self.assertTrue(email_log.body_encrypted)
        self.assertEqual(already_encrypted.body_text, already_encrypted_text)
        self.assertEqual(already_encrypted.body_html, already_encrypted_html)

    def test_reencrypt_continues_after_single_row_failure(self) -> None:
        # Create two plaintext rows
        log1 = EmailLog.objects.create(
            to_addr="a@example.com",
            subject="First",
            body_text="text1",
        )
        log2 = EmailLog.objects.create(
            to_addr="b@example.com",
            subject="Second",
            body_text="text2",
        )
        EmailLog.objects.filter(pk__in=[log1.pk, log2.pk]).update(
            body_text="plaintext",
            body_encrypted=False,
        )

        call_count = 0
        original_encrypt = encrypt_model_secret

        def fail_first_call(instance, field, value):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("transient failure")
            return original_encrypt(instance, field, value)

        stdout = StringIO()
        with patch(
            "apps.notifications.management.commands.reencrypt_email_logs.encrypt_model_secret",
            side_effect=fail_first_call,
        ):
            call_command("reencrypt_email_logs", stdout=stdout)

        output = stdout.getvalue()
        self.assertIn("failed=1", output)

    def test_reencrypt_batch_size_zero_raises_error(self) -> None:
        with self.assertRaises(CommandError):
            call_command("reencrypt_email_logs", "--batch-size", "0")
