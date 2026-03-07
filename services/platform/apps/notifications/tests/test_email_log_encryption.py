from __future__ import annotations

from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.core.management.base import CommandError
from django.test import TestCase

from apps.common.encryption import encrypt_value, is_encrypted
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

    def test_encryption_failure_saves_with_marker(self) -> None:
        with patch("apps.notifications.models.encrypt_value", side_effect=RuntimeError("encryption failed")):
            email_log = EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Reset password",
                body_text="Sensitive plaintext",
                body_html="<p>Sensitive plaintext</p>",
            )

        email_log.refresh_from_db()
        self.assertFalse(email_log.body_encrypted)
        self.assertEqual(email_log.body_text, "Sensitive plaintext")
        self.assertEqual(email_log.body_html, "<p>Sensitive plaintext</p>")

    def test_no_partial_encryption_on_second_field_failure(self) -> None:
        call_count = 0

        def encrypt_first_fail_second(value):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                return f"aes:encrypted_{call_count}"
            raise RuntimeError("second field encryption failed")

        with patch("apps.notifications.models.encrypt_value", side_effect=encrypt_first_fail_second):
            email_log = EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Invoice",
                body_text="Plain text body",
                body_html="<p>HTML body</p>",
            )

        email_log.refresh_from_db()
        self.assertFalse(email_log.body_encrypted)
        # Both fields should be restored to original plaintext
        self.assertEqual(email_log.body_text, "Plain text body")
        self.assertEqual(email_log.body_html, "<p>HTML body</p>")

    def test_encryption_failure_emits_critical_alert(self) -> None:
        with (
            patch("apps.notifications.models.encrypt_value", side_effect=RuntimeError("key corrupted")),
            self.assertLogs("apps.notifications.models", level="CRITICAL") as cm,
        ):
            EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Security alert",
                body_text="Alert body",
            )

        self.assertTrue(any("ENCRYPTION_FAILURE_ALERT" in msg for msg in cm.output))

    @patch("apps.notifications.models.ENCRYPTION_AVAILABLE", False)
    def test_encryption_available_false_logs_warning(self) -> None:
        with self.assertLogs("apps.notifications.models", level="WARNING") as cm:
            email_log = EmailLog.objects.create(
                to_addr="customer@example.com",
                subject="Test",
                body_text="Some text",
            )

        email_log.refresh_from_db()
        self.assertFalse(email_log.body_encrypted)
        self.assertTrue(any("ENCRYPTION_AVAILABLE is False" in msg for msg in cm.output))

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
        self.assertTrue(email_log.body_encrypted)
        self.assertEqual(already_encrypted.body_text, already_encrypted_text)
        self.assertEqual(already_encrypted.body_html, already_encrypted_html)

    def test_reencrypt_continues_after_single_row_failure(self) -> None:
        # Create two plaintext rows
        log1 = EmailLog.objects.create(
            to_addr="a@example.com", subject="First", body_text="text1",
        )
        log2 = EmailLog.objects.create(
            to_addr="b@example.com", subject="Second", body_text="text2",
        )
        EmailLog.objects.filter(pk__in=[log1.pk, log2.pk]).update(
            body_text="plaintext", body_encrypted=False,
        )

        call_count = 0
        original_encrypt = encrypt_value

        def fail_first_call(value):
            nonlocal call_count
            call_count += 1
            if call_count == 1:
                raise RuntimeError("transient failure")
            return original_encrypt(value)

        stdout = StringIO()
        with patch("apps.notifications.management.commands.reencrypt_email_logs.encrypt_value", side_effect=fail_first_call):
            call_command("reencrypt_email_logs", stdout=stdout)

        output = stdout.getvalue()
        self.assertIn("failed=1", output)

    def test_reencrypt_batch_size_zero_raises_error(self) -> None:
        with self.assertRaises(CommandError):
            call_command("reencrypt_email_logs", "--batch-size", "0")
