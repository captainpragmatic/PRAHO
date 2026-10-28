"""Notification secrets are sealed for their own row and field, or refused (#751 follow-up, secret hooks).

The save hooks encrypted a value only when it did not start with "aes:", so anything that looked like
ciphertext was stored as is: a superseded value, plaintext that happens to start "aes:v2:", or another
row's ciphertext. A value is now kept only when it decrypts for this row and field; a keyring that lacks
the key raises KeyringDecryptionError (a rotation rolling out, not a bad value); anything else that looks
like ciphertext is refused. Only the secret fields being written are sealed, so a status write on a row
that holds an unreadable value still succeeds, and a field's digest is written with it.
"""

from __future__ import annotations

import json
import os
from unittest.mock import patch

from django.test import TestCase

from apps.common.encryption import EncryptionError, KeyringDecryptionError
from apps.notifications.models import EmailLog, EmailSuppression, PendingDeliveryEvent, recipient_digest
from apps.notifications.services import EmailService

LOOKALIKES = ("aes:v1:superseded", "aes:v2:not-ciphertext")


def _email(**fields: object) -> EmailLog:
    return EmailLog(to_addr="person@example.com", subject="Subject", status="queued", **fields)


class EmailLogSealTests(TestCase):
    def test_a_value_that_only_looks_like_ciphertext_is_refused(self) -> None:
        for field in ("body_text", "body_html", "envelope"):
            for value in LOOKALIKES:
                with self.subTest(field=field, value=value), self.assertRaises(EncryptionError, msg="never stored"):
                    _email(**{field: value}).save()

    def test_another_rows_ciphertext_is_refused(self) -> None:
        first = EmailLog.objects.create(to_addr="a@example.com", subject="A", body_text="Secret body")

        with self.assertRaises(EncryptionError, msg="bound to another row: unreadable here"):
            _email(body_text=first.body_text).save()

    def test_plaintext_is_sealed_for_its_row(self) -> None:
        row = EmailLog.objects.create(to_addr="a@example.com", subject="A", body_text="Hello")

        self.assertTrue(row.body_text.startswith("aes:v2:"))
        self.assertEqual(EmailLog.objects.get(pk=row.pk).get_decrypted_body_text(), "Hello")

    def test_a_key_missing_from_the_keyring_is_not_a_bad_value(self) -> None:
        row = EmailLog.objects.get(pk=EmailLog.objects.create(to_addr="a@example.com", subject="A", body_text="Hi").pk)

        with (
            patch("apps.common.encryption.get_encryption_keys", return_value=[os.urandom(32)]),
            self.assertRaises(KeyringDecryptionError),
        ):
            row.save()

    def test_a_status_write_on_a_row_holding_an_unreadable_value_succeeds(self) -> None:
        row = EmailLog.objects.create(to_addr="a@example.com", subject="A", body_text="Hi")
        EmailLog.objects.filter(pk=row.pk).update(body_text="aes:v1:superseded")
        row = EmailLog.objects.get(pk=row.pk)

        row.status = "failed"
        row.save(update_fields=["status"])

        self.assertEqual(EmailLog.objects.get(pk=row.pk).status, "failed")

    def test_an_envelope_write_writes_its_recipient_digests(self) -> None:
        row = EmailLog.objects.create(
            to_addr="a@example.com", subject="A", envelope=json.dumps({"to": ["a@example.com"], "cc": [], "bcc": []})
        )

        row.envelope = json.dumps({"to": ["a@example.com"], "cc": ["late@example.com"], "bcc": []})
        row.save(update_fields=["envelope"])

        stored = EmailLog.objects.get(pk=row.pk).recipient_hashes or ""
        self.assertIn(recipient_digest("late@example.com"), stored, "erasure must find the new copy")


class PendingDeliveryEventSealTests(TestCase):
    def test_a_recipient_that_only_looks_like_ciphertext_is_refused(self) -> None:
        with self.assertRaises(EncryptionError):
            PendingDeliveryEvent(provider_id="pid", event_type="bounced", recipient="aes:v2:not-ciphertext").save()

    def test_a_recipient_write_writes_its_digest(self) -> None:
        event = PendingDeliveryEvent.objects.create(provider_id="pid", event_type="bounced", recipient="old@example.com")

        event.recipient = "new@example.com"
        event.save(update_fields=["recipient"])

        self.assertEqual(PendingDeliveryEvent.objects.get(pk=event.pk).recipient_hash, recipient_digest("new@example.com"))


class EmailSuppressionSealTests(TestCase):
    def test_an_address_that_only_looks_like_ciphertext_is_refused(self) -> None:
        with self.assertRaises(EncryptionError):
            EmailSuppression(email_hash="0" * 64, reason="hard_bounce", email_encrypted="aes:v2:not-ciphertext").save()

    def test_a_bounce_is_recorded_on_a_row_holding_an_unreadable_address(self) -> None:
        first = EmailSuppression.suppress("bounced@example.com", "hard_bounce")
        EmailSuppression.objects.filter(pk=first.pk).update(email_encrypted="aes:v1:superseded")

        again = EmailSuppression.suppress("bounced@example.com", "hard_bounce")

        self.assertEqual(again.bounce_count, 2)


class SendEmailSealTests(TestCase):
    def test_a_body_that_cannot_be_sealed_is_a_failed_result_not_an_exception(self) -> None:
        result = EmailService.send_email(to=["person@example.com"], subject="Subject", body_text="aes:v2:not-ciphertext")

        self.assertFalse(result.success)
        self.assertFalse(EmailLog.objects.exists())
