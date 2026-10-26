"""A stored message that cannot be decrypted fails permanently, once (#751 follow-up, secret consumers).

A body or envelope written under a superseded format (or garbled) raises DecryptionError when the worker
rebuilds the message. That was handled as a transient provider failure: the row went back to the queue,
and every sweep picked it up again to fail the same way. It can never be sent as written.
"""

from __future__ import annotations

import json
import os
from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.test import TestCase
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task

LEGACY_CIPHERTEXT = "aes:v1:bm90LXJlYWRhYmxlLWFueS1tb3Jl"


class UnreadableStoredMessageTests(TestCase):
    def _legacy(self, **stored: str) -> EmailLog:
        row = EmailLog.objects.create(
            envelope=json.dumps({"to": ["legacy@example.com"]}),
            to_addr="legacy@example.com",
            subject="Legacy",
            body_text="Body",
            status="queued",
        )
        EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(minutes=11), **stored)
        return row

    def test_a_message_whose_body_cannot_be_decrypted_fails_permanently_once(self) -> None:
        for field in ("body_text", "body_html", "envelope"):
            with self.subTest(field=field):
                row = self._legacy(**{field: LEGACY_CIPHERTEXT})

                with patch("django_q.tasks.schedule") as schedule:
                    send_email_task(str(row.pk))
                with patch("django_q.tasks.async_task", return_value="task-id") as enqueue:
                    process_email_queue()
                    retry_failed_emails()

                row.refresh_from_db()
                self.assertEqual(row.status, "failed")
                self.assertIs(row.provider_response.get("permanent_failure"), True, "it can never be sent")
                schedule.assert_not_called()
                enqueue.assert_not_called()
                self.assertEqual(mail.outbox, [])


class StaleKeyringTests(TestCase):
    """A worker whose keyring lacks the key a message was written with (a key rotation still rolling out)."""

    def test_a_message_the_worker_cannot_open_yet_waits_for_the_right_keys(self) -> None:
        with patch("django_q.tasks.async_task", return_value="task-id"), self.captureOnCommitCallbacks(execute=True):
            result = EmailService.send_email(
                to=["rotated@example.com"], subject="Rotated", body_text="Body", async_send=True
            )

        with patch("apps.common.encryption.get_encryption_keys", return_value=[os.urandom(32)]):
            send_email_task(result.email_log_id)

        row = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(row.status, "queued", "a stale keyring is the operator's to fix, not the message's")
        self.assertIsNot(row.provider_response.get("permanent_failure"), True)

        EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)  # The rollout completed; it is due
        send_email_task(result.email_log_id)

        self.assertEqual(len(mail.outbox), 1, "the original message is delivered once the keys are right")
