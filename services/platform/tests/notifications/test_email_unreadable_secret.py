"""A stored message that cannot be decrypted fails permanently, once (#751 follow-up, secret consumers).

A body or envelope written under a superseded format (or garbled) raises DecryptionError when the worker
rebuilds the message. That was handled as a transient provider failure: the row went back to the queue,
and every sweep picked it up again to fail the same way. It can never be sent as written.
"""

from __future__ import annotations

from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.test import TestCase
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task

LEGACY_CIPHERTEXT = "aes:v1:bm90LXJlYWRhYmxlLWFueS1tb3Jl"


class UnreadableStoredMessageTests(TestCase):
    def _legacy(self, **stored: str) -> EmailLog:
        row = EmailLog.objects.create(to_addr="legacy@example.com", subject="Legacy", body_text="Body", status="queued")
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
