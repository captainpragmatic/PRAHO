"""Tests for async email attachments (#228, #358), under the stored-message contract.

#228: `_send_async` accepted attachments but never forwarded them to the task, so a proforma email queued
for async delivery arrived with no PDF. Attachments now travel by reference: the row keeps where each one
comes from, and every send (first, retry, rate-limited, recovered) makes it again. Each path below must
deliver the attachment.

#358: attachment bytes must not bloat the task broker. They never enter it now (tasks carry only the
message id); a set of referenced attachments over `notifications.max_async_attachment_kb` is still sent
synchronously, and raw bytes with no source are always sent synchronously.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core import mail
from django.test import TestCase
from django_q.models import Schedule

from apps.notifications import attachments as sources
from apps.notifications.attachments import AttachmentRef
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import _schedule_email_retry, send_email_task

_PDF = ("proforma_PRO-001.pdf", b"%PDF-1.4 fake pdf bytes", "application/pdf")
_REF = AttachmentRef("test_proforma", "PRO-001")


class ReferencedAttachmentCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        registered = patch.dict(sources.ATTACHMENT_SOURCES, {"test_proforma": lambda source_id: _PDF})
        registered.start()
        self.addCleanup(registered.stop)

    def send(self, **overrides: Any) -> str:
        arguments: dict[str, Any] = {
            "to": "customer@example.ro",
            "subject": "Your proforma",
            "body_text": "Attached.",
            "attachments": [_REF],
            "async_send": True,
            **overrides,
        }
        with self.captureOnCommitCallbacks(execute=True):
            result = EmailService.send_email(**arguments)
        self.assertTrue(result.success, result.error)
        return str(result.email_log_id)


class AsyncAttachmentTestCase(ReferencedAttachmentCase):
    @patch("django_q.tasks.async_task", return_value="task-1")
    def test_the_queued_email_keeps_its_attachment_and_the_task_carries_no_bytes(self, enqueue) -> None:
        email_log_id = self.send()

        self.assertEqual(set(enqueue.call_args.kwargs) - {"task_name"}, {"email_log_id"})
        filenames = list(EmailLog.objects.get(pk=email_log_id).attachment_refs.values_list("filename", flat=True))
        self.assertEqual(filenames, [_PDF[0]])

    @patch("django_q.tasks.async_task", return_value="task-1")
    def test_the_worker_attaches_the_file(self, _enqueue) -> None:
        email_log_id = self.send()

        send_email_task(email_log_id)

        self.assertEqual(mail.outbox[0].attachments, [_PDF])

    @patch("django_q.tasks.async_task", return_value="task-1")
    def test_a_message_without_attachments_sends_a_plain_message(self, _enqueue) -> None:
        email_log_id = self.send(attachments=None)

        send_email_task(email_log_id)

        self.assertEqual(mail.outbox[0].attachments, [])


class RetryPathAttachmentTestCase(ReferencedAttachmentCase):
    """Siblings of #228: a retried email must not arrive without its PDF."""

    @patch("django_q.tasks.async_task", return_value="task-1")
    def test_a_retried_email_still_carries_its_attachment(self, _enqueue) -> None:
        email_log_id = self.send()
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("smtp down")):
            failed = send_email_task(email_log_id)
        self.assertTrue(failed["retry_scheduled"], "a transient failure must schedule a retry")
        schedule = Schedule.objects.get(func="apps.notifications.tasks.send_email_task")
        self.assertEqual(schedule.kwargs, f"{{'email_log_id': '{email_log_id}'}}")
        EmailLog.objects.filter(pk=email_log_id).update(next_attempt_at=None)  # The retry is due

        send_email_task(email_log_id)

        self.assertEqual(mail.outbox[-1].attachments, [_PDF])

    @patch("django_q.tasks.schedule")
    def test_schedule_email_retry_carries_only_the_id(self, schedule) -> None:
        email_log_id = str(EmailLog.objects.create(to_addr="customer@example.ro", subject="s", body_text="b").pk)

        _schedule_email_retry(email_log_id, 1)

        extra = set(schedule.call_args.kwargs) - {"next_run", "schedule_type", "repeats", "name"}
        self.assertEqual(extra, {"email_log_id"})


class RateLimitedQueueTestCase(ReferencedAttachmentCase):
    """The rate-limiter queue path must not degrade the email (attachments, cc, bcc, tags)."""

    @patch("django_q.tasks.async_task", return_value="task-1")
    @patch("apps.notifications.services.EmailRateLimiter.check_rate_limit", return_value=(False, 0))
    def test_rate_limited_queue_preserves_the_full_email(self, _limit, enqueue) -> None:
        email_log_id = self.send(cc=["cc@example.ro"], bcc=["bcc@example.ro"], tags={"kind": "proforma"})

        self.assertTrue(enqueue.called, "rate-limited async send must queue the task")
        row = EmailLog.objects.get(pk=email_log_id)
        envelope = row.get_envelope()
        self.assertEqual(
            (envelope["cc"], envelope["bcc"], envelope["tags"]),
            (["cc@example.ro"], ["bcc@example.ro"], {"kind": "proforma"}),
        )
        self.assertEqual(row.attachment_refs.count(), 1)


class AttachmentSizeGuardTestCase(ReferencedAttachmentCase):
    """#358: large attachment sets are sent synchronously; raw bytes never go through the broker."""

    def _cap(self, cap_kb: int) -> Any:
        def _stub(key: str, default: int = 0) -> int:
            return cap_kb if key == "notifications.max_async_attachment_kb" else default

        return patch("apps.notifications.services.SettingsService.get_integer_setting", side_effect=_stub)

    @patch("django_q.tasks.async_task", return_value="task-1")
    def test_a_small_referenced_attachment_still_goes_async(self, enqueue) -> None:
        with self._cap(5120):
            self.send()
        self.assertTrue(enqueue.called)

    @patch("django_q.tasks.async_task", return_value="task-2")
    def test_a_referenced_set_over_the_cap_is_sent_synchronously(self, enqueue) -> None:
        big = ("big.pdf", b"x" * 4096, "application/pdf")
        with patch.dict(sources.ATTACHMENT_SOURCES, {"test_proforma": lambda source_id: big}), self._cap(1):
            self.send()
        self.assertFalse(enqueue.called)
        self.assertEqual(mail.outbox[0].attachments, [big])

    @patch("django_q.tasks.async_task", return_value="task-3")
    def test_cap_zero_always_allows_async_for_references(self, enqueue) -> None:
        big = ("big.pdf", b"x" * 100_000, "application/pdf")
        with patch.dict(sources.ATTACHMENT_SOURCES, {"test_proforma": lambda source_id: big}), self._cap(0):
            self.send()
        self.assertTrue(enqueue.called)

    @patch("django_q.tasks.async_task", return_value="task-4")
    def test_raw_bytes_are_always_sent_synchronously(self, enqueue) -> None:
        with self._cap(0):
            self.send(attachments=[_PDF])
        self.assertFalse(enqueue.called, "raw bytes never travel through the task broker")
        self.assertEqual(mail.outbox[0].attachments, [_PDF])
