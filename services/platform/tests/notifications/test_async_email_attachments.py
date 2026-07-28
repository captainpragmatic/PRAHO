"""
Tests for async email attachments (#228).

`_send_async` accepted an `attachments` argument but never forwarded it to `send_email_task`, and
the task had no `attachments` parameter at all. So an email queued for async delivery — e.g. a
proforma email carrying its PDF — arrived with no attachment.
"""

from __future__ import annotations

from unittest.mock import patch

from django.core import mail
from django.test import TestCase

from apps.notifications.services import EmailService
from apps.notifications.tasks import _schedule_email_retry, send_email_task

_PDF = ("proforma_PRO-001.pdf", b"%PDF-1.4 fake pdf bytes", "application/pdf")


class AsyncEmailAttachmentForwardingTestCase(TestCase):
    """#228: the attachment must reach the async task, not be silently dropped."""

    @patch("django_q.tasks.async_task")
    def test_send_async_forwards_attachments_to_the_task(self, mock_async_task) -> None:
        mock_async_task.return_value = "task-123"

        EmailService.send_email(
            to="customer@example.ro",
            subject="Your proforma",
            body_text="Attached.",
            attachments=[_PDF],
            async_send=True,
        )

        self.assertTrue(mock_async_task.called, "async path must enqueue a task")
        _args, kwargs = mock_async_task.call_args
        self.assertEqual(kwargs.get("attachments"), [_PDF], "attachments must be forwarded to the task")


class SendEmailTaskAttachmentTestCase(TestCase):
    """The worker task must actually attach the files to the outgoing message."""

    def _email_log_id(self) -> str:
        # send_email(async_send=False) creates a log and sends synchronously; reuse its log id.
        result = EmailService.send_email(
            to="customer@example.ro",
            subject="seed",
            body_text="seed",
            async_send=False,
        )
        mail.outbox.clear()
        return str(result.email_log_id)

    def test_task_attaches_the_file_to_the_message(self) -> None:
        send_email_task(
            email_log_id=self._email_log_id(),
            to=["customer@example.ro"],
            subject="Your proforma",
            body_text="Attached.",
            attachments=[_PDF],
        )

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, [_PDF])

    def test_task_without_attachments_sends_a_plain_message(self) -> None:
        """Non-regression: a task with no attachments still sends, with none attached."""
        send_email_task(
            email_log_id=self._email_log_id(),
            to=["customer@example.ro"],
            subject="Plain",
            body_text="No attachment.",
        )

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, [])


class RetryPathAttachmentTestCase(TestCase):
    """Siblings of #228: every re-enqueue of send_email_task must carry the
    attachments — a retried proforma email must not arrive without its PDF."""

    def _email_log_id(self) -> str:
        result = EmailService.send_email(
            to="customer@example.ro", subject="seed", body_text="seed", async_send=False
        )
        mail.outbox.clear()
        return str(result.email_log_id)

    @patch("apps.notifications.tasks._schedule_email_retry")
    def test_failed_send_schedules_retry_with_attachments(self, mock_retry) -> None:
        with patch("django.core.mail.EmailMessage.send", side_effect=OSError("smtp down")):
            send_email_task(
                email_log_id=self._email_log_id(),
                to=["customer@example.ro"],
                subject="Your proforma",
                body_text="Attached.",
                attachments=[_PDF],
            )

        self.assertTrue(mock_retry.called, "a transient failure must schedule a retry")
        self.assertEqual(
            mock_retry.call_args.kwargs.get("attachments"),
            [_PDF],
            "the retry must carry the attachments or the redelivered email arrives without its PDF",
        )

    @patch("django_q.tasks.async_task")
    def test_schedule_email_retry_forwards_attachments_to_the_task(self, mock_async) -> None:
        _schedule_email_retry(
            email_log_id="log-1",
            to=["customer@example.ro"],
            subject="s",
            body_text="b",
            body_html=None,
            from_email=None,
            reply_to=None,
            cc=None,
            bcc=None,
            attachments=[_PDF],
            tags=None,
            track_opens=True,
            track_clicks=True,
            retry_count=1,
        )

        self.assertEqual(mock_async.call_args.kwargs.get("attachments"), [_PDF])


class RateLimitedQueueTestCase(TestCase):
    """The rate-limiter queue path re-enqueues the task too — it must not
    silently degrade the email (attachments, cc, bcc, tags all dropped)."""

    @patch("django_q.tasks.async_task")
    @patch("apps.notifications.services.EmailRateLimiter.check_rate_limit", return_value=(False, 0))
    def test_rate_limited_queue_preserves_the_full_email(self, _mock_rl, mock_async) -> None:
        EmailService.send_email(
            to="customer@example.ro",
            subject="Your proforma",
            body_text="Attached.",
            cc=["cc@example.ro"],
            bcc=["bcc@example.ro"],
            attachments=[_PDF],
            tags={"kind": "proforma"},
            async_send=True,
        )

        self.assertTrue(mock_async.called, "rate-limited async send must queue the task")
        kwargs = mock_async.call_args.kwargs
        self.assertEqual(kwargs.get("attachments"), [_PDF])
        self.assertEqual(kwargs.get("cc"), ["cc@example.ro"])
        self.assertEqual(kwargs.get("bcc"), ["bcc@example.ro"])
        self.assertEqual(kwargs.get("tags"), {"kind": "proforma"})


class AttachmentSizeGuardTestCase(TestCase):
    """#358: oversized async attachments are sent synchronously, not through the broker.

    Full attachment bytes travel by value through the django-q2 Postgres ORM broker
    (base64-inflated ~1.33x, re-persisted on retry). Above a configurable cap the send
    downgrades to synchronous so the bytes never bloat the queue table.
    """

    def _get_int_setting(self, cap_kb: int):
        """Return a get_integer_setting stub honouring the #358 cap, defaults otherwise."""

        def _stub(key: str, default: int = 0) -> int:
            if key == "notifications.max_async_attachment_kb":
                return cap_kb
            return default

        return _stub

    @patch("django_q.tasks.async_task")
    def test_small_attachment_still_goes_async(self, mock_async_task) -> None:
        mock_async_task.return_value = "task-1"
        with patch(
            "apps.notifications.services.SettingsService.get_integer_setting",
            side_effect=self._get_int_setting(5120),
        ):
            EmailService.send_email(
                to="customer@example.ro",
                subject="Small",
                body_text="ok",
                attachments=[_PDF],  # a few bytes, well under 5 MB
                async_send=True,
            )
        self.assertTrue(mock_async_task.called, "a small attachment must still be queued async")

    @patch("django_q.tasks.async_task")
    def test_oversized_attachment_downgrades_to_sync(self, mock_async_task) -> None:
        mock_async_task.return_value = "task-2"
        big = ("big.pdf", b"x" * 4096, "application/pdf")  # 4 KB
        mail.outbox.clear()
        with patch(
            "apps.notifications.services.SettingsService.get_integer_setting",
            side_effect=self._get_int_setting(1),  # 1 KB cap → 4 KB attachment is over
        ):
            EmailService.send_email(
                to="customer@example.ro",
                subject="Big",
                body_text="over cap",
                attachments=[big],
                async_send=True,
            )
        self.assertFalse(
            mock_async_task.called,
            "an oversized attachment must NOT be enqueued to the broker",
        )
        # It was sent synchronously in-process instead.
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, [big])

    @patch("django_q.tasks.async_task")
    def test_cap_zero_always_allows_async(self, mock_async_task) -> None:
        mock_async_task.return_value = "task-3"
        big = ("big.pdf", b"x" * 100_000, "application/pdf")
        with patch(
            "apps.notifications.services.SettingsService.get_integer_setting",
            side_effect=self._get_int_setting(0),  # 0 disables the guard
        ):
            EmailService.send_email(
                to="customer@example.ro",
                subject="Big but allowed",
                body_text="cap disabled",
                attachments=[big],
                async_send=True,
            )
        self.assertTrue(mock_async_task.called, "cap=0 must always allow async")
