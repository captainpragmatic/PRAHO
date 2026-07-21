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
from apps.notifications.tasks import send_email_task

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
