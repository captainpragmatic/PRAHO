"""Recovery tasks resolve legacy blank senders before actual worker delivery."""

from __future__ import annotations

from collections.abc import Callable
from datetime import timedelta
from typing import TypedDict, Unpack
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.test import TestCase, override_settings
from django.utils import timezone

from apps.notifications.models import EmailLog
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task
from apps.settings.services import SettingsService


class QueuedEmail(TypedDict):
    email_log_id: str
    to: list[str]
    subject: str
    body_text: str
    body_html: str | None
    from_email: str | None
    reply_to: str | None
    retry_count: int
    task_name: str


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    DEFAULT_FROM_EMAIL="deployment@example.test",
)
class EmailRecoverySenderTests(TestCase):
    COMPANY_SENDER = "company-sender@example.test"
    LOGGED_SENDER = "original-sender@example.test"

    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        with self.captureOnCommitCallbacks(execute=True):
            result = SettingsService.update_setting("company.email_noreply", self.COMPANY_SENDER)
        self.assertTrue(result.is_ok(), result)

    def assert_recovery_delivery(
        self, recover: Callable[[], dict[str, object]], status: str, expected_result: dict[str, int]
    ) -> None:
        pending: list[QueuedEmail] = []
        for logged_sender, expected_sender in (("", self.COMPANY_SENDER), (self.LOGGED_SENDER, self.LOGGED_SENDER)):
            with self.subTest(logged_sender=logged_sender):
                mail.outbox.clear()
                log = EmailLog.objects.create(
                    to_addr="recipient@example.test",
                    from_addr=logged_sender,
                    subject="Recovered email",
                    body_text="Recovered body",
                    status=status,
                )
                EmailLog.objects.filter(pk=log.pk).update(sent_at=timezone.now() - timedelta(minutes=11))
                pending.clear()

                def enqueue(task: str, **kwargs: Unpack[QueuedEmail]) -> str:
                    self.assertEqual(task, "apps.notifications.tasks.send_email_task")
                    pending.append(kwargs)
                    return kwargs["task_name"]

                with patch("django_q.tasks.async_task", side_effect=enqueue):
                    self.assertEqual(recover(), expected_result)

                self.assertEqual(len(pending), 1)
                payload = pending[0]
                # Run the worker after recovery returns, as the real queue does.
                delivered = send_email_task(
                    email_log_id=payload["email_log_id"],
                    to=payload["to"],
                    subject=payload["subject"],
                    body_text=payload["body_text"],
                    body_html=payload["body_html"],
                    from_email=payload["from_email"],
                    reply_to=payload["reply_to"],
                    retry_count=payload["retry_count"],
                )
                self.assertTrue(delivered["success"], delivered)
                self.assertEqual(len(mail.outbox), 1)
                self.assertEqual(mail.outbox[0].from_email, expected_sender)
                self.assertEqual(mail.outbox[0].to, [log.to_addr])
                self.assertEqual(mail.outbox[0].body, "Recovered body")
                log.refresh_from_db()
                self.assertEqual(log.from_addr, expected_sender)
                self.assertEqual(log.status, "sent")

    def test_stuck_queue_resolves_blank_sender_and_preserves_logged_sender(self) -> None:
        self.assert_recovery_delivery(process_email_queue, "queued", {"processed": 1, "failed": 0})

    def test_failed_retry_resolves_blank_sender_and_preserves_logged_sender(self) -> None:
        self.assert_recovery_delivery(retry_failed_emails, "failed", {"retried": 1, "skipped": 0})
