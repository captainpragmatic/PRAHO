"""Recovered and retried emails reject invalid subjects permanently."""

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
from apps.notifications.services import EmailService
from apps.notifications.tasks import _schedule_email_retry, process_email_queue, retry_failed_emails, send_email_task
from apps.settings.services import SettingsService


class QueuedEmail(TypedDict, total=False):
    email_log_id: str
    to: list[str]
    subject: str
    body_text: str
    body_html: str | None
    from_email: str | None
    reply_to: str | None
    cc: list[str] | None
    bcc: list[str] | None
    attachments: list[tuple[str, bytes, str]] | None
    tags: dict[str, str] | None
    track_opens: bool
    track_clicks: bool
    retry_count: int
    schedule: timedelta
    task_name: str


@override_settings(
    CACHES={"default": {"BACKEND": "django.core.cache.backends.locmem.LocMemCache"}},
    EMAIL_BACKEND="django.core.mail.backends.locmem.EmailBackend",
    LANGUAGE_CODE="en",
)
class SubjectRecoveryTests(TestCase):
    def setUp(self) -> None:
        cache.clear()
        self.addCleanup(cache.clear)
        self.pending: list[QueuedEmail] = []
        self.set_limit(10)

    def set_limit(self, value: int) -> None:
        result = SettingsService.update_setting("notifications.max_subject_length", value)
        self.assertTrue(result.is_ok(), result)

    def log(self, status: str, length: int = 11) -> EmailLog:
        log = EmailLog.objects.create(
            to_addr="recipient@example.test",
            from_addr="sender@example.test",
            subject="x" * length,
            body_text="Recovered body",
            status=status,
            provider_response={"existing": "preserved"},
        )
        EmailLog.objects.filter(pk=log.pk).update(sent_at=timezone.now() - timedelta(minutes=11))
        return log

    def enqueue(self, task: str, **kwargs: Unpack[QueuedEmail]) -> str:
        self.assertEqual(task, "apps.notifications.tasks.send_email_task")
        self.pending.append(kwargs)
        return "queued-test-email"

    def run_pending(self) -> list[dict[str, object]]:
        return [
            send_email_task(
                email_log_id=payload["email_log_id"],
                to=payload["to"],
                subject=payload["subject"],
                body_text=payload["body_text"],
                body_html=payload.get("body_html"),
                from_email=payload.get("from_email"),
                reply_to=payload.get("reply_to"),
                retry_count=payload.get("retry_count", 0),
            )
            for payload in self.pending
        ]

    def assert_permanent_failure(self, log: EmailLog) -> None:
        log.refresh_from_db()
        self.assertEqual(log.status, "failed")
        self.assertEqual(log.provider_response["final_error"], "Subject too long")
        self.assertIs(log.provider_response["permanent_failure"], True)
        self.assertEqual(log.provider_response["existing"], "preserved")
        self.assertEqual(mail.outbox, [])

    def recoveries(self) -> list[tuple[Callable[[], dict[str, object]], str, dict[str, int]]]:
        return [
            (process_email_queue, "queued", {"processed": 0, "failed": 1}),
            (retry_failed_emails, "failed", {"retried": 0, "skipped": 1}),
        ]

    def test_recovery_refuses_invalid_subject_before_enqueue_and_stays_permanent(self) -> None:
        for recover, status, expected in self.recoveries():
            with self.subTest(recovery=recover.__name__):
                EmailLog.objects.all().delete()
                self.pending.clear()
                mail.outbox.clear()
                self.set_limit(10)
                log = self.log(status)
                with patch("django_q.tasks.async_task", side_effect=self.enqueue):
                    result = recover()
                    self.run_pending()
                    self.assertEqual(mail.outbox, [])
                    self.assertEqual(result, expected)
                    self.assertEqual(self.pending, [])
                    self.assert_permanent_failure(log)
                    self.set_limit(20)
                    self.assertEqual(retry_failed_emails(), {"retried": 0, "skipped": 1})
                    self.assertEqual(self.pending, [])
                    self.assert_permanent_failure(log)

    def test_recovered_tasks_revalidate_the_limit_at_actual_delivery(self) -> None:
        for recover, status, _expected in self.recoveries():
            for length in (9, 10, 11):
                with self.subTest(recovery=recover.__name__, length=length):
                    EmailLog.objects.all().delete()
                    self.pending.clear()
                    mail.outbox.clear()
                    self.set_limit(11)
                    log = self.log(status, length)
                    with patch("django_q.tasks.async_task", side_effect=self.enqueue):
                        recover()
                        self.assertEqual(len(self.pending), 1)
                        self.set_limit(10)
                        results = self.run_pending()
                    if length == 11:
                        self.assertEqual(mail.outbox, [])
                        self.assertEqual(results[0]["success"], False)
                        self.assertEqual(results[0]["error"], "Subject too long")
                        self.assertEqual(results[0]["retry_scheduled"], False)
                        self.assert_permanent_failure(log)
                    else:
                        self.assertEqual([message.subject for message in mail.outbox], ["x" * length])
                        self.assertTrue(results[0]["success"])
                        log.refresh_from_db()
                        self.assertEqual(log.status, "sent")

    def test_already_queued_worker_rejects_invalid_subject_without_scheduling_a_retry(self) -> None:
        log = self.log("queued")
        with patch("django_q.tasks.async_task", side_effect=self.enqueue):
            result = send_email_task(str(log.pk), [log.to_addr], log.subject, "Body")
            self.assertEqual(mail.outbox, [])
            self.assertFalse(result["success"])
            self.assertEqual(result["retry_scheduled"], False)
            self.assertEqual(self.pending, [])
            self.assert_permanent_failure(log)
            self.set_limit(20)
            repeated = send_email_task(str(log.pk), [log.to_addr], log.subject, "Body")
        self.assertFalse(repeated["success"])
        self.assertEqual(repeated["error"], "Subject too long")
        self.assert_permanent_failure(log)

    def test_scheduled_retry_refuses_invalid_subject_before_enqueue(self) -> None:
        log = self.log("queued")
        with patch("django_q.tasks.async_task", side_effect=self.enqueue):
            _schedule_email_retry(
                email_log_id=str(log.pk),
                to=[log.to_addr],
                subject=log.subject,
                body_text="Body",
                body_html=None,
                from_email=log.from_addr,
                reply_to=None,
                cc=None,
                bcc=None,
                tags=None,
                track_opens=True,
                track_clicks=True,
                retry_count=1,
            )
            self.run_pending()
        self.assertEqual(mail.outbox, [])
        self.assertEqual(self.pending, [])
        self.assert_permanent_failure(log)

    def test_rate_limited_retry_marks_invalid_email_failed_instead_of_enqueueing(self) -> None:
        with patch("django_q.tasks.async_task", side_effect=self.enqueue):
            result = EmailService._queue_email_for_retry(
                to=["recipient@example.test"], subject="x" * 11, body_text="Body"
            )
            self.run_pending()
        self.assertEqual(mail.outbox, [])
        self.assertFalse(result.success)
        self.assertEqual(result.error, "Subject too long")
        self.assertEqual(self.pending, [])
        log = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(log.status, "failed")
        self.assertEqual(log.provider_response["final_error"], "Subject too long")
        self.assertIs(log.provider_response["permanent_failure"], True)
