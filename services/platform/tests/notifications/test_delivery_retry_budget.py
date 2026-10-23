"""Recovery must share the worker's durable budget and isolate terminal failures."""

import smtplib
from datetime import timedelta
from unittest.mock import patch

from anymail.exceptions import AnymailAPIError, AnymailRequestsAPIError
from django.test import TestCase
from django.utils import timezone
from django_q.models import Schedule
from requests import Response

from apps.notifications.delivery import claim_delivery, record_failure
from apps.notifications.models import EmailLog
from apps.notifications.tasks import _schedule_email_retry, process_email_queue, retry_failed_emails, send_email_task
from apps.settings.models import SystemSetting


class DeliveryRetryBudgetTests(TestCase):
    @staticmethod
    def api_error(status: int) -> AnymailAPIError:
        response = Response()
        response.status_code = status
        response.reason = "Provider response"
        response._content = b"{}"
        return AnymailRequestsAPIError("Provider API error", response=response)

    def log(self, **kwargs) -> EmailLog:
        row = EmailLog.objects.create(
            to_addr="recipient@example.com",
            from_addr="sender@example.com",
            subject="Delivery contract",
            body_text="Body",
            status="queued",
            **kwargs,
        )
        EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(minutes=11))
        return row

    def send(self, row: EmailLog):
        return send_email_task(str(row.pk))

    def test_permanent_provider_rejection_is_not_retried(self) -> None:
        row = self.log()
        with (
            patch("django.core.mail.EmailMessage.send", side_effect=smtplib.SMTPDataError(550, b"Rejected")),
            patch("apps.notifications.tasks._schedule_email_retry", return_value=True) as retry,
        ):
            result = self.send(row)
        self.assertFalse(result["retry_scheduled"])
        retry.assert_not_called()
        row.refresh_from_db()
        self.assertEqual(row.status, "failed")
        self.assertIs(row.provider_response["permanent_failure"], True)

    def test_permanent_api_rejections_end_the_row_without_scheduling(self) -> None:
        # 401, 403 and 404 (a missing SES configuration set among them) are the operator's to fix: they
        # block sending instead (test_email_operator_blocked).
        errors = [self.api_error(status) for status in (400, 422)]
        errors.append(
            AnymailAPIError(
                "SES message rejected",
                response={"Error": {"Code": "MessageRejected"}, "ResponseMetadata": {"HTTPStatusCode": 400}},
            )
        )
        for error in errors:
            with self.subTest(error=str(error)):
                row = self.log()
                with (
                    patch("django.core.mail.EmailMessage.send", side_effect=error),
                    patch("apps.notifications.tasks._schedule_email_retry", return_value=True) as retry,
                ):
                    result = self.send(row)
                retry.assert_not_called()
                self.assertFalse(result["retry_scheduled"])
                row.refresh_from_db()
                self.assertEqual((row.status, row.delivery_attempts), ("failed", 1))
                self.assertIs(row.provider_response["permanent_failure"], True)

    def test_api_throttling_timeouts_and_outages_remain_retryable(self) -> None:
        errors = [self.api_error(status) for status in (408, 409, 425, 429, 500, 503)]
        errors.append(AnymailAPIError("Provider connection interrupted"))
        errors.append(
            AnymailAPIError(
                "SES throttled request",
                response={"Error": {"Code": "Throttling"}, "ResponseMetadata": {"HTTPStatusCode": 400}},
            )
        )
        for error in errors:
            with self.subTest(error=str(error)):
                row = self.log()
                with (
                    patch("django.core.mail.EmailMessage.send", side_effect=error),
                    patch("apps.notifications.tasks._schedule_email_retry", return_value=True) as retry,
                ):
                    result = self.send(row)
                retry.assert_called_once()
                self.assertTrue(result["retry_scheduled"])
                row.refresh_from_db()
                self.assertEqual((row.status, row.delivery_attempts), ("queued", 1))

    def test_stale_task_arguments_cannot_reset_delivery_attempts(self) -> None:
        row = self.log()
        with (
            patch("django.core.mail.EmailMessage.send", side_effect=TimeoutError("temporary")) as send,
            patch("apps.notifications.tasks._schedule_email_retry", return_value=True),
            patch(
                "apps.notifications.tasks.SettingsService.get_integer_setting",
                side_effect=lambda key, default: 1 if key == "notifications.email_max_retries" else default,
            ),
        ):
            self.send(row)
            EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)  # The scheduled retry is due
            self.send(row)
            EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)
            final = self.send(row)
        self.assertEqual(send.call_count, 2)
        self.assertFalse(final["retry_scheduled"])
        row.refresh_from_db()
        self.assertEqual(row.status, "failed")

    def test_bad_retry_metadata_does_not_abort_later_messages(self) -> None:
        first = self.log(provider_response={"retry_count": "invalid"})
        second = self.log(provider_response={})
        EmailLog.objects.filter(pk__in=[first.pk, second.pk]).update(status="failed")
        with patch("django_q.tasks.async_task", return_value="queued") as enqueue:
            result = retry_failed_emails()
        self.assertEqual(result, {"retried": 1, "skipped": 1})
        self.assertEqual(enqueue.call_args.kwargs["email_log_id"], str(second.pk))

    def test_queue_recovery_keeps_persisted_retry_count(self) -> None:
        # The task carries only the id; the claim reads the persisted count from the row.
        row = self.log(provider_response={"retry_count": 2})
        with patch("django_q.tasks.async_task", return_value="queued") as enqueue:
            process_email_queue()
        self.assertEqual(set(enqueue.call_args.kwargs) - {"task_name"}, {"email_log_id"})
        claimed, refused = claim_delivery(str(row.pk))
        self.assertIsNone(refused)
        self.assertEqual(claimed.delivery_attempts, 3, "the row's count, not a fresh budget")

    def test_retry_is_a_future_schedule_with_valid_worker_arguments(self) -> None:
        row = self.log()
        started = timezone.now()
        self.assertTrue(
            _schedule_email_retry(str(row.pk), 1)
        )
        schedule = Schedule.objects.filter(func="apps.notifications.tasks.send_email_task").first()
        self.assertIsNotNone(schedule)
        self.assertGreater(schedule.next_run, started)
        self.assertEqual(schedule.schedule_type, Schedule.ONCE)
        self.assertNotIn("'schedule':", schedule.kwargs)
        self.assertEqual(schedule.kwargs, f"{{'email_log_id': '{row.pk}'}}", "a schedule carries only the id")


class EmailRetryLimitSettingsTests(TestCase):
    def test_configured_limit_controls_workers_failures_and_recovery(self) -> None:
        for maximum in (0, 2):
            with self.subTest(maximum=maximum):
                SystemSetting.objects.update_or_create(
                    key="notifications.email_max_retries",
                    defaults={
                        "value": maximum,
                        "default_value": 3,
                        "data_type": "integer",
                        "category": "notifications",
                    },
                )
                row = EmailLog.objects.create(to_addr="retry@example.com", subject="Budget", body_text="Body")
                for attempt in range(maximum + 1):
                    claimed, refused = claim_delivery(str(row.pk), row.subject, None, supplied_retry=0)
                    self.assertIsNone(refused)
                    self.assertEqual(claimed.delivery_attempts, attempt + 1)
                    failed, retry = record_failure(
                        str(row.pk), TimeoutError("provider unavailable"), claimed.claim_token
                    )
                    self.assertEqual(retry, attempt < maximum)
                    self.assertEqual(failed.status, "queued" if retry else "failed")
                    EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)  # The retry is due
                _, refused = claim_delivery(str(row.pk), row.subject, None, supplied_retry=0)
                self.assertFalse(refused["retry_scheduled"])
                # A stale queue row cannot obtain a new budget from recovery.
                EmailLog.objects.filter(pk=row.pk).update(
                    status="queued", sent_at=timezone.now() - timedelta(minutes=11)
                )
                with patch("django_q.tasks.async_task") as enqueue:
                    result = process_email_queue()
                enqueue.assert_not_called()
                self.assertEqual(result["processed"], 0)
                row.refresh_from_db()
                self.assertEqual((row.status, row.delivery_attempts), ("failed", maximum + 1))
