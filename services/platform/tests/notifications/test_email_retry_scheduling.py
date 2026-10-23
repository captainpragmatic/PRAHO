"""A retry is scheduled for its due time, runs once, and leaves nothing behind (#751 follow-up, H2 and M1).

H2: the rate-limited path passed `schedule=` to `async_task`, which django-q2 hands to the task as an
ordinary argument: the email was enqueued at once, and the task refused the unknown argument. M1: a
one-off retry schedule kept with `repeats=1` survives its run (django-q2 only sets it to 0), so it
piles up, and a later retry under the same name is skipped as already scheduled.
"""

from __future__ import annotations

import ast
from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.test import TestCase
from django.utils import timezone
from django_q.models import OrmQ, Schedule
from django_q.scheduler import scheduler
from freezegun import freeze_time

from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import _schedule_email_retry, send_email_task

SEND_TASK = "apps.notifications.tasks.send_email_task"


def queued_sends() -> int:
    """Send tasks waiting in the broker (other apps' tasks share it)."""
    return sum(1 for queued in OrmQ.objects.all() if queued.func() == SEND_TASK)


class RateLimitedRetryTests(TestCase):
    def test_a_rate_limited_email_waits_for_its_due_time_then_sends(self) -> None:
        with (
            patch("apps.notifications.services.EmailRateLimiter.check_rate_limit", return_value=(False, 0)),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = EmailService.send_email(to=["later@example.com"], subject="Later", body_text="Body", async_send=True)
        self.assertTrue(result.success, result.error)

        self.assertEqual(queued_sends(), 0, "nothing is due yet, so nothing is queued")
        schedules = list(Schedule.objects.filter(func=SEND_TASK))
        self.assertEqual(len(schedules), 1, "the retry waits as a schedule")
        (retry,) = schedules
        self.assertGreater(retry.next_run, timezone.now())
        self.assertEqual(ast.literal_eval(retry.kwargs), {"email_log_id": result.email_log_id})

        with freeze_time(retry.next_run + timedelta(seconds=1)):
            send_email_task(**ast.literal_eval(retry.kwargs))

        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(EmailLog.objects.get(pk=result.email_log_id).status, "sent")


class OneOffScheduleTests(TestCase):
    def test_a_retry_schedule_that_ran_leaves_no_row_behind(self) -> None:
        row = EmailLog.objects.create(to_addr="retry@example.com", subject="Retry", body_text="Body", status="queued")
        self.assertTrue(_schedule_email_retry(str(row.pk), 1))
        Schedule.objects.filter(func=SEND_TASK).update(next_run=timezone.now() - timedelta(seconds=1))

        scheduler()

        self.assertEqual(queued_sends(), 1, "the due retry was dispatched")
        self.assertFalse(Schedule.objects.filter(func=SEND_TASK).exists(), "a one-off retry is gone once it ran")
