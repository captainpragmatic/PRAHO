"""The email recovery drains run on a schedule (#751 follow-up, M3).

Nothing scheduled the queue sweep, the failed-email retry, the recovery of messages a dead worker left
`sending`, or the old-log cleanup: each existed and nothing ran it. `setup_scheduled_tasks`, which the
deploy runs, installs them.
"""

from __future__ import annotations

from datetime import timedelta
from io import StringIO
from unittest.mock import patch

from django.core.management import call_command
from django.test import TestCase, override_settings
from django.utils import timezone
from django_q.models import Schedule

from apps.notifications.models import EmailLog
from apps.notifications.tasks import recover_sending_emails

DRAINS = {
    "apps.notifications.tasks.process_email_queue",
    "apps.notifications.tasks.retry_failed_emails",
    "apps.notifications.tasks.recover_sending_emails",
    "apps.notifications.tasks.cleanup_old_email_logs",
}


@override_settings(AUDIT_CHAIN_ENABLED=False)
class DrainScheduleTests(TestCase):
    def test_setup_installs_every_email_drain(self) -> None:
        Schedule.objects.all().delete()

        call_command("setup_scheduled_tasks", stdout=StringIO())

        installed = set(Schedule.objects.filter(func__startswith="apps.notifications.").values_list("func", flat=True))
        self.assertEqual(installed, DRAINS)


class SendingRecoveryTests(TestCase):
    def _sending(self, **fields: object) -> EmailLog:
        row = EmailLog.objects.create(to_addr="stuck@example.com", subject="Stuck", body_text="Body", status="queued")
        EmailLog.objects.filter(pk=row.pk).update(status="sending", delivery_attempts=1, **fields)
        return row

    def test_a_message_whose_worker_died_is_sent_again_once(self) -> None:
        dead = self._sending(lease_until=timezone.now() - timedelta(minutes=1))
        held = self._sending(lease_until=timezone.now() + timedelta(minutes=5))

        with patch("django_q.tasks.async_task", return_value="task-id") as enqueue:
            recover_sending_emails()
            recover_sending_emails()

        enqueued = [call.kwargs.get("email_log_id") for call in enqueue.call_args_list]
        self.assertEqual(enqueued, [str(dead.pk)], "only the dead worker's message, and once until its new lease ends")
        held.refresh_from_db()
        self.assertEqual(held.status, "sending")
