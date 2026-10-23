"""An email is claimed by one worker at a time, and nothing written from a stale copy undoes another's.

Follow-up to #751 (H1): a terminal row is never sent again; a row another worker is sending is refused;
completion and failure write only the claim they own; the sweeps decide under the row lock; a delivery
callback touches only the message it names, never moves a status backwards, and one that arrives before
the provider id is recorded is applied once it is.
"""

from __future__ import annotations

import smtplib
import threading
import time
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import patch

from django.core import mail
from django.db import connection
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from apps.audit.models import AuditEvent
from apps.notifications.models import EmailLog, PendingDeliveryEvent
from apps.notifications.services import EmailService
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task


def _log(**kwargs: object) -> EmailLog:
    fields = {
        "to_addr": "recipient@example.com",
        "from_addr": "sender@example.com",
        "subject": "Claim contract",
        "body_text": "Body",
        "status": "queued",
        **kwargs,
    }
    row = EmailLog.objects.create(**fields)
    EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(minutes=11))
    row.refresh_from_db()
    return row


def _send(row: EmailLog) -> dict:
    return send_email_task(str(row.pk))


class TerminalRowsAreNeverSentAgainTests(TestCase):
    def test_a_finished_message_is_not_sent_a_second_time(self) -> None:
        for status in ("sent", "delivered", "bounced", "complained"):
            with self.subTest(status=status):
                mail.outbox.clear()
                row = _log(status=status, delivery_attempts=1)

                _send(row)

                self.assertEqual(mail.outbox, [], "a redelivered task must not send a finished message")
                row.refresh_from_db()
                self.assertEqual(row.status, status)

    def test_a_message_another_worker_is_sending_is_refused(self) -> None:
        row = _log()
        EmailLog.objects.filter(pk=row.pk).update(status="sending", delivery_attempts=1)

        _send(row)

        self.assertEqual(mail.outbox, [])
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("sending", 1))


class LeaseTests(TestCase):
    def test_a_message_whose_lease_is_held_is_refused_however_old_the_row(self) -> None:
        row = _log()
        EmailLog.objects.filter(pk=row.pk).update(
            status="sending",
            delivery_attempts=1,
            lease_until=timezone.now() + timedelta(minutes=5),
            sent_at=timezone.now() - timedelta(hours=2),  # Old enough for the no-lease fallback to reclaim it
        )

        _send(row)

        self.assertEqual(mail.outbox, [], "a live lease means a worker is sending it")
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("sending", 1))

    def test_a_message_whose_lease_expired_is_reclaimed_and_sent(self) -> None:
        row = _log()
        EmailLog.objects.filter(pk=row.pk).update(
            status="sending", delivery_attempts=1, lease_until=timezone.now() - timedelta(minutes=1)
        )

        _send(row)

        self.assertEqual(len(mail.outbox), 1, "the worker holding it died: the message is sent")
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("sent", 2))


class StaleWritesUndoNothingTests(TestCase):
    def test_a_failure_does_not_reopen_a_message_another_worker_finished(self) -> None:
        row = _log()

        def finished_elsewhere(*args: object, **kwargs: object) -> int:
            EmailLog.objects.filter(pk=row.pk).update(status="sent")
            raise TimeoutError("provider timed out")

        with (
            patch("django.core.mail.EmailMessage.send", finished_elsewhere),
            patch("apps.notifications.tasks._schedule_email_retry", return_value=True) as retry,
        ):
            _send(row)

        row.refresh_from_db()
        self.assertEqual(row.status, "sent")
        retry.assert_not_called()

    def test_a_success_does_not_revert_what_another_writer_recorded_meanwhile(self) -> None:
        row = _log()

        def changed_elsewhere(*args: object, **kwargs: object) -> int:
            EmailLog.objects.filter(pk=row.pk).update(status="bounced", delivery_attempts=5)
            return 1

        with patch("django.core.mail.EmailMessage.send", changed_elsewhere):
            _send(row)

        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("bounced", 5))

    def test_a_failure_still_writes_its_audit_event(self) -> None:
        row = _log()

        with patch(
            "django.core.mail.EmailMessage.send", side_effect=smtplib.SMTPDataError(550, b"Rejected")
        ):
            _send(row)

        self.assertTrue(AuditEvent.objects.filter(action="email_failed", metadata__email_log_id=str(row.pk)).exists())


class OwnershipBeforeSendingTests(TestCase):
    def test_a_claim_lost_while_the_message_is_built_sends_nothing(self) -> None:
        import uuid  # noqa: PLC0415

        row = _log()

        def reclaimed_elsewhere() -> None:
            EmailLog.objects.filter(pk=row.pk).update(claim_token=uuid.uuid4())

        with patch("apps.notifications.attachments.regenerate_attachments", side_effect=lambda row: reclaimed_elsewhere() or []):
            _send(row)

        self.assertEqual(mail.outbox, [], "a worker that lost its claim must not send")

    def test_a_failed_send_is_not_re_enqueued_by_the_sweep_before_its_retry_is_due(self) -> None:
        row = _log()
        with (
            patch("django.core.mail.EmailMessage.send", side_effect=TimeoutError("provider timed out")),
            patch("apps.notifications.tasks._schedule_email_retry", return_value=True),
        ):
            _send(row)
        EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(hours=1))

        with patch("django_q.tasks.async_task", return_value="task-id") as enqueue:
            process_email_queue()

        enqueue.assert_not_called()


class SweepTests(TestCase):
    def test_the_failed_retry_sweep_never_reopens_a_message_its_task_already_sent(self) -> None:
        row = _log(status="failed", provider_response={"retry_count": 1}, delivery_attempts=1)

        def sent_at_once(*args: object, **kwargs: object) -> str:
            EmailLog.objects.filter(pk=row.pk).update(status="sent")
            return "task-id"

        with patch("django_q.tasks.async_task", side_effect=sent_at_once):
            retry_failed_emails()

        row.refresh_from_db()
        self.assertEqual(row.status, "sent")

    def test_the_queue_sweep_enqueues_a_stuck_message_once_not_every_pass(self) -> None:
        _log()

        with patch("django_q.tasks.async_task", return_value="task-id") as enqueue:
            process_email_queue()
            process_email_queue()

        self.assertEqual(enqueue.call_count, 1, "a row just re-enqueued is not stuck again until it is overdue")

    def test_the_queue_sweep_leaves_a_message_waiting_on_its_scheduled_retry(self) -> None:
        from apps.notifications.tasks import _schedule_email_retry  # noqa: PLC0415

        row = _log(delivery_attempts=1, provider_response={"retry_count": 1})
        _schedule_email_retry(str(row.pk), 3)

        with patch("django_q.tasks.async_task", return_value="task-id") as enqueue:
            process_email_queue()

        enqueue.assert_not_called()


class DeliveryCallbackTests(TestCase):
    def test_a_callback_for_an_unknown_message_touches_no_other_message(self) -> None:
        newest = _log(status="queued")

        EmailService.handle_delivery_event("delivered", "unknown-provider-id", newest.to_addr)

        newest.refresh_from_db()
        self.assertEqual(newest.status, "queued")

    def test_an_unknown_bounce_still_suppresses_the_address(self) -> None:
        from apps.notifications.services import EmailSuppressionService  # noqa: PLC0415

        EmailService.handle_delivery_event("bounced", "unknown-provider-id", "gone@example.com")

        self.assertTrue(EmailSuppressionService.is_suppressed("gone@example.com"))

    def test_a_bounce_is_never_overwritten_by_a_later_delivered(self) -> None:
        row = _log(status="bounced", provider_id="pid-1")

        EmailService.handle_delivery_event("delivered", "pid-1", row.to_addr)

        row.refresh_from_db()
        self.assertEqual(row.status, "bounced")

    def test_a_callback_that_arrives_before_the_provider_id_is_recorded_is_applied(self) -> None:
        row = _log()

        def accepted_then_bounced(message: object, *args: object, **kwargs: object) -> int:
            message.anymail_status = SimpleNamespace(message_id="pid-early", status={"sent"}, esp_response={})
            EmailService.handle_delivery_event("bounced", "pid-early", row.to_addr)
            return 1

        with patch("django.core.mail.EmailMessage.send", accepted_then_bounced):
            _send(row)

        row.refresh_from_db()
        self.assertEqual((row.provider_id, row.status), ("pid-early", "bounced"))



class BufferedCallbackTests(TestCase):
    """A callback buffered while the success write commits is still applied, and soft bounces still count."""

    def test_a_callback_buffered_after_the_provider_id_was_recorded_is_applied_by_the_sweep(self) -> None:
        # The race: the callback found no row, then the success write committed, then the callback buffered.
        row = _log(status="sent", provider_id="pid-raced")
        PendingDeliveryEvent.objects.create(provider_id="pid-raced", event_type="bounced", metadata={})

        process_email_queue()

        row.refresh_from_db()
        self.assertEqual(row.status, "bounced", "a buffered callback must not wait forever")
        self.assertFalse(PendingDeliveryEvent.objects.filter(provider_id="pid-raced").exists())

    def test_an_unmatched_callback_expires_after_the_window_and_a_recent_one_waits(self) -> None:
        from apps.notifications.services import PENDING_DELIVERY_EVENT_WINDOW  # noqa: PLC0415

        old = PendingDeliveryEvent.objects.create(provider_id="pid-never", event_type="bounced", metadata={})
        recent = PendingDeliveryEvent.objects.create(provider_id="pid-soon", event_type="bounced", metadata={})
        PendingDeliveryEvent.objects.filter(pk=old.pk).update(
            created_at=timezone.now() - PENDING_DELIVERY_EVENT_WINDOW - timedelta(minutes=1)
        )

        process_email_queue()

        self.assertEqual(set(PendingDeliveryEvent.objects.values_list("pk", flat=True)), {recent.pk})

    def test_a_buffered_soft_bounce_still_counts_towards_suppression(self) -> None:
        from apps.notifications.services import EmailSuppressionService  # noqa: PLC0415

        for _ in range(2):
            _log(status="soft_bounced")
        row = _log()

        def accepted_then_soft_bounced(message: object, *args: object, **kwargs: object) -> int:
            message.anymail_status = SimpleNamespace(message_id="pid-soft", status={"sent"}, esp_response={})
            EmailService.handle_delivery_event("soft_bounced", "pid-soft", row.to_addr)
            return 1

        with patch("django.core.mail.EmailMessage.send", accepted_then_soft_bounced):
            _send(row)

        row.refresh_from_db()
        self.assertEqual(row.status, "soft_bounced")
        self.assertTrue(
            EmailSuppressionService.is_suppressed(row.to_addr), "the third soft bounce in the window suppresses"
        )

    def test_the_buffered_recipient_is_not_stored_in_plain_text(self) -> None:
        EmailService.handle_delivery_event("soft_bounced", "pid-unknown", "private@example.com")

        stored = PendingDeliveryEvent.objects.values().get()
        self.assertTrue(stored.get("recipient"), "the recipient is kept for the replay")
        self.assertNotIn("private@example.com", repr(stored))


class ConcurrentClaimTests(TransactionTestCase):
    """On PostgreSQL two workers given the same message send it once."""

    def test_two_workers_claiming_one_message_send_it_once(self) -> None:
        if connection.vendor != "postgresql":
            self.skipTest("row locks need PostgreSQL")
        row = _log()
        sends: list[str] = []
        lock = threading.Lock()

        def slow_send(*args: object, **kwargs: object) -> int:
            with lock:
                sends.append(threading.current_thread().name)
            time.sleep(0.5)
            return 1

        def worker() -> None:
            try:
                _send(row)
            finally:
                connection.close()

        with patch("django.core.mail.EmailMessage.send", slow_send):
            threads = [threading.Thread(target=worker, name=f"w{i}") for i in range(2)]
            for thread in threads:
                thread.start()
            for thread in threads:
                thread.join(10)

        self.assertEqual(len(sends), 1, sends)
