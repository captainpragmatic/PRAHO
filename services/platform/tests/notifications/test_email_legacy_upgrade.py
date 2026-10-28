"""Exercise persisted pre-envelope email tasks across the #754 upgrade."""

from __future__ import annotations

import json
import os
import threading
from datetime import timedelta
from multiprocessing import Value
from queue import Queue
from unittest.mock import patch

from django.core import mail
from django.db import connection, transaction
from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from django_q.brokers.orm import ORM
from django_q.conf import Conf
from django_q.models import OrmQ, Schedule, Task
from django_q.monitor import monitor
from django_q.scheduler import scheduler
from django_q.signing import SignedPackage
from django_q.tasks import async_task, schedule
from django_q.worker import worker

from apps.common.model_secrets import encrypt_model_secret
from apps.notifications.legacy import LegacyEmailRecoveryRequiredError
from apps.notifications.models import EmailLog
from apps.notifications.tasks import process_email_queue, recover_sending_emails, retry_failed_emails, send_email_task


class LegacyFixtures:
    def legacy_row(self, **fields: object) -> EmailLog:
        row = EmailLog.objects.create(
            to_addr="primary@example.com",
            from_addr="sender@example.com",
            subject="Legacy document",
            body_text="Original body",
            **({"status": "queued"} | fields),
        )
        self.assertIsNone(row.envelope)
        self.assertFalse(row.attachment_refs.exists())
        self.assertEqual(row.get_decrypted_body_text(), "Original body")
        return row

    def payload(self, row: EmailLog) -> dict[str, object]:
        # Literal kwargs emitted by 5f1226a5 EmailService._send_async, not today's publisher.
        return {
            "email_log_id": str(row.pk),
            "to": [row.to_addr],
            "subject": row.subject,
            "body_text": "Original body",
            "body_html": None,
            "from_email": row.from_addr,
            "reply_to": None,
            "cc": None,
            "bcc": None,
            "attachments": [("invoice.pdf", b"%PDF-1.4 original", "application/pdf")],
            "tags": {"kind": "invoice"},
            "track_opens": False,
            "track_clicks": False,
        }


class LegacyEmailUpgradeTests(LegacyFixtures, TestCase):
    def test_old_primary_recipient_payload_delivers_exact_attachment(self) -> None:
        row = self.legacy_row()
        result = send_email_task(**self.payload(row))
        self.assertTrue(result["success"])
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].to, [row.to_addr])
        self.assertEqual(mail.outbox[0].attachments, [("invoice.pdf", b"%PDF-1.4 original", "application/pdf")])
        self.assertEqual(mail.outbox[0].metadata, {"kind": "invoice"})
        self.assertIs(mail.outbox[0].track_opens, False)
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("sent", 1))
        self.assertEqual(EmailLog.objects.count(), 1)

    def test_id_only_legacy_row_never_sends_an_incomplete_message(self) -> None:
        row = self.legacy_row()
        with self.assertRaisesRegex(RuntimeError, "Legacy email requires recovery"):
            send_email_task(str(row.pk))
        self.assertEqual(mail.outbox, [])
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts, row.envelope), ("queued", 0, None))

    def test_original_positional_and_rate_limited_calls_are_supported(self) -> None:
        for rate_limited in (False, True):
            with self.subTest(rate_limited=rate_limited):
                row = self.legacy_row()
                payload = self.payload(row)
                if rate_limited:
                    payload["schedule"] = timedelta(seconds=60)
                    send_email_task(**payload)
                else:
                    send_email_task(*payload.values())
                self.assertEqual(mail.outbox[-1].attachments, payload["attachments"])
                self.assertEqual(mail.outbox[-1].body, "Original body")

    def test_partial_old_sweep_cannot_replace_a_full_payload(self) -> None:
        row = self.legacy_row()
        partial = {k: v for k, v in self.payload(row).items() if k in {"email_log_id", "to", "subject", "body_text"}}
        with self.assertRaises(LegacyEmailRecoveryRequiredError):
            send_email_task(**partial)
        row.refresh_from_db()
        self.assertIsNone(row.envelope)
        self.assertEqual(row.delivery_attempts, 0)
        send_email_task(**self.payload(row))
        send_email_task(**partial)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, self.payload(row)["attachments"])

    def test_retries_and_additional_recipients_are_held_without_mutation(self) -> None:
        changes = [
            {"retry_count": 0},
            {"retry_count": 1},
            {"retry_count": -1},
            {"to": ["primary@example.com", "other@example.com"]},
            {"cc": ["other@example.com"]},
            {"bcc": ["other@example.com"]},
            {"subject": "Wrong"},
            {"body_text": "Wrong"},
            {"from_email": "wrong@example.com"},
            {"attachments": [("file", "not bytes", "application/pdf")]},
            {"track_opens": "false"},
            {"tags": {"key": 1}},
            {"unknown": "secret-body"},
            {"schedule": "not a timedelta"},
        ]
        for changed in changes:
            with self.subTest(changed=changed):
                row = self.legacy_row()
                with self.assertRaisesRegex(LegacyEmailRecoveryRequiredError, "^Legacy email requires recovery$"):
                    send_email_task(**(self.payload(row) | changed))
                row.refresh_from_db()
                self.assertEqual((row.envelope, row.status, row.delivery_attempts), (None, "queued", 0))
        self.assertEqual(mail.outbox, [])

    def test_hold_diagnostics_do_not_expose_message_contents(self) -> None:
        row = self.legacy_row()
        with (
            self.assertLogs("apps.notifications.legacy", level="WARNING") as logs,
            self.assertRaises(LegacyEmailRecoveryRequiredError),
        ):
            send_email_task(**(self.payload(row) | {"body_text": "DO-NOT-LOG-BODY"}))
        text = " ".join(logs.output)
        self.assertIn(str(row.pk), text)
        self.assertIn("LegacyEmailRecoveryRequiredError", text)
        self.assertNotIn("DO-NOT-LOG-BODY", text)
        self.assertNotIn(row.to_addr, text)
        self.assertNotIn("invoice.pdf", text)

    def test_duplicate_arguments_are_held(self) -> None:
        row = self.legacy_row()
        with self.assertRaises(LegacyEmailRecoveryRequiredError):
            send_email_task(
                str(row.pk), [row.to_addr], **{k: v for k, v in self.payload(row).items() if k != "email_log_id"}
            )
        self.assertEqual(mail.outbox, [])

    def test_terminal_erased_and_uncertain_sending_rows_are_unchanged(self) -> None:
        for status in ("sent", "delivered", "bounced", "complained", "soft_bounced", "rejected", "failed", "sending"):
            with self.subTest(status=status):
                row = self.legacy_row(status=status)
                if status in {"failed", "sending"}:
                    with self.assertRaises(LegacyEmailRecoveryRequiredError):
                        send_email_task(**self.payload(row))
                else:
                    send_email_task(**self.payload(row))
                row.refresh_from_db()
                self.assertEqual((row.status, row.envelope, row.delivery_attempts), (status, None, 0))
        for response in ({"permanent_failure": True}, {"retry_exhausted": True}, {"erased": True}):
            row = self.legacy_row(provider_response=response)
            send_email_task(**self.payload(row))
            row.refresh_from_db()
            self.assertIsNone(row.envelope)
            self.assertEqual(row.provider_response, response)
        self.assertEqual(mail.outbox, [])

    def test_existing_envelope_wins_over_any_stale_legacy_payload(self) -> None:
        row = self.legacy_row()
        stale = self.payload(row)
        row.envelope = json.dumps({"to": [row.to_addr], "tags": {"kind": "current"}})
        row.save(update_fields=["envelope"])
        send_email_task(**stale)
        self.assertEqual(mail.outbox[0].metadata, {"kind": "current"})
        self.assertEqual(mail.outbox[0].attachments, [])

    def test_raw_attachment_failure_never_retries_without_the_attachment(self) -> None:
        row = self.legacy_row()
        with patch("django.core.mail.EmailMessage.send", side_effect=TimeoutError("Provider timeout")):
            send_email_task(**self.payload(row))
        EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)
        send_email_task(str(row.pk))
        row.refresh_from_db()
        self.assertTrue(row.provider_response["permanent_failure"])
        self.assertEqual(mail.outbox, [])

    def test_no_attachment_message_can_retry_from_its_encrypted_envelope(self) -> None:
        row = self.legacy_row()
        with patch("django.core.mail.EmailMessage.send", side_effect=TimeoutError("Provider timeout")):
            send_email_task(**(self.payload(row) | {"attachments": None}))
        row.refresh_from_db()
        self.assertTrue(row.envelope.startswith("aes:v2:"))
        self.assertNotIn("primary@example.com", row.envelope)
        EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)
        send_email_task(str(row.pk))
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].body, "Original body")

    def test_valid_display_name_recipients_keep_their_original_envelope(self) -> None:
        row = self.legacy_row()
        recipients = ["Primary Person <primary@example.com>"]
        row.envelope = json.dumps({"to": recipients})
        row.save(update_fields=["envelope"])
        result = send_email_task(str(row.pk))
        self.assertTrue(result["success"])
        self.assertEqual(mail.outbox[0].to, recipients)

    def test_invalid_decoded_envelopes_fail_permanently_without_sending(self) -> None:
        for data in (
            {},
            [],
            {"to": []},
            {"to": "primary@example.com"},
            {"to": ["bad"]},
            {"to": ["primary@example.com"], "cc": "hidden@example.com"},
            {"to": ["primary@example.com"], "tags": []},
        ):
            with self.subTest(data=data):
                row = self.legacy_row()
                ciphertext = encrypt_model_secret(row, "envelope", json.dumps(data))
                EmailLog.objects.filter(pk=row.pk).update(envelope=ciphertext)
                send_email_task(str(row.pk))
                row.refresh_from_db()
                self.assertEqual(row.status, "failed")
                self.assertTrue(row.provider_response["permanent_failure"])
        self.assertEqual(mail.outbox, [])

    def test_missing_envelopes_do_not_starve_any_recovery_drain(self) -> None:
        for status, drain in (
            ("queued", process_email_queue),
            ("failed", retry_failed_emails),
            ("sending", recover_sending_emails),
        ):
            with self.subTest(status=status):
                legacy = self.legacy_row(status=status)
                complete = self.legacy_row(status=status)
                complete.envelope = json.dumps({"to": [complete.to_addr]})
                complete.save(update_fields=["envelope"])
                EmailLog.objects.filter(pk__in=[legacy.pk, complete.pk]).update(
                    sent_at=timezone.now() - timedelta(hours=1),
                    lease_until=timezone.now() - timedelta(minutes=1),
                )
                with (
                    patch("django_q.tasks.async_task", return_value="task-id") as enqueue,
                    patch("apps.notifications.tasks._batch", return_value=1),
                ):
                    drain()
                self.assertEqual([call.kwargs["email_log_id"] for call in enqueue.call_args_list], [str(complete.pk)])
                legacy.refresh_from_db()
                self.assertEqual((legacy.status, legacy.delivery_attempts, legacy.envelope), (status, 0, None))
                EmailLog.objects.filter(pk=complete.pk).update(status="sent")

    def test_secondary_recipient_erasure_before_enrichment_holds_without_sending(self) -> None:
        from apps.audit.services import GDPRDeletionService  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        person = User.objects.create_user(email="erased-copy@example.com", password="safe-pass-123")
        row = self.legacy_row()
        payload = self.payload(row) | {"bcc": [person.email]}
        request = GDPRDeletionService.create_deletion_request(user=person, deletion_type="anonymize").unwrap()
        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())
        row.refresh_from_db()
        self.assertIsNone(row.envelope)  # Erasure could not discover the hidden BCC on this old row.
        with self.assertRaises(LegacyEmailRecoveryRequiredError):
            send_email_task(**payload)
        self.assertEqual(mail.outbox, [])

    def test_future_due_legacy_task_keeps_its_original_attachment_unprepared(self) -> None:
        row = self.legacy_row(next_attempt_at=timezone.now() + timedelta(minutes=5))
        with self.assertRaises(LegacyEmailRecoveryRequiredError):
            send_email_task(**self.payload(row))
        row.refresh_from_db()
        self.assertEqual((row.envelope, row.delivery_attempts, row.meta), (None, 0, {}))
        EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)
        send_email_task(**self.payload(row))
        self.assertEqual(mail.outbox[0].attachments, self.payload(row)["attachments"])

    def test_non_object_retry_metadata_still_fails_permanently(self) -> None:
        for status in ("queued", "sending"):
            for response in (["corrupt"], "corrupt"):
                with self.subTest(status=status, response=response):
                    row = self.legacy_row(
                        provider_response=response, status=status, lease_until=timezone.now() - timedelta(minutes=1)
                    )
                    row.envelope = json.dumps({"to": [row.to_addr]})
                    row.save(update_fields=["envelope"])
                    result = send_email_task(str(row.pk))
                    self.assertFalse(result["success"])
                    row.refresh_from_db()
                    self.assertTrue(row.provider_response["permanent_failure"])
                    self.assertEqual(mail.outbox, [])

    def test_pre_digest_display_name_primary_erased_before_recovery_is_held(self) -> None:
        from apps.audit.services import GDPRDeletionService  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        person = User.objects.create_user(email="primary@example.com", password="safe-pass-123")
        row = self.legacy_row()
        # Before migration 0010, no digest was available for erasure discovery.
        EmailLog.objects.filter(pk=row.pk).update(to_addr="Primary Person <primary@example.com>", recipient_hashes=None)
        row.refresh_from_db()
        payload = self.payload(row)
        request = GDPRDeletionService.create_deletion_request(user=person, deletion_type="anonymize").unwrap()
        self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())
        row.refresh_from_db()
        self.assertIsNone(row.envelope)
        self.assertIsNone(row.recipient_hashes)
        self.assertEqual(row.to_addr, "Primary Person <primary@example.com>")
        with self.assertRaises(LegacyEmailRecoveryRequiredError):
            send_email_task(**payload)
        self.assertEqual(mail.outbox, [])
        row.refresh_from_db()
        self.assertIsNone(row.envelope)
        self.assertEqual(row.delivery_attempts, 0)

    def test_stored_retry_budget_is_not_reset_by_an_original_payload(self) -> None:
        for attempts, delivered in ((0, True), (3, True), (4, False)):
            with self.subTest(attempts=attempts):
                row = self.legacy_row(delivery_attempts=attempts)
                result = send_email_task(**self.payload(row))
                self.assertEqual(result["success"], delivered)
                row.refresh_from_db()
                self.assertEqual(row.delivery_attempts, attempts + int(delivered))


class LegacyBrokerRetentionTests(LegacyFixtures, TestCase):
    """Use the installed ORM broker, worker and monitor, with an in-process queue."""

    def setUp(self) -> None:
        super().setUp()
        self.broker = ORM(list_key="email-upgrade-test")
        # These framework maintenance calls close TestCase's intentionally open transaction.
        for module in ("worker", "monitor", "scheduler"):
            cleanup = patch(f"django_q.{module}.close_old_django_connections")
            cleanup.start()
            self.addCleanup(cleanup.stop)
        for name, value in (("SYNC", False), ("ACK_FAILURES", False), ("MAX_ATTEMPTS", 0)):
            setting = patch.object(Conf, name, value)
            setting.start()
            self.addCleanup(setting.stop)

    def run_package(self, package: OrmQ) -> Task:
        task = SignedPackage.loads(package.payload)
        task["ack_id"] = package.pk
        pending, results = Queue(), Queue()
        pending.put(task)
        pending.put("STOP")
        worker(pending, results, Value("d", -1), timeout=-1)
        results.put("STOP")
        monitor(results, self.broker)
        return Task.objects.get(pk=task["id"])

    def enqueue(self, payload: dict[str, object], **options: object) -> OrmQ:
        async_task("apps.notifications.tasks.send_email_task", **payload, broker=self.broker, sync=False, **options)
        return OrmQ.objects.filter(key=self.broker.list_key).latest("pk")

    def test_key_failure_preserves_original_signed_package_until_keys_return(self) -> None:
        row = self.legacy_row()
        package = self.enqueue(self.payload(row))
        original = package.payload
        with patch("apps.common.encryption.get_encryption_keys", return_value=[os.urandom(32)]):
            result = self.run_package(package)
        self.assertFalse(result.success)
        self.assertIn("Legacy email requires recovery", result.result)
        package.refresh_from_db()
        self.assertEqual(package.payload, original)
        row.refresh_from_db()
        self.assertEqual((row.envelope, row.delivery_attempts), (None, 0))
        result = self.run_package(package)
        self.assertTrue(result.success)
        self.assertFalse(OrmQ.objects.filter(pk=package.pk).exists())
        self.assertEqual(mail.outbox[0].attachments, self.payload(row)["attachments"])
        # Existing Django-Q behavior: Task results copy the old kwargs; no new application blob store.
        self.assertEqual(result.kwargs["attachments"], self.payload(row)["attachments"])

    def test_future_due_package_stays_in_broker_until_due(self) -> None:
        row = self.legacy_row(next_attempt_at=timezone.now() + timedelta(minutes=5))
        package = self.enqueue(self.payload(row))
        original = package.payload
        result = self.run_package(package)
        self.assertFalse(result.success)
        package.refresh_from_db()
        self.assertEqual(package.payload, original)
        row.refresh_from_db()
        self.assertEqual((row.envelope, row.delivery_attempts, row.meta), (None, 0, {}))
        EmailLog.objects.filter(pk=row.pk).update(next_attempt_at=None)
        self.assertTrue(self.run_package(package).success)
        self.assertEqual(mail.outbox[0].attachments, self.payload(row)["attachments"])

    def test_task_ack_override_would_drop_a_held_payload_and_must_block_rollout(self) -> None:
        row = self.legacy_row()
        package = self.enqueue(self.payload(row) | {"bcc": ["held@example.com"]}, ack_failure=True)
        result = self.run_package(package)
        self.assertFalse(result.success)
        self.assertFalse(OrmQ.objects.filter(pk=package.pk).exists())
        self.assertEqual(mail.outbox, [])
        self.assertEqual(result.kwargs["bcc"], ["held@example.com"])

    def test_old_one_off_retry_schedule_keeps_its_payload_after_refusal(self) -> None:
        row = self.legacy_row()
        payload = self.payload(row) | {"retry_count": 1}
        scheduled = schedule(
            "apps.notifications.tasks.send_email_task",
            **payload,
            schedule_type="O",
            repeats=1,
            next_run=timezone.now() - timedelta(minutes=1),
            cluster=Conf.CLUSTER_NAME,
        )
        before = scheduled.kwargs
        Schedule.objects.exclude(pk=scheduled.pk).update(next_run=timezone.now() + timedelta(days=1))
        scheduler(self.broker)
        package = OrmQ.objects.filter(key=self.broker.list_key).latest("pk")
        result = self.run_package(package)
        self.assertFalse(result.success)
        self.assertTrue(OrmQ.objects.filter(pk=package.pk).exists())
        scheduled.refresh_from_db()
        self.assertEqual((scheduled.kwargs, scheduled.repeats), (before, 0))
        self.assertEqual(mail.outbox, [])


class LegacyClaimRaceTests(LegacyFixtures, TransactionTestCase):
    """Run real concurrent row-lock interleavings on PostgreSQL, serial trajectories on SQLite."""

    def test_two_legacy_workers_send_once(self) -> None:
        row = self.legacy_row()
        payload = self.payload(row)
        sends: list[str] = []
        errors: list[BaseException] = []
        start = threading.Barrier(2)

        def deliver() -> None:
            try:
                if connection.vendor == "postgresql":
                    start.wait(5)
                send_email_task(**payload)
            except BaseException as error:
                errors.append(error)
            finally:
                if connection.vendor == "postgresql":
                    connection.close()

        with patch("django.core.mail.EmailMessage.send", side_effect=lambda **kwargs: sends.append("sent") or 1):
            if connection.vendor == "postgresql":
                threads = [threading.Thread(target=deliver) for _ in range(2)]
                for thread in threads:
                    thread.start()
                for thread in threads:
                    thread.join(10)
                self.assertTrue(all(not thread.is_alive() for thread in threads))
            else:
                deliver()
                deliver()
        self.assertEqual(errors, [])
        self.assertEqual(sends, ["sent"])
        row.refresh_from_db()
        self.assertEqual((row.status, row.delivery_attempts), ("sent", 1))

    def test_sweep_while_legacy_claim_is_prepared_cannot_send_a_partial_message(self) -> None:
        row = self.legacy_row()
        EmailLog.objects.filter(pk=row.pk).update(sent_at=timezone.now() - timedelta(hours=1))
        original = EmailLog.save
        prepared, release = threading.Event(), threading.Event()
        errors: list[BaseException] = []

        def pause_preparation(instance: EmailLog, *args: object, **kwargs: object) -> None:
            original(instance, *args, **kwargs)
            if kwargs.get("update_fields") and "envelope" in kwargs["update_fields"]:
                prepared.set()
                if not release.wait(10):
                    raise TimeoutError("Test preparation was not released")

        def deliver() -> None:
            try:
                send_email_task(**self.payload(row))
            except BaseException as error:
                errors.append(error)
            finally:
                connection.close()

        if connection.vendor == "postgresql":
            with patch.object(EmailLog, "save", pause_preparation), patch("django_q.tasks.async_task") as enqueue:
                thread = threading.Thread(target=deliver)
                thread.start()
                try:
                    self.assertTrue(prepared.wait(10))
                    process_email_queue()
                    enqueue.assert_not_called()  # Uncommitted envelope is still invisible to the sweep.
                finally:
                    release.set()
                    thread.join(10)
                self.assertFalse(thread.is_alive())
        else:
            with patch("django_q.tasks.async_task") as enqueue:
                process_email_queue()
                enqueue.assert_not_called()
                send_email_task(**self.payload(row))
        self.assertEqual(errors, [])
        self.assertEqual(mail.outbox[0].attachments, self.payload(row)["attachments"])
        row.refresh_from_db()
        self.assertEqual(row.delivery_attempts, 1)

    def test_primary_erasure_between_preparation_and_send_prevents_delivery(self) -> None:
        from apps.audit.person_events import capture_subject  # noqa: PLC0415
        from apps.audit.services import GDPRDeletionService  # noqa: PLC0415
        from apps.users.models import User  # noqa: PLC0415

        person = User.objects.create_user(email="primary@example.com", password="safe-pass-123")
        subject = capture_subject(person)
        row = self.legacy_row()
        errors: list[BaseException] = []
        erase_started = threading.Event()

        def erase() -> None:
            try:
                with transaction.atomic():
                    erase_started.set()
                    GDPRDeletionService._erase_emails(subject)
            except BaseException as error:
                errors.append(error)
            finally:
                connection.close()

        # This boundary is immediately before renewing the claim/provider I/O. Erasure must
        # see the committed recipient digests, clear the token, and stop this invocation.
        from apps.notifications import tasks  # noqa: PLC0415

        renew = tasks.renew_claim

        def erase_then_renew(email_log_id: str, token: object) -> bool:
            if connection.vendor == "postgresql":
                thread = threading.Thread(target=erase)
                thread.start()
                self.assertTrue(erase_started.wait(5))
                thread.join(10)
                self.assertFalse(thread.is_alive())
            else:
                with transaction.atomic():
                    GDPRDeletionService._erase_emails(subject)
            return renew(email_log_id, token)

        with patch.object(tasks, "renew_claim", side_effect=erase_then_renew):
            send_email_task(**self.payload(row))
        self.assertEqual(errors, [])
        self.assertEqual(mail.outbox, [])
        row.refresh_from_db()
        self.assertEqual(row.status, "failed")
        self.assertEqual(row.meta, {"erased": True})
