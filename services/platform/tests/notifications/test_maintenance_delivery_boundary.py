"""Async-only notices and durable intent policy hold at the actual provider boundary."""

from __future__ import annotations

import builtins
from contextlib import contextmanager
from datetime import timedelta
from unittest.mock import patch

from django.core import mail
from django.core.cache import cache
from django.core.mail.backends.locmem import EmailBackend
from django.db import connection, transaction
from django.test import TransactionTestCase
from django.urls import reverse
from freezegun import freeze_time

from apps.infrastructure.node_maintenance_models import NodeMaintenanceDelivery
from apps.infrastructure.node_maintenance_service import change_window
from apps.notifications import attachments as attachment_sources
from apps.notifications.attachments import AttachmentRef
from apps.notifications.models import EmailLog, EmailTemplate
from apps.notifications.services import EmailService
from apps.notifications.tasks import retry_failed_emails, send_email_task
from tests.infrastructure.test_node_maintenance_admission import MaintenanceAdmissionFixture


@contextmanager
def missing_queue_import():
    original = builtins.__import__

    def import_module(name, *args, **kwargs):
        if name == "django_q.tasks":
            raise ImportError("Disposable fixture: queue unavailable")
        return original(name, *args, **kwargs)

    with patch("builtins.__import__", side_effect=import_module):
        yield


class MaintenanceDeliveryBoundaryTests(TransactionTestCase):
    def setUp(self) -> None:
        cache.clear()
        for key, category in (("boundary_fixture", "system"), ("maintenance_scheduled", "maintenance")):
            EmailTemplate.objects.update_or_create(
                key=key,
                locale="en",
                defaults={
                    "subject": "Hosting notice",
                    "body_html": "<p>Current notice</p>",
                    "body_text": "Current notice",
                    "category": category,
                },
            )

    def notice(self, **overrides):
        arguments = {
            "template_key": "boundary_fixture",
            "recipient": "owner@example.test",
            "locale": "en",
            "context": {},
            "async_send": True,
            **overrides,
        }
        return EmailService.send_template_email(**arguments)

    def test_required_async_missing_queue_never_falls_back_to_provider_or_publishes_log(self):
        with missing_queue_import():
            result = self.notice(require_async=True)
        self.assertFalse(result.success)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(EmailLog.objects.exists())

    def test_required_async_refuses_explicit_sync_before_provider(self):
        result = self.notice(require_async=True, async_send=False)
        self.assertFalse(result.success)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(EmailLog.objects.exists())

    def test_required_async_refuses_raw_attachment_sync_downgrade(self):
        result = self.notice(
            require_async=True, attachments=[("note.txt", b"bytes without durable source", "text/plain")]
        )
        self.assertFalse(result.success)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(EmailLog.objects.exists())

    def test_required_async_refuses_oversize_reference_sync_downgrade(self):
        def large_source(source_id):
            return "large.txt", b"x" * (5120 * 1024 + 1), "text/plain"

        with patch.dict(attachment_sources.ATTACHMENT_SOURCES, {"boundary_large": large_source}):
            result = self.notice(require_async=True, attachments=[AttachmentRef("boundary_large", "1")])
        self.assertFalse(result.success)
        self.assertEqual(mail.outbox, [])
        self.assertFalse(EmailLog.objects.exists())

    def test_unrelated_mail_keeps_its_existing_missing_queue_sync_fallback(self):
        with missing_queue_import():
            result = self.notice()
        self.assertTrue(result.success, result.error)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(EmailLog.objects.get(pk=result.email_log_id).status, "sent")

    def test_unrelated_raw_attachment_still_sends_whole_synchronously(self):
        result = self.notice(attachments=[("note.txt", b"original bytes", "text/plain")])
        self.assertTrue(result.success, result.error)
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, [("note.txt", "original bytes", "text/plain")])

    def test_async_only_path_returns_one_log_and_sends_outside_the_producer_transaction(self):
        queued = []
        provider_transactions = []
        original_send = EmailBackend.send_messages

        def capture_queue(function, *args, **kwargs):
            queued.append((function, args, kwargs))
            return "fixture-task"

        def observe_provider(backend, messages):
            provider_transactions.append(connection.in_atomic_block)
            return original_send(backend, messages)

        with patch("django_q.tasks.async_task", side_effect=capture_queue):
            with transaction.atomic():
                result = self.notice(require_async=True)
                self.assertTrue(result.success, result.error)
                self.assertEqual(queued, [])
                self.assertEqual(mail.outbox, [])
            self.assertEqual(len(queued), 1)
            function, args, kwargs = queued[0]
            self.assertEqual(function, "apps.notifications.tasks.send_email_task")
            self.assertEqual(args, ())
            self.assertEqual(kwargs["email_log_id"], result.email_log_id)
            with patch.object(EmailBackend, "send_messages", new=observe_provider):
                outcome = send_email_task(kwargs["email_log_id"])
        self.assertTrue(outcome["success"])
        self.assertEqual(provider_transactions, [False])
        self.assertEqual(EmailLog.objects.count(), 1)
        self.assertEqual(EmailLog.objects.get(pk=result.email_log_id).status, "sent")

    def test_reserved_maintenance_sync_without_intent_is_terminally_refused_before_provider(self):
        result = self.notice(template_key="maintenance_scheduled", async_send=False)
        self.assertFalse(result.success)
        self.assertEqual(mail.outbox, [])
        row = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(row.status, "failed")
        self.assertIs(row.provider_response["permanent_failure"], True)
        self.assertIsNone(row.claim_token)

    def test_reserved_maintenance_worker_without_intent_stays_refused_on_retry_and_replay(self):
        with patch("django_q.tasks.async_task"):
            result = self.notice(template_key="maintenance_scheduled", require_async=True)
        self.assertTrue(result.success, result.error)
        outcome = send_email_task(result.email_log_id)
        self.assertFalse(outcome["success"])
        self.assertEqual(mail.outbox, [])
        row = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(row.status, "failed")
        self.assertIs(row.provider_response["permanent_failure"], True)
        self.assertIsNone(row.claim_token)
        with patch("django_q.tasks.async_task") as enqueue:
            retry_failed_emails()
            repeated = send_email_task(result.email_log_id)
        self.assertFalse(repeated["success"])
        enqueue.assert_not_called()
        self.assertEqual(mail.outbox, [])


class MaintenanceRecipientChangeTests(MaintenanceAdmissionFixture, TransactionTestCase):
    def setUp(self) -> None:
        # Keep the public policy path away from midnight; advance the same clock
        # through completion rather than completing a future window in the past.
        clock = freeze_time("2026-11-02 12:00:00+00:00")
        self.clock = clock.start()
        self.addCleanup(clock.stop)
        super().setUp()

    def completed_log(self):
        self.customer.primary_email = "former-contact@example.test"
        self.customer.save(update_fields=["primary_email"])
        for key in ("maintenance_scheduled", "maintenance_completed", "maintenance_correction"):
            EmailTemplate.objects.update_or_create(
                key=key,
                locale="en",
                defaults={
                    "subject": "Hosting notice",
                    "body_html": "<p>{{ public_outcome }}</p>",
                    "body_text": "{{ public_outcome }}",
                    "category": "maintenance",
                },
            )
        with patch("django_q.tasks.async_task"):
            window = self.start(self.window())
            self.clock.move_to(window.ends_at + timedelta(seconds=1))
            change_window(
                window.pk,
                actor=self.actor,
                revision=window.revision,
                action="finish",
                reason="Operator verified maintenance stopped",
                outcome="completed",
                public_outcome="Hosting is available again.",
                attestation=True,
            )
        intent = NodeMaintenanceDelivery.objects.get(kind="completed")
        log = EmailLog.objects.get(pk=intent.email_log_id)
        self.assertEqual(log.to_addr, "former-contact@example.test")
        self.assertEqual(log.status, "queued")
        return log

    def test_public_customer_edit_invalidates_previously_queued_completion_recipient(self):
        log = self.completed_log()
        self.client.force_login(self.actor)
        body = {
            "name": self.customer.name,
            "company_name": self.customer.name,
            "customer_type": "company",
            "primary_email": "current-contact@example.test",
            "payment_terms": "30",
            "credit_limit": "0",
            "preferred_currency": "RON",
            "address_line1": "Review Street 1",
            "city": "Bucharest",
            "county": "Bucuresti",
            "postal_code": "010101",
            "country": "RO",
            "billing_same_as_primary": "on",
            "data_processing_consent": "on",
        }
        response = self.client.post(reverse("customers:edit", args=[self.customer.pk]), body)
        self.assertEqual(response.status_code, 302, getattr(response, "context", None))
        self.customer.refresh_from_db()
        self.assertEqual(self.customer.primary_email, "current-contact@example.test")

        result = send_email_task(str(log.pk))

        self.assertEqual(
            [message.to for message in mail.outbox], [], "The replaced contact received maintenance details"
        )
        self.assertFalse(result["success"], "A current completed intent still sent to the replaced contact address")
        self.assertEqual(mail.outbox, [])
        log.refresh_from_db()
        self.assertEqual(log.status, "failed")
        self.assertIs(log.provider_response["permanent_failure"], True)

    def test_current_completed_intent_delivers_without_holding_window_or_mail_transaction(self):
        log = self.completed_log()
        provider_transactions = []
        original_send = EmailBackend.send_messages

        def observe_provider(backend, messages):
            provider_transactions.append(connection.in_atomic_block)
            return original_send(backend, messages)

        with patch.object(EmailBackend, "send_messages", new=observe_provider):
            result = send_email_task(str(log.pk))

        self.assertTrue(result["success"])
        self.assertEqual([message.to for message in mail.outbox], [[self.customer.primary_email]])
        self.assertEqual(provider_transactions, [False])
        log.refresh_from_db()
        self.assertEqual(log.status, "sent")
        self.assertIsNotNone(NodeMaintenanceDelivery.objects.get(email_log=log).first_dispatch_claimed_at)
