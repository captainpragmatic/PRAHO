"""GDPR erasure reaches the emails PRAHO stored for the person (#751 follow-up, H4 GDPR).

A stored message names its recipients, carries a body written for them and may echo them in the
provider's response. Erasure finds every message that names the person as a recipient, in to, cc
or bcc, through keyed digests of the addresses (never the addresses), and scrubs it in place: rows
are never deleted, since notices reference them. A message not yet delivered is cancelled, and a
worker that claimed it earlier records nothing. Another member's messages are left alone. The
export lists the person's own messages without anyone else's address.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

from django.core import mail
from django.test import TestCase

from apps.audit.services import GDPRDeletionService, GDPRExportService
from apps.customers.models import Customer
from apps.notifications.delivery import claim_delivery, record_success
from apps.notifications.models import EmailLog, PendingDeliveryEvent
from apps.notifications.services import EmailService
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task
from apps.users.models import CustomerMembership, User

EMAIL = "ioana.rowe@example.test"
OTHER_EMAIL = "mihai.dobre@example.test"


class EmailErasureCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        self.person = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana", last_name="Rowe")
        self.other = User.objects.create_user(
            email=OTHER_EMAIL, password="x-pass-123", first_name="Mihai", last_name="Dobre"
        )
        enqueue = patch("django_q.tasks.async_task", return_value="task-1")
        enqueue.start()
        self.addCleanup(enqueue.stop)

    def send(self, **overrides: Any) -> EmailLog:
        arguments: dict[str, Any] = {
            "to": [EMAIL],
            "subject": "Your invoice, Ioana Rowe",
            "body_text": "Dear Ioana Rowe, your invoice is attached.",
            "body_html": "<p>Dear Ioana Rowe</p>",
            **overrides,
        }
        with self.captureOnCommitCallbacks(execute=True):
            result = EmailService.send_email(**arguments)
        self.assertTrue(result.success, result.error)
        return EmailLog.objects.get(pk=result.email_log_id)

    def erase(self) -> None:
        request = GDPRDeletionService.create_deletion_request(user=self.person, deletion_type="anonymize").unwrap()
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

    def assert_scrubbed(self, row: EmailLog) -> None:
        stored = EmailLog.objects.filter(pk=row.pk).values().get()
        stored.update(
            attachments=list(row.attachment_refs.values_list("filename", flat=True)),
        )
        text = repr(stored).lower()
        for identifier in ("ioana", "rowe", EMAIL):
            self.assertNotIn(identifier, text, f"{identifier} is still stored")
        self.assertFalse(stored["body_text"])
        self.assertFalse(stored["body_html"])
        self.assertFalse(stored["envelope"])


class ScrubTests(EmailErasureCase):
    def test_every_message_sent_to_the_person_is_scrubbed(self) -> None:
        sent = self.send()
        EmailLog.objects.filter(pk=sent.pk).update(
            provider_response={"esp_response": {"to": EMAIL}, "bounced_event": {"recipient": EMAIL}}
        )

        self.erase()

        self.assert_scrubbed(sent)

    def _assert_copy_scrubbed(self, field: str) -> None:
        # Display name and case differ from the account's address: the digest normalises both.
        row = self.send(to=[OTHER_EMAIL], **{field: ["Ioana Rowe <IOANA.ROWE@Example.TEST>"]})

        self.erase()

        self.assert_scrubbed(row)

    def test_a_message_naming_the_person_only_in_cc_is_scrubbed(self) -> None:
        self._assert_copy_scrubbed("cc")

    def test_a_message_naming_the_person_only_in_bcc_is_scrubbed(self) -> None:
        self._assert_copy_scrubbed("bcc")

    def test_another_members_message_is_kept(self) -> None:
        theirs = self.send(to=[OTHER_EMAIL], subject="Your invoice, Mihai", body_text="Dear Mihai")

        self.erase()

        theirs.refresh_from_db()
        self.assertEqual(theirs.to_addr, OTHER_EMAIL)
        self.assertEqual(theirs.subject, "Your invoice, Mihai")
        self.assertEqual(theirs.get_envelope()["to"], [OTHER_EMAIL])

    def test_a_buffered_callback_for_the_person_is_deleted(self) -> None:
        EmailService.handle_delivery_event("soft_bounced", "pid-not-yet", EMAIL)
        EmailService.handle_delivery_event("soft_bounced", "pid-theirs", OTHER_EMAIL)

        self.erase()

        self.assertEqual(list(PendingDeliveryEvent.objects.values_list("provider_id", flat=True)), ["pid-theirs"])


class LateCallbackTests(EmailErasureCase):
    def test_a_late_callback_for_an_erased_message_stores_nothing(self) -> None:
        sent = self.send()
        EmailLog.objects.filter(pk=sent.pk).update(status="sent", provider_id="pid-sent")

        self.erase()
        EmailService.handle_delivery_event("bounced", "pid-sent", EMAIL, metadata={"recipient": EMAIL})

        self.assertFalse(PendingDeliveryEvent.objects.exists(), "the callback is not buffered with the address")
        self.assert_scrubbed(sent)


class UndeliveredTests(EmailErasureCase):
    def test_a_queued_message_is_cancelled_and_never_sent(self) -> None:
        queued = self.send(async_send=True)
        EmailLog.objects.filter(pk=queued.pk).update(next_attempt_at=None)

        self.erase()
        send_email_task(str(queued.pk))
        with patch("django_q.tasks.async_task", return_value="task-2") as enqueue:
            process_email_queue()
            retry_failed_emails()

        self.assertEqual(mail.outbox, [], "an erased person's queued message is never sent")
        enqueue.assert_not_called()
        queued.refresh_from_db()
        self.assertEqual(queued.status, "failed")
        self.assertIs(queued.provider_response.get("permanent_failure"), True)

    def test_a_worker_that_claimed_before_the_erasure_records_nothing(self) -> None:
        queued = self.send(async_send=True)
        claimed, _refusal = claim_delivery(str(queued.pk))
        self.assertIsNotNone(claimed, "the worker holds the claim")
        token = claimed.claim_token

        self.erase()
        recorded = record_success(str(queued.pk), token, provider_id="pid-after", response={"to": EMAIL})

        self.assertFalse(recorded)
        self.assert_scrubbed(queued)


class ExportTests(EmailErasureCase):
    def test_the_export_lists_the_persons_messages_without_other_recipients(self) -> None:
        self.send(cc=[OTHER_EMAIL])
        self.send(to=[OTHER_EMAIL], subject="Only for Mihai", body_text="Dear Mihai")

        data = GDPRExportService._collect_user_data(self.person, {})

        messages = data.get("emails", [])
        self.assertEqual([message["subject"] for message in messages], ["Your invoice, Ioana Rowe"])
        self.assertNotIn(OTHER_EMAIL, repr(messages), "another recipient's address is theirs, not the person's")

    def test_the_export_includes_messages_to_the_persons_other_addresses(self) -> None:
        home = "ioana.home@example.test"
        customer = Customer.objects.create(
            name="Ioana Rowe", customer_type="individual", primary_email=home, status="active"
        )
        CustomerMembership.objects.create(user=self.person, customer=customer, role="owner", is_active=True)
        self.send(to=[home], subject="Your hosting renewal")

        data = GDPRExportService._collect_user_data(self.person, {})

        messages = data.get("emails", [])
        self.assertEqual([message["subject"] for message in messages], ["Your hosting renewal"])

    def test_the_export_counts_each_message(self) -> None:
        self.send()
        self.send(subject="Your second invoice")

        data = GDPRExportService._collect_user_data(self.person, {})

        without = GDPRExportService._count_records({**data, "emails": []})
        self.assertEqual(GDPRExportService._count_records(data), without + 2)
