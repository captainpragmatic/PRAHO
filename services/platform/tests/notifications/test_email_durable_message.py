"""An email is stored whole, and every send rebuilds it from the row (#751 follow-up, H4 and M1).

A queued task carries only the message id: no body, recipient or attachment bytes in the task tables.
The worker, the queue sweep and the failed-email sweep all rebuild the same message from the row:
every recipient, cc, bcc, tags, tracking flags, and each attachment regenerated from its source. A
regenerated attachment that differs from the one first sent is refused, not sent; an attachment that has
no source to regenerate it from is sent at once, never queued, and never resent without it.
"""

from __future__ import annotations

import datetime
from decimal import Decimal
from typing import Any
from unittest.mock import patch

from django.core import mail
from django.test import TestCase
from django.utils import timezone
from freezegun import freeze_time

from apps.billing.models import Currency, Invoice, InvoiceLine, ProformaInvoice, ProformaLine
from apps.common.legal import LegalDocument
from apps.customers.models import Customer
from apps.notifications import attachments as sources
from apps.notifications.attachments import AttachmentRef
from apps.notifications.models import EmailLog
from apps.notifications.services import EmailService
from apps.notifications.tasks import process_email_queue, retry_failed_emails, send_email_task

DOCUMENT = {"bytes": b"%PDF-1.4 original"}


def _test_source(source_id: str) -> tuple[str, bytes, str]:
    return f"doc-{source_id}.pdf", DOCUMENT["bytes"], "application/pdf"


class CapturedTasks:
    """async_task stand-in that keeps what each call enqueued."""

    def __init__(self) -> None:
        self.calls: list[dict[str, Any]] = []

    def __call__(self, func: str, *args: Any, **kwargs: Any) -> str:
        self.calls.append({"func": func, "args": args, **kwargs})
        return f"task-{len(self.calls)}"

    def run_last(self) -> Any:
        call = self.calls[-1]
        payload = {key: value for key, value in call.items() if key not in {"func", "args", "task_name"}}
        return send_email_task(*call["args"], **payload)


class DurableMessageCase(TestCase):
    def setUp(self) -> None:
        super().setUp()
        DOCUMENT["bytes"] = b"%PDF-1.4 original"
        registered = patch.dict(sources.ATTACHMENT_SOURCES, {"test_document": _test_source})
        registered.start()
        self.addCleanup(registered.stop)
        self.tasks = CapturedTasks()
        enqueue = patch("django_q.tasks.async_task", side_effect=self.tasks)
        enqueue.start()
        self.addCleanup(enqueue.stop)

    def send(self, **overrides: Any) -> str:
        arguments: dict[str, Any] = {
            "to": ["first@example.com", "second@example.com"],
            "subject": "Your document",
            "body_text": "secret-body",
            "cc": ["copy@example.com"],
            "bcc": ["hidden@example.com"],
            "tags": {"kind": "invoice"},
            "track_opens": False,
            "track_clicks": False,
            "async_send": True,
            **overrides,
        }
        # The task is published once the row commits.
        with self.captureOnCommitCallbacks(execute=True):
            result = EmailService.send_email(**arguments)
        self.assertTrue(result.success, result.error)
        return str(result.email_log_id)

    def run_enqueued(self) -> None:
        """Run every task the code under test enqueued, with exactly the arguments it gave."""
        for call in list(self.tasks.calls):
            payload = {key: value for key, value in call.items() if key not in {"func", "args", "task_name"}}
            send_email_task(*call["args"], **payload)
        self.tasks.calls.clear()

    def assert_whole(self, message: Any, *, attached: bool = False) -> None:
        self.assertEqual(message.to, ["first@example.com", "second@example.com"])
        self.assertEqual(message.cc, ["copy@example.com"])
        self.assertEqual(message.bcc, ["hidden@example.com"])
        if attached:
            self.assertEqual(message.attachments, [("doc-42.pdf", b"%PDF-1.4 original", "application/pdf")])
        self.assertEqual(message.body, "secret-body")
        self.assertIs(message.track_opens, False)
        self.assertIs(message.track_clicks, False)
        self.assertEqual(message.metadata, {"kind": "invoice"})


class TaskPayloadTests(DurableMessageCase):
    def test_a_queued_task_carries_only_the_message_id(self) -> None:
        email_log_id = self.send()

        call = self.tasks.calls[-1]
        payload = {key: value for key, value in call.items() if key not in {"func", "task_name"}}
        self.assertEqual(payload, {"args": (), "email_log_id": email_log_id})
        self.assertNotIn("secret-body", repr(call))
        self.assertNotIn("first", call["task_name"], "a task name is logged: it carries no recipient")


class PublishAfterCommitTests(DurableMessageCase):
    def test_nothing_is_queued_until_the_message_row_commits(self) -> None:
        with self.captureOnCommitCallbacks(execute=False) as pending:
            result = EmailService.send_email(to=["first@example.com"], subject="Later", body_text="Body")
            self.assertEqual(self.tasks.calls, [], "a worker must never see an id whose row is not committed")
        self.assertTrue(result.success, result.error)
        for callback in pending:
            callback()
        self.assertEqual(len(self.tasks.calls), 1)


    def test_an_enqueue_that_fails_after_commit_does_not_fail_the_caller(self) -> None:
        with (
            patch("django_q.tasks.async_task", side_effect=RuntimeError("broker down")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            result = EmailService.send_email(to=["first@example.com"], subject="Later", body_text="Body")

        self.assertTrue(result.success, "the message was stored; the queue sweep sends it")
        row = EmailLog.objects.get(pk=result.email_log_id)
        self.assertEqual(row.status, "queued")


class RebuiltMessageTests(DurableMessageCase):
    def test_the_worker_rebuilds_the_whole_message_from_the_row(self) -> None:
        self.send()

        self.tasks.run_last()

        self.assertEqual(len(mail.outbox), 1)
        self.assert_whole(mail.outbox[0])

    def test_the_queue_sweep_resends_the_whole_message(self) -> None:
        email_log_id = self.send()
        EmailLog.objects.filter(pk=email_log_id).update(sent_at=timezone.now() - datetime.timedelta(hours=1))

        self.tasks.calls.clear()
        process_email_queue()
        self.run_enqueued()

        self.assert_whole(mail.outbox[-1])

    def test_the_failed_email_sweep_resends_the_whole_message(self) -> None:
        email_log_id = self.send()
        EmailLog.objects.filter(pk=email_log_id).update(status="failed", provider_response={"retry_count": 1})

        self.tasks.calls.clear()
        retry_failed_emails()
        self.run_enqueued()

        self.assert_whole(mail.outbox[-1])


class AttachmentSafetyTests(DurableMessageCase):
    def test_an_attachment_by_reference_is_regenerated_at_send_time(self) -> None:
        self.send(attachments=[AttachmentRef("test_document", "42")])

        self.tasks.run_last()

        self.assert_whole(mail.outbox[0], attached=True)

    def test_a_document_that_changed_since_the_first_send_is_not_sent(self) -> None:
        email_log_id = self.send(attachments=[AttachmentRef("test_document", "42")])
        DOCUMENT["bytes"] = b"%PDF-1.4 edited"

        self.tasks.run_last()

        self.assertEqual(mail.outbox, [], "a different document must never go out under the first one")
        row = EmailLog.objects.get(pk=email_log_id)
        self.assertEqual(row.status, "failed")
        self.assertIs(row.provider_response.get("permanent_failure"), True)

    def test_an_attachment_without_a_source_is_sent_at_once_not_queued(self) -> None:
        email_log_id = self.send(attachments=[("upload.pdf", b"%PDF-1.4 raw", "application/pdf")])

        self.assertEqual(self.tasks.calls, [], "raw bytes never travel through the task tables")
        self.assertEqual(len(mail.outbox), 1)
        self.assertEqual(mail.outbox[0].attachments, [("upload.pdf", b"%PDF-1.4 raw", "application/pdf")])
        self.assertIs(EmailLog.objects.get(pk=email_log_id).meta.get("attachments_unrecoverable"), True)

    def test_a_message_whose_attachment_cannot_be_rebuilt_is_never_resent_without_it(self) -> None:
        email_log_id = self.send(attachments=[("upload.pdf", b"%PDF-1.4 raw", "application/pdf")])
        # However it was first handled, the message is now a retryable failure.
        EmailLog.objects.filter(pk=email_log_id).update(status="failed", provider_response={"retry_count": 1})
        mail.outbox.clear()
        self.tasks.calls.clear()

        retry_failed_emails()
        self.run_enqueued()

        self.assertEqual(mail.outbox, [], "never sent without the attachment it was written with")
        self.assertIs(EmailLog.objects.get(pk=email_log_id).provider_response.get("permanent_failure"), True)

    def test_a_regenerated_set_over_the_size_cap_is_refused(self) -> None:
        DOCUMENT["bytes"] = b"x" * 2048
        with patch.object(sources, "MAX_REGENERATED_BYTES", 1024):
            email_log_id = self.send(attachments=[AttachmentRef("test_document", "42")])
            self.tasks.run_last()

        self.assertEqual(mail.outbox, [])
        self.assertIs(EmailLog.objects.get(pk=email_log_id).provider_response.get("permanent_failure"), True)


class LegalDocumentSourceTests(DurableMessageCase):
    def test_a_legal_document_is_attached_by_reference(self) -> None:
        document = LegalDocument.objects.create(
            kind="terms",
            language="en",
            release="2026-11-01.1",
            effective_on=datetime.date(2026, 11, 1),
            body_markdown="Terms",
            body_html="<p>Terms</p>",
            sha256="0" * 64,
        )
        self.send(attachments=[AttachmentRef("legal_document", str(document.pk))])

        self.tasks.run_last()

        (sent,) = mail.outbox[0].attachments
        filename, content, mimetype = sent
        # Django decodes a text/* attachment into str when attaching; the bytes are the release's.
        as_bytes = content.encode() if isinstance(content, str) else content
        self.assertEqual((filename, as_bytes, mimetype), document.attachment())


class RealDocumentSourceTests(DurableMessageCase):
    """The real ReportLab generators render the same bytes for the same document at any time.

    The first render is hashed when the message is queued; the worker renders again later. A PDF that
    stamps the render time into its bytes would fail that check on every unchanged document.
    """

    def setUp(self) -> None:
        super().setUp()
        self.currency, _ = Currency.objects.get_or_create(code="RON", defaults={"symbol": "lei", "decimals": 2})
        self.customer = Customer.objects.create(
            customer_type="company", company_name="Render Twice SRL", primary_email="render@example.ro", status="active"
        )

    def send_then_work_later(self, ref: AttachmentRef) -> None:
        with freeze_time("2026-10-23 10:00:00"):
            self.send(attachments=[ref])
        with freeze_time("2026-10-23 10:05:00"):
            self.tasks.run_last()

    def test_a_queued_proforma_is_sent_with_its_pdf(self) -> None:
        proforma = ProformaInvoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="PRO-RENDER-001",
            subtotal_cents=5000,
            tax_cents=1050,
            total_cents=6050,
            valid_until=timezone.now() + datetime.timedelta(days=30),
            bill_to_name="Render Twice SRL",
        )
        ProformaLine.objects.create(
            proforma=proforma, kind="service", description="Hosting", quantity=1, unit_price_cents=5000,
            tax_rate=Decimal("0.21"), line_total_cents=5000,
        )

        self.send_then_work_later(AttachmentRef("proforma_pdf", str(proforma.pk)))

        self.assertEqual(len(mail.outbox), 1, "an unchanged proforma must not be refused as changed")
        self.assertEqual(mail.outbox[0].attachments[0][0], "proforma_PRO-RENDER-001.pdf")

    def test_a_queued_built_in_invoice_is_sent_with_its_pdf(self) -> None:
        invoice = Invoice.objects.create(
            customer=self.customer,
            currency=self.currency,
            number="INV-RENDER-001",
            subtotal_cents=10000,
            tax_cents=2100,
            total_cents=12100,
            status="issued",
            bill_to_name="Render Twice SRL",
        )
        InvoiceLine.objects.create(
            invoice=invoice, kind="service", description="Hosting", quantity=1, unit_price_cents=10000,
            tax_rate=Decimal("0.21"), line_total_cents=10000,
        )

        self.send_then_work_later(AttachmentRef("invoice_pdf", str(invoice.pk)))

        self.assertEqual(len(mail.outbox), 1, "an unchanged invoice must not be refused as changed")
        self.assertEqual(mail.outbox[0].attachments[0][0], "invoice_INV-RENDER-001.pdf")
