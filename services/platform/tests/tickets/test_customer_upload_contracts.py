"""Customer upload/download contracts with signed identity and real file storage."""

import base64
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase, override_settings

from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment, TicketComment
from apps.tickets.services import TicketStatusService
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class CustomerUploadContracts(HMACTestMixin, TestCase):
    def setUp(self):
        cache.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        self.directory = Path(directory.name)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.user = User.objects.create_user(email="upload@example.com", password="Upload-secure123!")
        self.customer = Customer.objects.create(name="Upload Company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.ticket = Ticket.objects.create(
            customer=self.customer, title="Diagnostics", description="Timeout", status="open"
        )

    def upload(self, files, **overrides):
        return self.portal_post(
            f"/api/tickets/{self.ticket.pk}/reply/",
            {
                "user_id": self.user.pk,
                "customer_id": self.customer.pk,
                "content": "Diagnostic details",
                "attachments": files,
                **overrides,
            },
        )

    def file(self, name="diagnostics.txt", content=b"Timeout at 12:00 UTC\n"):
        return {
            "filename": name,
            "content": base64.b64encode(content).decode(),
            "size": 999,
            "content_type": "fake/type",
        }

    def download(self, attachment, **overrides):
        return self.portal_post(
            f"/api/tickets/{self.ticket.pk}/attachments/{attachment.pk}/download/",
            {
                "user_id": self.user.pk,
                "customer_id": self.customer.pk,
                **overrides,
            },
        )

    def test_reply_and_file_roundtrip_use_actual_bytes_and_authenticated_author(self):
        response = self.upload([self.file()])
        self.assertEqual(response.status_code, 201, response.content)
        attachment = TicketAttachment.objects.get(ticket=self.ticket)
        self.assertEqual(attachment.uploaded_by, self.user)
        self.assertEqual(attachment.comment.content, "Diagnostic details")
        self.assertEqual(attachment.content_type, "text/plain")
        self.assertEqual(attachment.file_size, len(b"Timeout at 12:00 UTC\n"))
        response = self.download(attachment)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"Timeout at 12:00 UTC\n")

    def test_invalid_file_rejects_entire_reply_before_any_write(self):
        invalid = [
            self.file("../escape.txt"),
            self.file("bad.exe"),
            {"filename": "bad.txt", "content": "!"},
            self.file("huge.txt", b"x" * (1024 * 1024 + 1)),
            self.file("header\r\n.txt"),
            self.file(content=b""),
        ]
        for file in invalid:
            with self.subTest(file=file["filename"]):
                response = self.upload([self.file(), file])
                self.assertEqual(response.status_code, 400, response.content)
                self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
                self.assertFalse(TicketAttachment.objects.exists())
        self.assertEqual(self.upload([self.file()] * 6).status_code, 400)
        self.assertEqual(self.upload([self.file(content=b"x" * 600000)] * 2).status_code, 400)
        self.assertEqual(list(self.directory.rglob("*.txt")), [])

    def test_storage_failure_rolls_back_reply_and_cleans_written_files(self):
        with patch.object(TicketAttachment, "save", side_effect=OSError("storage failed")):
            response = self.upload([self.file()])
        self.assertEqual(response.status_code, 500)
        self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
        self.assertEqual(list(self.directory.rglob("*.txt")), [])

    def test_foreign_customer_closed_ticket_internal_and_unsafe_files_fail_closed(self):
        other = Customer.objects.create(name="Other customer", status="active")
        other_user = User.objects.create_user(email="other-upload@example.com", password="Other-secure123!")
        CustomerMembership.objects.create(user=other_user, customer=other, role="owner", is_primary=True)
        self.assertEqual(self.upload([self.file()], customer_id=other.pk, user_id=other_user.pk).status_code, 404)
        self.assertEqual(self.upload([self.file()]).status_code, 201)
        attachment = TicketAttachment.objects.get(ticket=self.ticket)
        self.assertEqual(self.download(attachment, customer_id=other.pk, user_id=other_user.pk).status_code, 404)
        attachment.comment.is_public = False
        attachment.comment.save(update_fields=["is_public"])
        self.assertEqual(self.download(attachment).status_code, 404)
        attachment.comment.is_public = True
        attachment.comment.save(update_fields=["is_public"])
        attachment.is_safe = False
        attachment.save(update_fields=["is_safe"])
        self.assertIn(self.download(attachment).status_code, (403, 404))

        TicketStatusService.close_ticket(self.ticket, "fixed")
        before = self.ticket.comments.count()
        self.assertEqual(self.upload([self.file()]).status_code, 400)
        self.assertEqual(self.ticket.comments.count(), before)
