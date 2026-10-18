"""Attachments are stored under random names, and a reply is bounded before anything is stored.

A stored name used to be the uploader's own filename under `tickets/attachments/`, so it could be
guessed, and it carried whatever the filename said about a person. Now the stored name is random
and the name the uploader gave is kept only in `filename`, for display and download. Older rows keep
their stored names and stay readable.

The edge caps a staff request at a fixed size, because Caddy cannot read settings. Django enforces
the limits in effect, and the settings cannot be raised past what that fixed cap allows.
"""

import base64
import tempfile
from pathlib import Path

from django.conf import settings
from django.core.cache import cache
from django.core.files.base import ContentFile
from django.core.files.uploadedfile import SimpleUploadedFile, TemporaryUploadedFile
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.customers.models import Customer
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket, TicketAttachment, TicketComment
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

TEXT = b"Timeout at 12:00 UTC\n"
PERSONAL_NAME = "Ion Popescu contract.txt"


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class AttachmentStorageAndLimitTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.media = Path(directory.name)
        self.user = User.objects.create_user(email="stored@example.test", password="Stored-secure123!")
        self.customer = Customer.objects.create(name="Stored Company", status="active")
        CustomerMembership.objects.create(user=self.user, customer=self.customer, role="owner", is_primary=True)
        self.ticket = Ticket.objects.create(customer=self.customer, title="Files", description="x", status="open")

    def _api_reply(self, files: list[tuple[str, bytes]]) -> int:
        return self.portal_post(
            f"/api/tickets/{self.ticket.pk}/reply/",
            {
                "user_id": self.user.pk,
                "customer_id": self.customer.pk,
                "content": "Customer files",
                "attachments": [
                    {"filename": name, "content": base64.b64encode(content).decode()} for name, content in files
                ],
            },
        ).status_code

    def _staff_reply(self, files: list[tuple[str, bytes]]) -> None:
        self.client.force_login(self.user)
        self.client.post(
            reverse("tickets:reply", args=[self.ticket.pk]),
            {"reply": "Staff files", "attachments": [SimpleUploadedFile(name, content) for name, content in files]},
        )

    def test_attachment_storage_names_are_random(self) -> None:
        self._staff_reply([(PERSONAL_NAME, TEXT)])
        self.assertEqual(self._api_reply([(PERSONAL_NAME, TEXT)]), 201)
        self._staff_reply([(PERSONAL_NAME, TEXT)])

        attachments = list(TicketAttachment.objects.filter(ticket=self.ticket))
        names = [attachment.file.name for attachment in attachments]
        self.assertEqual(len(attachments), 3)
        self.assertEqual(len(set(names)), 3, "the same upload twice gets two different names")
        for attachment in attachments:
            self.assertEqual(attachment.filename, PERSONAL_NAME)
            self.assertTrue(attachment.file.name.startswith("tickets/attachments/"), attachment.file.name)
            self.assertTrue(attachment.file.name.endswith(".txt"), attachment.file.name)
            for leaked in ("Ion", "Popescu", "contract"):
                self.assertNotIn(leaked, attachment.file.name)
            self.assertEqual(attachment.file.read(), TEXT)

    def test_an_attachment_stored_under_its_old_name_stays_readable(self) -> None:
        legacy = self.media / "tickets" / "attachments" / "evidence.txt"
        legacy.parent.mkdir(parents=True)
        legacy.write_bytes(TEXT)
        attachment = TicketAttachment.objects.create(
            ticket=self.ticket, filename="evidence.txt", file_size=len(TEXT), content_type="text/plain"
        )
        TicketAttachment.objects.filter(pk=attachment.pk).update(file="tickets/attachments/evidence.txt")
        self.client.force_login(self.user)

        response = self.client.get(reverse("tickets:download_attachment", args=[attachment.pk]))

        self.assertEqual(response.status_code, 200)
        self.assertEqual(b"".join(response.streaming_content) if response.streaming else response.content, TEXT)

    def test_six_tiny_files_are_refused_on_both_paths(self) -> None:
        files = [(f"part{index}.txt", TEXT) for index in range(6)]

        self.assertEqual(self._api_reply(files), 400)
        self._staff_reply(files)

        self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
        self.assertFalse(TicketAttachment.objects.exists())
        self.assertEqual([path for path in self.media.rglob("*") if path.is_file()], [])

    def test_attachment_limits_cannot_be_raised_past_the_edge_cap(self) -> None:
        for key, refused, accepted in (
            ("tickets.max_attachments_per_reply", 6, 5),
            ("tickets.max_file_size_bytes", 10 * 1024 * 1024 + 1, 10 * 1024 * 1024),
        ):
            with self.subTest(key=key):
                self.assertTrue(SettingsService.update_setting(key, refused, reason="test").is_err())
                self.assertTrue(SettingsService.update_setting(key, accepted, reason="test").is_ok())

    def test_a_large_upload_spools_to_disk_not_memory(self) -> None:
        self.assertEqual(settings.FILE_UPLOAD_MAX_MEMORY_SIZE, 2621440)
        body = ContentFile(b"a" * (settings.FILE_UPLOAD_MAX_MEMORY_SIZE + 1), name="large.txt")

        request = RequestFactory().post("/reply/", {"reply": "x", "attachments": body})

        self.assertIsInstance(request.FILES["attachments"], TemporaryUploadedFile)
