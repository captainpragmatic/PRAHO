"""Staff and customer replies check files with one validator, and refuse a reply with a bad file whole.

Before, the staff reply had its own type list (including zip and rar, which the scanner always
refused), stored the type guessed from the name, and kept a reply's comment while dropping a
refused file. The customer API refused the whole reply. Both now behave the same way.
"""

import base64
import re
import tempfile
from pathlib import Path

from django.core.cache import cache
from django.core.files.uploadedfile import SimpleUploadedFile
from django.http import HttpResponse
from django.test import RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.api.tickets.serializers import TicketAttachmentSerializer
from apps.customers.models import Customer
from apps.settings.catalog import CATALOG_BY_KEY
from apps.settings.services import SettingsService
from apps.tickets.models import Ticket, TicketAttachment, TicketComment
from apps.tickets.security import ALLOWED_TYPES
from apps.tickets.views import _DEFAULT_MAX_ATTACHMENTS_PER_REPLY, _check_reply_attachments
from apps.users.models import CustomerMembership, User
from tests.helpers.hmac import HMAC_TEST_MIDDLEWARE, HMAC_TEST_SECRET, HMACTestMixin

PDF = b"%PDF-1.4\n1 0 obj\n<<>>\nendobj\n"
PNG_AS_PDF = b"\x89PNG\r\n\x1a\n\x00\x00\x00\rIHDR" + bytes(32)
TEXT = b"Timeout at 12:00 UTC\n"
SAMPLES = (
    ("report.pdf", PDF, True),
    ("notes.txt", TEXT, True),
    ("invoice.pdf", PNG_AS_PDF, False),
    ("archive.zip", b"PK\x03\x04" + bytes(32), False),
    ("tool.exe", b"MZ" + bytes(32), False),
)


@override_settings(PLATFORM_API_SECRET=HMAC_TEST_SECRET, MIDDLEWARE=HMAC_TEST_MIDDLEWARE, HMAC_ALLOW_LEGACY_SECRET=True)
class OneValidatorTests(HMACTestMixin, TestCase):
    def setUp(self) -> None:
        cache.clear()
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.media = Path(directory.name)
        self.user = User.objects.create_user(email="one@example.test", password="One-secure123!")
        self.customer = Customer.objects.create(name="One Company", status="active")
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

    def _staff_reply(self, files: list[tuple[str, bytes]]) -> HttpResponse:
        self.client.force_login(self.user)
        return self.client.post(
            reverse("tickets:reply", args=[self.ticket.pk]),
            {
                "reply": "Staff files",
                "attachments": [SimpleUploadedFile(name, content, content_type="application/pdf") for name, content in files],
            },
        )

    def test_staff_and_api_accept_and_refuse_the_same_files(self) -> None:
        for name, content, accepted in SAMPLES:
            with self.subTest(name=name):
                TicketAttachment.objects.all().delete()
                TicketComment.objects.all().delete()
                api_status = self._api_reply([(name, content)])
                api_accepted = api_status == 201
                api_rows = TicketAttachment.objects.count()
                self._staff_reply([(name, content)])
                staff_accepted = TicketAttachment.objects.count() > api_rows

                self.assertEqual((api_accepted, staff_accepted), (accepted, accepted), api_status)

    def test_a_reply_with_a_refused_file_saves_nothing_on_both_paths(self) -> None:
        files = [("report.pdf", PDF), ("invoice.pdf", PNG_AS_PDF)]

        self.assertEqual(self._api_reply(files), 400)
        response = self._staff_reply(files)

        self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
        self.assertFalse(TicketAttachment.objects.filter(ticket=self.ticket).exists())
        self.assertEqual(list(self.media.rglob("*.*")), [], "no file reaches storage")
        self.assertEqual(response.status_code, 302)
        messages = [str(message) for message in response.wsgi_request._messages]
        self.assertTrue(any("invoice.pdf" in message and "not a PDF" in message for message in messages), messages)

    def test_a_control_character_filename_never_reaches_storage_on_either_path(self) -> None:
        # The API receives the raw JSON name and refuses it. A staff upload's name is multipart:
        # Django strips non-printable characters before the view sees it, so only the clean name is stored.
        self.assertEqual(self._api_reply([("ctrl\x07.txt", TEXT)]), 400)
        self._staff_reply([("ctrl\x07.txt", TEXT)])

        self.assertEqual(list(TicketAttachment.objects.values_list("filename", flat=True)), ["ctrl.txt"])

    def test_the_staff_reply_refuses_more_files_than_the_setting_allows(self) -> None:
        SettingsService.update_setting("tickets.max_attachments_per_reply", 2, reason="test")

        self._staff_reply([(f"part{index}.txt", TEXT) for index in range(3)])

        self.assertFalse(TicketComment.objects.filter(ticket=self.ticket).exists())
        self.assertFalse(TicketAttachment.objects.exists())

    def test_the_attachment_limit_setting_drives_the_reply_check(self) -> None:
        def three_files() -> list[SimpleUploadedFile]:
            return [SimpleUploadedFile(f"part{index}.txt", TEXT) for index in range(3)]

        request = RequestFactory().post("/reply/", {"reply": "x", "attachments": three_files()})
        self.assertEqual(len(_check_reply_attachments(request)[0]), 3, "three files fit the default of five")
        SettingsService.update_setting("tickets.max_attachments_per_reply", 2, reason="test")
        request = RequestFactory().post("/reply/", {"reply": "x", "attachments": three_files()})
        accepted, reason = _check_reply_attachments(request)

        self.assertEqual(accepted, [])
        self.assertIn("at most 2 files", str(reason))

    def test_the_view_fallback_matches_the_catalog_default(self) -> None:
        self.assertEqual(
            CATALOG_BY_KEY["tickets.max_attachments_per_reply"].default, _DEFAULT_MAX_ATTACHMENTS_PER_REPLY
        )

    def test_extension_setting_cannot_add_an_unsupported_type(self) -> None:
        refused = SettingsService.update_setting("tickets.allowed_file_extensions", [".pdf", ".exe"], reason="test")
        accepted = SettingsService.update_setting("tickets.allowed_file_extensions", [".pdf", ".txt"], reason="test")

        self.assertTrue(refused.is_err())
        self.assertTrue(accepted.is_ok(), accepted)

    def test_the_extension_setting_choices_match_the_identified_types(self) -> None:
        rules = CATALOG_BY_KEY["tickets.allowed_file_extensions"].validation or {}

        self.assertEqual(set(rules["item_choices"]), set(ALLOWED_TYPES))

    def test_both_file_pickers_offer_only_identified_types(self) -> None:
        services = Path(__file__).resolve().parents[3]
        for service in ("platform", "portal"):
            with self.subTest(service=service):
                template = services / service / "templates" / "tickets" / "partials" / "status_and_comments.html"
                offered = re.findall(r'accept="([^"]+)"', template.read_text(encoding="utf-8"))
                self.assertEqual([set(value.split(",")) for value in offered], [set(ALLOWED_TYPES)])

    def test_ticket_detail_serializes_without_is_safe(self) -> None:
        self._api_reply([("notes.txt", TEXT)])
        attachment = TicketAttachment.objects.get(ticket=self.ticket)

        self.assertNotIn("is_safe", TicketAttachmentSerializer(attachment).data)
        self.assertNotIn("is_safe", {field.name for field in TicketAttachment._meta.get_fields()})
        self.assertNotIn("virus_scan_result", {field.name for field in TicketAttachment._meta.get_fields()})
