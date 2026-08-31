"""Regression coverage for ticket API error transparency (#471)."""

import json
import logging
import shutil
import tempfile
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.http import HttpResponse as DjangoHttpResponse
from django.test import RequestFactory, TestCase, override_settings

from apps.api.tickets.views import customer_tickets_api, ticket_attachment_download_api
from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment
from apps.users.models import CustomerMembership, User


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class TicketsAPIErrorHandlingTests(TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        super().setUpClass()
        cls._media_root = tempfile.mkdtemp(prefix="praho-ticket-api-errors-")
        cls.enterClassContext(override_settings(MEDIA_ROOT=cls._media_root))
        cls.addClassCleanup(shutil.rmtree, cls._media_root, ignore_errors=True)

    def setUp(self) -> None:
        self.user = User.objects.create_user(email="ticket-errors@example.com", password="testpass123")
        self.customer = Customer.objects.create(
            name="Ticket Errors SRL",
            customer_type="company",
            status="active",
            primary_email=self.user.email,
        )
        CustomerMembership.objects.create(
            user=self.user,
            customer=self.customer,
            role="owner",
            is_primary=True,
            is_active=True,
        )
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            created_by=self.user,
            title="Ticket API error handling",
            description="Exercise API failure boundaries",
            status="open",
        )
        self.missing_storage_name = "tickets/attachments/missing-471.txt"
        self.missing_attachment = TicketAttachment(
            ticket=self.ticket,
            filename="missing-471.txt",
            file_size=17,
            content_type="text/plain",
            is_safe=True,
        )
        self.missing_attachment.file.name = self.missing_storage_name
        self.missing_attachment.save()

    def _download(self, attachment_id: int):
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/attachments/{attachment_id}/download/",
            data=json.dumps({"customer_id": self.customer.pk, "action": "download_attachment"}),
            content_type="application/json",
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return ticket_attachment_download_api(
                request,
                ticket_id=self.ticket.pk,
                attachment_id=attachment_id,
            )

    def _tickets_list(self):
        request = RequestFactory().post(
            "/api/tickets/",
            data=json.dumps({"customer_id": self.customer.pk, "action": "get_tickets"}),
            content_type="application/json",
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return customer_tickets_api(request)

    def _healthy_attachment(self) -> tuple[TicketAttachment, bytes]:
        content = b"HEALTHY-ATTACHMENT-BYTES"
        attachment = TicketAttachment.objects.create(
            ticket=self.ticket,
            file=ContentFile(content, name="healthy.txt"),
            filename="healthy.txt",
            file_size=len(content),
            content_type="text/plain",
            is_safe=True,
        )
        return attachment, content

    def test_missing_storage_file_returns_404_without_leaking_details_and_logs_warning(self) -> None:
        with self.assertLogs("apps.api.tickets.views", level=logging.WARNING) as captured:
            response = self._download(self.missing_attachment.pk)

        self.assertEqual(response.status_code, 404)

        warning_records = [record for record in captured.records if record.levelno == logging.WARNING]
        self.assertEqual(len(warning_records), 1)
        self.assertIn(str(self.missing_attachment.pk), warning_records[0].getMessage())
        self.assertIn(str(self.ticket.ticket_number), warning_records[0].getMessage())

        response.render()
        body = response.content.decode()
        self.assertNotIn(self.missing_storage_name, body)
        self.assertNotIn("FileNotFoundError", body)
        self.assertNotIn("No such file or directory", body)

    def test_json_endpoint_error_response_includes_traceback_log(self) -> None:
        with (
            patch(
                "apps.api.tickets.views.TicketListSerializer",
                side_effect=RuntimeError("serializer exploded"),
            ),
            self.assertLogs("apps.api.tickets.views", level=logging.ERROR) as captured,
        ):
            response = self._tickets_list()

        self.assertEqual(response.status_code, 500)
        self.assertEqual(
            response.data,
            {"success": False, "error": "Unable to fetch tickets"},
        )

        error_records = [record for record in captured.records if record.levelno == logging.ERROR]
        self.assertEqual(len(error_records), 1)
        self.assertIsNotNone(error_records[0].exc_info)

    def test_download_non_oserror_stays_generic_500_with_traceback(self) -> None:
        attachment, content = self._healthy_attachment()

        def response_factory(response_content=b"", *args, **kwargs):
            if response_content == content:
                raise RuntimeError("response construction failed")
            return DjangoHttpResponse(response_content, *args, **kwargs)

        with (
            patch("apps.api.tickets.views.HttpResponse", side_effect=response_factory),
            self.assertLogs("apps.api.tickets.views", level=logging.ERROR) as captured,
        ):
            response = self._download(attachment.pk)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.content, b"Unable to download attachment")

        error_records = [record for record in captured.records if record.levelno == logging.ERROR]
        self.assertEqual(len(error_records), 1)
        self.assertIsNotNone(error_records[0].exc_info)

    def test_missing_attachment_row_returns_404(self) -> None:
        response = self._download(self.missing_attachment.pk + 1_000_000)

        self.assertEqual(response.status_code, 404)

    def test_unsafe_attachment_returns_404(self) -> None:
        attachment = TicketAttachment(
            ticket=self.ticket,
            filename="unsafe.txt",
            file_size=6,
            content_type="text/plain",
            is_safe=False,
        )
        attachment.file.name = "tickets/attachments/unsafe-not-written.txt"
        attachment.save()

        response = self._download(attachment.pk)

        self.assertEqual(response.status_code, 404)

    def test_healthy_attachment_downloads_with_headers(self) -> None:
        attachment, content = self._healthy_attachment()

        response = self._download(attachment.pk)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, content)
        self.assertEqual(response["Content-Disposition"], 'attachment; filename="healthy.txt"')
