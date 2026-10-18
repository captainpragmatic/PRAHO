"""Attachment downloads are private, keep any filename intact, and leave an audit trail.

Both download paths (the staff and customer page, and the customer API the Portal calls) answer
`private, no-store` with an RFC 6266 disposition, and each download is audited by attachment and
ticket id. The audit event holds no filename, because a filename can carry a person's data and the
audit log outlives the ticket.
"""

from __future__ import annotations

import json
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.test import Client, RequestFactory
from django.urls import reverse

from apps.api.tickets.views import ticket_attachment_download_api
from apps.audit.models import AuditEvent
from apps.tickets.models import TicketAttachment
from tests.tickets.test_ticket_attachment_visibility import AttachmentVisibilityBaseTest


class AttachmentDownloadHeadersAndAuditTests(AttachmentVisibilityBaseTest):
    def _web_download(self, attachment: TicketAttachment):
        client = Client()
        client.force_login(self.customer_user)
        return client.get(reverse("tickets:download_attachment", args=[attachment.pk]))

    def _api_download(self, attachment: TicketAttachment):
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/attachments/{attachment.pk}/download/",
            data=json.dumps({"customer_id": self.customer.pk, "action": "download_attachment"}),
            content_type="application/json",
        )
        def authenticate(request: object, roles: object = None) -> tuple[object, None]:
            # As the real check does: it records the verified portal member on the request.
            request._customer_user = self.customer_user  # type: ignore[attr-defined]  # request-scoped auth context, as secure_auth sets it
            return self.customer, None

        with patch("apps.api.secure_auth.get_authenticated_customer", side_effect=authenticate):
            return ticket_attachment_download_api(request, ticket_id=self.ticket.pk, attachment_id=attachment.pk)

    def test_staff_and_api_downloads_are_private_no_store(self) -> None:
        for response in (self._web_download(self.att_public), self._api_download(self.att_public)):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response["Cache-Control"], "private, no-store")
            self.assertEqual(response["Content-Disposition"], 'attachment; filename="evidence.txt"')

    def test_non_latin1_filename_round_trips(self) -> None:
        attachment = TicketAttachment.objects.create(
            ticket=self.ticket,
            comment=self.public_comment,
            file=ContentFile(b"bytes", name="factura.txt"),
            filename="Factură Ștefan.txt",
            file_size=5,
            content_type="text/plain",
        )
        for response in (self._web_download(attachment), self._api_download(attachment)):
            self.assertEqual(response.status_code, 200)
            self.assertEqual(
                response["Content-Disposition"], "attachment; filename*=utf-8''Factur%C4%83%20%C8%98tefan.txt"
            )

    def test_attachment_download_is_audited_without_filename(self) -> None:
        self._web_download(self.att_public)
        self._api_download(self.att_public)

        events = list(AuditEvent.objects.filter(action="ticket_attachment_downloaded").order_by("timestamp"))
        self.assertEqual(len(events), 2)
        # Both name the member who downloaded, the API one included: a customer can have several.
        self.assertEqual([(event.user, event.metadata["channel"]) for event in events],
                         [(self.customer_user, "web"), (self.customer_user, "api")])
        for event in events:
            self.assertEqual(event.metadata["attachment_id"], self.att_public.pk)
            self.assertEqual(event.metadata["ticket_id"], str(self.ticket.pk))
            stored = json.dumps([event.description, event.metadata, event.old_values, event.new_values])
            self.assertNotIn("evidence", stored)
