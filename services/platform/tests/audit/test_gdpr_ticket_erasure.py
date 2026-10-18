"""GDPR erasure reaches the person's support tickets (row 74, owner decision OF4).

A ticket the person raised alone is theirs: its text, contact details, comments and attachment
files go. A ticket that holds another member's evidence keeps that member's content and loses only
the person's identity. A historical reply with no author is ambiguous: its content stays, and only
the person's name and email are removed from it. API replies record the member who sent them, so
the next erasure can tell one member from another.
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.test import RequestFactory, TestCase, override_settings

from apps.api.tickets.views import customer_ticket_reply_api
from apps.audit.services import GDPRDeletionService
from apps.customers.models import Customer
from apps.tickets.models import SupportCategory, Ticket, TicketAttachment, TicketComment
from apps.users.models import CustomerMembership, User

EMAIL = "ioana.rowe@example.test"
OTHER_EMAIL = "mihai.dobre@example.test"
TEXT = b"Timeout at 12:00 UTC\n"


class TicketErasureTests(TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.media = Path(directory.name)
        self.person = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana", last_name="Rowe")
        self.other = User.objects.create_user(
            email=OTHER_EMAIL, password="x-pass-123", first_name="Mihai", last_name="Dobre"
        )
        self.customer = Customer.objects.create(name="Rowe Dobre SRL", customer_type="company", status="active")
        for user, role in ((self.person, "owner"), (self.other, "tech")):
            CustomerMembership.objects.create(user=user, customer=self.customer, role=role, is_active=True)
        self.category = SupportCategory.objects.create(name="General", name_en="General")

    def _ticket(self, created_by: User, **fields: object) -> Ticket:
        return Ticket.objects.create(
            customer=self.customer, created_by=created_by, category=self.category, status="open", **fields
        )

    def _attach(self, ticket: Ticket, comment: TicketComment, uploader: User) -> TicketAttachment:
        attachment = TicketAttachment(
            ticket=ticket,
            comment=comment,
            filename="Ioana Rowe contract.txt",
            file_size=len(TEXT),
            content_type="text/plain",
            uploaded_by=uploader,
        )
        attachment.file.save("ticket_upload.txt", ContentFile(TEXT), save=False)
        attachment.save()
        return attachment

    def _erase(self) -> None:
        request = GDPRDeletionService.create_deletion_request(user=self.person, deletion_type="anonymize").unwrap()
        with self.captureOnCommitCallbacks(execute=True):
            self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_ok())

    def _files(self) -> list[Path]:
        return [path for path in self.media.rglob("*") if path.is_file()]

    def test_erasure_anonymises_the_persons_tickets_and_deletes_their_files(self) -> None:
        ticket = self._ticket(
            self.person,
            title="Ioana Rowe cannot log in",
            description="Hello, I am Ioana Rowe, phone +40722123456",
            contact_person="Ioana Rowe",
            contact_email=EMAIL,
            contact_phone="+40722123456",
            satisfaction_comment="Thanks, Ioana",
        )
        mine = TicketComment.objects.create(
            ticket=ticket,
            content="My CNP is 2900101123456",
            comment_type="customer",
            author=self.person,
            author_name="Ioana Rowe",
            author_email=EMAIL,
        )
        TicketComment.objects.create(ticket=ticket, content="Hi Ioana, fixed.", comment_type="support")
        self._attach(ticket, mine, self.person)
        self.assertTrue(self._files())

        self._erase()

        ticket.refresh_from_db()
        text = " ".join(
            [
                ticket.title,
                ticket.description,
                ticket.contact_person,
                ticket.contact_email,
                ticket.contact_phone,
                ticket.satisfaction_comment,
            ]
            + [f"{c.content} {c.author_name} {c.author_email}" for c in ticket.comments.all()]
        ).lower()
        for identifier in ("ioana", "rowe", EMAIL, "+40722123456", "2900101123456"):
            self.assertNotIn(identifier, text)
        self.assertFalse(TicketAttachment.objects.filter(ticket=ticket).exists())
        self.assertEqual(self._files(), [])

    def test_erasure_keeps_other_members_ticket_content(self) -> None:
        ticket = self._ticket(
            self.other,
            title="Server down",
            description="Mihai here: the server is down",
            contact_person="Mihai Dobre",
            contact_email=OTHER_EMAIL,
        )
        theirs = TicketComment.objects.create(
            ticket=ticket,
            content="Still down at 14:00",
            comment_type="customer",
            author=self.other,
            author_name="Mihai Dobre",
            author_email=OTHER_EMAIL,
        )
        mine = TicketComment.objects.create(
            ticket=ticket,
            content="Same for me since noon",
            comment_type="customer",
            author=self.person,
            author_name="Ioana Rowe",
            author_email=EMAIL,
        )
        self._attach(ticket, theirs, self.other)

        self._erase()

        ticket.refresh_from_db()
        theirs.refresh_from_db()
        mine.refresh_from_db()
        self.assertEqual((ticket.title, ticket.description), ("Server down", "Mihai here: the server is down"))
        self.assertEqual((ticket.contact_person, ticket.contact_email), ("Mihai Dobre", OTHER_EMAIL))
        self.assertEqual((theirs.content, theirs.author_email), ("Still down at 14:00", OTHER_EMAIL))
        self.assertEqual(mine.content, "Same for me since noon")
        self.assertEqual((mine.author_name, mine.author_email), ("", ""))
        self.assertTrue(TicketAttachment.objects.filter(ticket=ticket).exists())
        self.assertTrue(self._files())

    def test_ambiguous_historical_reply_keeps_content_and_loses_only_identity(self) -> None:
        ticket = self._ticket(self.other, title="Billing question", description="Which plan?")
        historical = TicketComment.objects.create(
            ticket=ticket,
            content="The invoice address is wrong",
            comment_type="customer",
            author=None,
            author_name="Ioana Rowe",
            author_email=EMAIL.upper(),
        )

        self._erase()

        historical.refresh_from_db()
        self.assertEqual(historical.content, "The invoice address is wrong")
        self.assertEqual((historical.author_name, historical.author_email), ("", ""))

    def test_a_ticket_with_an_unknown_customer_reply_is_not_treated_as_the_persons_alone(self) -> None:
        ticket = self._ticket(self.person, title="Ioana's ticket", description="Shared problem")
        TicketComment.objects.create(
            ticket=ticket,
            content="Seen it too",
            comment_type="customer",
            author=None,
            author_name="Someone",
            author_email="someone@example.test",
        )

        self._erase()

        ticket.refresh_from_db()
        self.assertEqual(ticket.comments.get(author_email="someone@example.test").content, "Seen it too")

    def test_a_failed_erasure_leaves_the_tickets_and_files(self) -> None:
        ticket = self._ticket(self.person, title="Ioana Rowe cannot log in", description="Ioana here")
        comment = TicketComment.objects.create(
            ticket=ticket, content="Hi", comment_type="customer", author=self.person, author_email=EMAIL
        )
        self._attach(ticket, comment, self.person)
        request = GDPRDeletionService.create_deletion_request(user=self.person, deletion_type="anonymize").unwrap()

        with (
            patch.object(GDPRDeletionService, "_sweep_erasure", side_effect=RuntimeError("sweep failed")),
            self.captureOnCommitCallbacks(execute=True),
        ):
            self.assertTrue(GDPRDeletionService.process_deletion_request(request).is_err())

        ticket.refresh_from_db()
        self.assertEqual(ticket.title, "Ioana Rowe cannot log in")
        self.assertTrue(TicketAttachment.objects.filter(ticket=ticket).exists())
        self.assertTrue(self._files())


class ApiRepliesNameTheirAuthorTests(TestCase):
    def setUp(self) -> None:
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        setting = override_settings(MEDIA_ROOT=directory.name)
        setting.enable()
        self.addCleanup(setting.disable)
        self.first = User.objects.create_user(email=EMAIL, password="x-pass-123", first_name="Ioana")
        self.second = User.objects.create_user(email=OTHER_EMAIL, password="x-pass-123", first_name="Mihai")
        self.customer = Customer.objects.create(name="Rowe Dobre SRL", customer_type="company", status="active")
        for user in (self.first, self.second):
            CustomerMembership.objects.create(user=user, customer=self.customer, role="owner", is_active=True)
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            created_by=self.first,
            title="Shared",
            description="x",
            status="open",
            contact_person="Ioana",
            contact_email=EMAIL,
        )

    def _reply(self, user: User, content: str, attachments: list[dict[str, str]] | None = None) -> None:
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/reply/",
            data=json.dumps({"content": content, "user_id": user.pk, "attachments": attachments or []}),
            content_type="application/json",
        )

        def authenticate(request: object, **_: object) -> tuple[Customer, None]:
            request._customer_user = user  # type: ignore[attr-defined]  # as get_authenticated_customer sets it
            return self.customer, None

        with patch("apps.api.secure_auth.get_authenticated_customer", side_effect=authenticate):
            response = customer_ticket_reply_api(request, ticket_id=self.ticket.pk)
        self.assertEqual(response.status_code, 201, getattr(response, "data", None))

    def test_two_members_replying_through_the_api_are_attributed_to_each_member(self) -> None:
        upload = [{"filename": "log.txt", "content": base64.b64encode(TEXT).decode()}]
        self._reply(self.first, "From Ioana")
        self._reply(self.second, "From Mihai", attachments=upload)

        first = TicketComment.objects.get(ticket=self.ticket, content="From Ioana")
        second = TicketComment.objects.get(ticket=self.ticket, content="From Mihai")
        self.assertEqual((first.author, first.author_email), (self.first, EMAIL))
        self.assertEqual((second.author, second.author_email), (self.second, OTHER_EMAIL))
        self.assertEqual(TicketAttachment.objects.get(comment=second).uploaded_by, self.second)
