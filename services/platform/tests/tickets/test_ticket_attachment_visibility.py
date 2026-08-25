"""#278 follow-up: attachment visibility must follow the parent comment on EVERY surface.

The unification routed comment visibility through one ``is_public`` predicate, but two
attachment surfaces stayed out of sync:

- ``ticket_attachment_download_api`` gated only on ticket ownership + ``is_safe`` — a
  customer could enumerate sequential attachment ids on their OWN ticket and download
  files attached to non-public (internal) staff comments that no list/detail response
  ever shows.
- Comment-less (ticket-level) attachments were dropped by every ``comment__is_public``
  filter (LEFT-join three-valued logic) yet still served by both download endpoints —
  "doesn't exist" on one surface, "downloadable" on another.

These tests create rows where ``comment_type`` and ``is_public`` DISAGREE (the only
shape that can distinguish the predicates) and pin the unified rule everywhere:
an attachment is customer-visible iff it has no parent comment or its parent comment
is public.
"""

import json
import shutil
import tempfile
from unittest.mock import patch

from django.core.files.base import ContentFile
from django.test import Client, RequestFactory, TestCase, override_settings
from django.urls import reverse

from apps.api.tickets.serializers import TicketDetailSerializer, TicketListSerializer
from apps.api.tickets.views import (
    _annotate_visible_counts,
    customer_ticket_detail_api,
    ticket_attachment_download_api,
)
from apps.customers.models import Customer
from apps.tickets.models import Ticket, TicketAttachment, TicketComment
from apps.users.models import CustomerMembership, User


def _attachment(ticket: Ticket, comment: TicketComment | None, marker: bytes) -> TicketAttachment:
    return TicketAttachment.objects.create(
        ticket=ticket,
        comment=comment,
        file=ContentFile(marker, name="evidence.txt"),
        filename="evidence.txt",
        file_size=len(marker),
        content_type="text/plain",
        is_safe=True,
    )


@override_settings(DISABLE_AUDIT_SIGNALS=True)
class AttachmentVisibilityBaseTest(TestCase):
    """Shared fixture: one ticket with public / non-public / comment-less attachments.

    MEDIA_ROOT is a PER-CLASS tempdir, never module-level: under Linux's fork start
    method, ``manage.py test --parallel`` workers inherit the parent's imported module,
    so a module-level ``mkdtemp`` is one shared directory across every concurrently
    running class — and the first ``tearDownClass`` rmtree deletes the files out from
    under the others (masked on macOS, whose spawn workers re-import per process).
    """

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls._media_root = tempfile.mkdtemp(prefix="praho-attach-vis-")
        cls.enterClassContext(override_settings(MEDIA_ROOT=cls._media_root))
        cls.addClassCleanup(shutil.rmtree, cls._media_root, ignore_errors=True)

    def setUp(self):
        self.customer_user = User.objects.create_user(email="cust-attvis@example.com", password="testpass123")
        self.customer = Customer.objects.create(
            name="AttachVis SRL",
            customer_type="company",
            status="active",
            primary_email=self.customer_user.email,
        )
        CustomerMembership.objects.create(
            user=self.customer_user, customer=self.customer, role="owner", is_primary=True, is_active=True
        )
        self.ticket = Ticket.objects.create(
            customer=self.customer,
            title="Attachment visibility",
            description="d",
            status="open",
            created_by=self.customer_user,
        )
        self.public_comment = TicketComment.objects.create(
            ticket=self.ticket, content="public reply", comment_type="support", is_public=True
        )
        # The divergent shape: comment_type says customer-facing, is_public says hidden.
        self.nonpublic_comment = TicketComment.objects.create(
            ticket=self.ticket, content="internal cost breakdown", comment_type="support", is_public=False
        )
        self.att_public = _attachment(self.ticket, self.public_comment, b"PUBLIC-BYTES")
        self.att_hidden = _attachment(self.ticket, self.nonpublic_comment, b"STAFF-ONLY-BYTES")
        self.att_ticket_level = _attachment(self.ticket, None, b"TICKET-LEVEL-BYTES")


class ApiAttachmentDownloadVisibilityTests(AttachmentVisibilityBaseTest):
    """POST /api/tickets/{t}/attachments/{a}/download/ must honor comment visibility."""

    def _download(self, attachment_id: int):
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/attachments/{attachment_id}/download/",
            data=json.dumps({"customer_id": self.customer.pk, "action": "download_attachment"}),
            content_type="application/json",
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            return ticket_attachment_download_api(request, ticket_id=self.ticket.pk, attachment_id=attachment_id)

    def test_nonpublic_comment_attachment_is_not_downloadable(self):
        """THE #278 hole: hidden from every list, but served on direct (enumerable) id.

        DRF's dispatch converts the view's Http404 into a 404 Response.
        """
        response = self._download(self.att_hidden.pk)
        self.assertEqual(response.status_code, 404)

    def test_public_comment_attachment_downloads(self):
        response = self._download(self.att_public.pk)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"PUBLIC-BYTES")

    def test_ticket_level_attachment_downloads(self):
        """comment IS NULL == ticket-level == customer-visible (matches the web endpoint)."""
        response = self._download(self.att_ticket_level.pk)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.content, b"TICKET-LEVEL-BYTES")

    def test_cross_customer_ownership_guard_unchanged(self):
        other = Customer.objects.create(
            name="Other SRL", customer_type="company", status="active", primary_email="other-attvis@example.com"
        )
        request = RequestFactory().post("/api/tickets/x/attachments/y/download/", data="{}",
                                        content_type="application/json")
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(other, None)):
            response = ticket_attachment_download_api(
                request, ticket_id=self.ticket.pk, attachment_id=self.att_public.pk
            )
        self.assertEqual(response.status_code, 404)


class WebAttachmentDownloadDivergentCaseTests(AttachmentVisibilityBaseTest):
    """Lock in the web fix for the shape where the OLD predicate and is_public disagree.

    Pre-#278 the web gate was ``comment_type == "internal"`` — a non-public *support*
    comment's attachment sailed through. The only pre-existing test used an
    internal+non-public comment, where old and new predicates agree, so it could not
    catch a regression back to comment_type.
    """

    def test_nonpublic_support_attachment_denied_for_customer(self):
        client = Client()
        client.login(email="cust-attvis@example.com", password="testpass123")
        response = client.get(reverse("tickets:download_attachment", args=[self.att_hidden.pk]))
        self.assertEqual(response.status_code, 403)

    def test_public_and_ticket_level_attachments_allowed_for_customer(self):
        client = Client()
        client.login(email="cust-attvis@example.com", password="testpass123")
        self.assertEqual(client.get(reverse("tickets:download_attachment", args=[self.att_public.pk])).status_code, 200)
        self.assertEqual(
            client.get(reverse("tickets:download_attachment", args=[self.att_ticket_level.pk])).status_code, 200
        )


class VisibleCountParityTests(AttachmentVisibilityBaseTest):
    """Counts/lists must agree with what the download endpoints actually serve.

    Also exercises the ``_annotate_visible_counts`` path itself — the serializer's
    annotation branch was previously only ever tested through its un-annotated
    fallback — on a ticket holding multiple comments AND multiple attachments, the
    only shape that would expose cartesian-join fan-out if ``distinct=`` regressed.
    """

    def test_customer_counts_include_ticket_level_attachment(self):
        # Visible: att_public + att_ticket_level. Hidden: att_hidden. Comments: 1 of 2 public.
        data = TicketListSerializer(self.ticket, context={"for_customer": True}).data
        self.assertEqual(data["comments_count"], 1)
        self.assertEqual(data["attachments_count"], 2)

    def test_annotated_counts_match_fallback_counts(self):
        annotated = _annotate_visible_counts(Ticket.objects.filter(pk=self.ticket.pk)).get()
        data = TicketListSerializer(annotated, context={"for_customer": True}).data
        self.assertEqual(data["comments_count"], 1)
        self.assertEqual(data["attachments_count"], 2)

    def test_detail_serializer_lists_ticket_level_attachment(self):
        data = TicketDetailSerializer(self.ticket, context={"for_customer": True}).data
        listed = {a["filename"] for a in data["attachments"]}
        self.assertEqual(len(data["attachments"]), 2)
        self.assertEqual(listed, {"evidence.txt"})
        listed_ids = {a["id"] for a in data["attachments"]}
        self.assertEqual(listed_ids, {self.att_public.pk, self.att_ticket_level.pk})

    def test_staff_serializer_counts_everything(self):
        data = TicketListSerializer(self.ticket).data
        self.assertEqual(data["comments_count"], 2)
        self.assertEqual(data["attachments_count"], 3)

    def test_staff_counts_survive_annotation(self):
        """A staff view reusing _annotate_visible_counts must NOT silently get filtered counts."""
        annotated = _annotate_visible_counts(Ticket.objects.filter(pk=self.ticket.pk)).get()
        data = TicketListSerializer(annotated).data  # no for_customer context
        self.assertEqual(data["comments_count"], 2)
        self.assertEqual(data["attachments_count"], 3)

    def test_public_internal_comment_is_visible(self):
        """The fourth divergent quadrant: comment_type='internal' with is_public=True.

        is_public is THE predicate — a public comment is visible whatever its type.
        Without this fixture, re-coupling the predicate to comment_type (e.g. adding
        ~Q(comment_type='internal') "for safety") would ship green through every suite.
        """
        public_internal = TicketComment.objects.create(
            ticket=self.ticket, content="PUBLIC-INTERNAL-QUADRANT", comment_type="internal", is_public=True
        )
        att = _attachment(self.ticket, public_internal, b"QUADRANT-BYTES")

        visible = TicketComment.visible_to(
            TicketComment.objects.filter(ticket=self.ticket), self.customer_user
        ).values_list("content", flat=True)
        self.assertIn("PUBLIC-INTERNAL-QUADRANT", visible)

        data = TicketListSerializer(self.ticket, context={"for_customer": True}).data
        self.assertEqual(data["comments_count"], 2)  # public support + public internal
        self.assertEqual(data["attachments_count"], 3)  # + the quadrant attachment

        detail = TicketDetailSerializer(self.ticket, context={"for_customer": True}).data
        self.assertIn(att.pk, {a["id"] for a in detail["attachments"]})


class ApiDetailEndpointPrefetchTests(AttachmentVisibilityBaseTest):
    """Drive the REAL customer_ticket_detail_api endpoint, not a hand-built serializer.

    The endpoint feeds the serializer through Prefetch querysets
    (apps/api/tickets/views.py) — a prefetch regressing to a bare
    ``comment__is_public=True`` filter would silently drop ticket-level attachments
    from the live API while direct-serializer tests stay green, because
    ``obj.attachments.all()`` on an un-prefetched instance re-queries the DB.
    """

    def test_detail_endpoint_payload_matches_visibility_rules(self):
        request = RequestFactory().post(
            f"/api/tickets/{self.ticket.pk}/",
            data=json.dumps({"customer_id": self.customer.pk, "action": "get_ticket_detail"}),
            content_type="application/json",
        )
        with patch("apps.api.secure_auth.get_authenticated_customer", return_value=(self.customer, None)):
            response = customer_ticket_detail_api(request, ticket_id=self.ticket.pk)

        self.assertEqual(response.status_code, 200)
        ticket_data = response.data["data"]["ticket"]
        self.assertEqual({c["content"] for c in ticket_data["comments"]}, {"public reply"})
        self.assertEqual(
            {a["id"] for a in ticket_data["attachments"]},
            {self.att_public.pk, self.att_ticket_level.pk},  # ticket-level included, hidden excluded
        )
